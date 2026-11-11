//! `zeno-license` — the `EnterpriseLicenseKey` of the Zeno–Llull products.
//!
//! A license is a short token signed by the vendor with Ed25519:
//!
//! ```text
//! zl1.<base64url(customer|plan|expires_at)>.<base64url(signature)>
//! ```
//!
//! Verification needs only the vendor's 32-byte *public* key, so it can run
//! offline inside an SDK or statelessly inside the Cloud Prover (the token is
//! the API credential; no key database is required). The private key never
//! leaves the vendor.
#![cfg_attr(not(feature = "cli"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const PREFIX: &str = "zl1";
const CONTEXT: &[u8] = b"zeno-llull/license/v1\0";

/// What a license grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// Customer identifier; usage is metered per customer.
    pub customer: String,
    /// Commercial plan, e.g. `enterprise` or `pay-per-proof`.
    pub plan: String,
    /// Expiry as Unix time in seconds.
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LicenseError {
    Malformed,
    BadSignature,
    Expired { expired_at: u64 },
    InvalidKey,
    InvalidField,
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed license key"),
            Self::BadSignature => write!(f, "license signature is invalid"),
            Self::Expired { expired_at } => write!(f, "license expired at unix time {expired_at}"),
            Self::InvalidKey => write!(f, "invalid vendor key"),
            Self::InvalidField => write!(f, "customer and plan must be non-empty and free of '|'"),
        }
    }
}

fn signed_message(payload: &[u8]) -> Vec<u8> {
    [CONTEXT, payload].concat()
}

/// Parses a hex-encoded 32-byte key.
pub fn parse_key_hex(hex: &str) -> Result<[u8; 32], LicenseError> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(LicenseError::InvalidKey);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| LicenseError::InvalidKey)?;
    }
    Ok(out)
}

/// Hex encoding of a key.
pub fn key_to_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Vendor side: signs a license with the private key.
pub fn issue(private_key: &[u8; 32], claims: &Claims) -> Result<String, LicenseError> {
    let valid = |s: &str| !s.is_empty() && !s.contains('|') && s.len() <= 128;
    if !valid(&claims.customer) || !valid(&claims.plan) {
        return Err(LicenseError::InvalidField);
    }
    let payload = format!("{}|{}|{}", claims.customer, claims.plan, claims.expires_at);
    let signature = SigningKey::from_bytes(private_key).sign(&signed_message(payload.as_bytes()));
    Ok(format!(
        "{PREFIX}.{}.{}",
        B64.encode(payload.as_bytes()),
        B64.encode(signature.to_bytes())
    ))
}

/// The public key matching a private key.
pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(private_key)
        .verifying_key()
        .to_bytes()
}

/// Verifies a license against the vendor's public key at time `now`
/// (Unix seconds) and returns what it grants.
pub fn verify(token: &str, vendor_public_key: &[u8; 32], now: u64) -> Result<Claims, LicenseError> {
    let mut parts = token.trim().split('.');
    let (Some(PREFIX), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(LicenseError::Malformed);
    };
    let payload = B64.decode(payload).map_err(|_| LicenseError::Malformed)?;
    let signature = B64.decode(signature).map_err(|_| LicenseError::Malformed)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| LicenseError::Malformed)?;

    let key = VerifyingKey::from_bytes(vendor_public_key).map_err(|_| LicenseError::InvalidKey)?;
    key.verify_strict(
        &signed_message(&payload),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| LicenseError::BadSignature)?;

    // Only parse fields of an authenticated payload.
    let text = core::str::from_utf8(&payload).map_err(|_| LicenseError::Malformed)?;
    let mut fields = text.split('|');
    let (Some(customer), Some(plan), Some(expires), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(LicenseError::Malformed);
    };
    let expires_at: u64 = expires.parse().map_err(|_| LicenseError::Malformed)?;
    if now >= expires_at {
        return Err(LicenseError::Expired {
            expired_at: expires_at,
        });
    }
    Ok(Claims {
        customer: customer.to_string(),
        plan: plan.to_string(),
        expires_at,
    })
}

/// Vendor side: generates a fresh `(private, public)` key pair.
#[cfg(feature = "cli")]
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    (key.to_bytes(), key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Claims {
        Claims {
            customer: "acme-bank".into(),
            plan: "enterprise".into(),
            expires_at: 2_000_000_000,
        }
    }

    #[test]
    fn issue_and_verify() {
        let (sk, pk) = generate_keypair();
        assert_eq!(public_key(&sk), pk);
        let token = issue(&sk, &claims()).unwrap();
        assert_eq!(verify(&token, &pk, 1_900_000_000).unwrap(), claims());
        assert_eq!(parse_key_hex(&key_to_hex(&pk)).unwrap(), pk);
    }

    #[test]
    fn rejects_expired_forged_and_malformed() {
        let (sk, pk) = generate_keypair();
        let (other_sk, other_pk) = generate_keypair();
        let token = issue(&sk, &claims()).unwrap();

        assert_eq!(
            verify(&token, &pk, 2_000_000_000),
            Err(LicenseError::Expired {
                expired_at: 2_000_000_000
            })
        );
        // Signed by someone else, or checked against another vendor key.
        assert_eq!(
            verify(&token, &other_pk, 0),
            Err(LicenseError::BadSignature)
        );
        let forged = issue(&other_sk, &claims()).unwrap();
        assert_eq!(verify(&forged, &pk, 0), Err(LicenseError::BadSignature));

        // Extending the expiry without the private key breaks the signature.
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!(
            "zl1.{}.{}",
            B64.encode(b"acme-bank|enterprise|9999999999"),
            parts[2]
        );
        assert_eq!(verify(&tampered, &pk, 0), Err(LicenseError::BadSignature));

        for bad in [
            "",
            "zl1",
            "zl1.a.b",
            "zl2.a.b",
            "x.y.z.w",
            &token[..token.len() - 3],
        ] {
            assert!(verify(bad, &pk, 0).is_err(), "{bad}");
        }
        assert!(issue(
            &sk,
            &Claims {
                customer: "a|b".into(),
                ..claims()
            }
        )
        .is_err());
        assert!(issue(
            &sk,
            &Claims {
                plan: String::new(),
                ..claims()
            }
        )
        .is_err());
        assert!(parse_key_hex("abc").is_err());
    }
}
