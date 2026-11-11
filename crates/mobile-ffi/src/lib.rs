//! `mobile-ffi` — the native Zeno–Llull SDK for iOS (Swift), Android
//! (Kotlin) and Python, generated from this single Rust API with UniFFI.
//!
//! ```python
//! prover = Prover(r1cs_bytes, ["3"])
//! prover.prove_step(wtns_bytes)          # once per step
//! proof = prover.finalize()              # succinct zero-knowledge proof
//! statement = Verifier(r1cs_bytes).verify(proof)
//! ```

use ark_ff::PrimeField;
use sdk_bindings::{circom::SdkError, CircomIvc, CircomParams, Fr};
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

uniffi::setup_scaffolding!();

/// Any failure of the SDK, with a human-readable reason.
#[derive(Debug, uniffi::Error)]
pub enum ZenoError {
    /// The circuit, witness or state passed in is not usable.
    InvalidInput { reason: String },
    /// A proof or prover state failed verification.
    VerificationFailed { reason: String },
    /// The license key is invalid or expired.
    License { reason: String },
}

impl std::fmt::Display for ZenoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput { reason }
            | Self::VerificationFailed { reason }
            | Self::License { reason } => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for ZenoError {}

impl From<SdkError> for ZenoError {
    fn from(e: SdkError) -> Self {
        let reason = e.to_string();
        match e {
            SdkError::Ivc(_) | SdkError::MalformedProof => Self::VerificationFailed { reason },
            _ => Self::InvalidInput { reason },
        }
    }
}

fn parse_state(z: &[String]) -> Result<Vec<Fr>, ZenoError> {
    z.iter()
        .map(|s| {
            Fr::from_str(s).map_err(|_| ZenoError::InvalidInput {
                reason: format!("`{s}` is not a decimal field element"),
            })
        })
        .collect()
}

fn state_strings(z: &[Fr]) -> Vec<String> {
    z.iter().map(|f| f.into_bigint().to_string()).collect()
}

/// The public statement proven by a proof: `zi = F^steps(z0)`.
#[derive(uniffi::Record)]
pub struct Statement {
    pub steps: u64,
    pub z0: Vec<String>,
    pub zi: Vec<String>,
}

/// What a license key grants.
#[derive(uniffi::Record)]
pub struct License {
    pub customer: String,
    pub plan: String,
    pub expires_at: u64,
}

/// Incremental prover for a Circom step circuit (BN254/Grumpkin).
#[derive(uniffi::Object)]
pub struct Prover {
    inner: Mutex<CircomIvc>,
}

#[uniffi::export]
impl Prover {
    /// `r1cs`: the compiled step circuit; `z0`: initial state as decimal strings.
    #[uniffi::constructor]
    pub fn new(r1cs: Vec<u8>, z0: Vec<String>) -> Result<Self, ZenoError> {
        let ivc = CircomIvc::new(&r1cs, parse_state(&z0)?)?;
        Ok(Self {
            inner: Mutex::new(ivc),
        })
    }

    /// Folds one more step, given its Circom witness (`.wtns` bytes).
    pub fn prove_step(&self, wtns: Vec<u8>) -> Result<(), ZenoError> {
        let mut ivc = self.inner.lock().expect("prover lock");
        Ok(ivc.prove_step(&wtns, &mut rand::rngs::OsRng)?)
    }

    /// Checks the prover's own state.
    pub fn verify(&self) -> Result<(), ZenoError> {
        Ok(self.inner.lock().expect("prover lock").verify()?)
    }

    /// Number of steps folded so far.
    pub fn steps(&self) -> u64 {
        self.inner.lock().expect("prover lock").acc.i
    }

    /// Current state `z_i` as decimal strings.
    pub fn state(&self) -> Vec<String> {
        state_strings(&self.inner.lock().expect("prover lock").acc.zi)
    }

    /// Produces a succinct zero-knowledge proof of the computation so far.
    pub fn finalize(&self) -> Result<Vec<u8>, ZenoError> {
        let ivc = self.inner.lock().expect("prover lock");
        Ok(ivc.finalize(&mut rand::rngs::OsRng)?)
    }
}

/// Verifier for proofs of one step circuit.
#[derive(uniffi::Object)]
pub struct Verifier {
    params: CircomParams,
    verifications: AtomicU64,
}

#[uniffi::export]
impl Verifier {
    #[uniffi::constructor]
    pub fn new(r1cs: Vec<u8>) -> Result<Self, ZenoError> {
        Ok(Self {
            params: CircomParams::setup(&r1cs)?,
            verifications: AtomicU64::new(0),
        })
    }

    /// Verifies a proof and returns the statement it proves.
    pub fn verify(&self, proof: Vec<u8>) -> Result<Statement, ZenoError> {
        self.verifications.fetch_add(1, Ordering::Relaxed);
        let statement = self.params.verify_proof(&proof)?.statement;
        Ok(Statement {
            steps: statement.i,
            z0: state_strings(&statement.z0),
            zi: state_strings(&statement.zi),
        })
    }

    /// Number of verifications performed, for license usage reporting.
    pub fn verifications(&self) -> u64 {
        self.verifications.load(Ordering::Relaxed)
    }
}

/// Verifies an `EnterpriseLicenseKey` against the vendor's public key (hex)
/// at Unix time `now` (seconds).
#[uniffi::export]
pub fn verify_license(
    key: String,
    vendor_public_key: String,
    now: u64,
) -> Result<License, ZenoError> {
    let err = |e: zeno_license::LicenseError| ZenoError::License {
        reason: e.to_string(),
    };
    let public = zeno_license::parse_key_hex(&vendor_public_key).map_err(err)?;
    let claims = zeno_license::verify(&key, &public, now).map_err(err)?;
    Ok(License {
        customer: claims.customer,
        plan: claims.plan,
        expires_at: claims.expires_at,
    })
}
