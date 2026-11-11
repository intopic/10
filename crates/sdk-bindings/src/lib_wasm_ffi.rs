//! WebAssembly / TypeScript API (`@zenollull/wasm-sdk`).
//!
//! ```js
//! const prover = new ZenoLlullProver(r1csBytes, ["3"]);
//! prover.proveStep(wtnsBytes);          // once per step, any number of times
//! const proof = prover.finalize();      // zero-knowledge proof bytes
//! const st = new ZenoLlullVerifier(r1csBytes).verify(proof);  // throws if invalid
//! ```

use crate::{circom::SdkError, CircomIvc, CircomParams, Fr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use rand::rngs::OsRng;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

fn js_err(e: SdkError) -> JsError {
    JsError::new(&e.to_string())
}

fn parse_field(s: &str) -> Result<Fr, JsError> {
    Fr::from_str(s).map_err(|_| js_err(SdkError::InvalidFieldElement))
}

fn field_to_string(f: &Fr) -> String {
    f.into_bigint().to_string()
}

/// The public statement proven by a proof: `zi = F^steps(z0)`.
#[wasm_bindgen(getter_with_clone)]
pub struct Statement {
    pub steps: u32,
    pub z0: Vec<String>,
    pub zi: Vec<String>,
}

/// Incremental prover for a Circom step circuit.
#[wasm_bindgen]
pub struct ZenoLlullProver {
    inner: CircomIvc,
}

#[wasm_bindgen]
impl ZenoLlullProver {
    /// `r1cs`: the compiled step circuit; `z0`: initial state as decimal strings.
    #[wasm_bindgen(constructor)]
    pub fn new(r1cs: &[u8], z0: Vec<String>) -> Result<ZenoLlullProver, JsError> {
        let z0 = z0
            .iter()
            .map(|s| parse_field(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            inner: CircomIvc::new(r1cs, z0).map_err(js_err)?,
        })
    }

    /// Folds one more step, given its Circom witness (`.wtns` bytes).
    #[wasm_bindgen(js_name = proveStep)]
    pub fn prove_step(&mut self, wtns: &[u8]) -> Result<(), JsError> {
        self.inner.prove_step(wtns, &mut OsRng).map_err(js_err)
    }

    /// Checks the prover's own state; throws if it is invalid.
    pub fn verify(&self) -> Result<(), JsError> {
        self.inner.verify().map_err(js_err)
    }

    /// Number of steps folded so far.
    #[wasm_bindgen(getter)]
    pub fn steps(&self) -> u32 {
        self.inner.acc.i as u32
    }

    /// Current state `z_i` as decimal strings.
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<String> {
        self.inner.acc.zi.iter().map(field_to_string).collect()
    }

    /// Serialized size of the prover state in bytes; constant in `steps`.
    #[wasm_bindgen(getter, js_name = stateSize)]
    pub fn state_size(&self) -> usize {
        self.inner.acc.compressed_size()
    }

    /// Produces a succinct zero-knowledge proof of the computation so far.
    pub fn finalize(&self) -> Result<Vec<u8>, JsError> {
        self.inner.finalize(&mut OsRng).map_err(js_err)
    }
}

/// Stateless verifier for proofs of one step circuit.
#[wasm_bindgen]
pub struct ZenoLlullVerifier {
    params: CircomParams,
    verifications: u32,
}

#[wasm_bindgen]
impl ZenoLlullVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(r1cs: &[u8]) -> Result<ZenoLlullVerifier, JsError> {
        Ok(Self {
            params: CircomParams::setup(r1cs).map_err(js_err)?,
            verifications: 0,
        })
    }

    /// Verifies a proof and returns the statement it proves; throws if invalid.
    pub fn verify(&mut self, proof: &[u8]) -> Result<Statement, JsError> {
        self.verifications += 1;
        let proof = self.params.verify_proof(proof).map_err(js_err)?.statement;
        Ok(Statement {
            steps: proof.i as u32,
            z0: proof.z0.iter().map(field_to_string).collect(),
            zi: proof.zi.iter().map(field_to_string).collect(),
        })
    }
}

#[wasm_bindgen]
impl ZenoLlullVerifier {
    /// Number of proofs this instance was asked to verify, for usage
    /// reporting under an enterprise license.
    #[wasm_bindgen(getter)]
    pub fn verifications(&self) -> u32 {
        self.verifications
    }
}

/// What a license key grants.
#[wasm_bindgen(getter_with_clone)]
pub struct License {
    pub customer: String,
    pub plan: String,
    #[wasm_bindgen(js_name = expiresAt)]
    pub expires_at: f64,
}

/// Verifies an `EnterpriseLicenseKey` against the vendor's public key
/// (hex) at Unix time `now` (seconds); throws if it is invalid or expired.
#[wasm_bindgen(js_name = verifyLicense)]
pub fn verify_license(key: &str, vendor_public_key: &str, now: f64) -> Result<License, JsError> {
    let err = |e: zeno_license::LicenseError| JsError::new(&e.to_string());
    let public = zeno_license::parse_key_hex(vendor_public_key).map_err(err)?;
    let claims = zeno_license::verify(key, &public, now as u64).map_err(err)?;
    Ok(License {
        customer: claims.customer,
        plan: claims.plan,
        expires_at: claims.expires_at as f64,
    })
}

/// Current size of the WebAssembly linear memory in bytes (0 off-wasm).
/// WebAssembly memory never shrinks, so this is also the peak usage.
#[wasm_bindgen(js_name = wasmMemoryBytes)]
pub fn wasm_memory_bytes() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        (core::arch::wasm32::memory_size(0) * 65536) as f64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0.0
    }
}
