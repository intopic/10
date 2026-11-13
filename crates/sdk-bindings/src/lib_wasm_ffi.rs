//! WebAssembly / TypeScript API (`@zenollull/wasm-sdk`).
//!
//! ```js
//! const prover = new ZenoLlullProver(licenseKey, r1csBytes, ["3"]);
//! prover.proveStep(wtnsBytes);          // once per step, any number of times
//! const proof = prover.finalize();      // zero-knowledge proof bytes
//! const st = new ZenoLlullVerifier(r1csBytes).verify(proof);  // throws if invalid
//! ```

use crate::{api, circom::SdkError, CircomParams};
use wasm_bindgen::prelude::*;

/// `await initThreadPool(navigator.hardwareConcurrency)` starts the Web
/// Worker pool; call it once before proving in the multi-threaded build.
#[cfg(all(target_arch = "wasm32", feature = "wasm-threads"))]
pub use wasm_bindgen_rayon::init_thread_pool;

fn js_err(e: SdkError) -> JsError {
    JsError::new(&e.to_string())
}

/// The public statement proven by a proof: `zi = F^steps(z0)`.
#[wasm_bindgen(getter_with_clone)]
pub struct Statement {
    pub steps: u32,
    pub z0: Vec<String>,
    pub zi: Vec<String>,
}

/// Incremental prover for a Circom step circuit. It runs only under a valid
/// license key, checked against the vendor key compiled into the package.
#[wasm_bindgen]
pub struct ZenoLlullProver {
    inner: api::LicensedProver,
}

#[wasm_bindgen]
impl ZenoLlullProver {
    /// `license`: the `EnterpriseLicenseKey`; `r1cs`: the compiled step
    /// circuit; `z0`: initial state as decimal strings. Throws if the license
    /// is invalid or expired.
    #[wasm_bindgen(constructor)]
    pub fn new(license: &str, r1cs: &[u8], z0: Vec<String>) -> Result<ZenoLlullProver, JsError> {
        Ok(Self {
            inner: api::LicensedProver::new(license, r1cs, &z0).map_err(js_err)?,
        })
    }

    /// Folds one more step, given its Circom witness (`.wtns` bytes). Throws
    /// once the license has expired or its step quota is used up.
    #[wasm_bindgen(js_name = proveStep)]
    pub fn prove_step(&mut self, wtns: &[u8]) -> Result<(), JsError> {
        self.inner.prove_step(wtns).map_err(js_err)
    }

    /// Checks the prover's own state; throws if it is invalid.
    pub fn verify(&self) -> Result<(), JsError> {
        self.inner.verify().map_err(js_err)
    }

    /// Number of steps folded so far.
    #[wasm_bindgen(getter)]
    pub fn steps(&self) -> u32 {
        self.inner.steps() as u32
    }

    /// Current state `z_i` as decimal strings.
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<String> {
        self.inner.state()
    }

    /// Serialized size of the prover state in bytes; constant in `steps`.
    #[wasm_bindgen(getter, js_name = stateSize)]
    pub fn state_size(&self) -> usize {
        self.inner.state_size()
    }

    /// Produces a succinct zero-knowledge proof of the computation so far.
    pub fn finalize(&self) -> Result<Vec<u8>, JsError> {
        self.inner.finalize().map_err(js_err)
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
        self.verifications = self.verifications.saturating_add(1);
        let st = api::statement_of(&self.params.verify_proof(proof).map_err(js_err)?);
        Ok(Statement {
            steps: st.steps as u32,
            z0: st.z0,
            zi: st.zi,
        })
    }

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
    /// Largest number of steps one prover may fold; `undefined`: unlimited.
    #[wasm_bindgen(js_name = maxSteps)]
    pub max_steps: Option<f64>,
    /// `true` when the package was built without a vendor key and checks
    /// licenses against the public development key.
    #[wasm_bindgen(js_name = developmentBuild)]
    pub development_build: bool,
}

/// Verifies an `EnterpriseLicenseKey` against the vendor key compiled into
/// the package, at the current time; throws if it is invalid or expired.
#[wasm_bindgen(js_name = verifyLicense)]
pub fn verify_license(key: &str) -> Result<License, JsError> {
    let info = api::check_license(key).map_err(js_err)?;
    Ok(License {
        customer: info.customer,
        plan: info.plan,
        expires_at: info.expires_at as f64,
        max_steps: info.max_steps.map(|m| m as f64),
        development_build: info.development_build,
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
