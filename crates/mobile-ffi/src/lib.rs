//! `mobile-ffi` — the native Zeno–Llull SDK for iOS (Swift), Android
//! (Kotlin) and Python, generated from this single Rust API with UniFFI.
//!
//! ```python
//! prover = Prover(license_key, r1cs_bytes, ["3"])
//! prover.prove_step(wtns_bytes)          # once per step
//! proof = prover.finalize()              # succinct zero-knowledge proof
//! statement = Verifier(r1cs_bytes).verify(proof)
//! ```

use sdk_bindings::{api, circom::SdkError, CircomParams};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, MutexGuard,
};

uniffi::setup_scaffolding!();

/// Any failure of the SDK, with a human-readable reason.
#[derive(Debug, uniffi::Error)]
pub enum ZenoError {
    /// The circuit, witness or state passed in is not usable.
    InvalidInput { reason: String },
    /// A proof or prover state failed verification.
    VerificationFailed { reason: String },
    /// The license key is invalid or expired, or its quota is used up.
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
            SdkError::Ivc(_) | SdkError::MalformedProof | SdkError::UnsupportedProofVersion(_) => {
                Self::VerificationFailed { reason }
            }
            SdkError::License(_) | SdkError::QuotaExceeded { .. } => Self::License { reason },
            _ => Self::InvalidInput { reason },
        }
    }
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
    /// Largest number of steps one prover may fold; `None`: unlimited.
    pub max_steps: Option<u64>,
    /// `true` when the library was built without a vendor key and checks
    /// licenses against the public development key.
    pub development_build: bool,
}

/// Incremental prover for a Circom step circuit (BN254/Grumpkin). It runs
/// only under a valid license key, checked against the vendor key compiled
/// into the library.
#[derive(uniffi::Object)]
pub struct Prover {
    inner: Mutex<api::LicensedProver>,
}

impl Prover {
    /// A panic in one call must not make every later call panic too.
    fn lock(&self) -> MutexGuard<'_, api::LicensedProver> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl Prover {
    /// `license`: the `EnterpriseLicenseKey`; `r1cs`: the compiled step
    /// circuit; `z0`: initial state as decimal strings.
    #[uniffi::constructor]
    pub fn new(license: String, r1cs: Vec<u8>, z0: Vec<String>) -> Result<Self, ZenoError> {
        Ok(Self {
            inner: Mutex::new(api::LicensedProver::new(&license, &r1cs, &z0)?),
        })
    }

    /// Continues a computation saved with `save_state`, for the same
    /// circuit; the state is fully checked first.
    #[uniffi::constructor]
    pub fn resume(license: String, r1cs: Vec<u8>, state: Vec<u8>) -> Result<Self, ZenoError> {
        Ok(Self {
            inner: Mutex::new(api::LicensedProver::resume(&license, &r1cs, &state)?),
        })
    }

    /// The prover state, to continue later with `Prover.resume`.
    /// **Secret**: it holds the folded witnesses; store it encrypted.
    pub fn save_state(&self) -> Vec<u8> {
        self.lock().save_state()
    }

    /// Folds one more step, given its Circom witness (`.wtns` bytes).
    pub fn prove_step(&self, wtns: Vec<u8>) -> Result<(), ZenoError> {
        Ok(self.lock().prove_step(&wtns)?)
    }

    /// Checks the prover's own state.
    pub fn verify(&self) -> Result<(), ZenoError> {
        Ok(self.lock().verify()?)
    }

    /// Number of steps folded so far.
    pub fn steps(&self) -> u64 {
        self.lock().steps()
    }

    /// Current state `z_i` as decimal strings.
    pub fn state(&self) -> Vec<String> {
        self.lock().state()
    }

    /// Produces a succinct zero-knowledge proof of the computation so far.
    pub fn finalize(&self) -> Result<Vec<u8>, ZenoError> {
        Ok(self.lock().finalize()?)
    }
}

/// Mode B on the device: calldata for `ZenoLlullVerifier.sol` (folding of
/// every step and `finalizeUniversal`) computed from the Circom files, so
/// witnesses never leave the device. `ptau`: a public Powers-of-Tau file or
/// the prefix this circuit needs (`zeno-evm trim-ptau`).
#[derive(uniffi::Object)]
pub struct OnChainProver {
    inner: Mutex<sdk_bindings::onchain::OnChainProver>,
}

impl OnChainProver {
    fn lock(&self) -> MutexGuard<'_, sdk_bindings::onchain::OnChainProver> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl OnChainProver {
    #[uniffi::constructor]
    pub fn new(
        license: String,
        r1cs: Vec<u8>,
        ptau: Vec<u8>,
        z0: Vec<String>,
    ) -> Result<Self, ZenoError> {
        Ok(Self {
            inner: Mutex::new(sdk_bindings::onchain::OnChainProver::new(
                &license, &r1cs, &ptau, &z0,
            )?),
        })
    }

    /// The circuit's `vk` (hex): what the session is opened with.
    pub fn vk(&self) -> String {
        sdk_bindings::onchain::to_hex(&self.lock().vk())
    }

    /// Calldata of `openSession(vk, z0)`.
    pub fn open_session_calldata(&self) -> Vec<u8> {
        self.lock().open_session_calldata()
    }

    /// Folds one more step locally, given its Circom witness (`.wtns`).
    pub fn prove_step(&self, wtns: Vec<u8>) -> Result<(), ZenoError> {
        Ok(self.lock().prove_step(&wtns)?)
    }

    /// Folded steps not yet taken by `take_calldata`.
    pub fn pending_steps(&self) -> u64 {
        self.lock().pending_steps() as u64
    }

    /// Calldata of `verifyFoldedProofBatch` for the pending steps (send it
    /// with `protocolFee × pending_steps` wei); `session_id` in hex.
    pub fn take_calldata(&self, session_id: String) -> Result<Vec<u8>, ZenoError> {
        let session = sdk_bindings::onchain::parse_session(&session_id)?;
        Ok(self.lock().take_calldata(&session)?)
    }

    /// Calldata of `finalizeUniversal` (send it with `protocolFee` wei).
    pub fn finalize(&self, session_id: String) -> Result<Vec<u8>, ZenoError> {
        let session = sdk_bindings::onchain::parse_session(&session_id)?;
        Ok(self.lock().finalize(&session)?)
    }

    /// Steps folded so far.
    pub fn steps(&self) -> u64 {
        self.lock().steps()
    }

    /// Current state `z_i` as decimal strings.
    pub fn state(&self) -> Vec<String> {
        self.lock().state()
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
        let st = api::statement_of(&self.params.verify_proof(&proof)?);
        Ok(Statement {
            steps: st.steps,
            z0: st.z0,
            zi: st.zi,
        })
    }

    /// Number of verifications performed, for license usage reporting.
    pub fn verifications(&self) -> u64 {
        self.verifications.load(Ordering::Relaxed)
    }
}

/// Verifies an `EnterpriseLicenseKey` against the vendor key compiled into
/// the library, at the current time.
#[uniffi::export]
pub fn verify_license(key: String) -> Result<License, ZenoError> {
    let info = api::check_license(&key)?;
    Ok(License {
        customer: info.customer,
        plan: info.plan,
        expires_at: info.expires_at,
        max_steps: info.max_steps,
        development_build: info.development_build,
    })
}
