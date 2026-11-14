//! `sdk-bindings` — the developer-facing SDK of the Zeno–Llull engine.
//!
//! * [`circom`]: parsers for Circom's `.r1cs` and `.wtns` binary formats.
//! * [`CircomIvc`]: IVC over a Circom step circuit on the BN254/Grumpkin
//!   cycle (Circom's default prime is the BN254 scalar field).
//! * [`api`]: what every binding shares — the licensed prover, the statement
//!   of a proof, state conversions.
//! * [`onchain`]: mode B on the device — calldata for `ZenoLlullVerifier.sol`
//!   (folding and `finalizeUniversal`) from `.r1cs` / `.wtns` files.
//! * [`lib_wasm_ffi`]: the WebAssembly / TypeScript API built on top of it.
#![forbid(unsafe_code)]

pub mod api;
pub mod circom;
pub mod lib_wasm_ffi;
pub mod onchain;

use circom::{parse_wtns, CircomR1cs, CircuitLimits, SdkError};
use decider_zk::{CompressedIvcProof, ProofFormatError};
use rand::RngCore;
use std::sync::Arc;
use zeno_ivc::{IvcParams, R1csStep, ZenoAccumulator};

/// Primary curve: BN254 (application logic runs in its scalar field).
pub type Primary = ark_bn254::g1::Config;
/// Secondary curve: Grumpkin.
pub type Secondary = ark_grumpkin::GrumpkinConfig;
/// The application field.
pub type Fr = ark_bn254::Fr;
/// A finalized succinct zero-knowledge proof.
pub type Proof = CompressedIvcProof<Primary, Secondary>;

const LABEL: &[u8] = b"zeno-llull/sdk/v1";

/// Parameters derived from a Circom step circuit; enough to verify proofs.
pub struct CircomParams {
    pub r1cs: CircomR1cs<Fr>,
    pub ivc: IvcParams<Primary, Secondary>,
}

impl CircomParams {
    /// Parses a `.r1cs` file and derives the transparent IVC parameters.
    pub fn setup(r1cs_bytes: &[u8]) -> Result<Self, SdkError> {
        Self::setup_with_limits(r1cs_bytes, CircuitLimits::default())
    }

    /// [`Self::setup`] for circuits within `limits`.
    pub fn setup_with_limits(r1cs_bytes: &[u8], limits: CircuitLimits) -> Result<Self, SdkError> {
        let r1cs = CircomR1cs::<Fr>::parse_with_limits(r1cs_bytes, limits)?;
        let ivc = IvcParams::setup(&r1cs.step(None), LABEL)?;
        Ok(Self { r1cs, ivc })
    }

    /// Verifies a serialized zero-knowledge proof and returns it decoded;
    /// the public statement is `(proof.i, proof.z0, proof.zi)`.
    pub fn verify_proof(&self, bytes: &[u8]) -> Result<Proof, SdkError> {
        let proof = Proof::from_bytes(bytes).map_err(|e| match e {
            ProofFormatError::UnsupportedVersion(v) => SdkError::UnsupportedProofVersion(v),
            _ => SdkError::MalformedProof,
        })?;
        proof.verify(&self.ivc)?;
        Ok(proof)
    }
}

/// Overwrites a step's wire values (the witness of one step) with zeros.
pub(crate) fn wipe_step(mut step: R1csStep<Fr>) {
    use zeroize::Zeroize;
    if let Some(wires) = step.assignment.as_mut() {
        wires.zeroize();
    }
}

/// An IVC prover for a Circom step circuit. The parameters are shared
/// (`Arc`): provers of the same circuit can use one copy.
pub struct CircomIvc {
    pub params: Arc<CircomParams>,
    pub acc: ZenoAccumulator<Primary, Secondary>,
}

impl CircomIvc {
    /// Starts a computation at state `z0`.
    pub fn new(r1cs_bytes: &[u8], z0: Vec<Fr>) -> Result<Self, SdkError> {
        Self::new_with_limits(r1cs_bytes, z0, CircuitLimits::default())
    }

    /// [`Self::new`] for circuits within `limits` (services that accept
    /// circuits from clients set their own).
    pub fn new_with_limits(
        r1cs_bytes: &[u8],
        z0: Vec<Fr>,
        limits: CircuitLimits,
    ) -> Result<Self, SdkError> {
        let params = CircomParams::setup_with_limits(r1cs_bytes, limits)?;
        Self::with_params(Arc::new(params), z0)
    }

    /// Starts a computation at state `z0` with already derived parameters.
    pub fn with_params(params: Arc<CircomParams>, z0: Vec<Fr>) -> Result<Self, SdkError> {
        let acc = ZenoAccumulator::new(&params.ivc, z0)?;
        Ok(Self { params, acc })
    }

    /// The prover state as bytes, to pause the computation and continue it
    /// later with [`Self::resume`]. **Secret**: it holds the folded
    /// witnesses (see `ZenoAccumulator::to_bytes`).
    pub fn save_state(&self) -> Vec<u8> {
        self.acc.to_bytes()
    }

    /// Continues a computation from [`Self::save_state`]; the state is
    /// fully checked against the circuit first.
    pub fn resume(params: Arc<CircomParams>, state: &[u8]) -> Result<Self, SdkError> {
        let acc = ZenoAccumulator::from_bytes(&params.ivc, state)?;
        Ok(Self { params, acc })
    }

    /// Folds one step, given the Circom witness (`.wtns`) of that step. The
    /// witness must take the current state as its `step_in`.
    pub fn prove_step(
        &mut self,
        wtns_bytes: &[u8],
        rng: &mut impl RngCore,
    ) -> Result<(), SdkError> {
        let assignment = parse_wtns::<Fr>(wtns_bytes)?;
        let step: R1csStep<Fr> = self.params.r1cs.step(Some(assignment));
        let w = step.assignment.as_ref().expect("assignment was just set");
        if w.len() != step.num_wires {
            return Err(SdkError::WitnessLength {
                expected: step.num_wires,
                got: w.len(),
            });
        }
        if step
            .z_in_wires
            .iter()
            .zip(&self.acc.zi)
            .any(|(i, z)| w[*i] != *z)
        {
            return Err(SdkError::StateMismatch);
        }
        if let Some(row) = step.first_unsatisfied(w) {
            return Err(SdkError::UnsatisfiedWitness { constraint: row });
        }
        let result = self.acc.prove_step(&self.params.ivc, &step, rng);
        wipe_step(step);
        result?;
        Ok(())
    }

    /// Overwrites the prover's secret state (the folded witnesses) with
    /// zeros; the prover cannot be used afterwards.
    pub fn wipe(&mut self) {
        self.acc.wipe();
    }

    /// Verifies the current prover state.
    pub fn verify(&self) -> Result<(), SdkError> {
        Ok(self.acc.verify(&self.params.ivc)?)
    }

    /// Produces a serialized succinct zero-knowledge proof of the computation
    /// so far.
    pub fn finalize(&self, rng: &mut impl RngCore) -> Result<Vec<u8>, SdkError> {
        Ok(Proof::prove(&self.params.ivc, &self.acc, rng)?.to_bytes())
    }
}
