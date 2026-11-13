//! `sdk-bindings` — the developer-facing SDK of the Zeno–Llull engine.
//!
//! * [`circom`]: parsers for Circom's `.r1cs` and `.wtns` binary formats.
//! * [`CircomIvc`]: IVC over a Circom step circuit on the BN254/Grumpkin
//!   cycle (Circom's default prime is the BN254 scalar field).
//! * [`api`]: what every binding shares — the licensed prover, the statement
//!   of a proof, state conversions.
//! * [`lib_wasm_ffi`]: the WebAssembly / TypeScript API built on top of it.
#![forbid(unsafe_code)]

pub mod api;
pub mod circom;
pub mod lib_wasm_ffi;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circom::{parse_wtns, CircomR1cs, CircuitLimits, SdkError};
use decider_zk::CompressedIvcProof;
use rand::RngCore;
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
        let proof = Proof::deserialize_compressed(bytes).map_err(|_| SdkError::MalformedProof)?;
        proof.verify(&self.ivc)?;
        Ok(proof)
    }
}

/// An IVC prover for a Circom step circuit.
pub struct CircomIvc {
    pub params: CircomParams,
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
        let acc = ZenoAccumulator::new(&params.ivc, z0)?;
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
        self.acc.prove_step(&self.params.ivc, &step, rng)?;
        Ok(())
    }

    /// Verifies the current prover state.
    pub fn verify(&self) -> Result<(), SdkError> {
        Ok(self.acc.verify(&self.params.ivc)?)
    }

    /// Produces a serialized succinct zero-knowledge proof of the computation
    /// so far.
    pub fn finalize(&self, rng: &mut impl RngCore) -> Result<Vec<u8>, SdkError> {
        let proof = Proof::prove(&self.params.ivc, &self.acc, rng)?;
        let mut bytes = Vec::with_capacity(proof.compressed_size());
        proof
            .serialize_compressed(&mut bytes)
            .expect("serializing to a Vec cannot fail");
        Ok(bytes)
    }
}
