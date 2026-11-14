//! Mode D on a server: the CycleFold IVC over a Circom step circuit, decided
//! on-chain by one `finalizeRecursive` call whatever the number of steps.
//!
//! A server-class component (about 2 GB of memory and tens of seconds per
//! proof, and a Powers-of-Tau file with 2^20 powers): bridges, rollups and
//! applications that aggregate their users' claims run it on their own
//! machines. Phones and browsers use mode B ([`crate::onchain`]) instead.
//!
//! ```text
//! let circuit = Arc::new(RecursiveCircuit::new(r1cs, &srs)?);   // once per circuit
//! let mut p = RecursiveProver::new(license, circuit, &["3"])?;   // once per computation
//! p.prove_step(wtns0)?; p.prove_step(wtns1)?;
//! let call = p.finalize()?;   // send call.calldata with recursiveFee(call.steps) wei
//! ```

use crate::{
    api::{parse_state, state_strings, unix_now},
    circom::{parse_wtns, CircomR1cs, SdkError},
    onchain::to_hex,
    Fr,
};
use evm_verifier::{
    kzg::Srs,
    recursive::{self, Bn254Config, GrumpkinConfig, RecursiveParams},
    Word, CIRCOM_RECURSIVE_LABEL,
};
use std::sync::Arc;
use zeno_ivc::cyclefold::CycleFoldAccumulator;

/// Powers of τ mode D needs.
pub const RECURSIVE_POWERS: usize = 1 << 20;

/// A circuit prepared for mode D (its parameters and keys), shared by every
/// computation of the circuit. Preparing it takes a while: do it once.
pub struct RecursiveCircuit {
    pub r1cs: CircomR1cs<Fr>,
    pub params: RecursiveParams,
}

impl RecursiveCircuit {
    /// `srs` must hold [`RECURSIVE_POWERS`] powers (e.g. the public
    /// `ppot_0080_20.ptau`, loaded with [`Self::load_srs`]).
    pub fn new(r1cs: CircomR1cs<Fr>, srs: &Srs) -> Result<Self, SdkError> {
        if srs.powers_g1.len() < RECURSIVE_POWERS {
            return Err(SdkError::Evm(format!(
                "mode D needs a reference string of {RECURSIVE_POWERS} powers, this one has {}",
                srs.powers_g1.len()
            )));
        }
        let params = RecursiveParams::setup(&r1cs.step(None), CIRCOM_RECURSIVE_LABEL, srs)?;
        Ok(Self { r1cs, params })
    }

    /// Parses a `.r1cs` file and prepares it over a `.ptau` file.
    pub fn from_files(r1cs: &[u8], ptau: &[u8]) -> Result<Self, SdkError> {
        Self::new(CircomR1cs::<Fr>::parse(r1cs)?, &Self::load_srs(ptau)?)
    }

    /// Loads and checks the first [`RECURSIVE_POWERS`] powers of a `.ptau`.
    pub fn load_srs(ptau: &[u8]) -> Result<Srs, SdkError> {
        Srs::from_ptau(ptau, RECURSIVE_POWERS, &mut rand::rngs::OsRng)
            .map_err(|e| SdkError::Evm(e.to_string()))
    }

    /// The system's on-chain identity (`ZenoRecursiveVerifier`).
    pub fn system_id(&self) -> Word {
        self.params.system_id()
    }
}

/// What `finalizeRecursive` needs, and how to find the decision afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveCall {
    /// Calldata of `finalizeRecursive`; send it with
    /// `recursiveFee(steps)` wei (`decisionFee + stepFee × steps`, capped at
    /// `maxFee`; the contract's view function gives the exact value).
    pub calldata: Vec<u8>,
    pub steps: u64,
    pub z0: Vec<String>,
    pub zi: Vec<String>,
    /// `keccak256(vk primary ‖ vk closing ‖ CycleFold shape)`.
    pub system_id: Word,
    /// The key of the claim in `ZenoRecursiveVerifier.decided`.
    pub decided_key: Word,
}

impl RecursiveCall {
    /// The call as JSON (hex strings), for tools and services.
    pub fn to_json(&self) -> String {
        let strings = |z: &[String]| {
            let items: Vec<String> = z.iter().map(|s| format!("\"{s}\"")).collect();
            format!("[{}]", items.join(","))
        };
        format!(
            "{{\"systemId\":\"{}\",\"decidedKey\":\"{}\",\"steps\":{},\"z0\":{},\"zi\":{},\"finalizeRecursive\":\"{}\"}}",
            to_hex(&self.system_id),
            to_hex(&self.decided_key),
            self.steps,
            strings(&self.z0),
            strings(&self.zi),
            to_hex(&self.calldata),
        )
    }
}

fn claims(license: &str) -> Result<zeno_license::Claims, SdkError> {
    zeno_license::verify_for_this_build(license, unix_now())
        .map_err(|e| SdkError::License(e.to_string()))
}

/// One mode-D computation.
pub struct RecursiveProver {
    circuit: Arc<RecursiveCircuit>,
    ivc: CycleFoldAccumulator<Bn254Config, GrumpkinConfig>,
    license: String,
    quota: Option<u64>,
}

impl RecursiveProver {
    /// Starts at state `z0` (decimal strings) under `license`.
    pub fn new(
        license: &str,
        circuit: Arc<RecursiveCircuit>,
        z0: &[String],
    ) -> Result<Self, SdkError> {
        let quota = claims(license)?.max_steps;
        let ivc = CycleFoldAccumulator::new(&circuit.params.ivc, parse_state(z0)?)?;
        Ok(Self {
            circuit,
            ivc,
            license: license.to_string(),
            quota,
        })
    }

    /// Folds one more step, given its Circom witness (`.wtns`).
    pub fn prove_step(&mut self, wtns: &[u8]) -> Result<(), SdkError> {
        claims(&self.license)?;
        if let Some(max_steps) = self.quota {
            if self.ivc.i >= max_steps {
                return Err(SdkError::QuotaExceeded { max_steps });
            }
        }
        let r1cs = &self.circuit.r1cs;
        let step = r1cs.step(Some(parse_wtns::<Fr>(wtns)?));
        let wires = step.assignment.as_ref().expect("just set");
        if wires.len() != r1cs.num_wires {
            return Err(SdkError::WitnessLength {
                expected: r1cs.num_wires,
                got: wires.len(),
            });
        }
        let k = r1cs.num_outputs;
        if wires[k + 1..=2 * k] != self.ivc.zi[..] {
            return Err(SdkError::StateMismatch);
        }
        if let Some(constraint) = step.first_unsatisfied(wires) {
            return Err(SdkError::UnsatisfiedWitness { constraint });
        }
        let result = self
            .ivc
            .prove_step(&self.circuit.params.ivc, &step, &mut rand::rngs::OsRng);
        crate::wipe_step(step);
        result?;
        Ok(())
    }

    /// Steps folded so far.
    pub fn steps(&self) -> u64 {
        self.ivc.i
    }

    /// Current state `z_i` as decimal strings.
    pub fn state(&self) -> Vec<String> {
        state_strings(&self.ivc.zi)
    }

    /// The recursive proof as a `finalizeRecursive` call, checked before it
    /// is returned.
    pub fn finalize(&self) -> Result<RecursiveCall, SdkError> {
        claims(&self.license)?;
        if self.ivc.i == 0 {
            return Err(SdkError::Evm("no step was folded".into()));
        }
        let params = &self.circuit.params;
        let proof = recursive::prove(params, &self.ivc, &mut rand::rngs::OsRng)
            .map_err(|e| SdkError::Evm(e.to_string()))?;
        if !recursive::verify(params, &proof) {
            return Err(SdkError::Evm("the recursive proof does not verify".into()));
        }
        let (calldata, _) = recursive::calldata(params, &proof);
        Ok(RecursiveCall {
            calldata,
            steps: proof.i,
            z0: state_strings(&proof.z0),
            zi: state_strings(&proof.zi),
            system_id: params.system_id(),
            decided_key: params.decided_key(&proof),
        })
    }

    /// Overwrites every witness of the computation with zeros.
    pub fn wipe(&mut self) {
        self.ivc.wipe();
    }
}

impl Drop for RecursiveProver {
    fn drop(&mut self) {
        self.wipe();
    }
}
