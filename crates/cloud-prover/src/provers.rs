//! The three kinds of session the service runs, one per mode:
//!
//! * `transparent` (mode A) — the Nova IVC of the SDK; `finalize-snark`
//!   returns the transparent zero-knowledge proof (~10 KB);
//! * `universal` (mode B) — the steps are folded by `ZenoLlullVerifier.sol`
//!   itself; `finalize-evm` returns the `verifyFoldedProofBatch` and
//!   `finalizeUniversal` calldata;
//! * `recursive` (mode D) — the CycleFold IVC; `finalize-evm` returns one
//!   `finalizeRecursive` call, whatever the number of steps.
//!
//! Modes B and D need the reference string the service loaded at start
//! (`ZENO_PTAU_PATH`); mode D needs 2^20 powers.

use evm_verifier::{
    kzg::Srs,
    recursive::{self, Bn254Config, GrumpkinConfig, RecursiveParams},
    word, Word, CIRCOM_RECURSIVE_LABEL,
};
use sdk_bindings::{
    api::state_strings,
    circom::{parse_wtns, CircomR1cs, CircuitLimits, SdkError},
    onchain::{to_hex, OnChainCircuit, OnChainProver},
    CircomIvc, CircomParams, Fr,
};
use serde_json::{json, Value};
use std::sync::{Arc, Weak};
use zeno_ivc::cyclefold::CycleFoldAccumulator;

/// Powers of τ mode D needs.
pub const RECURSIVE_POWERS: usize = 1 << 20;

/// What a session proves for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Transparent,
    Universal,
    Recursive,
}

impl Mode {
    pub fn parse(name: Option<&str>) -> Result<Self, String> {
        match name.unwrap_or("transparent") {
            "transparent" => Ok(Self::Transparent),
            "universal" => Ok(Self::Universal),
            "recursive" => Ok(Self::Recursive),
            other => Err(format!(
                "unknown mode `{other}` (transparent, universal or recursive)"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Transparent => "transparent",
            Self::Universal => "universal",
            Self::Recursive => "recursive",
        }
    }
}

/// A circuit prepared for mode D, shared by its sessions.
pub struct RecursiveCircuit {
    pub r1cs: CircomR1cs<Fr>,
    pub params: RecursiveParams,
}

impl RecursiveCircuit {
    pub fn new(r1cs: CircomR1cs<Fr>, srs: &Srs) -> Result<Self, SdkError> {
        if srs.powers_g1.len() < RECURSIVE_POWERS {
            return Err(SdkError::Evm(format!(
                "mode recursive needs a reference string of {RECURSIVE_POWERS} powers, the service has {}",
                srs.powers_g1.len()
            )));
        }
        let params = RecursiveParams::setup(&r1cs.step(None), CIRCOM_RECURSIVE_LABEL, srs)?;
        Ok(Self { r1cs, params })
    }
}

/// A mode-D session: the CycleFold IVC over a Circom step circuit.
pub struct RecursiveSession {
    circuit: Arc<RecursiveCircuit>,
    ivc: CycleFoldAccumulator<Bn254Config, GrumpkinConfig>,
}

impl RecursiveSession {
    pub fn start(circuit: Arc<RecursiveCircuit>, z0: Vec<Fr>) -> Result<Self, SdkError> {
        let ivc = CycleFoldAccumulator::new(&circuit.params.ivc, z0)?;
        Ok(Self { circuit, ivc })
    }

    fn prove_step(&mut self, wtns: &[u8]) -> Result<(), SdkError> {
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
        wipe_wires(step);
        result?;
        Ok(())
    }

    /// The recursive proof as the `finalizeRecursive` call, checked before
    /// it is handed out.
    pub fn finalize(&self) -> Result<Value, SdkError> {
        let params = &self.circuit.params;
        if self.ivc.i == 0 {
            return Err(SdkError::Evm("no step was folded".into()));
        }
        let proof = recursive::prove(params, &self.ivc, &mut rand::rngs::OsRng)
            .map_err(|e| SdkError::Evm(e.to_string()))?;
        if !recursive::verify(params, &proof) {
            return Err(SdkError::Evm("the recursive proof does not verify".into()));
        }
        let (calldata, _) = recursive::calldata(params, &proof);
        let claim: Vec<Word> = core::iter::once(word(&Fr::from(proof.i)))
            .chain(proof.z0.iter().chain(&proof.zi).map(word))
            .collect();
        Ok(json!({
            "mode": "recursive",
            "steps": proof.i,
            "z0": state_strings(&proof.z0),
            "zi": state_strings(&proof.zi),
            "system_id": to_hex(&params.system_id()),
            "decided_key": to_hex(&params.decided_key(&proof)),
            "claim": to_hex(&claim.concat()),
            "finalizeRecursive": to_hex(&calldata),
            "decision_fees": 1,
        }))
    }
}

/// The prover behind a session. It always lives behind an `Arc<Mutex<_>>`,
/// one per session, so the size of the variants does not matter.
#[allow(clippy::large_enum_variant)]
pub enum Prover {
    Transparent(CircomIvc),
    Universal(OnChainProver),
    Recursive(RecursiveSession),
}

impl Prover {
    pub fn mode(&self) -> Mode {
        match self {
            Self::Transparent(_) => Mode::Transparent,
            Self::Universal(_) => Mode::Universal,
            Self::Recursive(_) => Mode::Recursive,
        }
    }

    pub fn steps(&self) -> u64 {
        match self {
            Self::Transparent(ivc) => ivc.acc.i,
            Self::Universal(p) => p.steps(),
            Self::Recursive(s) => s.ivc.i,
        }
    }

    pub fn state(&self) -> Vec<String> {
        match self {
            Self::Transparent(ivc) => state_strings(&ivc.acc.zi),
            Self::Universal(p) => p.state(),
            Self::Recursive(s) => state_strings(&s.ivc.zi),
        }
    }

    pub fn prove_step(&mut self, wtns: &[u8]) -> Result<(), SdkError> {
        match self {
            Self::Transparent(ivc) => ivc.prove_step(wtns, &mut rand::rngs::OsRng),
            Self::Universal(p) => p.prove_step(wtns),
            Self::Recursive(s) => s.prove_step(wtns),
        }
    }

    /// Mode B: the calls that put the session on-chain and decide it, for
    /// the session id the contract returned from `openSession`.
    pub fn finalize_universal(&mut self, session: &Word) -> Result<Value, SdkError> {
        let Self::Universal(p) = self else {
            return Err(SdkError::Evm("not a universal session".into()));
        };
        let pending = p.pending_steps();
        let batch = if pending > 0 {
            Some(to_hex(&p.take_calldata(session)?))
        } else {
            None
        };
        let finalize = to_hex(&p.finalize(session)?);
        Ok(json!({
            "mode": "universal",
            "vk": to_hex(&p.vk()),
            "steps": p.steps(),
            "zi": p.state(),
            "verifyFoldedProofBatch": batch,
            "batch_steps": pending,
            "finalizeUniversal": finalize,
            "decision_fees": 1,
        }))
    }
}

/// A session's secrets are wiped when it ends, however it ends (finalized,
/// closed after an error, or swept when idle): the last reference to the
/// prover drops it, and dropping it overwrites every witness with zeros.
impl Drop for Prover {
    fn drop(&mut self) {
        match self {
            Self::Transparent(ivc) => ivc.wipe(),
            Self::Universal(p) => p.wipe(),
            Self::Recursive(s) => s.ivc.wipe(),
        }
    }
}

fn wipe_wires(mut step: zeno_ivc::R1csStep<Fr>) {
    use zeroize::Zeroize;
    if let Some(wires) = step.assignment.as_mut() {
        wires.zeroize();
    }
}

/// The parameters of a circuit, cached while one of its sessions lives.
pub enum Cached {
    Transparent(Weak<CircomParams>),
    Universal(Weak<OnChainCircuit>),
    Recursive(Weak<RecursiveCircuit>),
}

impl Cached {
    pub fn alive(&self) -> bool {
        match self {
            Self::Transparent(w) => w.strong_count() > 0,
            Self::Universal(w) => w.strong_count() > 0,
            Self::Recursive(w) => w.strong_count() > 0,
        }
    }
}

/// Builds a session's prover from a circuit's parameters (cached or not).
pub enum Params {
    Transparent(Arc<CircomParams>),
    Universal(Arc<OnChainCircuit>),
    Recursive(Arc<RecursiveCircuit>),
}

impl Params {
    /// Derives the parameters of `r1cs` for `mode`.
    pub fn derive(
        mode: Mode,
        r1cs: &[u8],
        limits: CircuitLimits,
        srs: Option<&Srs>,
    ) -> Result<Self, SdkError> {
        let srs = || {
            srs.ok_or_else(|| {
                SdkError::Evm("EVM modes are not enabled on this service (ZENO_PTAU_PATH)".into())
            })
        };
        Ok(match mode {
            Mode::Transparent => {
                Self::Transparent(Arc::new(CircomParams::setup_with_limits(r1cs, limits)?))
            }
            Mode::Universal => {
                let r1cs = CircomR1cs::<Fr>::parse_with_limits(r1cs, limits)?;
                Self::Universal(Arc::new(OnChainCircuit::new(r1cs, srs()?)?))
            }
            Mode::Recursive => {
                let r1cs = CircomR1cs::<Fr>::parse_with_limits(r1cs, limits)?;
                Self::Recursive(Arc::new(RecursiveCircuit::new(r1cs, srs()?)?))
            }
        })
    }

    pub fn from_cache(cached: &Cached) -> Option<Self> {
        match cached {
            Cached::Transparent(w) => w.upgrade().map(Self::Transparent),
            Cached::Universal(w) => w.upgrade().map(Self::Universal),
            Cached::Recursive(w) => w.upgrade().map(Self::Recursive),
        }
    }

    pub fn cache(&self) -> Cached {
        match self {
            Self::Transparent(p) => Cached::Transparent(Arc::downgrade(p)),
            Self::Universal(p) => Cached::Universal(Arc::downgrade(p)),
            Self::Recursive(p) => Cached::Recursive(Arc::downgrade(p)),
        }
    }

    pub fn start(self, z0: Vec<Fr>) -> Result<Prover, SdkError> {
        Ok(match self {
            Self::Transparent(p) => Prover::Transparent(CircomIvc::with_params(p, z0)?),
            Self::Universal(c) => Prover::Universal(OnChainProver::start(c, z0)?),
            Self::Recursive(c) => Prover::Recursive(RecursiveSession::start(c, z0)?),
        })
    }
}
