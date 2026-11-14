//! Mode B on the device: a Circom step circuit folded **by the contract**
//! (`ZenoLlullVerifier.sol`) and decided on-chain by the universal decider,
//! with every proof computed here. Witnesses never leave the device; the
//! chain sees hiding commitments and a masked (zero-knowledge) final proof.
//!
//! ```text
//! let mut p = OnChainProver::new(license, r1cs, ptau, &["3"])?;
//! send(p.open_session_calldata());          // the contract returns the session id
//! p.prove_step(wtns0)?; p.prove_step(wtns1)?;
//! send(p.take_calldata(&session)?, value = fee × steps);   // verifyFoldedProofBatch
//! send(p.finalize(&session)?, value = fee);                // finalizeUniversal
//! ```
//!
//! `ptau` is a Powers-of-Tau file of a public ceremony, or the prefix of it
//! this circuit needs (`zeno-evm trim-ptau`, often a few KB to a few MB).
//! The circuit's `vk` is the same whichever is used; a dApp accepts a
//! session only if it was opened with the `vk` published for the circuit.

use crate::{
    api::{parse_state, state_strings},
    circom::{parse_wtns, CircomR1cs, SdkError},
    Fr,
};
use evm_verifier::{
    abi,
    kzg::Srs,
    universal::{CircuitKey, Dims},
    EvmParams, OnChainFolder, StepProof, Word, CIRCOM_UNIVERSAL_LABEL,
};
use zeno_license::Claims;

/// Parses a session id given as 32 bytes of hex (`0x` optional).
pub fn parse_session(hex: &str) -> Result<Word, SdkError> {
    let hex = hex.trim().trim_start_matches("0x");
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(SdkError::Evm("a session id is 32 bytes of hex".into()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| SdkError::Evm("a session id is 32 bytes of hex".into()))?;
    }
    Ok(out)
}

/// `0x`-prefixed hex.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * bytes.len());
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A circuit prepared for mode B: its parameters and universal key, shared
/// by every session of the circuit.
pub struct OnChainCircuit {
    pub r1cs: CircomR1cs<Fr>,
    pub params: EvmParams,
    pub key: CircuitKey,
}

impl OnChainCircuit {
    /// Commits to the circuit over `srs` (which must hold at least
    /// [`Self::srs_len`] powers).
    pub fn new(r1cs: CircomR1cs<Fr>, srs: &Srs) -> Result<Self, SdkError> {
        let shape = r1cs.folding_shape();
        let need = Dims::of(&shape).srs_len();
        if srs.powers_g1.len() < need {
            return Err(SdkError::Evm(format!(
                "the reference string has {} powers, the circuit needs {need}",
                srs.powers_g1.len()
            )));
        }
        let (params, key) = EvmParams::setup_universal(shape, CIRCOM_UNIVERSAL_LABEL, srs);
        Ok(Self { r1cs, params, key })
    }

    /// Powers of τ the circuit needs.
    pub fn srs_len(r1cs: &CircomR1cs<Fr>) -> usize {
        Dims::of(&r1cs.folding_shape()).srs_len()
    }
}

/// The prover of mode B for one session.
pub struct OnChainProver {
    circuit: std::sync::Arc<OnChainCircuit>,
    /// `None` once finalized.
    folder: Option<OnChainFolder>,
    z0: Vec<Fr>,
    state: Vec<Fr>,
    /// Folded steps whose calldata was not taken yet.
    pending: Vec<StepProof>,
    /// Steps folded so far (kept after finalization).
    folded: u64,
    /// Checked at every step and at finalization when set (the SDK); a
    /// service checks the caller's license itself.
    license: Option<String>,
    quota: Option<u64>,
}

fn claims(license: &str) -> Result<Claims, SdkError> {
    zeno_license::verify_for_this_build(license, crate::api::unix_now())
        .map_err(|e| SdkError::License(e.to_string()))
}

impl OnChainProver {
    /// Derives the circuit's universal key from `ptau` (checked: on-curve
    /// points, consecutive powers) and starts at state `z0`.
    pub fn new(license: &str, r1cs: &[u8], ptau: &[u8], z0: &[String]) -> Result<Self, SdkError> {
        let quota = claims(license)?.max_steps;
        let r1cs = CircomR1cs::<Fr>::parse(r1cs)?;
        let srs = Srs::from_ptau(ptau, OnChainCircuit::srs_len(&r1cs), &mut rand::rngs::OsRng)
            .map_err(|e| SdkError::Evm(e.to_string()))?;
        let circuit = std::sync::Arc::new(OnChainCircuit::new(r1cs, &srs)?);
        let mut prover = Self::start(circuit, parse_state(z0)?)?;
        prover.license = Some(license.to_string());
        prover.quota = quota;
        Ok(prover)
    }

    /// A session of a prepared circuit at state `z0`, without a license
    /// check of its own (for services that authenticate their callers).
    pub fn start(circuit: std::sync::Arc<OnChainCircuit>, z0: Vec<Fr>) -> Result<Self, SdkError> {
        if z0.len() != circuit.r1cs.num_outputs {
            return Err(SdkError::BadInterface {
                outputs: circuit.r1cs.num_outputs,
                public_inputs: z0.len(),
            });
        }
        let folder = OnChainFolder::new(&circuit.params);
        Ok(Self {
            circuit,
            folder: Some(folder),
            state: z0.clone(),
            z0,
            pending: Vec::new(),
            folded: 0,
            license: None,
            quota: None,
        })
    }

    fn check_license(&self) -> Result<(), SdkError> {
        match &self.license {
            Some(license) => claims(license).map(|_| ()),
            None => Ok(()),
        }
    }

    /// The circuit's on-chain identity: `keccak256` of its universal key.
    pub fn vk(&self) -> Word {
        self.circuit.params.vk
    }

    /// `openSession(vk, z0)`; the contract returns the session id.
    pub fn open_session_calldata(&self) -> Vec<u8> {
        abi::open_session(&self.circuit.params.vk, &self.z0)
    }

    fn folder(&mut self) -> Result<&mut OnChainFolder, SdkError> {
        self.folder
            .as_mut()
            .ok_or(SdkError::Evm("the session is finalized".into()))
    }

    /// Folds one more step locally, given its Circom witness. The step goes
    /// on-chain with the next [`Self::take_calldata`].
    pub fn prove_step(&mut self, wtns: &[u8]) -> Result<(), SdkError> {
        self.check_license()?;
        self.folder()?;
        if let Some(max_steps) = self.quota {
            if self.folded >= max_steps {
                return Err(SdkError::QuotaExceeded { max_steps });
            }
        }
        let r1cs = &self.circuit.r1cs;
        let wires = parse_wtns::<Fr>(wtns)?;
        let step = r1cs.step(Some(wires));
        let wires = step.assignment.as_ref().expect("just set");
        if wires.len() != r1cs.num_wires {
            return Err(SdkError::WitnessLength {
                expected: r1cs.num_wires,
                got: wires.len(),
            });
        }
        let k = r1cs.num_outputs;
        if wires[k + 1..=2 * k] != self.state[..] {
            return Err(SdkError::StateMismatch);
        }
        if let Some(constraint) = step.first_unsatisfied(wires) {
            return Err(SdkError::UnsatisfiedWitness { constraint });
        }
        let (w, x) = r1cs.folding_assignment(wires)?;
        crate::wipe_step(step);
        let next = x[k..].to_vec();
        let params = &self.circuit.params;
        let folder = self.folder.as_mut().expect("checked above");
        let proof = folder
            .fold_step(params, w, x, &mut rand::rngs::OsRng)
            .map_err(|e| SdkError::Evm(e.to_string()))?;
        self.pending.push(proof);
        self.state = next;
        self.folded += 1;
        Ok(())
    }

    /// Steps folded but not yet taken: the next [`Self::take_calldata`]
    /// must be sent with `protocolFee × pending_steps` wei.
    pub fn pending_steps(&self) -> usize {
        self.pending.len()
    }

    /// `verifyFoldedProofBatch` for every step folded since the last call,
    /// for the session the contract returned from `openSession`. Send it
    /// with `protocolFee × pending_steps()` wei, from the account that
    /// opened the session.
    pub fn take_calldata(&mut self, session: &Word) -> Result<Vec<u8>, SdkError> {
        if self.pending.is_empty() {
            return Err(SdkError::Evm("no folded step to send".into()));
        }
        let calldata = abi::verify_folded_proof_batch(session, &self.pending);
        self.pending.clear();
        Ok(calldata)
    }

    /// Masks the accumulator and proves it satisfiable: the
    /// `finalizeUniversal` call (send it with `protocolFee` wei). Every
    /// folded step must have been taken (and sent) first.
    pub fn finalize(&mut self, session: &Word) -> Result<Vec<u8>, SdkError> {
        self.check_license()?;
        if !self.pending.is_empty() {
            return Err(SdkError::Evm(
                "send the folded steps (take_calldata) before finalizing".into(),
            ));
        }
        let folder = self
            .folder
            .take()
            .ok_or(SdkError::Evm("the session is finalized".into()))?;
        if folder.steps == 0 {
            self.folder = Some(folder);
            return Err(SdkError::Evm("no step was folded".into()));
        }
        let c = &self.circuit;
        let (mask, _, proof) = folder
            .finalize_universal(&c.params, &c.key, &mut rand::rngs::OsRng)
            .map_err(|e| SdkError::Evm(e.to_string()))?;
        let key = abi::universal_key(&c.params, &c.key);
        Ok(abi::finalize_universal(
            session,
            &mask,
            &key,
            &proof.words(),
        ))
    }

    /// Steps folded so far.
    pub fn steps(&self) -> u64 {
        self.folded
    }

    /// Overwrites the accumulated witness with zeros.
    pub fn wipe(&mut self) {
        if let Some(folder) = self.folder.as_mut() {
            folder.wipe();
        }
    }

    /// Current state `z_i` as decimal strings.
    pub fn state(&self) -> Vec<String> {
        state_strings(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeno_license::{issue, DEV_PRIVATE_KEY};

    const R1CS: &[u8] = include_bytes!("../fixtures/step.r1cs");
    const PTAU: &[u8] = include_bytes!("../../evm-verifier/fixtures/pot7_test.ptau");
    const WTNS: [&[u8]; 3] = [
        include_bytes!("../fixtures/step0.wtns"),
        include_bytes!("../fixtures/step1.wtns"),
        include_bytes!("../fixtures/step2.wtns"),
    ];

    fn license(max_steps: Option<u64>) -> String {
        issue(
            &DEV_PRIVATE_KEY,
            &Claims {
                customer: "tests".into(),
                plan: "dev".into(),
                expires_at: crate::api::unix_now() + 3600,
                max_steps,
            },
        )
        .unwrap()
    }

    #[test]
    fn mode_b_on_the_device() {
        let session = parse_session(&format!("0x{}", "ab".repeat(32))).unwrap();
        let mut p = OnChainProver::new(&license(None), R1CS, PTAU, &["3".into()]).unwrap();
        // The vk is the circuit's: the same as from the trimmed ceremony file.
        let trimmed = evm_verifier::kzg::trim_ptau(PTAU, 8).unwrap();
        let q = OnChainProver::new(&license(None), R1CS, &trimmed, &["3".into()]).unwrap();
        assert_eq!(p.vk(), q.vk());
        assert_eq!(
            &p.open_session_calldata()[..4],
            &abi::selector("openSession(bytes32,uint256[])")
        );

        assert!(matches!(
            p.prove_step(WTNS[1]),
            Err(SdkError::StateMismatch)
        ));
        assert!(p.finalize(&session).is_err(), "nothing folded");
        p.prove_step(WTNS[0]).unwrap();
        p.prove_step(WTNS[1]).unwrap();
        assert_eq!(p.pending_steps(), 2);
        assert!(p.finalize(&session).is_err(), "steps not sent");
        let batch = p.take_calldata(&session).unwrap();
        assert_eq!(&batch[4..36], &session);
        p.prove_step(WTNS[2]).unwrap();
        p.take_calldata(&session).unwrap();
        assert_eq!(
            (p.steps(), p.state()),
            (3, vec!["130308420719099".to_string()])
        );
        let fin = p.finalize(&session).unwrap();
        assert_eq!(
            &fin[..4],
            &abi::selector("finalizeUniversal(bytes32,bytes,uint256[],uint256[])")
        );
        assert!(p.prove_step(WTNS[0]).is_err(), "finalized");

        // The license quota counts folded steps.
        let mut limited = OnChainProver::new(&license(Some(1)), R1CS, PTAU, &["3".into()]).unwrap();
        limited.prove_step(WTNS[0]).unwrap();
        assert!(matches!(
            limited.prove_step(WTNS[1]),
            Err(SdkError::QuotaExceeded { max_steps: 1 })
        ));
        assert!(parse_session("0x12").is_err());
    }
}
