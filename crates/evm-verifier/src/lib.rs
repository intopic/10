//! `evm-verifier` — prover-side companion of `contracts/ZenoLlullVerifier.sol`.
//!
//! On the EVM the *chain itself* is the folding verifier: every call to
//! `verifyFoldedProof` folds one step instance into an accumulator stored in
//! the contract, using the BN254 precompiles (two `ecMul`, two `ecAdd`) and a
//! Keccak Fiat–Shamir challenge. No recursive circuit is needed.
//!
//! **Trust model.** The contract enforces that the accumulator is the
//! correct fold of the submitted step instances and that their public states
//! chain (`z_out` of one step is `z_in` of the next). It does *not* decide
//! whether the accumulated witness is valid: that is the job of the succinct
//! decider proof produced by [`OnChainFolder::finalize`], which anyone can
//! check off-chain against the finalized on-chain accumulator with
//! [`verify_final`]. Verifying an inner-product argument on-chain would cost
//! a multi-scalar multiplication over thousands of points and is not done.
#![cfg_attr(not(feature = "cli"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod abi;
pub mod cf_uniform;
pub mod kzg;
pub mod recursive;
pub mod universal;

use alloc::vec::Vec;
use ark_bn254::{Fq, Fr, G1Projective as G1, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use core_r1cs::{R1CSInstance, R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness};
use decider_zk::spartan::{self, SpartanProof};
use llull_folder::{
    commit_witness, nifs_prove_relaxed_with, nifs_prove_with, sample_relaxed, CommitmentKey,
    FoldError,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Transcript tag of a step fold; must match the contract.
pub const TAG_FOLD: u64 = 1;
/// Transcript tag of the final masking fold; must match the contract.
pub const TAG_MASK: u64 = 3;

/// Label of the commitment keys of Circom circuits in mode B; part of every
/// circuit's `vk`. The SDK and `zeno-evm` both use it, so a
/// circuit has the same `vk` whoever proves it.
pub const CIRCOM_UNIVERSAL_LABEL: &[u8] = b"zeno-llull/evm/universal/v1";
/// Label of the parameters of Circom circuits in mode D; part of the system
/// id.
pub const CIRCOM_RECURSIVE_LABEL: &[u8] = b"zeno-llull/evm/recursive/v1";

/// A 32-byte big-endian EVM word.
pub type Word = [u8; 32];

/// Big-endian encoding of a field element as an EVM word.
pub fn word<F: PrimeField>(f: &F) -> Word {
    let mut out = [0u8; 32];
    let bytes = f.into_bigint().to_bytes_be();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Affine coordinates as EVM words; the identity is `(0, 0)` as in EIP-196.
pub fn point_words(p: &G1) -> [Word; 2] {
    match p.into_affine().xy() {
        Some((x, y)) => [word(&x), word(&y)],
        None => [[0u8; 32]; 2],
    }
}

pub(crate) fn relaxed_words(out: &mut Vec<Word>, u: &RelaxedR1CSInstance<G1>) {
    out.extend(point_words(&u.comm_e));
    out.push(word(&u.u));
    out.extend(point_words(&u.comm_w));
    out.extend(u.x.iter().map(word));
}

fn keccak(words: &[Word]) -> Word {
    let mut hasher = Keccak256::new();
    for w in words {
        hasher.update(w);
    }
    hasher.finalize().into()
}

/// The low 128 bits of `keccak256(words)`, as the contract computes it.
fn challenge(words: &[Word]) -> Fr {
    Fr::from_be_bytes_mod_order(&keccak(words)[16..])
}

/// Fiat–Shamir challenge of a step fold.
pub fn fold_challenge(
    vk: &Word,
    acc: &RelaxedR1CSInstance<G1>,
    step: &R1CSInstance<G1>,
    comm_t: &G1,
) -> Fr {
    let mut words = alloc::vec![word(&Fr::from(TAG_FOLD)), *vk];
    relaxed_words(&mut words, acc);
    // Same order as the contract: both points first, then the public inputs.
    words.extend(point_words(&step.comm_w));
    words.extend(point_words(comm_t));
    words.extend(step.x.iter().map(word));
    challenge(&words)
}

/// Fiat–Shamir challenge of the final masking fold.
pub fn mask_challenge(
    vk: &Word,
    acc: &RelaxedR1CSInstance<G1>,
    mask: &RelaxedR1CSInstance<G1>,
    comm_t: &G1,
) -> Fr {
    let mut words = alloc::vec![word(&Fr::from(TAG_MASK)), *vk];
    relaxed_words(&mut words, acc);
    relaxed_words(&mut words, mask);
    words.extend(point_words(comm_t));
    challenge(&words)
}

/// Parameters of one step circuit on BN254. `vk` is what a session is opened
/// with on-chain; it binds the circuit and the commitment key.
pub struct EvmParams {
    pub shape: R1CSShape<Fr>,
    pub ck: CommitmentKey<G1>,
    pub vk: Word,
    /// `[τ]₂` when the commitment key is a KZG key (on-chain decider mode).
    pub tau_g2: Option<G2Affine>,
}

impl EvmParams {
    /// Derives the parameters transparently (hash-to-curve Pedersen key).
    /// The final accumulator is then decided off-chain with [`verify_final`].
    /// The step circuit must expose `x = (z_in, z_out)` as its public inputs.
    pub fn setup(shape: R1CSShape<Fr>, label: &[u8]) -> Self {
        let len = shape
            .num_vars
            .max(shape.num_constraints)
            .next_power_of_two();
        let ck = CommitmentKey::<G1>::setup(label, len);
        Self::from_key(shape, ck, None, label)
    }

    /// Derives the parameters for the *universal* decider and commits to
    /// the circuit. The commitment key is long enough for the circuit's
    /// matrices ([`universal::Dims::srs_len`]) and `vk` is the circuit's
    /// on-chain identity [`universal::CircuitKey::circuit_id`]. No
    /// per-circuit secret is involved anywhere.
    pub fn setup_universal(
        shape: R1CSShape<Fr>,
        label: &[u8],
        srs: &kzg::Srs,
    ) -> (Self, universal::CircuitKey) {
        let dims = universal::Dims::of(&shape);
        Self::setup_universal_with_dims(shape, label, srs, dims)
    }

    /// [`Self::setup_universal`] with dimensions at least the circuit's own,
    /// shared by circuits decided together by [`universal::batch`].
    pub fn setup_universal_with_dims(
        shape: R1CSShape<Fr>,
        label: &[u8],
        srs: &kzg::Srs,
        dims: universal::Dims,
    ) -> (Self, universal::CircuitKey) {
        let ck = srs.commitment_key(label, dims.srs_len());
        let key = universal::CircuitKey::preprocess_with_dims(&shape, &ck, dims);
        let vk = key.circuit_id(&ck.h, &srs.tau_g2);
        let params = Self {
            shape,
            ck,
            vk,
            tau_g2: Some(srs.tau_g2),
        };
        (params, key)
    }

    fn from_key(
        shape: R1CSShape<Fr>,
        ck: CommitmentKey<G1>,
        tau_g2: Option<G2Affine>,
        label: &[u8],
    ) -> Self {
        assert!(
            shape.num_io > 0 && shape.num_io.is_multiple_of(2),
            "public inputs must be (z_in, z_out)"
        );
        let mut bytes = Vec::new();
        let ser = "serializing to a Vec cannot fail";
        shape.serialize_compressed(&mut bytes).expect(ser);
        ck.gens.serialize_compressed(&mut bytes).expect(ser);
        ck.h.serialize_compressed(&mut bytes).expect(ser);
        tau_g2.serialize_compressed(&mut bytes).expect(ser);
        let mut hasher = Sha256::new();
        hasher.update(b"zeno-llull/evm-vk/v1");
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label);
        hasher.update(&bytes);
        Self {
            shape,
            ck,
            vk: hasher.finalize().into(),
            tau_g2,
        }
    }

    /// The decider's transcript binding of `vk`.
    fn digest(&self) -> Fq {
        Fq::from_be_bytes_mod_order(&self.vk)
    }

    /// State arity `k`: public inputs are `(z_in[k], z_out[k])`.
    pub fn arity(&self) -> usize {
        self.shape.num_io / 2
    }
}

/// What `verifyFoldedProof` needs for one step.
#[derive(Clone, Debug)]
pub struct StepProof {
    pub comm_w: G1,
    pub comm_t: G1,
    pub public_inputs: Vec<Fr>,
}

/// What `finalize` needs: the masking instance and its cross term.
#[derive(Clone, Debug)]
pub struct MaskProof {
    pub mask: RelaxedR1CSInstance<G1>,
    pub comm_t: G1,
}

/// The prover's mirror of the on-chain accumulator, plus its witness.
pub struct OnChainFolder {
    pub acc: RelaxedR1CSInstance<G1>,
    pub witness: RelaxedR1CSWitness<G1>,
    pub steps: u64,
}

impl OnChainFolder {
    /// The state of a freshly opened session.
    pub fn new(params: &EvmParams) -> Self {
        Self {
            acc: RelaxedR1CSInstance::default_for(&params.shape),
            witness: RelaxedR1CSWitness::default_for(&params.shape),
            steps: 0,
        }
    }

    /// Overwrites the accumulated witness with zeros.
    pub fn wipe(&mut self) {
        self.witness.wipe();
    }

    /// Folds one satisfied step `(w, x)` and returns what the contract needs
    /// to perform the same fold.
    pub fn fold_step(
        &mut self,
        params: &EvmParams,
        w: Vec<Fr>,
        x: Vec<Fr>,
        rng: &mut impl RngCore,
    ) -> Result<StepProof, FoldError> {
        params.shape.is_sat(&w, &x)?;
        let (u2, w2) = commit_witness(&params.ck, w, x, rng);
        let (acc, witness, comm_t) = nifs_prove_with(
            &params.ck,
            &params.shape,
            &self.acc,
            &self.witness,
            &u2,
            &w2,
            rng,
            |comm_t| fold_challenge(&params.vk, &self.acc, &u2, comm_t),
        )?;
        self.acc = acc;
        self.witness = witness;
        self.steps += 1;
        Ok(StepProof {
            comm_w: u2.comm_w,
            comm_t,
            public_inputs: u2.x,
        })
    }

    /// Folds a random satisfying relaxed pair into the accumulator, so that
    /// the final witness is uniformly distributed (zero-knowledge).
    #[allow(clippy::type_complexity)]
    fn mask(
        self,
        params: &EvmParams,
        rng: &mut impl RngCore,
    ) -> Result<(MaskProof, RelaxedR1CSInstance<G1>, RelaxedR1CSWitness<G1>), FoldError> {
        let (mask, mask_w) = sample_relaxed(&params.ck, &params.shape, rng);
        let (acc, witness, comm_t) = nifs_prove_relaxed_with(
            &params.ck,
            &params.shape,
            &self.acc,
            &self.witness,
            &mask,
            &mask_w,
            rng,
            |comm_t| mask_challenge(&params.vk, &self.acc, &mask, comm_t),
        )?;
        Ok((MaskProof { mask, comm_t }, acc, witness))
    }

    /// Mode A (transparent, off-chain decider): masks the accumulator and proves, succinctly,
    /// that the final accumulator is satisfiable. After the contract
    /// executes `finalize` with the returned [`MaskProof`], its accumulator
    /// equals the returned instance and the SNARK verifies against it
    /// off-chain.
    pub fn finalize(
        self,
        params: &EvmParams,
        rng: &mut impl RngCore,
    ) -> Result<(MaskProof, RelaxedR1CSInstance<G1>, SpartanProof<G1>), FoldError> {
        let (mask, acc, witness) = self.mask(params, rng)?;
        let snark = spartan::prove(&params.ck, &params.digest(), &params.shape, &acc, &witness);
        Ok((mask, acc, snark))
    }

    /// Mode B (universal on-chain decider): masks the accumulator and proves that it is
    /// satisfiable with the universal decider — no per-circuit keys, only
    /// the reference string and the public [`universal::CircuitKey`].
    /// `params` must come from [`EvmParams::setup_universal`].
    #[allow(clippy::type_complexity)]
    pub fn finalize_universal(
        self,
        params: &EvmParams,
        key: &universal::CircuitKey,
        rng: &mut impl RngCore,
    ) -> Result<
        (
            MaskProof,
            RelaxedR1CSInstance<G1>,
            universal::UniversalProof,
        ),
        DeciderError,
    > {
        if params.tau_g2.is_none() {
            return Err(DeciderError::NotKzg);
        }
        let (mask, acc, witness) = self.mask(params, rng)?;
        llull_folder::check_accumulator(&params.ck, &params.shape, &acc, &witness)
            .map_err(|_| DeciderError::Unsatisfied)?;
        let proof = universal::prove(params, key, &acc, &witness);
        if !universal::verify(params, key, &acc, &proof) {
            return Err(DeciderError::Unsatisfied);
        }
        Ok((mask, acc, proof))
    }
}

/// The accumulator the contract holds after executing `finalize*` with
/// `mask`: the masking fold recomputed from public data only.
pub fn fold_relaxed_mask(
    params: &EvmParams,
    acc: &RelaxedR1CSInstance<G1>,
    mask: &MaskProof,
) -> RelaxedR1CSInstance<G1> {
    let r = mask_challenge(&params.vk, acc, &mask.mask, &mask.comm_t);
    llull_folder::fold_relaxed_instance(acc, &mask.mask, &mask.comm_t, r)
}

/// Errors of the on-chain decider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeciderError {
    Fold(FoldError),
    /// The parameters were not derived over a KZG reference string.
    NotKzg,
    /// The accumulated witness does not satisfy the circuit.
    Unsatisfied,
}

impl From<FoldError> for DeciderError {
    fn from(e: FoldError) -> Self {
        Self::Fold(e)
    }
}

impl core::fmt::Display for DeciderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fold(e) => write!(f, "{e}"),
            Self::NotKzg => write!(f, "on-chain decider needs KZG parameters"),
            Self::Unsatisfied => write!(f, "accumulated witness does not satisfy the circuit"),
        }
    }
}

/// Off-chain decider: checks the succinct proof against the accumulator read
/// from the on-chain session. The caller must also check that the session is
/// `finalized` and was opened with `params.vk`; its `state` is then the
/// result of `steps` valid applications of the step function to `z0`.
pub fn verify_final(
    params: &EvmParams,
    onchain_acc: &RelaxedR1CSInstance<G1>,
    snark: &SpartanProof<G1>,
) -> bool {
    spartan::verify(
        &params.ck,
        &params.digest(),
        &params.shape,
        onchain_acc,
        snark,
    )
}
