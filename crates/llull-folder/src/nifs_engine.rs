//! NIFS prove / verify (spec §2.4, eq. 6–7) with Zeno-style accumulation:
//! an unbounded sequence of steps collapses into one constant-size `(U, W)`.

use crate::{
    llull_combinator::compute_cross_term,
    pedersen::CommitmentKey,
    transcript::{fold_challenge, poseidon_config},
};
use alloc::vec::Vec;
use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::{cfg_iter, rand::RngCore};
use core::fmt;
use core_r1cs::{
    R1CSError, R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};

/// Errors of the folding engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoldError {
    R1CS(R1CSError),
    /// `comm_W` does not open to `(W, r_W)`.
    WitnessCommitmentMismatch,
    /// `comm_E` does not open to `(E, r_E)`.
    ErrorCommitmentMismatch,
}

impl From<R1CSError> for FoldError {
    fn from(e: R1CSError) -> Self {
        Self::R1CS(e)
    }
}

impl fmt::Display for FoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::R1CS(e) => write!(f, "{e}"),
            Self::WitnessCommitmentMismatch => write!(f, "comm_W does not open to the witness"),
            Self::ErrorCommitmentMismatch => write!(f, "comm_E does not open to the error vector"),
        }
    }
}

/// Transparent public parameters for folding instances of one R1CS shape.
#[derive(Clone)]
pub struct PublicParams<C: CurveGroup>
where
    C::BaseField: PrimeField,
{
    /// Pedersen key; long enough for both `W` and `E`.
    pub ck: CommitmentKey<C>,
    /// Poseidon parameters of the Fiat–Shamir sponge.
    pub poseidon: PoseidonConfig<C::BaseField>,
    /// Binding digest of the shape and commitment key (`vk` in eq. 5).
    pub digest: C::BaseField,
}

impl<C: CurveGroup> PublicParams<C>
where
    C::BaseField: PrimeField + Absorb,
{
    /// Derives all parameters deterministically. No trusted setup.
    pub fn setup(shape: &R1CSShape<C::ScalarField>, label: &[u8]) -> Self {
        let ck: CommitmentKey<C> =
            CommitmentKey::setup(label, shape.num_vars.max(shape.num_constraints));
        let mut hasher = Sha256::new();
        hasher.update(b"zeno-llull/pp-digest/v1");
        let mut bytes = Vec::new();
        shape
            .serialize_compressed(&mut bytes)
            .expect("serializing to a Vec cannot fail");
        ck.h.serialize_compressed(&mut bytes)
            .expect("serializing to a Vec cannot fail");
        ck.gens
            .serialize_compressed(&mut bytes)
            .expect("serializing to a Vec cannot fail");
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label);
        hasher.update(&bytes);
        // 31 bytes always fit below the modulus of a ~255-bit field.
        let digest = C::BaseField::from_le_bytes_mod_order(&hasher.finalize()[..31]);
        Self {
            ck,
            poseidon: poseidon_config(),
            digest,
        }
    }
}

/// Commits to the witness of a fresh step, producing a strict R1CS pair.
pub fn commit_witness<C: CurveGroup>(
    ck: &CommitmentKey<C>,
    w: Vec<C::ScalarField>,
    x: Vec<C::ScalarField>,
    rng: &mut impl RngCore,
) -> (R1CSInstance<C>, R1CSWitness<C>) {
    let r_w = C::ScalarField::rand(rng);
    let comm_w = ck.commit(&w, r_w);
    (R1CSInstance { comm_w, x }, R1CSWitness { w, r_w })
}

/// Prover: folds the accumulator `(U1, W1)` with the fresh step `(U2, W2)`.
///
/// Field work is linear in the circuit size; the only group work is the MSM
/// committing to the cross term `T`. Returns the folded pair and `comm_T`.
pub fn nifs_prove<C: CurveGroup>(
    pp: &PublicParams<C>,
    shape: &R1CSShape<C::ScalarField>,
    u1: &RelaxedR1CSInstance<C>,
    w1: &RelaxedR1CSWitness<C>,
    u2: &R1CSInstance<C>,
    w2: &R1CSWitness<C>,
    rng: &mut impl RngCore,
) -> Result<(RelaxedR1CSInstance<C>, RelaxedR1CSWitness<C>, C), FoldError>
where
    C::BaseField: PrimeField + Absorb,
{
    let z1 = shape.z(&w1.w, &u1.x, u1.u)?;
    let z2 = shape.z(&w2.w, &u2.x, C::ScalarField::one())?;
    let t = compute_cross_term(shape, &z1, &z2);
    let r_t = C::ScalarField::rand(rng);
    let comm_t = pp.ck.commit(&t, r_t);

    let r = fold_challenge(&pp.poseidon, pp.digest, u1, u2, &comm_t);

    // E2 = 0 and r_E2 = 0 for a fresh step, so the r² terms vanish.
    let w = cfg_iter!(w1.w)
        .zip(cfg_iter!(w2.w))
        .map(|(a, b)| *a + r * b)
        .collect();
    let e = cfg_iter!(w1.e)
        .zip(cfg_iter!(t))
        .map(|(a, b)| *a + r * b)
        .collect();
    let folded_w = RelaxedR1CSWitness {
        e,
        r_e: w1.r_e + r * r_t,
        w,
        r_w: w1.r_w + r * w2.r_w,
    };
    let folded_u = fold_instance(u1, u2, &comm_t, r);
    Ok((folded_u, folded_w, comm_t))
}

/// Verifier: folds the public instances in `O(1)` with exactly two scalar
/// multiplications (`r·comm_T` and `r·comm_W2`).
pub fn nifs_verify<C: CurveGroup>(
    poseidon: &PoseidonConfig<C::BaseField>,
    pp_digest: C::BaseField,
    u1: &RelaxedR1CSInstance<C>,
    u2: &R1CSInstance<C>,
    comm_t: &C,
) -> RelaxedR1CSInstance<C>
where
    C::BaseField: PrimeField + Absorb,
{
    let r = fold_challenge(poseidon, pp_digest, u1, u2, comm_t);
    fold_instance(u1, u2, comm_t, r)
}

fn fold_instance<C: CurveGroup>(
    u1: &RelaxedR1CSInstance<C>,
    u2: &R1CSInstance<C>,
    comm_t: &C,
    r: C::ScalarField,
) -> RelaxedR1CSInstance<C> {
    RelaxedR1CSInstance {
        comm_e: u1.comm_e + *comm_t * r,
        u: u1.u + r,
        comm_w: u1.comm_w + u2.comm_w * r,
        x: u1.x.iter().zip(&u2.x).map(|(a, b)| *a + r * b).collect(),
    }
}

/// Full (non-succinct) decider: the accumulator satisfies the relaxed R1CS
/// relation with *zero* residual and both commitments open correctly.
pub fn check_accumulator<C: CurveGroup>(
    ck: &CommitmentKey<C>,
    shape: &R1CSShape<C::ScalarField>,
    u: &RelaxedR1CSInstance<C>,
    w: &RelaxedR1CSWitness<C>,
) -> Result<(), FoldError> {
    shape.is_sat_relaxed(&w.w, &u.x, u.u, &w.e)?;
    if ck.commit(&w.w, w.r_w) != u.comm_w {
        return Err(FoldError::WitnessCommitmentMismatch);
    }
    if ck.commit(&w.e, w.r_e) != u.comm_e {
        return Err(FoldError::ErrorCommitmentMismatch);
    }
    Ok(())
}
