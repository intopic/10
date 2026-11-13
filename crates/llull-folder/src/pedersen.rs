//! Additively homomorphic Pedersen vector commitments with a transparent
//! setup (spec §2.2, eq. 2): `Com(v; r) = Σ v_i·G_i + r·H`.

use crate::msm::ProverMsm;
use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, Zero};
use ark_std::cfg_into_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"zeno-llull/pedersen/v1";

/// Public commitment parameters: `n` vector generators and a blinding generator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentKey<C: CurveGroup> {
    pub gens: Vec<C::Affine>,
    pub h: C::Affine,
}

/// Derives a curve point with unknown discrete log from `(label, index)` by
/// try-and-increment over SHA-256 output. Nothing-up-my-sleeve: anyone can
/// recompute it, so no trusted setup is involved.
pub fn hash_to_curve<C: CurveGroup>(label: &[u8], index: u64) -> C::Affine {
    let mut counter = 0u32;
    loop {
        let mut bytes = [0u8; 64];
        for (block, chunk) in bytes.chunks_mut(32).enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(DOMAIN);
            hasher.update((label.len() as u64).to_le_bytes());
            hasher.update(label);
            hasher.update(index.to_le_bytes());
            hasher.update(counter.to_le_bytes());
            hasher.update([block as u8]);
            chunk.copy_from_slice(&hasher.finalize());
        }
        if let Some(p) = C::Affine::from_random_bytes(&bytes) {
            let p = p.clear_cofactor();
            if !p.is_zero() {
                return p;
            }
        }
        counter += 1;
    }
}

impl<C: CurveGroup> CommitmentKey<C> {
    /// Deterministically derives a key able to commit to vectors of length `n`.
    pub fn setup(label: &[u8], n: usize) -> Self {
        let gens = cfg_into_iter!(0..n as u64)
            .map(|i| hash_to_curve::<C>(label, i + 1))
            .collect();
        Self {
            gens,
            h: hash_to_curve::<C>(label, 0),
        }
    }

    /// Maximum committable vector length.
    pub fn len(&self) -> usize {
        self.gens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.gens.is_empty()
    }

    /// [`Self::commit`] with the arkworks multi-scalar multiplication, for
    /// every check of a commitment against an opening (verifiers and
    /// deciders), whatever the prover uses.
    pub fn commit_reference(&self, v: &[C::ScalarField], r: C::ScalarField) -> C {
        self.commit_with(v, r, |b, s| C::msm_unchecked(b, s))
    }

    /// Circuit witnesses are dominated by zeros and ones (bit decompositions),
    /// so those are handled by plain point additions and only the remaining
    /// scalars go through the multi-scalar multiplication.
    fn commit_with(
        &self,
        v: &[C::ScalarField],
        r: C::ScalarField,
        msm: impl Fn(&[C::Affine], &[C::ScalarField]) -> C,
    ) -> C {
        assert!(v.len() <= self.gens.len(), "commitment key too short");
        let mut ones = C::zero();
        let mut bases = Vec::new();
        let mut scalars = Vec::new();
        for (s, g) in v.iter().zip(&self.gens) {
            if s.is_zero() {
                continue;
            } else if s.is_one() {
                ones += g;
            } else {
                bases.push(*g);
                scalars.push(*s);
            }
        }
        let msm = if scalars.is_empty() {
            C::zero()
        } else {
            msm(&bases, &scalars)
        };
        msm + ones + self.h * r
    }
}

impl<C: ProverMsm> CommitmentKey<C> {
    /// `Com(v; r) = Σ v_i·G_i + r·H`, as the prover computes it (see
    /// [`ProverMsm`]). Panics if `v` is longer than the key.
    pub fn commit(&self, v: &[C::ScalarField], r: C::ScalarField) -> C {
        self.commit_with(v, r, |b, s| C::prover_msm(b, s))
    }
}
