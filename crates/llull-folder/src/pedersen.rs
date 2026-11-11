//! Additively homomorphic Pedersen vector commitments with a transparent
//! setup (spec §2.2, eq. 2): `Com(v; r) = Σ v_i·G_i + r·H`.

use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
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

    /// `Com(v; r) = Σ v_i·G_i + r·H`. Panics if `v` is longer than the key.
    pub fn commit(&self, v: &[C::ScalarField], r: C::ScalarField) -> C {
        assert!(v.len() <= self.gens.len(), "commitment key too short");
        let msm = if v.iter().all(Zero::is_zero) {
            C::zero()
        } else {
            C::msm_unchecked(&self.gens[..v.len()], v)
        };
        msm + self.h * r
    }
}
