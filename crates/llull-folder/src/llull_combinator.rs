//! The Llull combinatorial operator: the cross term produced when two
//! independent states are combined (spec §2.3, eq. 3):
//!
//! ```text
//! T = (A·Z1) ∘ (B·Z2) + (A·Z2) ∘ (B·Z1) − u1·(C·Z2) − u2·(C·Z1)
//! ```

use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_std::cfg_into_iter;
use core_r1cs::R1CSShape;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Computes the cross-term vector `T ∈ F^m` for `Z1 = (W1, x1, u1)` and
/// `Z2 = (W2, x2, u2)`, both given as full `Z` vectors.
pub fn compute_cross_term<F: PrimeField>(shape: &R1CSShape<F>, z1: &[F], z2: &[F]) -> Vec<F> {
    let (u1, u2) = (z1[shape.num_cols() - 1], z2[shape.num_cols() - 1]);
    let (az1, bz1, cz1) = shape.mul_z(z1);
    let (az2, bz2, cz2) = shape.mul_z(z2);
    cfg_into_iter!(0..shape.num_constraints)
        .map(|i| az1[i] * bz2[i] + az2[i] * bz1[i] - u1 * cz2[i] - u2 * cz1[i])
        .collect()
}
