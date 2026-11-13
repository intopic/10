//! Helpers shared by every argument over multilinear extensions of an R1CS
//! (the transparent Spartan decider, the universal decider, the CycleFold
//! argument and the Hyrax openings), so that each exists once.
//!
//! Convention: tables are indexed big-endian, the first variable being the
//! most significant bit of the index.

use crate::R1CSShape;
use alloc::vec::Vec;
use ark_ff::PrimeField;

/// `⌈log2 v⌉` (`0` for `v ≤ 1`).
pub fn log2_ceil(v: usize) -> usize {
    v.next_power_of_two().trailing_zeros() as usize
}

/// `v` zero-padded to `len` entries.
pub fn padded<F: PrimeField>(v: &[F], len: usize) -> Vec<F> {
    let mut out = v.to_vec();
    out.resize(len, F::zero());
    out
}

/// The table `eq(r, x)` for all `x ∈ {0,1}^len(r)`.
pub fn eq_table<F: PrimeField>(r: &[F]) -> Vec<F> {
    let mut table = alloc::vec![F::one()];
    for ri in r {
        let mut next = Vec::with_capacity(table.len() * 2);
        for v in &table {
            let hi = *v * ri;
            next.push(*v - hi);
            next.push(hi);
        }
        table = next;
    }
    table
}

/// Column of the engine's `Z = (W, x, u)` inside the padded
/// `(W ‖ (u, x))` whose halves have `n` entries each.
pub fn padded_column<F: PrimeField>(shape: &R1CSShape<F>, n: usize, col: usize) -> usize {
    if col < shape.num_vars {
        col
    } else if col == shape.num_vars + shape.num_io {
        n
    } else {
        n + 1 + (col - shape.num_vars)
    }
}

/// `⟨a, b⟩` over the common length.
pub fn inner_product<F: PrimeField>(a: &[F], b: &[F]) -> F {
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        if a.len().min(b.len()) >= 1 << 12 {
            return a.par_iter().zip(b.par_iter()).map(|(x, y)| *x * y).sum();
        }
    }
    a.iter().zip(b).map(|(x, y)| *x * y).sum()
}
