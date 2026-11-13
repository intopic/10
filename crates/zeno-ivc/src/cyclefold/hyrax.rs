//! Hyrax-style row commitments (Wahby et al., S&P 2018) for the CycleFold
//! accumulator on the secondary curve.
//!
//! A vector `v` of length `M` is laid out as a matrix with `C` columns (`C` a
//! power of two) and committed row by row with the *same* `C` generators:
//!
//! ```text
//! com(v) = (Σ_j v[i·C + j]·G_j)_{i < ⌈M / C⌉}
//! ```
//!
//! The commitment is homomorphic row by row, which is all folding needs. Its
//! point is the final opening: a multilinear evaluation `ṽ(r)` is opened by
//! combining the rows with `eq(r_hi, ·)` and opening one row of length `C`,
//! i.e. `rows + C` group operations instead of `M`. That is what keeps the
//! closing circuit of the EVM decider small.
//!
//! There is no blinding: everything committed here (CycleFold witnesses and
//! cross terms) is a deterministic function of public data — the primary
//! commitments and the folding challenges.

use alloc::vec::Vec;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::cfg_iter;
use core_r1cs::{R1CSError, R1CSShape};
use llull_folder::{
    llull_combinator::compute_cross_term, msm::ProverMsm, CommitmentKey, FoldError,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// The `C` column generators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyraxKey<C: CurveGroup> {
    pub ck: CommitmentKey<C>,
}

impl<C: CurveGroup> HyraxKey<C> {
    /// Derives `cols` generators by hash-to-curve. No trusted setup.
    pub fn setup(label: &[u8], cols: usize) -> Self {
        assert!(
            cols.is_power_of_two(),
            "the column count must be a power of two"
        );
        Self {
            ck: CommitmentKey::setup(label, cols),
        }
    }

    pub fn cols(&self) -> usize {
        self.ck.len()
    }

    /// Number of row commitments of a vector of length `len`.
    pub fn rows(&self, len: usize) -> usize {
        len.div_ceil(self.cols())
    }

    /// [`Self::commit`] with the arkworks multi-scalar multiplication, for
    /// checks of commitments against openings.
    pub fn commit_reference(&self, v: &[C::ScalarField]) -> Vec<C> {
        let rows: Vec<&[C::ScalarField]> = v.chunks(self.cols()).collect();
        cfg_iter!(rows)
            .map(|row| self.ck.commit_reference(row, C::ScalarField::zero()))
            .collect()
    }
}

impl<C: ProverMsm> HyraxKey<C> {
    /// One commitment per row; the last row may be shorter (zero-padded).
    pub fn commit(&self, v: &[C::ScalarField]) -> Vec<C> {
        let rows: Vec<&[C::ScalarField]> = v.chunks(self.cols()).collect();
        cfg_iter!(rows)
            .map(|row| self.ck.commit(row, C::ScalarField::zero()))
            .collect()
    }
}

/// A fresh CycleFold instance: `u = 1`, `E = 0`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize)]
pub struct CfInstance<C: CurveGroup> {
    pub comm_w: Vec<C>,
    pub x: Vec<C::ScalarField>,
}

/// The running CycleFold accumulator `(comm_E, u, comm_W, x)`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize)]
pub struct CfRelaxedInstance<C: CurveGroup> {
    pub comm_e: Vec<C>,
    pub u: C::ScalarField,
    pub comm_w: Vec<C>,
    pub x: Vec<C::ScalarField>,
}

/// The accumulator's witness `(E, W)`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize)]
pub struct CfRelaxedWitness<F: PrimeField> {
    pub e: Vec<F>,
    pub w: Vec<F>,
}

impl<C: CurveGroup> CfRelaxedInstance<C> {
    /// The all-zero accumulator, satisfied by the all-zero witness.
    pub fn default_for(shape: &R1CSShape<C::ScalarField>, key: &HyraxKey<C>) -> Self {
        Self {
            comm_e: alloc::vec![C::zero(); key.rows(shape.num_constraints)],
            u: Zero::zero(),
            comm_w: alloc::vec![C::zero(); key.rows(shape.num_vars)],
            x: alloc::vec![Zero::zero(); shape.num_io],
        }
    }
}

impl<F: PrimeField> CfRelaxedWitness<F> {
    pub fn default_for(shape: &R1CSShape<F>) -> Self {
        Self {
            e: alloc::vec![F::zero(); shape.num_constraints],
            w: alloc::vec![F::zero(); shape.num_vars],
        }
    }
}

/// Commits to the witness of a fresh CycleFold instance.
pub fn cf_commit<C: ProverMsm>(
    key: &HyraxKey<C>,
    w: &[C::ScalarField],
    x: Vec<C::ScalarField>,
) -> CfInstance<C> {
    CfInstance {
        comm_w: key.commit(w),
        x,
    }
}

/// The cross term `T` of folding the accumulator with a fresh instance.
pub fn cf_cross_term<C: CurveGroup>(
    shape: &R1CSShape<C::ScalarField>,
    acc: &CfRelaxedInstance<C>,
    acc_w: &CfRelaxedWitness<C::ScalarField>,
    fresh: &CfInstance<C>,
    fresh_w: &[C::ScalarField],
) -> Result<Vec<C::ScalarField>, R1CSError> {
    let z1 = shape.z(&acc_w.w, &acc.x, acc.u)?;
    let z2 = shape.z(fresh_w, &fresh.x, C::ScalarField::from(1u64))?;
    Ok(compute_cross_term(shape, &z1, &z2))
}

/// `U ← U + r·u` on the instance side: one scalar multiplication per row of
/// `W` and per row of `T`.
pub fn cf_fold_instance<C: CurveGroup>(
    acc: &CfRelaxedInstance<C>,
    fresh: &CfInstance<C>,
    comm_t: &[C],
    r: C::ScalarField,
) -> CfRelaxedInstance<C> {
    assert_eq!(acc.comm_w.len(), fresh.comm_w.len(), "row count of W");
    assert_eq!(acc.comm_e.len(), comm_t.len(), "row count of E");
    CfRelaxedInstance {
        comm_e: acc
            .comm_e
            .iter()
            .zip(comm_t)
            .map(|(e, t)| *e + *t * r)
            .collect(),
        u: acc.u + r,
        comm_w: acc
            .comm_w
            .iter()
            .zip(&fresh.comm_w)
            .map(|(a, b)| *a + *b * r)
            .collect(),
        x: acc
            .x
            .iter()
            .zip(&fresh.x)
            .map(|(a, b)| *a + r * b)
            .collect(),
    }
}

/// `(E, W) ← (E + r·T, W + r·w)` on the witness side.
pub fn cf_fold_witness<F: PrimeField>(
    acc_w: &CfRelaxedWitness<F>,
    fresh_w: &[F],
    t: &[F],
    r: F,
) -> CfRelaxedWitness<F> {
    CfRelaxedWitness {
        e: cfg_iter!(acc_w.e)
            .zip(cfg_iter!(t))
            .map(|(e, t)| *e + r * t)
            .collect(),
        w: cfg_iter!(acc_w.w)
            .zip(cfg_iter!(fresh_w))
            .map(|(a, b)| *a + r * b)
            .collect(),
    }
}

/// Full (non-succinct) check of the accumulator: the relaxed relation holds
/// and every row commitment opens.
pub fn cf_check<C: CurveGroup>(
    key: &HyraxKey<C>,
    shape: &R1CSShape<C::ScalarField>,
    acc: &CfRelaxedInstance<C>,
    acc_w: &CfRelaxedWitness<C::ScalarField>,
) -> Result<(), FoldError> {
    shape.is_sat_relaxed(&acc_w.w, &acc.x, acc.u, &acc_w.e)?;
    if key.commit_reference(&acc_w.w) != acc.comm_w {
        return Err(FoldError::WitnessCommitmentMismatch);
    }
    if key.commit_reference(&acc_w.e) != acc.comm_e {
        return Err(FoldError::ErrorCommitmentMismatch);
    }
    Ok(())
}

/// The table `eq(r, k)` for all `k ∈ {0,1}^len(r)`, `r[0]` being the most
/// significant bit (the convention of `decider_zk::sumcheck::eq_table`).
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

/// The opening of `ṽ(r)` for a vector `v` with `C` columns, zero-padded to
/// `2^len(r)` entries, `r = (r_row ‖ r_col)` with `len(r_col) = log C`:
/// returns the row weights `L = eq(r_row, ·)` (one per committed row), the
/// combined row `v' = Σ_i L_i·row_i` and `ṽ(r) = ⟨v', eq(r_col, ·)⟩`.
pub fn hyrax_open<F: PrimeField>(v: &[F], cols: usize, r: &[F]) -> (Vec<F>, Vec<F>, F) {
    assert!(cols.is_power_of_two());
    let log_cols = cols.trailing_zeros() as usize;
    assert!(r.len() >= log_cols, "point too short");
    assert!(
        v.len() <= 1 << r.len(),
        "vector longer than the point allows"
    );
    let (r_row, r_col) = r.split_at(r.len() - log_cols);
    let rows = v.len().div_ceil(cols);
    let l: Vec<F> = eq_table(r_row)[..rows].to_vec();
    let mut combined = alloc::vec![F::zero(); cols];
    for (row, weight) in v.chunks(cols).zip(&l) {
        for (c, x) in combined.iter_mut().zip(row) {
            *c += *weight * x;
        }
    }
    let eval = combined
        .iter()
        .zip(eq_table(r_col))
        .map(|(a, b)| *a * b)
        .sum();
    (l, combined, eval)
}

/// The commitment side of the opening: `Σ_i L_i·C_i = Σ_j v'_j·G_j`.
pub fn hyrax_check<C: CurveGroup>(
    key: &HyraxKey<C>,
    rows: &[C],
    weights: &[C::ScalarField],
    combined: &[C::ScalarField],
) -> bool {
    assert_eq!(rows.len(), weights.len());
    let lhs: C = rows.iter().zip(weights).map(|(c, l)| *c * l).sum();
    lhs == key.ck.commit_reference(combined, C::ScalarField::zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    type G = ark_grumpkin::Projective;
    type F = ark_grumpkin::Fr;

    #[test]
    fn rows_are_homomorphic_and_padded() {
        let mut rng = test_rng();
        let key = HyraxKey::<G>::setup(b"test", 8);
        let a: Vec<F> = (0..21).map(|_| F::rand(&mut rng)).collect();
        let b: Vec<F> = (0..21).map(|_| F::rand(&mut rng)).collect();
        let r = F::rand(&mut rng);
        let (ca, cb) = (key.commit(&a), key.commit(&b));
        assert_eq!(ca.len(), 3);
        assert_eq!(key.rows(21), 3);
        let sum: Vec<F> = a.iter().zip(&b).map(|(x, y)| *x + r * y).collect();
        let expected: Vec<G> = ca.iter().zip(&cb).map(|(x, y)| *x + *y * r).collect();
        assert_eq!(key.commit(&sum), expected);
        // Each row uses the same generators: row i of `a` alone, moved to
        // row 0, commits to the same point.
        assert_eq!(key.commit(&a[8..16])[0], ca[1]);
    }

    #[test]
    fn opening_matches_the_multilinear_extension() {
        let mut rng = test_rng();
        let key = HyraxKey::<G>::setup(b"test", 8);
        // 29 entries: 4 committed rows of 8, the last one partial; 5 variables.
        let v: Vec<F> = (0..29).map(|_| F::rand(&mut rng)).collect();
        let r: Vec<F> = (0..5).map(|_| F::rand(&mut rng)).collect();
        let (l, combined, eval) = hyrax_open(&v, 8, &r);
        let direct: F = v.iter().zip(eq_table(&r)).map(|(a, b)| *a * b).sum();
        assert_eq!(eval, direct);
        let rows = key.commit(&v);
        assert!(hyrax_check(&key, &rows, &l, &combined));
        // A different combined row does not open the same rows.
        let mut forged = combined.clone();
        forged[3] += F::from(1u64);
        assert!(!hyrax_check(&key, &rows, &l, &forged));
    }
}
