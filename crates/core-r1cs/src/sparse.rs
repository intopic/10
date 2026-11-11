//! Compressed Sparse Row matrices over a prime field.

use alloc::vec::Vec;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::cfg_into_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A sparse matrix in CSR format.
///
/// Row `i` owns the entries `row_ptr[i]..row_ptr[i + 1]` of `col_idx` / `values`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SparseMatrix<F: Field> {
    pub num_rows: usize,
    pub num_cols: usize,
    pub row_ptr: Vec<usize>,
    pub col_idx: Vec<usize>,
    pub values: Vec<F>,
}

impl<F: Field> SparseMatrix<F> {
    /// Builds a CSR matrix from per-row lists of `(value, column)` entries.
    ///
    /// Zero coefficients are dropped. Panics if a column index is out of range.
    pub fn from_rows(rows: &[Vec<(F, usize)>], num_cols: usize) -> Self {
        let nnz = rows.iter().map(Vec::len).sum();
        let mut row_ptr = Vec::with_capacity(rows.len() + 1);
        let mut col_idx = Vec::with_capacity(nnz);
        let mut values = Vec::with_capacity(nnz);
        row_ptr.push(0);
        for row in rows {
            for (v, c) in row {
                assert!(*c < num_cols, "column index {c} out of range {num_cols}");
                if !v.is_zero() {
                    col_idx.push(*c);
                    values.push(*v);
                }
            }
            row_ptr.push(col_idx.len());
        }
        Self {
            num_rows: rows.len(),
            num_cols,
            row_ptr,
            col_idx,
            values,
        }
    }

    /// Number of stored non-zero entries.
    pub fn nnz(&self) -> usize {
        self.values.len()
    }

    /// Sparse matrix–vector product `M · z` in `O(nnz)`.
    pub fn mul_vec(&self, z: &[F]) -> Vec<F> {
        assert_eq!(z.len(), self.num_cols, "vector length mismatch");
        cfg_into_iter!(0..self.num_rows)
            .map(|i| {
                let (s, e) = (self.row_ptr[i], self.row_ptr[i + 1]);
                self.values[s..e]
                    .iter()
                    .zip(&self.col_idx[s..e])
                    .fold(F::zero(), |acc, (v, c)| acc + *v * z[*c])
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_pallas::Fr;

    #[test]
    fn csr_mul_vec_matches_dense() {
        // [[1, 0, 2], [0, 0, 0], [0, 3, 4]]
        let f = |x: u64| Fr::from(x);
        let rows = vec![
            vec![(f(1), 0), (f(2), 2)],
            vec![],
            vec![(f(3), 1), (f(4), 2), (f(0), 0)],
        ];
        let m = SparseMatrix::from_rows(&rows, 3);
        assert_eq!(m.nnz(), 4);
        assert_eq!(m.row_ptr, vec![0, 2, 2, 4]);
        let out = m.mul_vec(&[f(5), f(6), f(7)]);
        assert_eq!(out, vec![f(19), f(0), f(46)]);
    }
}
