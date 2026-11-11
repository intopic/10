//! Standard and relaxed R1CS (spec §2.1, eq. 1):
//!
//! ```text
//! (A·Z) ∘ (B·Z) = u · (C·Z) + E,      Z = (W, x, u)
//! ```

use crate::sparse::SparseMatrix;
use alloc::vec::Vec;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::fmt;

/// Errors raised when checking an R1CS relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum R1CSError {
    /// A vector does not have the length the shape expects.
    InvalidLength {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// The relation does not hold at the given constraint row.
    Unsatisfied { row: usize },
}

impl fmt::Display for R1CSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                what,
                expected,
                got,
            } => write!(
                f,
                "invalid length for {what}: expected {expected}, got {got}"
            ),
            Self::Unsatisfied { row } => write!(f, "R1CS relation unsatisfied at row {row}"),
        }
    }
}

/// An R1CS constraint system with matrices in CSR form.
///
/// Columns are laid out as `Z = (W, x, u)`: `num_vars` witness columns, then
/// `num_io` public-input columns, then the single relaxation-scalar column.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSShape<F: PrimeField> {
    pub num_constraints: usize,
    pub num_vars: usize,
    pub num_io: usize,
    pub a: SparseMatrix<F>,
    pub b: SparseMatrix<F>,
    pub c: SparseMatrix<F>,
}

impl<F: PrimeField> R1CSShape<F> {
    /// Assembles a shape from per-row `(value, column)` lists.
    pub fn new(
        num_vars: usize,
        num_io: usize,
        a: &[Vec<(F, usize)>],
        b: &[Vec<(F, usize)>],
        c: &[Vec<(F, usize)>],
    ) -> Self {
        assert!(
            a.len() == b.len() && b.len() == c.len(),
            "row count mismatch"
        );
        let cols = num_vars + num_io + 1;
        Self {
            num_constraints: a.len(),
            num_vars,
            num_io,
            a: SparseMatrix::from_rows(a, cols),
            b: SparseMatrix::from_rows(b, cols),
            c: SparseMatrix::from_rows(c, cols),
        }
    }

    /// Total number of columns of `Z`.
    pub fn num_cols(&self) -> usize {
        self.num_vars + self.num_io + 1
    }

    /// Concatenates `Z = (W, x, u)`.
    pub fn z(&self, w: &[F], x: &[F], u: F) -> Result<Vec<F>, R1CSError> {
        check_len("W", self.num_vars, w.len())?;
        check_len("x", self.num_io, x.len())?;
        let mut z = Vec::with_capacity(self.num_cols());
        z.extend_from_slice(w);
        z.extend_from_slice(x);
        z.push(u);
        Ok(z)
    }

    /// Returns `(A·Z, B·Z, C·Z)`.
    pub fn mul_z(&self, z: &[F]) -> (Vec<F>, Vec<F>, Vec<F>) {
        (self.a.mul_vec(z), self.b.mul_vec(z), self.c.mul_vec(z))
    }

    /// Checks `(A·Z) ∘ (B·Z) = u·(C·Z) + E` row by row.
    pub fn is_sat_relaxed(&self, w: &[F], x: &[F], u: F, e: &[F]) -> Result<(), R1CSError> {
        check_len("E", self.num_constraints, e.len())?;
        let z = self.z(w, x, u)?;
        let (az, bz, cz) = self.mul_z(&z);
        for row in 0..self.num_constraints {
            if az[row] * bz[row] != u * cz[row] + e[row] {
                return Err(R1CSError::Unsatisfied { row });
            }
        }
        Ok(())
    }

    /// Checks the strict relation `(A·Z) ∘ (B·Z) = C·Z` with `Z = (W, x, 1)`.
    pub fn is_sat(&self, w: &[F], x: &[F]) -> Result<(), R1CSError> {
        let z = self.z(w, x, F::one())?;
        let (az, bz, cz) = self.mul_z(&z);
        match (0..self.num_constraints).find(|&i| az[i] * bz[i] != cz[i]) {
            Some(row) => Err(R1CSError::Unsatisfied { row }),
            None => Ok(()),
        }
    }
}

fn check_len(what: &'static str, expected: usize, got: usize) -> Result<(), R1CSError> {
    if expected == got {
        Ok(())
    } else {
        Err(R1CSError::InvalidLength {
            what,
            expected,
            got,
        })
    }
}

/// Public part of a fresh step: `(comm_W, x)` with implicit `u = 1`, `E = 0`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSInstance<C: CurveGroup> {
    pub comm_w: C,
    pub x: Vec<C::ScalarField>,
}

/// Secret part of a fresh step.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSWitness<C: CurveGroup> {
    pub w: Vec<C::ScalarField>,
    pub r_w: C::ScalarField,
}

/// The constant-size accumulator `U = (comm_E, u, comm_W, x)` (spec §2.2).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RelaxedR1CSInstance<C: CurveGroup> {
    pub comm_e: C,
    pub u: C::ScalarField,
    pub comm_w: C,
    pub x: Vec<C::ScalarField>,
}

/// The prover-side accumulator witness `(E, r_E, W, r_W)` (spec §2.2).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RelaxedR1CSWitness<C: CurveGroup> {
    pub e: Vec<C::ScalarField>,
    pub r_e: C::ScalarField,
    pub w: Vec<C::ScalarField>,
    pub r_w: C::ScalarField,
}

impl<C: CurveGroup> RelaxedR1CSInstance<C> {
    /// The trivial accumulator: everything zero. It satisfies any shape with
    /// the all-zero witness, and is the starting point `U_0` of a fold chain.
    pub fn default_for(shape: &R1CSShape<C::ScalarField>) -> Self {
        Self {
            comm_e: C::zero(),
            u: C::ScalarField::zero(),
            comm_w: C::zero(),
            x: alloc::vec![C::ScalarField::zero(); shape.num_io],
        }
    }
}

impl<C: CurveGroup> RelaxedR1CSWitness<C> {
    /// The all-zero witness matching [`RelaxedR1CSInstance::default_for`].
    pub fn default_for(shape: &R1CSShape<C::ScalarField>) -> Self {
        Self {
            e: alloc::vec![C::ScalarField::zero(); shape.num_constraints],
            r_e: C::ScalarField::zero(),
            w: alloc::vec![C::ScalarField::zero(); shape.num_vars],
            r_w: C::ScalarField::zero(),
        }
    }
}
