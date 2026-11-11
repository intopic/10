//! The on-chain decider circuit (Groth16 over BN254).
//!
//! Public inputs `(u, x, c, w_c, e_c)`; witness `(W, E)`. It proves
//!
//! 1. `(A·Z) ∘ (B·Z) = u·(C·Z) + E` for `Z = (W, x, u)`, and
//! 2. `W(c) = w_c` and `E(c) = e_c`, reading `W`, `E` as polynomial
//!    coefficients.
//!
//! The contract derives `c` by hashing the accumulator *after* the
//! commitments are fixed and checks the KZG openings of `comm_W`, `comm_E`
//! at `c` against `w_c`, `e_c`. By Schwartz–Zippel the vectors inside the
//! circuit are the committed ones, so the accumulator is satisfiable.
//!
//! The circuit embeds the matrices of one application circuit, so its
//! Groth16 keys are specific to that circuit.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use core_r1cs::{R1CSShape, SparseMatrix};

/// One instance of the decider circuit. `None` assignments are used when
/// generating keys.
#[derive(Clone)]
pub struct DeciderCircuit<'a> {
    pub shape: &'a R1CSShape<Fr>,
    pub u: Option<Fr>,
    pub x: Option<Vec<Fr>>,
    pub c: Option<Fr>,
    pub w_eval: Option<Fr>,
    pub e_eval: Option<Fr>,
    pub w: Option<Vec<Fr>>,
    pub e: Option<Vec<Fr>>,
}

impl<'a> DeciderCircuit<'a> {
    /// The circuit without assignments, for key generation.
    pub fn blank(shape: &'a R1CSShape<Fr>) -> Self {
        Self {
            shape,
            u: None,
            x: None,
            c: None,
            w_eval: None,
            e_eval: None,
            w: None,
            e: None,
        }
    }

    /// Number of public inputs: `u`, `x`, `c`, `w_c`, `e_c`.
    pub fn num_public_inputs(shape: &R1CSShape<Fr>) -> usize {
        shape.num_io + 4
    }
}

fn get<T: Clone>(v: &Option<T>) -> Result<T, SynthesisError> {
    v.clone().ok_or(SynthesisError::AssignmentMissing)
}

fn row(matrix: &SparseMatrix<Fr>, i: usize, z: &[FpVar<Fr>]) -> FpVar<Fr> {
    (matrix.row_ptr[i]..matrix.row_ptr[i + 1]).fold(FpVar::zero(), |acc, k| {
        acc + &z[matrix.col_idx[k]] * matrix.values[k]
    })
}

fn horner(coeffs: &[FpVar<Fr>], c: &FpVar<Fr>) -> FpVar<Fr> {
    coeffs
        .iter()
        .rev()
        .fold(FpVar::zero(), |acc, a| acc * c + a)
}

impl ConstraintSynthesizer<Fr> for DeciderCircuit<'_> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let shape = self.shape;
        let u = FpVar::new_input(cs.clone(), || get(&self.u))?;
        let x = (0..shape.num_io)
            .map(|i| FpVar::new_input(cs.clone(), || get(&self.x).map(|x| x[i])))
            .collect::<Result<Vec<_>, _>>()?;
        let c = FpVar::new_input(cs.clone(), || get(&self.c))?;
        let w_eval = FpVar::new_input(cs.clone(), || get(&self.w_eval))?;
        let e_eval = FpVar::new_input(cs.clone(), || get(&self.e_eval))?;

        let w = (0..shape.num_vars)
            .map(|i| FpVar::new_witness(cs.clone(), || get(&self.w).map(|w| w[i])))
            .collect::<Result<Vec<_>, _>>()?;
        let e = (0..shape.num_constraints)
            .map(|i| FpVar::new_witness(cs.clone(), || get(&self.e).map(|e| e[i])))
            .collect::<Result<Vec<_>, _>>()?;

        // Z = (W, x, u), in the engine's column order.
        let mut z = w.clone();
        z.extend(x);
        z.push(u.clone());

        for (i, e_i) in e.iter().enumerate() {
            let rhs = &u * row(&shape.c, i, &z) + e_i;
            row(&shape.a, i, &z).mul_equals(&row(&shape.b, i, &z), &rhs)?;
        }
        horner(&w, &c).enforce_equal(&w_eval)?;
        horner(&e, &c).enforce_equal(&e_eval)?;
        Ok(())
    }
}
