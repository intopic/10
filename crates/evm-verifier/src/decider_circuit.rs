//! The on-chain decider circuit (Groth16 over BN254).
//!
//! Public inputs `(u, x, d, c, w_c, e_c)`; witness `(W, E)`. It proves
//!
//! 1. `(A·Z) ∘ (B·Z) = u·(C·Z) + E` for `Z = (W, x, u)`;
//! 2. `d = Poseidon(W, E)`;
//! 3. `W(c) = w_c` and `E(c) = e_c`, reading `W`, `E` as polynomial
//!    coefficients.
//!
//! The contract checks KZG openings of `comm_W`, `comm_E` at `c` against
//! `w_c`, `e_c`, with `c = keccak(accumulator, d)`.
//!
//! **Why the digest `d`.** The vectors inside the circuit must be the ones
//! committed on-chain. Agreement at one point `c` only implies equality
//! (Schwartz–Zippel) if the circuit's vectors were fixed *before* `c` was
//! known. Without `d`, a prover could pick `c`-dependent vectors that
//! satisfy the relation and merely coincide with the commitments at `c`.
//! Since `d` is a collision-resistant hash of the circuit's `(W, E)` and `c`
//! is derived from `d`, the vectors are fixed first.
//!
//! The circuit embeds the matrices of one application circuit, so its
//! Groth16 keys are specific to that circuit.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
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
    pub poseidon: &'a PoseidonConfig<Fr>,
    pub u: Option<Fr>,
    pub x: Option<Vec<Fr>>,
    pub digest: Option<Fr>,
    pub c: Option<Fr>,
    pub w_eval: Option<Fr>,
    pub e_eval: Option<Fr>,
    pub w: Option<Vec<Fr>>,
    pub e: Option<Vec<Fr>>,
}

impl<'a> DeciderCircuit<'a> {
    /// The circuit without assignments, for key generation.
    pub fn blank(shape: &'a R1CSShape<Fr>, poseidon: &'a PoseidonConfig<Fr>) -> Self {
        Self {
            shape,
            poseidon,
            digest: None,
            u: None,
            x: None,
            c: None,
            w_eval: None,
            e_eval: None,
            w: None,
            e: None,
        }
    }

    /// Number of public inputs: `u`, `x`, `d`, `c`, `w_c`, `e_c`.
    pub fn num_public_inputs(shape: &R1CSShape<Fr>) -> usize {
        shape.num_io + 5
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
        let digest = FpVar::new_input(cs.clone(), || get(&self.digest))?;
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
        // Bind (W, E) before the evaluation point is known.
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), self.poseidon);
        sponge.absorb(&w)?;
        sponge.absorb(&e)?;
        sponge.squeeze_field_elements(1)?[0].enforce_equal(&digest)?;

        horner(&w, &c).enforce_equal(&w_eval)?;
        horner(&e, &c).enforce_equal(&e_eval)?;
        Ok(())
    }
}

/// `d = Poseidon(W, E)`, exactly as the circuit computes it.
pub fn witness_digest(poseidon: &PoseidonConfig<Fr>, w: &[Fr], e: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon);
    sponge.absorb(&w.to_vec());
    sponge.absorb(&e.to_vec());
    sponge.squeeze_field_elements::<Fr>(1)[0]
}
