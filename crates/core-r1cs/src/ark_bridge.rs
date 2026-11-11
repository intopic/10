//! Bridge from arkworks `ConstraintSystem`s (and therefore any circuit written
//! with `ark-relations` / `ark-r1cs-std`) into the CSR [`R1CSShape`].
//!
//! arkworks orders columns as `(1, x, W)`; this engine uses `(W, x, u)`.

use crate::relaxed_r1cs::R1CSShape;
use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Extracts the constraint matrices of a synthesized constraint system.
pub fn shape_from_cs<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
) -> Result<R1CSShape<F>, SynthesisError> {
    cs.finalize();
    let m = cs.to_matrices().ok_or(SynthesisError::MissingCS)?;
    let num_io = m.num_instance_variables - 1;
    let num_vars = m.num_witness_variables;
    let remap = |rows: &[Vec<(F, usize)>]| -> Vec<Vec<(F, usize)>> {
        rows.iter()
            .map(|row| {
                row.iter()
                    .map(|&(v, col)| {
                        let new_col = if col == 0 {
                            num_vars + num_io
                        } else if col <= num_io {
                            num_vars + col - 1
                        } else {
                            col - num_io - 1
                        };
                        (v, new_col)
                    })
                    .collect()
            })
            .collect()
    };
    Ok(R1CSShape::new(
        num_vars,
        num_io,
        &remap(&m.a),
        &remap(&m.b),
        &remap(&m.c),
    ))
}

/// Extracts `(W, x)` from a constraint system synthesized in proving mode.
pub fn assignment_from_cs<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
) -> Result<(Vec<F>, Vec<F>), SynthesisError> {
    cs.finalize();
    let inner = cs.borrow().ok_or(SynthesisError::MissingCS)?;
    let w = inner.witness_assignment.clone();
    let x = inner.instance_assignment[1..].to_vec();
    Ok((w, x))
}
