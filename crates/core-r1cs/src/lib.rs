//! `core-r1cs` — constraint-system layer of the Zeno–Llull Nova IVC engine.
//!
//! * [`SparseMatrix`]: CSR (Compressed Sparse Row) matrices `A, B, C`.
//! * [`R1CSShape`]: the constraint system with `Z = (W, x, u)` column layout.
//! * [`R1CSInstance`] / [`R1CSWitness`]: a fresh (strict) R1CS step.
//! * [`RelaxedR1CSInstance`] / [`RelaxedR1CSWitness`]: the O(1) accumulator
//!   `U = (comm_E, u, comm_W, x)` and its witness `(E, r_E, W, r_W)`.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "arkworks-bridge")]
pub mod ark_bridge;
pub mod layout;
pub mod mle;
pub mod relaxed_r1cs;
pub mod sparse;

pub use relaxed_r1cs::{
    R1CSError, R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness,
};
pub use sparse::SparseMatrix;
