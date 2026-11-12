//! The universal on-chain decider (work in progress): no per-circuit keys.
//!
//! The application circuit's matrices are committed once, deterministically,
//! under the universal KZG reference string. A Spartan-style argument then
//! reduces the relaxed R1CS relation to multilinear evaluations of committed
//! polynomials, which are opened with [`hyperkzg`].

pub mod decider;
pub mod hyperkzg;
pub mod transcript;

pub use decider::{prove, verify, CircuitKey, Dims, UniversalProof};
