//! `llull-folder` — the Non-Interactive Folding Scheme (NIFS) of the
//! Zeno–Llull Nova IVC engine (spec §2.2–§2.5).
//!
//! No FFT and no trusted setup: Pedersen generators are derived transparently
//! by hash-to-curve, the prover does linear field work plus one MSM for the
//! cross term `T`, and the verifier does exactly two scalar multiplications.
#![cfg_attr(not(feature = "cli"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod llull_combinator;
pub mod nifs_engine;
pub mod pedersen;
pub mod transcript;

#[cfg(feature = "cli")]
pub mod demo_circuit;

pub use core_r1cs;
pub use nifs_engine::{
    check_accumulator, commit_witness, nifs_prove, nifs_prove_relaxed, nifs_verify,
    nifs_verify_relaxed, sample_relaxed, FoldError, PublicParams,
};
pub use pedersen::CommitmentKey;
