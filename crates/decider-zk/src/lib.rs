//! `decider-zk` — finalization of an IVC run into a proof that can be handed
//! to a third party (spec Faza 3).
//!
//! 1. **Masking.** The pending instance is folded, then each accumulator is
//!    folded with a fresh uniformly random satisfying relaxed pair. The
//!    resulting witnesses `W' = W + r·W_rand` are uniformly distributed and
//!    `E'` is a function of `(W', x', u')`, so anything derived from them
//!    reveals nothing about the computation's private inputs.
//! 2. **Compression.** [`CompressedIvcProof`] replaces the masked witnesses
//!    by two transparent SNARKs (sum-check + inner-product arguments), giving
//!    a proof of a few kilobytes that is independent of the step count and
//!    logarithmic in the circuit size. [`ZkIvcProof`] is the uncompressed
//!    variant that ships the masked witnesses themselves.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod compressed_snark;
pub mod fs_transcript;
pub mod ipa;
pub mod spartan;
pub mod sumcheck;

pub use compressed_snark::{
    CompressedIvcProof, FoldedStatement, ProofFormatError, ZkIvcProof, PROOF_MAGIC, PROOF_VERSION,
};
