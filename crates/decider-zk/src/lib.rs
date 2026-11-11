//! `decider-zk` — finalization of an IVC run into a proof that can be handed
//! to a third party (spec Faza 3, zero-knowledge masking).
//!
//! The prover state of `zeno-ivc` contains the accumulated witnesses in the
//! clear. [`ZkIvcProof::prove`] first folds the last pending instance, then
//! folds each accumulator with a fresh uniformly random satisfying relaxed
//! pair. The resulting witnesses `W' = W + r·W_rand` are uniformly
//! distributed, and `E'` is a function of `(W', x', u')`, so opening them
//! reveals nothing about the computation's private inputs beyond the public
//! statement `(i, z_0, z_i)` and the public instance scalars.
//!
//! This proof is zero-knowledge but **not succinct**: its size is linear in
//! the circuit size (and still independent of the number of steps).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod compressed_snark;

pub use compressed_snark::ZkIvcProof;
