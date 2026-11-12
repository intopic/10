//! `zeno-ivc` — Incrementally Verifiable Computation for the Zeno–Llull
//! engine (spec §2.6): every step proves `z_{i+1} = F(z_i)` *and* that the
//! previous step was folded correctly, over a 2-cycle of elliptic curves.
//!
//! The prover state ([`ZenoAccumulator`]) has a size independent of the
//! number of steps: like Zeno's series, infinitely many steps sum into one
//! bounded object.
#![cfg_attr(not(feature = "cli"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cyclefold;
pub mod gadgets;
pub mod ivc_stepper;
pub mod nonnative;
pub mod nova_ivc_circuit;
pub mod step_circuits;

pub use ivc_stepper::{IvcError, IvcParams, ZenoAccumulator};
pub use nova_ivc_circuit::{AugmentedCircuit, StepCircuit};
pub use step_circuits::{CubicStep, R1csStep, TrivialStep};
