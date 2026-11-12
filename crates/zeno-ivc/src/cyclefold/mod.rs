//! Recursive IVC with CycleFold, the route to deciding it on the EVM.
//!
//! The primary curve `G1` (BN254 for the EVM) carries the application
//! circuit. Its instances are folded *natively* in the primary circuit except
//! for the two commitment updates `W' = W + r·W_new` and `E' = E + r·T`,
//! which are delegated to tiny [`circuit::CycleFoldCircuit`] instances over
//! the other field of the cycle. Those are accumulated on the secondary curve
//! `G2` (Grumpkin) with [`hyrax`] row commitments, so that the final
//! accumulator can later be opened with `O(√M)` group operations instead of
//! `O(M)`.

pub mod augmented;
pub mod circuit;
pub mod hyrax;
pub mod ivc;

pub use augmented::CfAugmentedCircuit;
pub use circuit::{CycleFoldCircuit, CF_IO_LEN};
pub use hyrax::HyraxKey;
pub use ivc::{CycleFoldAccumulator, CycleFoldParams};
