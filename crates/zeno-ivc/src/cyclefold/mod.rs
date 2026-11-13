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

/// Bits of `t` in every folding challenge `r = 2^128 + 2t + 1`: one squeezed
/// element gives 127 bits of entropy (see [`crate::gadgets::ec`]).
pub const T_BITS: usize = 127;

/// Default number of columns of the CycleFold row commitments. With the
/// 943-constraint CycleFold circuit (936 witness variables) it gives 8 rows
/// for `W` and 8 for `E`: the smallest closing circuit (8 + 8 variable-base
/// and 128 fixed-base multiplications), for about 2.5k constraints per row
/// and step (66.8k constraints per step in all, 468k non-zero entries). It is
/// also the number of slots of the circuit's uniform layout.
pub const CF_COLUMNS: usize = 128;

pub mod augmented;
pub mod circuit;
pub mod closing;
pub mod hyrax;
pub mod ivc;

pub use augmented::CfAugmentedCircuit;
pub use circuit::{CycleFoldCircuit, CF_IO_LEN};
pub use hyrax::HyraxKey;
pub use ivc::{CycleFoldAccumulator, CycleFoldParams};
