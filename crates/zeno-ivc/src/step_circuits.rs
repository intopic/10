//! Ready-made step functions.

use crate::nova_ivc_circuit::StepCircuit;
use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// The identity step `F(z) = z`, used on the secondary curve.
#[derive(Clone, Copy, Debug, Default)]
pub struct TrivialStep;

impl<F: PrimeField> StepCircuit<F> for TrivialStep {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize(
        &self,
        _cs: ConstraintSystemRef<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(z.to_vec())
    }
}

/// `z ← z³ + z + 5`, iterated `rounds` times (2 constraints per round).
/// A simple, size-tunable stand-in for application logic.
#[derive(Clone, Copy, Debug)]
pub struct CubicStep {
    pub rounds: usize,
}

impl CubicStep {
    /// Native evaluation, for cross-checking the circuit.
    pub fn eval<F: PrimeField>(&self, z: F) -> F {
        (0..self.rounds).fold(z, |z, _| z * z * z + z + F::from(5u64))
    }
}

impl<F: PrimeField> StepCircuit<F> for CubicStep {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize(
        &self,
        cs: ConstraintSystemRef<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let five = F::from(5u64);
        let mut cur = z[0].clone();
        for _ in 0..self.rounds {
            // Each round output is its own witness, which keeps the linear
            // combinations flat: sq = cur², sq · cur = next − cur − 5.
            let sq = cur.square()?;
            let next = FpVar::new_witness(cs.clone(), || {
                let c = cur.value()?;
                Ok(c * c * c + c + five)
            })?;
            sq.mul_equals(&cur, &(&next - &cur - five))?;
            cur = next;
        }
        Ok(alloc::vec![cur])
    }
}
