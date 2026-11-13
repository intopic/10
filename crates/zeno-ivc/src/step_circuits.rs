//! Ready-made step functions.

use crate::nova_ivc_circuit::StepCircuit;
use alloc::{sync::Arc, vec::Vec};
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

/// A step function given as an external R1CS (e.g. compiled by Circom):
/// `(A·w) ∘ (B·w) = C·w` over the wire vector `w`, with `w[0] = 1`.
///
/// `z_in_wires` / `z_out_wires` say which wires carry the IVC state. Every
/// other wire is a private witness, taken from `assignment` (the full wire
/// vector of this step, as produced by the circuit's witness generator).
#[derive(Clone, Debug)]
pub struct R1csStep<F: PrimeField> {
    pub num_wires: usize,
    /// The matrices are shared: a step is built for every witness, and the
    /// constraints do not change between steps.
    pub a: Arc<Vec<Vec<(F, usize)>>>,
    pub b: Arc<Vec<Vec<(F, usize)>>>,
    pub c: Arc<Vec<Vec<(F, usize)>>>,
    pub z_in_wires: Vec<usize>,
    pub z_out_wires: Vec<usize>,
    /// Wire values for this step; `None` only when deriving parameters.
    pub assignment: Option<Vec<F>>,
}

impl<F: PrimeField> R1csStep<F> {
    /// Checks the wire assignment against the constraints natively and
    /// returns the index of the first violated constraint, if any.
    pub fn first_unsatisfied(&self, w: &[F]) -> Option<usize> {
        let eval = |row: &[(F, usize)]| {
            row.iter()
                .fold(F::zero(), |acc, (coeff, i)| acc + *coeff * w[*i])
        };
        (0..self.a.len()).find(|&k| eval(&self.a[k]) * eval(&self.b[k]) != eval(&self.c[k]))
    }
}

impl<F: PrimeField> StepCircuit<F> for R1csStep<F> {
    fn arity(&self) -> usize {
        self.z_in_wires.len()
    }

    fn synthesize(
        &self,
        cs: ConstraintSystemRef<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        if let Some(w) = &self.assignment {
            if w.len() != self.num_wires {
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        let mut wires: Vec<Option<FpVar<F>>> = alloc::vec![None; self.num_wires];
        wires[0] = Some(FpVar::one());
        for (wire, var) in self.z_in_wires.iter().zip(z) {
            wires[*wire] = Some(var.clone());
        }
        let wires = wires
            .into_iter()
            .enumerate()
            .map(|(i, wire)| match wire {
                Some(var) => Ok(var),
                None => FpVar::new_witness(cs.clone(), || {
                    Ok(self.assignment.as_ref().map_or(F::zero(), |w| w[i]))
                }),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let eval = |row: &[(F, usize)]| -> FpVar<F> {
            row.iter()
                .fold(FpVar::zero(), |acc, (coeff, i)| acc + &wires[*i] * *coeff)
        };
        for k in 0..self.a.len() {
            eval(&self.a[k]).mul_equals(&eval(&self.b[k]), &eval(&self.c[k]))?;
        }
        Ok(self.z_out_wires.iter().map(|i| wires[*i].clone()).collect())
    }
}
