//! A parameterizable step circuit used by the CLI, tests and benchmarks:
//! `z ← z³ + z + 5`, iterated `rounds` times (2 constraints per round).

use ark_ff::PrimeField;
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, Variable,
    },
};
use core_r1cs::{
    ark_bridge::{assignment_from_cs, shape_from_cs},
    R1CSShape,
};

/// The step function `F(z) = z³ + z + 5`, applied `rounds` times.
#[derive(Clone, Copy, Debug)]
pub struct CubicChain<F: PrimeField> {
    pub z_in: F,
    pub rounds: usize,
}

impl<F: PrimeField> CubicChain<F> {
    /// Native evaluation of the step.
    pub fn output(&self) -> F {
        (0..self.rounds).fold(self.z_in, |z, _| z * z * z + z + F::from(5u64))
    }

    /// Synthesizes the step and returns `(shape, W, x)` with `x = (z_in, z_out)`.
    #[allow(clippy::type_complexity)]
    pub fn synthesize(&self) -> Result<(R1CSShape<F>, Vec<F>, Vec<F>), SynthesisError> {
        let cs = ConstraintSystem::<F>::new_ref();
        self.generate_constraints(cs.clone())?;
        let shape = shape_from_cs(&cs)?;
        let (w, x) = assignment_from_cs(&cs)?;
        Ok((shape, w, x))
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CubicChain<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let five = F::from(5u64);
        let z_out_val = self.output();
        let z_in = cs.new_input_variable(|| Ok(self.z_in))?;
        let z_out = cs.new_input_variable(|| Ok(z_out_val))?;

        let (mut z, mut z_val) = (z_in, self.z_in);
        for round in 0..self.rounds {
            let sq_val = z_val * z_val;
            let next_val = sq_val * z_val + z_val + five;
            let sq = cs.new_witness_variable(|| Ok(sq_val))?;
            let next = if round + 1 == self.rounds {
                z_out
            } else {
                cs.new_witness_variable(|| Ok(next_val))?
            };
            // z · z = sq
            cs.enforce_constraint(lc!() + z, lc!() + z, lc!() + sq)?;
            // sq · z = next − z − 5
            cs.enforce_constraint(
                lc!() + sq,
                lc!() + z,
                lc!() + next - z - (five, Variable::One),
            )?;
            (z, z_val) = (next, next_val);
        }
        if self.rounds == 0 {
            // z_out = z_in
            cs.enforce_constraint(lc!() + z_in, lc!() + Variable::One, lc!() + z_out)?;
        }
        Ok(())
    }
}
