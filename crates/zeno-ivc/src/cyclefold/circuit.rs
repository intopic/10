//! The CycleFold circuit (Kothapalli, Setty, Tzialla — ePrint 2023/1192).
//!
//! It runs in the field `F = P::BaseField`, where points of the primary curve
//! `P` have native coordinates, and proves one scalar multiplication and
//! addition
//!
//! ```text
//! out = p1 + [r]·p2,   r = 2^128 + 2t + 1 for a 127-bit t.
//! ```
//!
//! The primary circuit folds its own commitments (points of `P`, whose
//! coordinates are foreign there) by delegating exactly this operation to
//! instances of this circuit, which are accumulated on the other curve of the
//! cycle. The scalar shape is that of every folding challenge of the
//! CycleFold IVC: it lets the low-weight gadgets of [`crate::gadgets::ec`] use
//! incomplete formulas that no prover can push into an exceptional case. Its
//! public input, in this order, is
//!
//! ```text
//! x = (r, p1.x, p1.y, p2.x, p2.y, out.x, out.y)
//! ```
//!
//! with the identity encoded as `(0, 0)`, which is never on a curve with
//! `b ≠ 0`. Input points are checked to lie on the curve (the primary curves
//! used here have prime order, so that is also the subgroup check).

use super::T_BITS;
use crate::gadgets::ec::{add_scalar_mul, odd_scalar, odd_scalar_var, AffineVar};
use alloc::vec::Vec;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use llull_folder::transcript::point_to_coords;

/// Length of the public input `x`.
pub const CF_IO_LEN: usize = 7;

/// One CycleFold statement `out = p1 + [r]·p2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CycleFoldCircuit<P: SWCurveConfig> {
    /// The `T_BITS` little-endian bits of `t`, with `r = 2^128 + 2t + 1`.
    pub t_bits: Vec<bool>,
    pub p1: Projective<P>,
    pub p2: Projective<P>,
}

impl<P: SWCurveConfig> CycleFoldCircuit<P>
where
    P::BaseField: PrimeField,
{
    pub fn new(t_bits: Vec<bool>, p1: Projective<P>, p2: Projective<P>) -> Self {
        assert_eq!(t_bits.len(), T_BITS, "t must have 127 bits");
        Self { t_bits, p1, p2 }
    }

    /// The statement `0 = 0 + [r]·0` with `t = 0`, used where a step has no
    /// fold (and to extract the shape).
    pub fn placeholder() -> Self {
        Self::new(
            alloc::vec![false; T_BITS],
            Projective::zero(),
            Projective::zero(),
        )
    }

    /// `r` as a scalar of `P`.
    pub fn r(&self) -> P::ScalarField {
        odd_scalar(&self.t_bits)
    }

    /// `p1 + [r]·p2`, computed natively.
    pub fn output(&self) -> Projective<P> {
        self.p1 + self.p2 * self.r()
    }

    /// The public input `x` of an honest instance.
    pub fn io(&self) -> Vec<P::BaseField> {
        let mut x = Vec::with_capacity(CF_IO_LEN);
        x.push(odd_scalar::<P::BaseField>(&self.t_bits));
        x.extend(point_to_coords(&self.p1));
        x.extend(point_to_coords(&self.p2));
        x.extend(point_to_coords(&self.output()));
        x
    }

    /// Generates the constraints. The structure is independent of the values.
    pub fn synthesize(&self, cs: ConstraintSystemRef<P::BaseField>) -> Result<(), SynthesisError> {
        synthesize_coords::<P>(
            cs,
            &self.t_bits,
            point_to_coords(&self.p1),
            point_to_coords(&self.p2),
        )
    }
}

/// The circuit on raw input coordinates, which need not be valid points (so
/// that tests can check the on-curve constraints). The output is assigned
/// from the circuit's own computation; for valid points it is `p1 + [r]·p2`.
fn synthesize_coords<P: SWCurveConfig>(
    cs: ConstraintSystemRef<P::BaseField>,
    t_bits: &[bool],
    p1: [P::BaseField; 2],
    p2: [P::BaseField; 2],
) -> Result<(), SynthesisError>
where
    P::BaseField: PrimeField,
{
    let r_in = FpVar::new_input(cs.clone(), || Ok(odd_scalar::<P::BaseField>(t_bits)))?;
    let p1 = AffineVar::new_input::<P>(&cs, p1)?;
    let p2 = AffineVar::new_input::<P>(&cs, p2)?;

    let t = t_bits
        .iter()
        .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
        .collect::<Result<Vec<_>, _>>()?;
    odd_scalar_var(&t)?.enforce_equal(&r_in)?;

    let out = add_scalar_mul::<P>(&cs, &p1, &p2, &t)?;
    let out_x = FpVar::new_input(cs.clone(), || out.x.value())?;
    let out_y = FpVar::new_input(cs.clone(), || out.y.value())?;
    out.x.enforce_equal(&out_x)?;
    out.y.enforce_equal(&out_y)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
    use ark_std::test_rng;
    use core_r1cs::{
        ark_bridge::{assignment_from_cs, shape_from_cs},
        R1CSShape,
    };

    type Shape<P> = R1CSShape<<P as ark_ec::CurveConfig>::BaseField>;
    type Assignment<P> = (
        Vec<<P as ark_ec::CurveConfig>::BaseField>,
        Vec<<P as ark_ec::CurveConfig>::BaseField>,
    );

    fn run<P: SWCurveConfig>(
        f: impl FnOnce(ConstraintSystemRef<P::BaseField>) -> Result<(), SynthesisError>,
    ) -> (Shape<P>, Assignment<P>)
    where
        P::BaseField: PrimeField,
    {
        let cs = ConstraintSystem::<P::BaseField>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        f(cs.clone()).unwrap();
        (
            shape_from_cs(&cs).unwrap(),
            assignment_from_cs(&cs).unwrap(),
        )
    }

    fn random_bits(rng: &mut impl ark_std::rand::RngCore) -> Vec<bool> {
        (0..T_BITS).map(|_| bool::rand(rng)).collect()
    }

    fn statements<P: SWCurveConfig>() -> Vec<CycleFoldCircuit<P>>
    where
        P::BaseField: PrimeField,
    {
        let mut rng = test_rng();
        let g = Projective::<P>::generator();
        let p = Projective::<P>::rand(&mut rng);
        let q = Projective::<P>::rand(&mut rng);
        let bits = random_bits(&mut rng);
        let mut one = alloc::vec![false; T_BITS];
        one[0] = true;
        let all_ones = alloc::vec![true; T_BITS];
        let r = CycleFoldCircuit::<P>::new(bits.clone(), p, q).r();
        alloc::vec![
            CycleFoldCircuit::new(bits.clone(), p, q),
            CycleFoldCircuit::new(all_ones, p, q),
            // Identity in every position, and an identity output.
            CycleFoldCircuit::new(bits.clone(), Projective::zero(), q),
            CycleFoldCircuit::new(bits.clone(), p, Projective::zero()),
            CycleFoldCircuit::new(alloc::vec![false; T_BITS], p, q),
            CycleFoldCircuit::new(bits.clone(), -(q * r), q),
            CycleFoldCircuit::placeholder(),
            // Doubling inside the final addition: p1 = [r]·p2.
            CycleFoldCircuit::new(bits, q * r, q),
            CycleFoldCircuit::new(one, g, g),
        ]
    }

    fn honest_statements_are_satisfied<P: SWCurveConfig>() -> Shape<P>
    where
        P::BaseField: PrimeField,
    {
        let mut shape = None;
        for statement in statements::<P>() {
            let (s, (w, x)) = run::<P>(|cs| statement.synthesize(cs));
            assert_eq!(x, statement.io(), "public input layout");
            s.is_sat(&w, &x).unwrap();
            // The shape does not depend on the values.
            if let Some(prev) = &shape {
                assert_eq!(prev, &s);
            }
            shape = Some(s);
        }
        shape.unwrap()
    }

    #[test]
    fn honest_statements_on_bn254_and_pallas() {
        let shape = honest_statements_are_satisfied::<ark_bn254::g1::Config>();
        assert_eq!(shape.num_io, CF_IO_LEN);
        std::println!(
            "CycleFold circuit (BN254): {} constraints, {} witness variables",
            shape.num_constraints,
            shape.num_vars
        );
        assert!(shape.num_constraints < 2048 && shape.num_vars < 2048);
        honest_statements_are_satisfied::<ark_pallas::PallasConfig>();
    }

    #[test]
    fn every_public_input_is_bound() {
        // Changing any coordinate of the statement, with the honest witness,
        // breaks satisfiability: the output is a function of (r, p1, p2).
        type P = ark_bn254::g1::Config;
        for statement in statements::<P>() {
            let (shape, (w, x)) = run::<P>(|cs| statement.synthesize(cs));
            for i in 0..CF_IO_LEN {
                let mut forged = x.clone();
                forged[i] += ark_bn254::Fq::from(1u64);
                assert!(shape.is_sat(&w, &forged).is_err(), "input {i} is free");
            }
        }
    }

    #[test]
    fn a_wrong_output_has_no_witness_in_the_honest_trace() {
        // The claimed output must equal p1 + [r]·p2: an honest trace for
        // (r, p1, p2) does not satisfy a different output.
        type P = ark_bn254::g1::Config;
        let mut rng = test_rng();
        let statement = CycleFoldCircuit::<P>::new(
            random_bits(&mut rng),
            Projective::rand(&mut rng),
            Projective::rand(&mut rng),
        );
        let (shape, (w, mut x)) = run::<P>(|cs| statement.synthesize(cs));
        let wrong = (statement.output() + Projective::<P>::generator()).into_affine();
        x[5] = wrong.x;
        x[6] = wrong.y;
        assert!(shape.is_sat(&w, &x).is_err());
    }

    #[test]
    fn off_curve_inputs_are_rejected() {
        type P = ark_bn254::g1::Config;
        type F = ark_bn254::Fq;
        let mut rng = test_rng();
        let bits = random_bits(&mut rng);
        let good = point_to_coords(&Projective::<P>::rand(&mut rng));
        // (1, 1) is not on y² = x³ + 3; neither is a valid x with a wrong y.
        let off = [F::from(1u64), F::from(1u64)];
        let wrong_y = [good[0], good[1] + F::from(1u64)];
        for (p1, p2) in [(off, good), (good, off), (wrong_y, good), (good, wrong_y)] {
            let cs = ConstraintSystem::<F>::new_ref();
            synthesize_coords::<P>(cs.clone(), &bits, p1, p2).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
        let cs = ConstraintSystem::<F>::new_ref();
        synthesize_coords::<P>(cs.clone(), &bits, good, good).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
