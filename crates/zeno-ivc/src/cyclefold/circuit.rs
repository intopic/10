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
//!
//! The witness and the constraints are laid out by type ([`layout`]), so that
//! the matrices repeat one small template over the 127 iterations of the
//! scalar multiplication: the EVM verifier evaluates them from that template
//! (`evm-verifier::cf_uniform`) instead of from their 4 380 entries.

use super::T_BITS;
use crate::gadgets::ec::{add, double, odd_scalar, AffineVar};
use alloc::vec::Vec;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, Field, One, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{
        fp::{AllocatedFp, FpVar},
        FieldVar,
    },
    R1CSVar,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable},
};
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

/// Number of slots per variable and constraint type in the uniform layout.
pub const CF_SLOTS: usize = 128;

/// Number of uniform variable (and constraint) types: one per role in an
/// iteration of the scalar multiplication.
pub const CF_UNIFORM_TYPES: usize = 7;

/// The witness and constraints of the circuit are laid out by *type*: the
/// 127 iterations of the scalar multiplication fill `CF_UNIFORM_TYPES`
/// blocks of `CF_SLOTS` consecutive witness variables and as many blocks of
/// consecutive constraints (slot `j` = iteration `j`, the last slot of each
/// block is empty), and the few remaining variables and constraints follow.
/// With `log2(CF_SLOTS)` low index bits for the slot and the high bits for
/// the type, the matrices are the same small template in every slot (plus a
/// few explicit entries), so the EVM verifier evaluates their multilinear
/// extensions from the template instead of from every entry.
///
/// Variable types (slot `j`): the bit `t_{126−j}` used by iteration `j`, the
/// digit `y_D = y_B·(2t − 1)`, then `λ, x_3, μ, x_4, y_4` of the
/// Eisenträger–Lauter–Montgomery step `A_{j+1} = 2A_j + D_j` (`A_0 = [3]B`,
/// `(x_3, ·) = A_j + D_j`, `A_{j+1} = (x_4, y_4)`). Constraint types: the
/// booleanity of the bit, the digit, and the five constraints of the step.
pub mod layout {
    pub const T: usize = 0;
    pub const DIGIT: usize = 1;
    pub const LAMBDA: usize = 2;
    pub const X3: usize = 3;
    pub const MU: usize = 4;
    pub const X4: usize = 5;
    pub const Y4: usize = 6;
}

/// The values of the uniform part of the trace, computed natively with the
/// formulas of the constraints (a zero denominator gives zero, as in the
/// gadgets; such a trace satisfies nothing).
struct Trace<F> {
    /// The base `B` (the generator when `p2` is the identity).
    b: (F, F),
    /// `A_0 = [3]B`.
    a0: (F, F),
    /// Per type, per iteration.
    cols: [Vec<F>; CF_UNIFORM_TYPES],
}

fn trace<P: SWCurveConfig>(t_bits: &[bool], p2: [P::BaseField; 2]) -> Trace<P::BaseField>
where
    P::BaseField: PrimeField,
{
    use crate::gadgets::ec::div;
    use ark_ec::AffineRepr;
    type F<P> = <P as ark_ec::CurveConfig>::BaseField;
    let (gx, gy) = P::GENERATOR
        .xy()
        .expect("the generator is not the identity");
    let (bx, by) = if p2[0].is_zero() && p2[1].is_zero() {
        (gx, gy)
    } else {
        (p2[0], p2[1])
    };
    // 2B (tangent), then 2B + B (chord).
    let l = div(F::<P>::from(3u64) * bx.square(), by.double());
    let x2 = l.square() - bx.double();
    let y2 = l * (bx - x2) - by;
    let l = div(by - y2, bx - x2);
    let x3b = l.square() - x2 - bx;
    let y3b = l * (x2 - x3b) - y2;

    let mut cols: [Vec<F<P>>; CF_UNIFORM_TYPES] = Default::default();
    let (mut xa, mut ya) = (x3b, y3b);
    for bit in t_bits.iter().rev() {
        let t = F::<P>::from(*bit);
        let yd = by * (t.double() - F::<P>::one());
        let lambda = div(yd - ya, bx - xa);
        let x3 = lambda.square() - xa - bx;
        let mu = div(ya.double(), xa - x3) - lambda;
        let x4 = mu.square() - xa - x3;
        let y4 = mu * (xa - x4) - ya;
        for (col, v) in cols.iter_mut().zip([t, yd, lambda, x3, mu, x4, y4]) {
            col.push(v);
        }
        (xa, ya) = (x4, y4);
    }
    Trace {
        b: (bx, by),
        a0: (x3b, y3b),
        cols,
    }
}

fn variable<F: PrimeField>(v: &FpVar<F>) -> Variable {
    match v {
        FpVar::Var(a) => a.variable,
        FpVar::Constant(_) => unreachable!("an allocated variable"),
    }
}

/// The variables of `B` and `[3]B`, shared by every iteration.
struct Bridge {
    b: (Variable, Variable),
    a0: (Variable, Variable),
}

/// Constraint `ty` of iteration `j`, over the uniform blocks `cols`.
fn uniform_row<F: PrimeField>(
    ty: usize,
    j: usize,
    cols: &[Vec<Variable>; CF_UNIFORM_TYPES],
    bridge: &Bridge,
) -> [LinearCombination<F>; 3] {
    use layout::*;
    let one = Variable::One;
    let two = F::from(2u64);
    let (bx, by) = bridge.b;
    let (xa, ya) = if j == 0 {
        bridge.a0
    } else {
        (cols[X4][j - 1], cols[Y4][j - 1])
    };
    let v = |t: usize| cols[t][j];
    match ty {
        // (1 − t)·t = 0
        T => [lc!() + one - v(T), lc!() + v(T), lc!()],
        // y_B·(2t − 1) = y_D
        DIGIT => [lc!() + by, lc!() + (two, v(T)) - one, lc!() + v(DIGIT)],
        // λ·(x_B − x_A) = y_D − y_A
        LAMBDA => [lc!() + v(LAMBDA), lc!() + bx - xa, lc!() + v(DIGIT) - ya],
        // λ² = x_3 + x_A + x_B
        X3 => [
            lc!() + v(LAMBDA),
            lc!() + v(LAMBDA),
            lc!() + v(X3) + xa + bx,
        ],
        // (μ + λ)·(x_A − x_3) = 2y_A
        MU => [
            lc!() + v(MU) + v(LAMBDA),
            lc!() + xa - v(X3),
            lc!() + (two, ya),
        ],
        // μ² = x_4 + x_A + x_3
        X4 => [lc!() + v(MU), lc!() + v(MU), lc!() + v(X4) + xa + v(X3)],
        // μ·(x_A − x_4) = y_4 + y_A
        Y4 => [lc!() + v(MU), lc!() + xa - v(X4), lc!() + v(Y4) + ya],
        _ => unreachable!("a uniform constraint type"),
    }
}

/// The circuit on raw input coordinates, which need not be valid points (so
/// that tests can check the on-curve constraints). The output is assigned
/// from the circuit's own computation; for valid points it is `p1 + [r]·p2`.
///
/// The constraints are those of [`crate::gadgets::ec::add_scalar_mul`] with
/// all `T_BITS` iterations in the Eisenträger–Lauter–Montgomery range,
/// allocated in the order of [`layout`]: first every uniform variable (and
/// `B`, `[3]B`), then the uniform constraints type by type, then the rest.
fn synthesize_coords<P: SWCurveConfig>(
    cs: ConstraintSystemRef<P::BaseField>,
    t_bits: &[bool],
    p1: [P::BaseField; 2],
    p2: [P::BaseField; 2],
) -> Result<(), SynthesisError>
where
    P::BaseField: PrimeField,
{
    type F<P> = <P as ark_ec::CurveConfig>::BaseField;
    let steps = t_bits.len();
    assert!(steps < CF_SLOTS, "one empty slot per type");
    // The iterations stay in the safe range of `scalar_mul_odd`.
    assert!(steps + 3 <= P::ScalarField::MODULUS_BIT_SIZE as usize);
    let tr = trace::<P>(t_bits, p2);

    // ---- Variables: the uniform blocks, then B and [3]B --------------------
    let mut cols: [Vec<Variable>; CF_UNIFORM_TYPES] = Default::default();
    for (block, values) in cols.iter_mut().zip(&tr.cols) {
        for slot in 0..CF_SLOTS {
            let v = values.get(slot).copied().unwrap_or_default();
            block.push(cs.new_witness_variable(|| Ok(v))?);
        }
    }
    let alloc = |v: F<P>| -> Result<FpVar<F<P>>, SynthesisError> {
        let var = cs.new_witness_variable(|| Ok(v))?;
        Ok(AllocatedFp::new(Some(v), var, cs.clone()).into())
    };
    let (bx, by) = (alloc(tr.b.0)?, alloc(tr.b.1)?);
    let (ax0, ay0) = (alloc(tr.a0.0)?, alloc(tr.a0.1)?);

    // ---- The uniform constraints, type by type -----------------------------
    let bridge = Bridge {
        b: (variable(&bx), variable(&by)),
        a0: (variable(&ax0), variable(&ay0)),
    };
    for ty in 0..CF_UNIFORM_TYPES {
        for slot in 0..CF_SLOTS {
            let [a, b, c] = if slot < steps {
                uniform_row(ty, slot, &cols, &bridge)
            } else {
                [lc!(), lc!(), lc!()]
            };
            cs.enforce_constraint(a, b, c)?;
        }
    }

    // ---- The rest: inputs, r, B, [3]B and the final addition ---------------
    use layout::{T, X4, Y4};
    let one = Variable::One;
    let two = F::<P>::from(2u64);
    let r_in = FpVar::new_input(cs.clone(), || Ok(odd_scalar::<F<P>>(t_bits)))?;
    let p1 = AffineVar::new_input::<P>(&cs, p1)?;
    let p2 = AffineVar::new_input::<P>(&cs, p2)?;
    // r = 2^(n+1) + 1 + Σ_j 2^(n−j)·t_{n−1−j}, slot j holding t_{n−1−j}.
    {
        let mut packed =
            lc!() + (odd_scalar::<F<P>>(&alloc::vec![false; steps]), one) - variable(&r_in);
        let mut weight = two;
        for slot in (0..steps).rev() {
            packed += (weight, cols[T][slot]);
            weight.double_in_place();
        }
        cs.enforce_constraint(packed, lc!() + one, lc!())?;
    }
    // B = p2, or the generator when p2 is the identity.
    {
        use ark_ec::AffineRepr;
        let (gx, gy) = P::GENERATOR
            .xy()
            .expect("the generator is not the identity");
        let inf = FpVar::from(p2.inf.clone());
        inf.mul_equals(&(FpVar::constant(gx) - &p2.x), &(&bx - &p2.x))?;
        inf.mul_equals(&(FpVar::constant(gy) - &p2.y), &(&by - &p2.y))?;
    }
    // [3]B = 2B + B, into the variables the first iteration uses.
    {
        let (x2, y2) = double(&cs, &bx, &by)?;
        let lambda = FpVar::new_witness(cs.clone(), || {
            Ok(crate::gadgets::ec::div(
                by.value()? - y2.value()?,
                bx.value()? - x2.value()?,
            ))
        })?;
        lambda.mul_equals(&(&bx - &x2), &(&by - &y2))?;
        lambda.mul_equals(&lambda, &(&ax0 + &x2 + &bx))?;
        lambda.mul_equals(&(&x2 - &ax0), &(&ay0 + &y2))?;
    }
    let last = |ty: usize| -> FpVar<F<P>> {
        let v = tr.cols[ty].last().copied().unwrap_or_default();
        AllocatedFp::new(Some(v), cols[ty][steps - 1], cs.clone()).into()
    };
    let product = AffineVar::select(
        &p2.inf,
        &AffineVar::identity(),
        &AffineVar {
            x: last(X4),
            y: last(Y4),
            inf: Boolean::FALSE,
        },
    )?;
    let out = add::<P>(&cs, &p1, &product)?;
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
    fn the_witness_follows_the_layout() {
        // Slot j of the bit block holds t_{126−j}, the last iteration's
        // (x_4, y_4) is [r]·p2, and the last slot of every uniform block of
        // constraints is empty.
        type P = ark_bn254::g1::Config;
        let mut rng = test_rng();
        let statement = CycleFoldCircuit::<P>::new(
            random_bits(&mut rng),
            Projective::rand(&mut rng),
            Projective::rand(&mut rng),
        );
        let (shape, (w, _)) = run::<P>(|cs| statement.synthesize(cs));
        let types = CF_UNIFORM_TYPES + 1;
        assert!(shape.num_vars <= types * CF_SLOTS && shape.num_constraints <= types * CF_SLOTS);
        let at = |ty: usize, j: usize| w[ty * CF_SLOTS + j];
        for j in 0..T_BITS {
            let bit = statement.t_bits[T_BITS - 1 - j];
            assert_eq!(at(layout::T, j), ark_bn254::Fq::from(bit));
        }
        let product = (statement.p2 * statement.r()).into_affine();
        assert_eq!(at(layout::X4, T_BITS - 1), product.x);
        assert_eq!(at(layout::Y4, T_BITS - 1), product.y);
        for ty in 0..CF_UNIFORM_TYPES {
            let row = ty * CF_SLOTS + CF_SLOTS - 1;
            for m in [&shape.a, &shape.b, &shape.c] {
                assert_eq!(m.row_ptr[row], m.row_ptr[row + 1], "slot 127 of type {ty}");
            }
        }
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
