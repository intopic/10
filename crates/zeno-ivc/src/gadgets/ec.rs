//! Low-weight gadgets for short-Weierstrass curves `y² = x³ + b` (`a = 0`:
//! BN254, Grumpkin, Pallas, Vesta) in affine coordinates, for curves of
//! prime order.
//!
//! Every intermediate value is its own witness, so each constraint touches a
//! handful of variables: the matrices stay sparse, which is what the
//! universal decider pays for (its reference string grows with the number of
//! non-zero entries, not with the number of constraints). The generic
//! arkworks gadgets build long symbolic linear combinations instead (about
//! 54 non-zero entries per constraint in a scalar multiplication).
//!
//! **Scalars.** [`scalar_mul_odd`] multiplies by `k = 2^(n+1) + 2t + 1` for an
//! `n`-bit `t`, using one Eisenträger–Lauter–Montgomery double-and-add
//! `2A ± B` per bit of `t` (signed digits `2t_i − 1`). With that scalar
//! shape, every intermediate multiple is `[k']B` with `k'` odd and
//! `3 ≤ k' < 2^(n+2)`, so for `2^(n+3)` below the group order none of the
//! incomplete formulas can hit an exceptional case, for *any* prover and
//! *any* base: every slope is uniquely determined. The folding challenges of
//! the CycleFold IVC are defined with this shape (`n = 127`).

use alloc::vec::Vec;
use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::{Field, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// A point in affine coordinates; the identity is `(0, 0)` with `inf` set.
/// The encoding is unique: `(0, 0)` is never on a curve with `b ≠ 0`.
#[derive(Clone, Debug)]
pub struct AffineVar<F: PrimeField> {
    pub x: FpVar<F>,
    pub y: FpVar<F>,
    pub inf: Boolean<F>,
}

fn witness<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    f: impl FnOnce() -> Result<F, SynthesisError>,
) -> Result<FpVar<F>, SynthesisError> {
    FpVar::new_witness(cs.clone(), f)
}

fn check_curve<P: SWCurveConfig>() {
    assert!(P::COEFF_A.is_zero(), "these gadgets assume a = 0");
    assert!(
        !P::COEFF_B.is_zero(),
        "(0, 0) encodes the identity only when b ≠ 0"
    );
}

impl<F: PrimeField> AffineVar<F> {
    pub fn identity() -> Self {
        Self {
            x: FpVar::zero(),
            y: FpVar::zero(),
            inf: Boolean::TRUE,
        }
    }

    /// The coordinates `(x, y)`, `(0, 0)` for the identity.
    pub fn coords(&self) -> [FpVar<F>; 2] {
        [self.x.clone(), self.y.clone()]
    }

    /// Enforces the encoding: `inf ⇒ x = 0`, and `y² = x³ + b·(1 − inf)`
    /// (which then forces `y = 0` for the identity, and puts every other
    /// point on the curve). Four constraints, plus the booleanity of `inf`.
    fn enforce_encoding<P: SWCurveConfig<BaseField = F>>(&self) -> Result<(), SynthesisError> {
        check_curve::<P>();
        let inf = FpVar::from(self.inf.clone());
        (&self.x * &inf).enforce_equal(&FpVar::zero())?;
        let x3 = self.x.square()? * &self.x;
        let rhs = x3 + (FpVar::one() - inf) * P::COEFF_B;
        self.y.square()?.enforce_equal(&rhs)
    }

    /// Allocates a witness point, checked to be on the curve (which for a
    /// prime-order curve is also the subgroup check).
    pub fn new_witness<P: SWCurveConfig<BaseField = F>>(
        cs: &ConstraintSystemRef<F>,
        p: &Projective<P>,
    ) -> Result<Self, SynthesisError> {
        let affine = p.into_affine();
        let (x, y) = affine.xy().unwrap_or((F::zero(), F::zero()));
        let point = Self {
            x: witness(cs, || Ok(x))?,
            y: witness(cs, || Ok(y))?,
            inf: Boolean::new_witness(cs.clone(), || Ok(affine.is_zero()))?,
        };
        point.enforce_encoding::<P>()?;
        Ok(point)
    }

    /// Allocates a point given as two public coordinates (`(0, 0)` for the
    /// identity); any other pair must lie on the curve.
    pub fn new_input<P: SWCurveConfig<BaseField = F>>(
        cs: &ConstraintSystemRef<F>,
        coords: [F; 2],
    ) -> Result<Self, SynthesisError> {
        let point = Self {
            x: FpVar::new_input(cs.clone(), || Ok(coords[0]))?,
            y: FpVar::new_input(cs.clone(), || Ok(coords[1]))?,
            inf: Boolean::new_witness(cs.clone(), || {
                Ok(coords[0].is_zero() && coords[1].is_zero())
            })?,
        };
        point.enforce_encoding::<P>()?;
        Ok(point)
    }

    pub fn constant<P: SWCurveConfig<BaseField = F>>(p: &Affine<P>) -> Self {
        let (x, y) = p.xy().unwrap_or((F::zero(), F::zero()));
        Self {
            x: FpVar::constant(x),
            y: FpVar::constant(y),
            inf: Boolean::constant(p.is_zero()),
        }
    }

    /// `cond ? a : b`, three constraints.
    pub fn select(cond: &Boolean<F>, a: &Self, b: &Self) -> Result<Self, SynthesisError> {
        Ok(Self {
            x: cond.select(&a.x, &b.x)?,
            y: cond.select(&a.y, &b.y)?,
            inf: cond.select(&a.inf, &b.inf)?,
        })
    }

    /// The point's value.
    pub fn value<P: SWCurveConfig<BaseField = F>>(&self) -> Result<Projective<P>, SynthesisError> {
        if self.inf.value()? {
            Ok(Projective::zero())
        } else {
            Ok(Affine::new_unchecked(self.x.value()?, self.y.value()?).into())
        }
    }
}

fn div<F: Field>(num: F, den: F) -> F {
    den.inverse().map(|inv| num * inv).unwrap_or_else(F::zero)
}

/// `2·(x, y)` for a point other than the identity (`y ≠ 0` on a prime-order
/// curve). Four constraints.
fn double<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    x: &FpVar<F>,
    y: &FpVar<F>,
) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
    let x_sq = x.square()?;
    let three = F::from(3u64);
    let lambda = witness(cs, || Ok(div(three * x_sq.value()?, y.value()?.double())))?;
    lambda.mul_equals(&y.double()?, &(&x_sq * three))?;
    let x2 = witness(cs, || Ok(lambda.value()?.square() - x.value()?.double()))?;
    lambda.mul_equals(&lambda, &(&x2 + x.double()?))?;
    let y2 = witness(cs, || {
        Ok(lambda.value()? * (x.value()? - x2.value()?) - y.value()?)
    })?;
    lambda.mul_equals(&(x - &x2), &(&y2 + y))?;
    Ok((x2, y2))
}

/// `A + D` for `A ≠ ±D`, both not the identity. Three constraints.
fn add_incomplete<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    (xa, ya): (&FpVar<F>, &FpVar<F>),
    (xd, yd): (&FpVar<F>, &FpVar<F>),
) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
    let lambda = witness(cs, || {
        Ok(div(yd.value()? - ya.value()?, xd.value()? - xa.value()?))
    })?;
    lambda.mul_equals(&(xd - xa), &(yd - ya))?;
    let x3 = witness(cs, || {
        Ok(lambda.value()?.square() - xa.value()? - xd.value()?)
    })?;
    lambda.mul_equals(&lambda, &(&x3 + xa + xd))?;
    let y3 = witness(cs, || {
        Ok(lambda.value()? * (xa.value()? - x3.value()?) - ya.value()?)
    })?;
    lambda.mul_equals(&(xa - &x3), &(&y3 + ya))?;
    Ok((x3, y3))
}

/// `2A + D = (A + D) + A` (Eisenträger–Lauter–Montgomery) for `A ≠ ±D` and
/// `A + D ≠ ±A`, without computing `y(A + D)`. Five constraints.
fn double_and_add<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    (xa, ya): (&FpVar<F>, &FpVar<F>),
    (xd, yd): (&FpVar<F>, &FpVar<F>),
) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
    // λ = slope through A and D; x3 = x(A + D).
    let lambda = witness(cs, || {
        Ok(div(yd.value()? - ya.value()?, xd.value()? - xa.value()?))
    })?;
    lambda.mul_equals(&(xd - xa), &(yd - ya))?;
    let x3 = witness(cs, || {
        Ok(lambda.value()?.square() - xa.value()? - xd.value()?)
    })?;
    lambda.mul_equals(&lambda, &(&x3 + xa + xd))?;
    // μ = slope through A + D and A: (μ + λ)·(x_A − x3) = 2·y_A.
    let mu = witness(cs, || {
        Ok(div(ya.value()?.double(), xa.value()? - x3.value()?) - lambda.value()?)
    })?;
    (&mu + &lambda).mul_equals(&(xa - &x3), &ya.double()?)?;
    let x4 = witness(cs, || {
        Ok(mu.value()?.square() - xa.value()? - x3.value()?)
    })?;
    mu.mul_equals(&mu, &(&x4 + xa + &x3))?;
    let y4 = witness(cs, || {
        Ok(mu.value()? * (xa.value()? - x4.value()?) - ya.value()?)
    })?;
    mu.mul_equals(&(xa - &x4), &(&y4 + ya))?;
    Ok((x4, y4))
}

/// Complete addition: every combination of identity, equal, opposite and
/// distinct inputs. About 20 constraints. Whenever the result is computed
/// from a slope (neither input the identity, not opposite), that slope is
/// uniquely determined.
pub fn add<P: SWCurveConfig>(
    cs: &ConstraintSystemRef<P::BaseField>,
    p1: &AffineVar<P::BaseField>,
    p2: &AffineVar<P::BaseField>,
) -> Result<AffineVar<P::BaseField>, SynthesisError>
where
    P::BaseField: PrimeField,
{
    check_curve::<P>();
    let three = P::BaseField::from(3u64);
    let same_x = p1.x.is_eq(&p2.x)?;
    let s = FpVar::from(same_x.clone());

    // λ·den = num, with den = (x2 − x1) + s·2y1 and
    // num = (y2 − y1) + s·(3x1² − y2 + y1): the chord slope when x1 ≠ x2,
    // the tangent slope when x1 = x2 (then y1 ≠ 0 unless p1 is the
    // identity, in which case the slope is unused).
    let x1_sq = p1.x.square()?;
    let s_y1 = &s * &p1.y;
    let s_corr = &s * (&x1_sq * three - &p2.y + &p1.y);
    let den = &p2.x - &p1.x + s_y1.double()?;
    let num = &p2.y - &p1.y + &s_corr;
    let lambda = witness(cs, || Ok(div(num.value()?, den.value()?)))?;
    lambda.mul_equals(&den, &num)?;
    let x3 = witness(cs, || {
        Ok(lambda.value()?.square() - p1.x.value()? - p2.x.value()?)
    })?;
    lambda.mul_equals(&lambda, &(&x3 + &p1.x + &p2.x))?;
    let y3 = witness(cs, || {
        Ok(lambda.value()? * (p1.x.value()? - x3.value()?) - p1.y.value()?)
    })?;
    lambda.mul_equals(&(&p1.x - &x3), &(&y3 + &p1.y))?;

    // Same x and different y: p2 = −p1, the sum is the identity.
    let opposite = &same_x & &!p1.y.is_eq(&p2.y)?;
    let sum = AffineVar::select(
        &opposite,
        &AffineVar::identity(),
        &AffineVar {
            x: x3,
            y: y3,
            inf: Boolean::FALSE,
        },
    )?;
    let sum = AffineVar::select(&p2.inf, p1, &sum)?;
    AffineVar::select(&p1.inf, p2, &sum)
}

/// `[2^(n+1) + 2t + 1]·B` for the `n` little-endian bits of `t`, complete in
/// `B` (the identity maps to the identity). About `6n + 16` constraints.
pub fn scalar_mul_odd<P: SWCurveConfig>(
    cs: &ConstraintSystemRef<P::BaseField>,
    b: &AffineVar<P::BaseField>,
    t: &[Boolean<P::BaseField>],
) -> Result<AffineVar<P::BaseField>, SynthesisError>
where
    P::BaseField: PrimeField,
{
    check_curve::<P>();
    assert!(
        t.len() + 3 < P::ScalarField::MODULUS_BIT_SIZE as usize,
        "the scalar must stay well below the group order"
    );
    // A base that is never the identity; the result is discarded otherwise.
    let g = AffineVar::constant::<P>(&P::GENERATOR);
    let bx = b.inf.select(&g.x, &b.x)?;
    let by = b.inf.select(&g.y, &b.y)?;

    // [3]B: the leading 1 and a forced +1 digit.
    let (dx, dy) = double(cs, &bx, &by)?;
    let (mut ax, mut ay) = add_incomplete(cs, (&dx, &dy), (&bx, &by))?;
    // acc ← 2·acc + d·B with d = 2t_i − 1, most significant bit first. The
    // multiple k' of B stays odd with 3 ≤ k' < 2^(n+2): acc ≠ ±D and
    // acc + D ≠ ±acc, so no slope is ever undetermined.
    let one = FpVar::one();
    for bit in t.iter().rev() {
        let digit = FpVar::from(bit.clone()).double()? - &one;
        let yd = &by * digit;
        let (x, y) = double_and_add(cs, (&ax, &ay), (&bx, &yd))?;
        ax = x;
        ay = y;
    }
    // The multiple is never the identity, so the result is the identity
    // exactly when B is.
    Ok(AffineVar {
        x: b.inf.select(&FpVar::zero(), &ax)?,
        y: b.inf.select(&FpVar::zero(), &ay)?,
        inf: b.inf.clone(),
    })
}

/// `A + [2^(n+1) + 2t + 1]·B`, complete in `A` and `B`.
pub fn add_scalar_mul<P: SWCurveConfig>(
    cs: &ConstraintSystemRef<P::BaseField>,
    a: &AffineVar<P::BaseField>,
    b: &AffineVar<P::BaseField>,
    t: &[Boolean<P::BaseField>],
) -> Result<AffineVar<P::BaseField>, SynthesisError>
where
    P::BaseField: PrimeField,
{
    let product = scalar_mul_odd::<P>(cs, b, t)?;
    add::<P>(cs, a, &product)
}

/// The scalar `2^(n+1) + 2t + 1` for the `n` little-endian bits of `t`.
pub fn odd_scalar<S: PrimeField>(t: &[bool]) -> S {
    let mut k = S::one();
    let mut weight = S::from(2u64);
    for bit in t {
        if *bit {
            k += weight;
        }
        weight.double_in_place();
    }
    k + weight
}

/// The little-endian bits of `2^(n+1) + 2t + 1`, as circuit booleans.
pub fn odd_scalar_bits<F: PrimeField>(t: &[Boolean<F>]) -> Vec<Boolean<F>> {
    let mut bits = Vec::with_capacity(t.len() + 2);
    bits.push(Boolean::TRUE);
    bits.extend_from_slice(t);
    bits.push(Boolean::TRUE);
    bits
}

/// `2^(n+1) + 2t + 1` as a native field element.
pub fn odd_scalar_var<F: PrimeField>(t: &[Boolean<F>]) -> Result<FpVar<F>, SynthesisError> {
    let packed = Boolean::le_bits_to_fp(t)?;
    let top = F::from(2u64).pow([t.len() as u64 + 1]);
    Ok(packed.double()? + FpVar::constant(top + F::one()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_ff::{AdditiveGroup, One};
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
    use ark_std::{rand::Rng, test_rng};
    use core_r1cs::ark_bridge::{assignment_from_cs, shape_from_cs};

    type P = ark_grumpkin::GrumpkinConfig;
    type F = ark_bn254::Fr;
    type G = Projective<P>;

    fn new_cs() -> ConstraintSystemRef<F> {
        let cs = ConstraintSystem::<F>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        cs
    }

    /// The witnesses allocated after `start` that can be changed alone
    /// without breaking the extracted R1CS.
    fn free_witnesses(cs: &ConstraintSystemRef<F>, start: usize) -> Vec<usize> {
        let shape = shape_from_cs(cs).unwrap();
        let (mut w, x) = assignment_from_cs(cs).unwrap();
        shape.is_sat(&w, &x).unwrap();
        let mut free = Vec::new();
        for idx in start..w.len() {
            w[idx] += F::one();
            if shape.is_sat(&w, &x).is_ok() {
                free.push(idx);
            }
            w[idx] -= F::one();
        }
        free
    }

    fn points() -> Vec<G> {
        let mut rng = test_rng();
        let p = G::rand(&mut rng);
        let mut v = vec![
            G::zero(),
            p,
            -p,
            p.double(),
            G::generator(),
            G::rand(&mut rng),
        ];
        // A point with x = 0, if the curve has one (y² = b).
        if let Some(y) = P::COEFF_B.sqrt() {
            v.push(Affine::<P>::new(F::zero(), y).into());
        }
        v
    }

    #[test]
    fn complete_addition_on_every_case() {
        for a in points() {
            for b in points() {
                let cs = new_cs();
                let pa = AffineVar::new_witness::<P>(&cs, &a).unwrap();
                let pb = AffineVar::new_witness::<P>(&cs, &b).unwrap();
                let sum = add::<P>(&cs, &pa, &pb).unwrap();
                assert_eq!(sum.value::<P>().unwrap(), a + b, "{a} + {b}");
                let [x, y] = sum.coords();
                let expected = (a + b).into_affine().xy().unwrap_or((F::zero(), F::zero()));
                assert_eq!((x.value().unwrap(), y.value().unwrap()), expected);
                assert!(cs.is_satisfied().unwrap());
            }
        }
    }

    #[test]
    fn complete_addition_result_is_pinned() {
        // Generic, doubling and opposite inputs: the slope and the result are
        // determined. The only free witnesses are the unused inverse hints of
        // equality tests whose operands are equal (one per such test).
        let mut rng = test_rng();
        let p = G::rand(&mut rng);
        for (a, b, equal_tests) in [(p, G::rand(&mut rng), 0), (p, p, 2), (p, -p, 1)] {
            let cs = new_cs();
            let pa = AffineVar::new_witness::<P>(&cs, &a).unwrap();
            let pb = AffineVar::new_witness::<P>(&cs, &b).unwrap();
            let start = cs.num_witness_variables();
            add::<P>(&cs, &pa, &pb).unwrap();
            assert_eq!(free_witnesses(&cs, start).len(), equal_tests, "{a} + {b}");
        }
    }

    #[test]
    fn identity_inputs_cannot_be_forged() {
        // (0, 0) must carry inf = 1, and any other point must be on the curve.
        let cs = new_cs();
        let p = AffineVar {
            x: FpVar::new_witness(cs.clone(), || Ok(F::zero())).unwrap(),
            y: FpVar::new_witness(cs.clone(), || Ok(F::zero())).unwrap(),
            inf: Boolean::new_witness(cs.clone(), || Ok(false)).unwrap(),
        };
        p.enforce_encoding::<P>().unwrap();
        assert!(!cs.is_satisfied().unwrap());
        let cs = new_cs();
        let p = AffineVar {
            x: FpVar::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap(),
            y: FpVar::new_witness(cs.clone(), || Ok(F::zero())).unwrap(),
            inf: Boolean::new_witness(cs.clone(), || Ok(true)).unwrap(),
        };
        p.enforce_encoding::<P>().unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn scalar_multiplication_matches_native() {
        let mut rng = test_rng();
        for n in [1usize, 2, 5, 127] {
            for case in 0..6 {
                let t: Vec<bool> = match case {
                    0 => vec![false; n],
                    1 => vec![true; n],
                    _ => (0..n).map(|_| rng.gen()).collect(),
                };
                for b in points() {
                    let a = G::rand(&mut rng);
                    let cs = new_cs();
                    let pa = AffineVar::new_witness::<P>(&cs, &a).unwrap();
                    let pb = AffineVar::new_witness::<P>(&cs, &b).unwrap();
                    let bits: Vec<_> = t
                        .iter()
                        .map(|v| Boolean::new_witness(cs.clone(), || Ok(*v)).unwrap())
                        .collect();
                    let before = cs.num_constraints();
                    let out = add_scalar_mul::<P>(&cs, &pa, &pb, &bits).unwrap();
                    let k: ark_grumpkin::Fr = odd_scalar(&t);
                    assert_eq!(out.value::<P>().unwrap(), a + b * k);
                    assert!(cs.is_satisfied().unwrap());
                    assert!(cs.num_constraints() - before <= 6 * n + 45);
                    let packed = odd_scalar_var(&bits).unwrap().value().unwrap();
                    assert_eq!(packed, odd_scalar::<F>(&t));
                }
            }
        }
    }

    #[test]
    fn scalar_multiplication_is_pinned() {
        let mut rng = test_rng();
        let t: Vec<bool> = (0..127).map(|_| rng.gen()).collect();
        let cs = new_cs();
        let pa = AffineVar::new_witness::<P>(&cs, &G::rand(&mut rng)).unwrap();
        let pb = AffineVar::new_witness::<P>(&cs, &G::rand(&mut rng)).unwrap();
        let bits: Vec<_> = t
            .iter()
            .map(|v| Boolean::new_witness(cs.clone(), || Ok(*v)).unwrap())
            .collect();
        let start = cs.num_witness_variables();
        add_scalar_mul::<P>(&cs, &pa, &pb, &bits).unwrap();
        assert_eq!(free_witnesses(&cs, start), Vec::<usize>::new());
    }

    #[test]
    fn scalar_multiplication_is_sparse() {
        let mut rng = test_rng();
        let cs = new_cs();
        let pa = AffineVar::new_witness::<P>(&cs, &G::rand(&mut rng)).unwrap();
        let pb = AffineVar::new_witness::<P>(&cs, &G::rand(&mut rng)).unwrap();
        let bits: Vec<_> = (0..127)
            .map(|_| Boolean::new_witness(cs.clone(), || Ok(rng.gen::<bool>())).unwrap())
            .collect();
        add_scalar_mul::<P>(&cs, &pa, &pb, &bits).unwrap();
        cs.finalize();
        let m = cs.to_matrices().unwrap();
        let nnz = m.a_num_non_zero + m.b_num_non_zero + m.c_num_non_zero;
        assert!(
            m.num_constraints < 1000,
            "{} constraints",
            m.num_constraints
        );
        assert!(nnz < 6 * m.num_constraints, "{nnz} non-zero entries");
    }
}
