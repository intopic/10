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
use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
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

/// Affine coordinates `(x, y)` of a point known not to be the identity.
type Coords<F> = (FpVar<F>, FpVar<F>);

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

pub(crate) fn div<F: Field>(num: F, den: F) -> F {
    den.inverse().map(|inv| num * inv).unwrap_or_else(F::zero)
}

/// `2·(x, y)` for a point other than the identity (`y ≠ 0` on a prime-order
/// curve). Four constraints.
pub(crate) fn double<F: PrimeField>(
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
/// `B` (the identity maps to the identity). `6n + 16` constraints while
/// `n ≤ bits(|G|) − 3`; beyond that the last iterations, where the multiple
/// approaches the group order, use complete additions (40 constraints each),
/// so any `n` is sound.
pub fn scalar_mul_odd<P: SWCurveConfig>(
    cs: &ConstraintSystemRef<P::BaseField>,
    b: &AffineVar<P::BaseField>,
    t: &[Boolean<P::BaseField>],
) -> Result<AffineVar<P::BaseField>, SynthesisError>
where
    P::BaseField: PrimeField,
{
    check_curve::<P>();
    // Iteration j starts from [k]B with k odd, 3 ≤ k < 2^(j+2), and needs
    // k ≢ ±1 and 2k ± 1 ≢ 0 (mod |G|): guaranteed while 2^(j+3) ≤ |G|, i.e.
    // for j ≤ bits(|G|) − 4.
    let safe = (P::ScalarField::MODULUS_BIT_SIZE as usize).saturating_sub(3);
    // A base that is never the identity; the result is discarded otherwise.
    let g = AffineVar::constant::<P>(&P::GENERATOR);
    let bx = b.inf.select(&g.x, &b.x)?;
    let by = b.inf.select(&g.y, &b.y)?;

    // [3]B: the leading 1 and a forced +1 digit.
    let (dx, dy) = double(cs, &bx, &by)?;
    let (mut ax, mut ay) = add_incomplete(cs, (&dx, &dy), (&bx, &by))?;
    // acc ← 2·acc + d·B with d = 2t_i − 1, most significant bit first; in the
    // safe range no slope is ever undetermined.
    let one = FpVar::one();
    let digits: Vec<FpVar<P::BaseField>> = t
        .iter()
        .rev()
        .map(|bit| Ok(&by * (FpVar::from(bit.clone()).double()? - &one)))
        .collect::<Result<_, SynthesisError>>()?;
    for yd in digits.iter().take(safe) {
        let (x, y) = double_and_add(cs, (&ax, &ay), (&bx, yd))?;
        ax = x;
        ay = y;
    }
    let mut acc = AffineVar {
        x: ax,
        y: ay,
        inf: Boolean::FALSE,
    };
    for yd in digits.iter().skip(safe) {
        let doubled = add::<P>(cs, &acc, &acc)?;
        let d = AffineVar {
            x: bx.clone(),
            y: yd.clone(),
            inf: Boolean::FALSE,
        };
        acc = add::<P>(cs, &doubled, &d)?;
    }
    AffineVar::select(&b.inf, &AffineVar::identity(), &acc)
}

/// The `t` with `2^(n+1) + 2t + 1 ≡ s (mod |S|)` for `n = bits(|S|)`: how a
/// verifier hands an arbitrary scalar to [`scalar_mul_odd`].
pub fn odd_t<S: PrimeField>(s: S) -> S {
    let n = S::MODULUS_BIT_SIZE as u64;
    let top = S::from(2u64).pow([n + 1]);
    (s - S::one() - top) * S::from(2u64).inverse().expect("odd modulus")
}

/// The `bits(|S|)` little-endian bits of [`odd_t`].
pub fn odd_digits<S: PrimeField>(s: S) -> Vec<bool> {
    use ark_ff::BigInteger;
    odd_t(s).into_bigint().to_bits_le()[..S::MODULUS_BIT_SIZE as usize].to_vec()
}

/// One 2-bit window of a fixed-base multiplication: the constant point
/// `(d + 2)·4^i·B` for the digit `d = b0 + 2·b1`, as linear combinations of
/// `1, b0, b1, b0·b1` (one constraint for the product).
fn window_lookup<P: SWCurveConfig>(
    table: &[Affine<P>; 4],
    b0: &Boolean<P::BaseField>,
    b1: &Boolean<P::BaseField>,
) -> Result<Coords<P::BaseField>, SynthesisError>
where
    P::BaseField: PrimeField,
{
    let b01 = FpVar::from(b0 & b1);
    let (f0, f1) = (FpVar::from(b0.clone()), FpVar::from(b1.clone()));
    let coord = |c: [P::BaseField; 4]| {
        FpVar::constant(c[0])
            + &f0 * (c[1] - c[0])
            + &f1 * (c[2] - c[0])
            + &b01 * (c[3] - c[2] - c[1] + c[0])
    };
    let xy = |p: &Affine<P>| p.xy().expect("table entries are never the identity");
    let c: Vec<(P::BaseField, P::BaseField)> = table.iter().map(xy).collect();
    Ok((
        coord([c[0].0, c[1].0, c[2].0, c[3].0]),
        coord([c[0].1, c[1].1, c[2].1, c[3].1]),
    ))
}

/// `[s + o]·B` for a constant base `B`, the little-endian bits of `s`, and
/// the constant offset `o = Σ_i 2·4^i` (returned as the point `[o]·B`).
///
/// Window `i` adds `(d_i + 2)·4^i·B`, so before it the running multiple `m`
/// satisfies `m < 2·4^i ≤` the window's multiple: the incomplete addition
/// cannot hit `±` its input while `m + 5·4^i < |G|`; the remaining top
/// windows use complete additions. About 4 constraints per window.
pub fn fixed_base_mul_offset<P: SWCurveConfig>(
    cs: &ConstraintSystemRef<P::BaseField>,
    base: &Affine<P>,
    bits: &[Boolean<P::BaseField>],
) -> Result<(AffineVar<P::BaseField>, Projective<P>), SynthesisError>
where
    P::BaseField: PrimeField,
{
    use num_bigint::BigUint;
    check_curve::<P>();
    let order = BigUint::from_bytes_le(&{
        use ark_ff::BigInteger;
        P::ScalarField::MODULUS.to_bytes_le()
    });
    let mut bits = bits.to_vec();
    if bits.len() % 2 == 1 {
        bits.push(Boolean::FALSE);
    }
    let mut power = Projective::<P>::from(*base); // 4^i·B
    let mut offset = Projective::<P>::zero();
    let mut acc: Option<AffineVar<P::BaseField>> = None;
    for (i, pair) in bits.chunks(2).enumerate() {
        let table: [Affine<P>; 4] =
            core::array::from_fn(|d| (power * P::ScalarField::from(d as u64 + 2)).into_affine());
        offset += power.double();
        let (x, y) = window_lookup::<P>(&table, &pair[0], &pair[1])?;
        acc = Some(match acc {
            None => AffineVar {
                x,
                y,
                inf: Boolean::FALSE,
            },
            Some(prev) => {
                // m ≤ 5·(4^i − 1)/3 < 2·4^i; incomplete iff m + 5·4^i < |G|.
                let four_i = BigUint::from(4u8).pow(i as u32);
                let bound =
                    (BigUint::from(5u8) * (&four_i - 1u8)) / 3u8 + BigUint::from(5u8) * &four_i;
                if bound < order {
                    let (x, y) = add_incomplete(cs, (&prev.x, &prev.y), (&x, &y))?;
                    AffineVar {
                        x,
                        y,
                        inf: Boolean::FALSE,
                    }
                } else {
                    let entry = AffineVar {
                        x,
                        y,
                        inf: Boolean::FALSE,
                    };
                    add::<P>(cs, &prev, &entry)?
                }
            }
        });
        power.double_in_place();
        power.double_in_place();
    }
    Ok((acc.unwrap_or_else(AffineVar::identity), offset))
}

/// `Σ_j [s_j]·B_j` for constant bases and the little-endian bits of each
/// scalar: one offset fixed-base multiplication per base, complete additions
/// to combine them, and one subtraction of the summed offsets.
pub fn fixed_base_msm<P: SWCurveConfig>(
    cs: &ConstraintSystemRef<P::BaseField>,
    bases: &[Affine<P>],
    scalars: &[Vec<Boolean<P::BaseField>>],
) -> Result<AffineVar<P::BaseField>, SynthesisError>
where
    P::BaseField: PrimeField,
{
    assert_eq!(bases.len(), scalars.len());
    let mut total = AffineVar::identity();
    let mut offset = Projective::<P>::zero();
    for (base, bits) in bases.iter().zip(scalars) {
        let (product, o) = fixed_base_mul_offset::<P>(cs, base, bits)?;
        total = add::<P>(cs, &total, &product)?;
        offset += o;
    }
    add::<P>(
        cs,
        &total,
        &AffineVar::constant::<P>(&(-offset).into_affine()),
    )
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
    use ark_ff::One;
    use ark_ff::UniformRand;
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

    fn bits_of(cs: &ConstraintSystemRef<F>, v: &[bool]) -> Vec<Boolean<F>> {
        v.iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect()
    }

    #[test]
    fn full_width_scalar_multiplication_with_complete_tail() {
        // Any scalar s, handed over as the digits of t with
        // 2^255 + 2t + 1 ≡ s: the tail near the group order is complete, so
        // s = 0 and s = ±1 work too.
        type S = ark_grumpkin::Fr;
        let mut rng = test_rng();
        let scalars = [
            S::from(0u64),
            S::from(1u64),
            -S::from(1u64),
            S::from(2u64),
            S::rand(&mut rng),
            S::rand(&mut rng),
        ];
        for s in scalars {
            for b in points() {
                let cs = new_cs();
                let pb = AffineVar::new_witness::<P>(&cs, &b).unwrap();
                let t = bits_of(&cs, &odd_digits(s));
                let start = cs.num_witness_variables();
                let before = cs.num_constraints();
                let out = scalar_mul_odd::<P>(&cs, &pb, &t).unwrap();
                assert_eq!(out.value::<P>().unwrap(), b * s, "[{s}]·{b}");
                assert!(cs.is_satisfied().unwrap());
                assert!(cs.num_constraints() - before < 6 * 254 + 200);
                if !b.is_zero() && !s.is_zero() && s != S::from(1u64) && s != -S::from(1u64) {
                    // The only free witnesses are the unused inverse hints of
                    // the equality tests inside the tail's complete doublings
                    // (x1 = x2 and y1 = y2): two per doubling, value 1.
                    let (w, _) = assignment_from_cs(&cs).unwrap();
                    let free = free_witnesses(&cs, start);
                    let tail = 254 - (S::MODULUS_BIT_SIZE as usize - 3);
                    assert!(free.len() <= 2 * (tail + 1), "{free:?}");
                    assert!(free.iter().all(|&i| w[i] == F::one()), "{free:?}");
                }
            }
        }
    }

    #[test]
    fn fixed_base_msm_matches_native() {
        use ark_ff::BigInteger;
        type S = ark_grumpkin::Fr;
        let mut rng = test_rng();
        let bases: Vec<Affine<P>> = (0..4).map(|_| G::rand(&mut rng).into_affine()).collect();
        let cases: Vec<Vec<Vec<bool>>> = vec![
            // Random canonical scalars.
            (0..4)
                .map(|_| S::rand(&mut rng).into_bigint().to_bits_le()[..254].to_vec())
                .collect(),
            // Zero, n − 1, and 254 one-bits (≥ n: taken modulo n).
            vec![
                vec![false; 254],
                (-S::from(1u64)).into_bigint().to_bits_le()[..254].to_vec(),
                vec![true; 254],
                vec![true; 3],
            ],
        ];
        for scalars in cases {
            let cs = new_cs();
            let vars: Vec<Vec<Boolean<F>>> = scalars.iter().map(|v| bits_of(&cs, v)).collect();
            let start = cs.num_witness_variables();
            let before = cs.num_constraints();
            let out = fixed_base_msm::<P>(&cs, &bases, &vars).unwrap();
            let expected: G = bases
                .iter()
                .zip(&scalars)
                .map(|(b, v)| *b * S::from_le_bytes_mod_order(&bits_to_bytes(v)))
                .sum();
            assert_eq!(out.value::<P>().unwrap(), expected);
            assert!(cs.is_satisfied().unwrap());
            let per_base = (cs.num_constraints() - before) / bases.len();
            assert!(per_base < 600, "{per_base} constraints per base");
            if scalars[0].len() == 254 && scalars[0].iter().any(|b| *b) {
                assert_eq!(free_witnesses(&cs, start), Vec::<usize>::new());
            }
        }
    }

    fn bits_to_bytes(v: &[bool]) -> Vec<u8> {
        let mut out = vec![0u8; v.len().div_ceil(8)];
        for (i, b) in v.iter().enumerate() {
            if *b {
                out[i / 8] |= 1 << (i % 8);
            }
        }
        out
    }
}
