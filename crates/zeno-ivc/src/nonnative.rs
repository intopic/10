//! Minimal non-native arithmetic for the folding verifier circuit.
//!
//! The recursive circuit lives in the field `F`, but the scalars `u` and `x`
//! of the instances it folds live in the other field `S` of the curve cycle.
//! The only operation needed is `c ≡ a + r·x (mod p_S)`, which is proven as
//! the integer identity
//!
//! ```text
//! a + r·x = q·p_S + c
//! ```
//!
//! checked both modulo the native modulus `n` and modulo `2^128`. Since every
//! term is range-bounded so that both sides are below `n · 2^128`, the two
//! congruences imply equality over the integers (CRT).

use alloc::vec::Vec;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use num_bigint::BigUint;

const LIMB: usize = 64;
/// Carries are signed and bounded by 2^67 in absolute value; they are stored
/// with this offset as `CARRY_BITS`-bit unsigned integers.
const CARRY_BITS: usize = 70;
const CARRY_OFFSET_LOG: usize = 69;

fn modulus<F: PrimeField>() -> BigUint {
    BigUint::from_bytes_le(&F::MODULUS.to_bytes_le())
}

fn biguint_to_field<F: PrimeField>(v: &BigUint) -> F {
    F::from_le_bytes_mod_order(&v.to_bytes_le())
}

fn bits_value<F: PrimeField>(bits: &[Boolean<F>]) -> Result<BigUint, SynthesisError> {
    let mut bytes = alloc::vec![0u8; bits.len().div_ceil(8)];
    for (i, bit) in bits.iter().enumerate() {
        if bit.value()? {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    Ok(BigUint::from_bytes_le(&bytes))
}

fn alloc_bits<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    value: &Result<BigUint, SynthesisError>,
    n: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    (0..n)
        .map(|i| Boolean::new_witness(cs.clone(), || value.clone().map(|v| v.bit(i as u64))))
        .collect()
}

/// Packs little-endian bits into one field element, reducing modulo `n`.
pub fn pack_bits<F: PrimeField>(bits: &[Boolean<F>]) -> Result<FpVar<F>, SynthesisError> {
    let shift = F::from(2u64).pow([128]);
    let mut acc = FpVar::zero();
    let mut weight = F::one();
    for chunk in bits.chunks(128) {
        acc += Boolean::le_bits_to_fp(chunk)? * weight;
        weight *= shift;
    }
    Ok(acc)
}

/// The two least-significant 64-bit limbs of a bit vector.
fn low_limbs<F: PrimeField>(bits: &[Boolean<F>]) -> Result<[FpVar<F>; 2], SynthesisError> {
    let limb = |k: usize| -> Result<FpVar<F>, SynthesisError> {
        let start = (k * LIMB).min(bits.len());
        let end = ((k + 1) * LIMB).min(bits.len());
        if start == end {
            Ok(FpVar::zero())
        } else {
            Boolean::le_bits_to_fp(&bits[start..end])
        }
    };
    Ok([limb(0)?, limb(1)?])
}

/// Returns the little-endian bits of some `c ≡ a + r·x (mod p_S)` with
/// `c < 2^{bitlen(p_S)}`, where `a`, `r`, `x` are given by their bits.
///
/// `c` is canonical (`c < p_S`) for an honest prover; a non-canonical `c`
/// still represents the correct residue class.
pub fn mul_add_mod<F: PrimeField, S: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    a: &[Boolean<F>],
    r: &[Boolean<F>],
    x: &[Boolean<F>],
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let p = modulus::<S>();
    let n = modulus::<F>();
    let s_bits = S::MODULUS_BIT_SIZE as usize;
    let one = BigUint::from(1u8);

    // Static range analysis: both sides of the identity are below n·2^128.
    let lhs_max = (&one << a.len()) + (&one << (r.len() + x.len()));
    let q_bits = (lhs_max.bits() as usize + 1).saturating_sub(s_bits).max(1);
    let rhs_max = ((&one << q_bits) - &one) * &p + (&one << s_bits);
    let bound = &n << 128;
    assert!(
        lhs_max < bound && rhs_max < bound,
        "non-native range overflow"
    );
    assert!(&lhs_max / &p < (&one << q_bits), "quotient does not fit");

    // Witnesses: quotient and remainder.
    let values = (|| Ok::<_, SynthesisError>((bits_value(a)?, bits_value(r)?, bits_value(x)?)))();
    let lhs = values.as_ref().map(|(a, r, x)| a + r * x).map_err(|e| *e);
    let q_val = lhs.as_ref().map(|l| l / &p).map_err(|e| *e);
    let c_val = lhs.as_ref().map(|l| l % &p).map_err(|e| *e);
    let q = alloc_bits(cs, &q_val, q_bits)?;
    let c = alloc_bits(cs, &c_val, s_bits)?;

    // (1) The identity modulo the native field.
    let p_native = biguint_to_field::<F>(&p);
    let rhs = pack_bits(&q)? * p_native + pack_bits(&c)? - pack_bits(a)?;
    pack_bits(r)?.mul_equals(&pack_bits(x)?, &rhs)?;

    // (2) The identity modulo 2^128, on 64-bit limbs with signed carries.
    let [a0, a1] = low_limbs(a)?;
    let [r0, r1] = low_limbs(r)?;
    let [x0, x1] = low_limbs(x)?;
    let [q0, q1] = low_limbs(&q)?;
    let [c0, c1] = low_limbs(&c)?;
    let p_digits = p.to_u64_digits();
    let p0 = F::from(p_digits[0]);
    let p1 = F::from(p_digits.get(1).copied().unwrap_or(0));
    let t0 = &a0 + &r0 * &x0 - &q0 * p0 - &c0;
    let t1_partial = &a1 + &r0 * &x1 + &r1 * &x0 - &q0 * p1 - &q1 * p0 - &c1;

    // Carry values, computed over the integers with a positive offset.
    let mask = (&one << LIMB) - &one;
    let offset = &one << CARRY_OFFSET_LOG;
    let limbs_of = |v: &BigUint| (v & &mask, (v >> LIMB) & &mask);
    let carries = match (&values, &q_val, &c_val) {
        (Ok((av, rv, xv)), Ok(qv), Ok(cv)) => {
            let ((a0, a1), (r0, r1), (x0, x1)) = (limbs_of(av), limbs_of(rv), limbs_of(xv));
            let ((q0, q1), (c0, c1)) = (limbs_of(qv), limbs_of(cv));
            let (p0, p1) = limbs_of(&p);
            // k0 = (a0 + r0·x0 − q0·p0 − c0) / 2^64, stored as k0 + offset.
            let pos0 = (&offset << LIMB) + &a0 + &r0 * &x0;
            let neg0 = &q0 * &p0 + &c0;
            let k0 = (pos0 - neg0) >> LIMB;
            let pos1 = (&offset << LIMB) + &a1 + &r0 * &x1 + &r1 * &x0 + &k0;
            let neg1 = &q0 * &p1 + &q1 * &p0 + &c1 + &offset;
            let k1 = (pos1 - neg1) >> LIMB;
            Ok((k0, k1))
        }
        _ => Err(SynthesisError::AssignmentMissing),
    };
    let k0_val = carries.as_ref().map(|k| k.0.clone()).map_err(|e| *e);
    let k1_val = carries.as_ref().map(|k| k.1.clone()).map_err(|e| *e);
    let offset_f = F::from(2u64).pow([CARRY_OFFSET_LOG as u64]);
    let two_64 = F::from(2u64).pow([LIMB as u64]);
    let k0 = Boolean::le_bits_to_fp(&alloc_bits(cs, &k0_val, CARRY_BITS)?)? - offset_f;
    let k1 = Boolean::le_bits_to_fp(&alloc_bits(cs, &k1_val, CARRY_BITS)?)? - offset_f;
    t0.enforce_equal(&(&k0 * two_64))?;
    (t1_partial + &k0).enforce_equal(&(k1 * two_64))?;

    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn to_bits<F: PrimeField, S: PrimeField>(
        cs: &ConstraintSystemRef<F>,
        v: &S,
        n: usize,
    ) -> Vec<Boolean<F>> {
        v.into_bigint().to_bits_le()[..n]
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect()
    }

    fn from_bits<S: PrimeField>(bits: &[Boolean<impl PrimeField>]) -> S {
        let v: Vec<bool> = bits.iter().map(|b| b.value().unwrap()).collect();
        S::from_bigint(S::BigInt::from_bits_le(&v)).unwrap()
    }

    fn check<F: PrimeField, S: PrimeField>() {
        let mut rng = test_rng();
        let s_bits = S::MODULUS_BIT_SIZE as usize;
        for case in 0..20 {
            let cs = ConstraintSystem::<F>::new_ref();
            let a = if case == 0 {
                -S::from(1u64)
            } else {
                S::rand(&mut rng)
            };
            let r = S::from(u128::rand(&mut rng));
            let x_bits: Vec<bool> = (0..250).map(|_| bool::rand(&mut rng)).collect();
            let x = S::from_bigint(S::BigInt::from_bits_le(&x_bits)).unwrap();
            let (av, rv, xv) = (
                to_bits(&cs, &a, s_bits),
                to_bits(&cs, &r, 128),
                to_bits(&cs, &x, 250),
            );
            let before = cs.num_constraints();
            let c = mul_add_mod::<F, S>(&cs, &av, &rv, &xv).unwrap();
            assert_eq!(from_bits::<S>(&c), a + r * x);
            assert!(cs.is_satisfied().unwrap());
            assert!(cs.num_constraints() - before < 800);

            // u ← u + r is the same gadget with the constant x = 1.
            let c = mul_add_mod::<F, S>(&cs, &av, &rv, &[Boolean::TRUE]).unwrap();
            assert_eq!(from_bits::<S>(&c), a + r);
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn mul_add_is_correct_on_both_cycles() {
        check::<ark_pallas::Fr, ark_pallas::Fq>();
        check::<ark_pallas::Fq, ark_pallas::Fr>();
        check::<ark_bn254::Fr, ark_bn254::Fq>();
        check::<ark_bn254::Fq, ark_bn254::Fr>();
    }

    #[test]
    fn every_witness_of_the_gadget_is_pinned_down() {
        // Mutation test: changing any single witness allocated by the gadget
        // (quotient, remainder, carry bits or products) breaks satisfiability.
        type F = ark_pallas::Fr;
        type S = ark_pallas::Fq;
        let mut rng = test_rng();
        let cs = ConstraintSystem::<F>::new_ref();
        let (a, r) = (S::rand(&mut rng), S::from(u128::rand(&mut rng)));
        let x = S::from(u128::rand(&mut rng));
        let (av, rv, xv) = (
            to_bits(&cs, &a, 255),
            to_bits(&cs, &r, 128),
            to_bits(&cs, &x, 250),
        );
        let start = cs.num_witness_variables();
        mul_add_mod::<F, S>(&cs, &av, &rv, &xv).unwrap();
        let end = cs.num_witness_variables();
        assert!(cs.is_satisfied().unwrap());
        // Check against the extracted matrices: arkworks caches evaluated
        // linear combinations, so its own checker would miss the mutation.
        let shape = core_r1cs::ark_bridge::shape_from_cs(&cs).unwrap();
        let (mut w, x) = core_r1cs::ark_bridge::assignment_from_cs(&cs).unwrap();
        shape.is_sat(&w, &x).unwrap();
        for idx in start..end {
            w[idx] += F::from(1u64);
            assert!(
                shape.is_sat(&w, &x).is_err(),
                "witness {idx} is unconstrained"
            );
            w[idx] -= F::from(1u64);
        }
    }
}
