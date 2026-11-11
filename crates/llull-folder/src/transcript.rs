//! Fiat–Shamir challenge derivation with an arithmetic (Poseidon) sponge
//! (spec §2.4, eq. 5).
//!
//! The sponge runs over the *base* field of the commitment curve, so that
//! commitments are absorbed as native coordinates. This is what makes the
//! same hash cheap inside the recursive circuit on the other curve of the
//! cycle. Scalars are absorbed as two 128-bit limbs and the challenge is a
//! 128-bit value, as in Nova.

use alloc::vec::Vec;
use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use core_r1cs::{R1CSInstance, RelaxedR1CSInstance};

/// Bit length of folding challenges.
pub const CHALLENGE_BITS: usize = 128;
/// Bit length of the limbs used to absorb scalar-field elements.
pub const LIMB_BITS: usize = 128;
/// Bit length of IVC state hashes; small enough to embed in both fields of a cycle.
pub const HASH_BITS: usize = 250;
/// Domain separator of the folding challenge.
pub const DOMAIN_FOLD: u64 = 1;
/// Domain separator of the IVC state hash.
pub const DOMAIN_STATE: u64 = 2;
/// Domain separator of the challenge folding two relaxed instances.
pub const DOMAIN_FOLD_RELAXED: u64 = 3;

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 60;
const RATE: usize = 4;
const CAPACITY: usize = 1;

/// Poseidon parameters (width 5, x^α S-box, 8 full + 60 partial rounds),
/// generated with the reference Grain LFSR procedure for the field `F`.
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    let alpha = sbox_exponent::<F>();
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );
    PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, alpha, mds, ark, RATE, CAPACITY)
}

/// Smallest `α ≥ 3` with `gcd(α, p − 1) = 1`, so that `x ↦ x^α` is a permutation.
fn sbox_exponent<F: PrimeField>() -> u64 {
    let mut p_minus_one = F::MODULUS;
    p_minus_one.sub_with_borrow(&F::BigInt::from(1u64));
    [3u64, 5, 7, 11, 13]
        .into_iter()
        .find(|&alpha| {
            // p − 1 mod α, computed limb by limb from the most significant limb.
            let rem = p_minus_one.as_ref().iter().rev().fold(0u128, |acc, limb| {
                ((acc << 64) | *limb as u128) % alpha as u128
            });
            rem != 0
        })
        .expect("no small S-box exponent for this field")
}

/// Splits a scalar-field element into little-endian `LIMB_BITS`-bit limbs
/// living in the base field.
pub fn scalar_to_limbs<S: PrimeField, B: PrimeField>(s: &S) -> Vec<B> {
    s.into_bigint()
        .to_bits_le()
        .chunks(LIMB_BITS)
        .take((S::MODULUS_BIT_SIZE as usize).div_ceil(LIMB_BITS))
        .map(|chunk| B::from_bigint(B::BigInt::from_bits_le(chunk)).expect("limb fits"))
        .collect()
}

/// Affine coordinates of a point; the identity is encoded as `(0, 0)`, which
/// is never on a short-Weierstrass curve with `b ≠ 0`.
pub fn point_to_coords<C: CurveGroup>(p: &C) -> [C::BaseField; 2]
where
    C::BaseField: PrimeField,
{
    match p.into_affine().xy() {
        Some((x, y)) => [x, y],
        None => [C::BaseField::from(0u64); 2],
    }
}

/// Interprets little-endian bits as a field element.
pub fn bits_to_field<F: PrimeField>(bits: &[bool]) -> F {
    F::from_bigint(F::BigInt::from_bits_le(bits)).expect("challenge fits in the field")
}

/// Field elements absorbed for a relaxed instance: `comm_E, u, comm_W, x`.
pub fn absorb_relaxed<C: CurveGroup>(out: &mut Vec<C::BaseField>, u: &RelaxedR1CSInstance<C>)
where
    C::BaseField: PrimeField,
{
    out.extend(point_to_coords(&u.comm_e));
    out.extend(scalar_to_limbs::<_, C::BaseField>(&u.u));
    out.extend(point_to_coords(&u.comm_w));
    for xi in &u.x {
        out.extend(scalar_to_limbs::<_, C::BaseField>(xi));
    }
}

/// The folding challenge `r = H(vk, U1, U2, comm_T)`.
pub fn fold_challenge<C: CurveGroup>(
    config: &PoseidonConfig<C::BaseField>,
    pp_digest: C::BaseField,
    u1: &RelaxedR1CSInstance<C>,
    u2: &R1CSInstance<C>,
    comm_t: &C,
) -> C::ScalarField
where
    C::BaseField: PrimeField + Absorb,
{
    let mut input = Vec::with_capacity(17 + 4 * u1.x.len());
    input.push(C::BaseField::from(DOMAIN_FOLD));
    input.push(pp_digest);
    absorb_relaxed(&mut input, u1);
    input.extend(point_to_coords(&u2.comm_w));
    for xi in &u2.x {
        input.extend(scalar_to_limbs::<_, C::BaseField>(xi));
    }
    input.extend(point_to_coords(comm_t));

    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&input);
    bits_to_field(&sponge.squeeze_bits(CHALLENGE_BITS))
}

/// The IVC state hash `H(vk, i, z_0, z_i, U_i)` (spec §2.6), returned as
/// `HASH_BITS` little-endian bits. It is computed over the base field of the
/// curve `C` whose instances are being accumulated, i.e. the native field of
/// the recursive circuit that folds them.
pub fn state_hash<C: CurveGroup>(
    config: &PoseidonConfig<C::BaseField>,
    pp_digest: C::BaseField,
    i: u64,
    z0: &[C::BaseField],
    zi: &[C::BaseField],
    u: &RelaxedR1CSInstance<C>,
) -> Vec<bool>
where
    C::BaseField: PrimeField + Absorb,
{
    let mut input = Vec::with_capacity(13 + z0.len() + zi.len() + 2 * u.x.len());
    input.push(C::BaseField::from(DOMAIN_STATE));
    input.push(pp_digest);
    input.push(C::BaseField::from(i));
    input.extend_from_slice(z0);
    input.extend_from_slice(zi);
    absorb_relaxed(&mut input, u);

    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&input);
    sponge.squeeze_bits(HASH_BITS)
}

/// The challenge `r = H(vk, U1, U2, comm_T)` for folding two *relaxed*
/// instances (used by the zero-knowledge masking layer).
pub fn fold_challenge_relaxed<C: CurveGroup>(
    config: &PoseidonConfig<C::BaseField>,
    pp_digest: C::BaseField,
    u1: &RelaxedR1CSInstance<C>,
    u2: &RelaxedR1CSInstance<C>,
    comm_t: &C,
) -> C::ScalarField
where
    C::BaseField: PrimeField + Absorb,
{
    let mut input = Vec::with_capacity(24 + 4 * u1.x.len());
    input.push(C::BaseField::from(DOMAIN_FOLD_RELAXED));
    input.push(pp_digest);
    absorb_relaxed(&mut input, u1);
    absorb_relaxed(&mut input, u2);
    input.extend(point_to_coords(comm_t));

    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&input);
    bits_to_field(&sponge.squeeze_bits(CHALLENGE_BITS))
}
