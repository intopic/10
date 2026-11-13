//! Multi-scalar multiplication with batched affine additions, for the prover.
//!
//! Pippenger's bucket method with signed digits, where the points of every
//! bucket are summed in affine coordinates: all the independent additions of
//! a window are done together, sharing one field inversion (Montgomery's
//! trick), so an addition costs about 6 multiplications instead of the 11 of
//! a mixed projective addition. The points of a window are sorted by bucket
//! and each bucket is reduced as a binary tree, so no two additions of a
//! batch ever touch the same point.
//!
//! The result is exactly `Σ s_i·B_i`: every special case of affine addition
//! (an identity input, equal points, opposite points) is handled. It is meant
//! for the prover only; verifiers keep the arkworks implementation.

use alloc::vec::Vec;
use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup, VariableBaseMSM,
};
use ark_ff::{AdditiveGroup, Field, One, PrimeField, Zero};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// The multi-scalar multiplication of the prover's commitments: [`msm`]
/// with the `batch-affine-msm` feature, arkworks otherwise. Implemented for
/// every short-Weierstrass curve; checks of commitments (decider and
/// accumulator verification) use arkworks regardless, through
/// `CommitmentKey::commit_reference`.
pub trait ProverMsm: CurveGroup {
    fn prover_msm(bases: &[Self::Affine], scalars: &[Self::ScalarField]) -> Self;
}

impl<P: SWCurveConfig> ProverMsm for Projective<P> {
    fn prover_msm(bases: &[Affine<P>], scalars: &[P::ScalarField]) -> Self {
        #[cfg(feature = "batch-affine-msm")]
        {
            msm(bases, scalars)
        }
        #[cfg(not(feature = "batch-affine-msm"))]
        {
            Self::msm_unchecked(bases, scalars)
        }
    }
}

/// Below this many terms the arkworks implementation is used.
pub const MIN_TERMS: usize = 1 << 10;

/// Points reduced together: their buffer stays in a core's L2 cache.
const CHUNK: u32 = 1 << 12;

/// `Σ scalars[i]·bases[i]` over the common length of the two slices.
pub fn msm<P: SWCurveConfig>(bases: &[Affine<P>], scalars: &[P::ScalarField]) -> Projective<P> {
    let n = bases.len().min(scalars.len());
    let (bases, scalars) = (&bases[..n], &scalars[..n]);
    if n < MIN_TERMS {
        return Projective::<P>::msm_unchecked(bases, scalars);
    }
    let c = window_bits(n);
    let digits = signed_digits::<P::ScalarField>(scalars, c);
    let windows = digits.len() / n;
    let window = |w: usize| window_sum(bases, &digits[w * n..(w + 1) * n], c);
    #[cfg(feature = "parallel")]
    let sums: Vec<Projective<P>> = (0..windows).into_par_iter().map(window).collect();
    #[cfg(not(feature = "parallel"))]
    let sums: Vec<Projective<P>> = (0..windows).map(window).collect();
    // Σ_w 2^(c·w)·S_w, from the top window down.
    let mut total = Projective::<P>::zero();
    for s in sums.iter().rev() {
        for _ in 0..c {
            total.double_in_place();
        }
        total += s;
    }
    total
}

/// Window width for `n` terms, larger than for projective buckets (an
/// affine addition is cheaper, the bucket reduction is not): the best
/// measured on 4 cores were 11 for 11k terms, 13 for 77k, 14 for 2^18 and
/// 16 for 2^20.
fn window_bits(n: usize) -> usize {
    let log = ark_std::log2(n) as usize;
    let c = log * 69 / 100 + 2 + usize::from(log >= 19);
    c.clamp(4, 16)
}

/// Signed base-`2^c` digits `d ∈ [−2^(c−1), 2^(c−1))` of every scalar,
/// window-major: digit `w` of scalar `i` at `w·n + i`.
fn signed_digits<F: PrimeField>(scalars: &[F], c: usize) -> Vec<i32> {
    let n = scalars.len();
    let bits = F::MODULUS_BIT_SIZE as usize;
    // One more window for the final carry.
    let windows = bits.div_ceil(c) + 1;
    let mut digits = alloc::vec![0i32; windows * n];
    // Chunks of scalars, each holding its slice of every window.
    let chunk = n.div_ceil(64).max(256);
    let mut grid: Vec<Vec<&mut [i32]>> = (0..n.div_ceil(chunk))
        .map(|_| Vec::with_capacity(windows))
        .collect();
    for window in digits.chunks_mut(n) {
        for (k, part) in window.chunks_mut(chunk).enumerate() {
            grid[k].push(part);
        }
    }
    let fill = |(mut parts, ss): (Vec<&mut [i32]>, &[F])| {
        for (j, s) in ss.iter().enumerate() {
            digits_of(s, c, windows, |w, d| parts[w][j] = d);
        }
    };
    #[cfg(feature = "parallel")]
    grid.into_par_iter()
        .zip(scalars.par_chunks(chunk))
        .for_each(fill);
    #[cfg(not(feature = "parallel"))]
    grid.into_iter().zip(scalars.chunks(chunk)).for_each(fill);
    digits
}

/// The `windows` signed digits of one scalar, least significant first.
fn digits_of<F: PrimeField>(s: &F, c: usize, windows: usize, mut put: impl FnMut(usize, i32)) {
    let radix = 1i64 << c;
    let half = radix >> 1;
    let mask = (radix - 1) as u64;
    let limbs = s.into_bigint();
    let limbs = limbs.as_ref();
    let mut carry = 0i64;
    for w in 0..windows {
        let bit = w * c;
        let raw = if bit >= 64 * limbs.len() {
            0
        } else {
            let (limb, shift) = (bit / 64, bit % 64);
            let mut v = limbs[limb] >> shift;
            if shift + c > 64 && limb + 1 < limbs.len() {
                v |= limbs[limb + 1] << (64 - shift);
            }
            (v & mask) as i64
        };
        let mut d = raw + carry;
        carry = 0;
        if d >= half {
            d -= radix;
            carry = 1;
        }
        put(w, d as i32);
    }
    debug_assert_eq!(carry, 0);
}

/// `Σ_i d_i·B_i` for the digits of one window.
fn window_sum<P: SWCurveConfig>(bases: &[Affine<P>], digits: &[i32], c: usize) -> Projective<P> {
    // |d| ≤ 2^(c−1): bucket indices 0 ..= 2^(c−1), index 0 unused.
    let buckets = (1usize << (c - 1)) + 1;
    // Counting sort of the non-zero digits by |d|; start[j] is the first
    // slot of bucket j and start[buckets] the number of points.
    let mut start = alloc::vec![0u32; buckets + 1];
    for &d in digits {
        if d != 0 {
            start[d.unsigned_abs() as usize] += 1;
        }
    }
    let mut acc = 0u32;
    for s in start.iter_mut() {
        let k = *s;
        *s = acc;
        acc += k;
    }
    let total = acc as usize;
    if total == 0 {
        return Projective::zero();
    }
    let mut fill = start.clone();
    let mut points = alloc::vec![Affine::<P>::identity(); total];
    for (b, &d) in bases.iter().zip(digits) {
        if d != 0 {
            let slot = &mut fill[d.unsigned_abs() as usize];
            points[*slot as usize] = if d < 0 { -*b } else { *b };
            *slot += 1;
        }
    }
    // Bucket j holds points[start[j] .. start[j] + len[j]]; reduce every
    // bucket to one point, halving all of them at once.
    let mut len: Vec<u32> = (0..buckets).map(|j| start[j + 1] - start[j]).collect();
    let mut scratch = Scratch::default();
    // Consecutive buckets in chunks of about CHUNK points, each reduced
    // completely while it is in cache.
    let mut j0 = 0;
    while j0 < buckets {
        let mut j1 = j0 + 1;
        while j1 < buckets && start[j1 + 1] - start[j0] <= CHUNK {
            j1 += 1;
        }
        while len[j0..j1].iter().any(|&l| l > 1) {
            halve(&mut points, &start[j0..j1], &mut len[j0..j1], &mut scratch);
        }
        j0 = j1;
    }
    // Σ_j j·bucket_j by running sums.
    let mut running = Projective::<P>::zero();
    let mut sum = Projective::<P>::zero();
    for j in (1..buckets).rev() {
        if len[j] == 1 {
            running += points[start[j] as usize];
        }
        sum += running;
    }
    sum
}

/// What one pair addition needs.
#[derive(Clone, Copy)]
enum Pair {
    /// The chord or tangent slope's denominator is in the batch.
    Slope { tangent: bool },
    /// The result is known without a slope.
    Known,
}

struct Scratch<F> {
    dens: Vec<F>,
    kinds: Vec<Pair>,
}

impl<F> Default for Scratch<F> {
    fn default() -> Self {
        Self {
            dens: Vec::new(),
            kinds: Vec::new(),
        }
    }
}

/// One round: in every bucket with `k ≥ 2` points, `(p_2i, p_2i+1) ↦
/// p_2i + p_2i+1` into position `i`, an odd last point moved after them.
fn halve<P: SWCurveConfig>(
    points: &mut [Affine<P>],
    start: &[u32],
    len: &mut [u32],
    scratch: &mut Scratch<P::BaseField>,
) {
    scratch.dens.clear();
    scratch.kinds.clear();
    // Denominators of every pair, and their running products.
    let mut product = P::BaseField::one();
    for (j, &l) in len.iter().enumerate() {
        let s = start[j] as usize;
        for i in 0..(l as usize) / 2 {
            let (a, b) = (&points[s + 2 * i], &points[s + 2 * i + 1]);
            let (kind, den) = if a.infinity || b.infinity {
                (Pair::Known, None)
            } else if a.x != b.x {
                (Pair::Slope { tangent: false }, Some(b.x - a.x))
            } else if a.y == b.y && !a.y.is_zero() {
                (Pair::Slope { tangent: true }, Some(a.y.double()))
            } else {
                // Opposite points (or a point of order 2): the identity.
                (Pair::Known, None)
            };
            scratch.kinds.push(kind);
            scratch.dens.push(product);
            if let Some(d) = den {
                product *= d;
            }
        }
    }
    // One inversion for the whole round.
    let mut inv = product.inverse().expect("all denominators are non-zero");
    // Walk back: dens[k] becomes the inverse of pair k's denominator.
    let mut k = scratch.kinds.len();
    for (j, &l) in len.iter().enumerate().rev() {
        let s = start[j] as usize;
        for i in (0..(l as usize) / 2).rev() {
            k -= 1;
            if let Pair::Slope { tangent } = scratch.kinds[k] {
                let (a, b) = (&points[s + 2 * i], &points[s + 2 * i + 1]);
                let den = if tangent { a.y.double() } else { b.x - a.x };
                let prefix = scratch.dens[k];
                scratch.dens[k] = inv * prefix;
                inv *= den;
            }
        }
    }
    // The sums, in place (position i is written after pairs ≤ i are read).
    let mut k = 0;
    for (j, l) in len.iter_mut().enumerate() {
        let s = start[j] as usize;
        let pairs = (*l as usize) / 2;
        for i in 0..pairs {
            let (a, b) = (points[s + 2 * i], points[s + 2 * i + 1]);
            points[s + i] = match scratch.kinds[k] {
                Pair::Known => {
                    if a.infinity {
                        b
                    } else if b.infinity {
                        a
                    } else {
                        Affine::identity()
                    }
                }
                Pair::Slope { tangent } => {
                    let lambda = if tangent {
                        (a.x.square().double() + a.x.square() + P::COEFF_A) * scratch.dens[k]
                    } else {
                        (b.y - a.y) * scratch.dens[k]
                    };
                    let x = lambda.square() - a.x - b.x;
                    let y = lambda * (a.x - x) - a.y;
                    Affine::new_unchecked(x, y)
                }
            };
            k += 1;
        }
        if *l % 2 == 1 {
            points[s + pairs] = points[s + *l as usize - 1];
        }
        *l = l.div_ceil(2);
    }
}

/// The digits as integers, for tests: `Σ_w d_w·2^(c·w)` must be the scalar.
#[cfg(test)]
fn recompose<F: PrimeField>(digits: &[i32], n: usize, i: usize, c: usize) -> F {
    let windows = digits.len() / n;
    let mut acc = F::zero();
    let base = F::from(2u64).pow([c as u64]);
    for w in (0..windows).rev() {
        acc *= base;
        let d = digits[w * n + i];
        let v = F::from(d.unsigned_abs() as u64);
        acc += if d < 0 { -v } else { v };
    }
    acc
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_std::{rand::Rng, test_rng};

    fn check<P: SWCurveConfig>(bases: &[Affine<P>], scalars: &[P::ScalarField]) {
        let expected = Projective::<P>::msm_unchecked(bases, scalars);
        assert_eq!(msm(bases, scalars), expected);
    }

    fn random_bases<P: SWCurveConfig>(n: usize) -> Vec<Affine<P>> {
        let mut rng = test_rng();
        let g = Projective::<P>::rand(&mut rng);
        // Cheap distinct points: consecutive multiples of a random point.
        let mut acc = g;
        let proj: Vec<Projective<P>> = (0..n)
            .map(|_| {
                acc += g;
                acc
            })
            .collect();
        Projective::normalize_batch(&proj)
    }

    #[test]
    fn digits_recompose_the_scalars() {
        let mut rng = test_rng();
        type F = ark_bn254::Fr;
        let mut scalars: Vec<F> = (0..200).map(|_| F::rand(&mut rng)).collect();
        scalars.extend([F::zero(), F::one(), -F::one(), F::from(u64::MAX)]);
        for c in 4..=16 {
            let digits = signed_digits(&scalars, c);
            let half = 1i32 << (c - 1);
            for (i, s) in scalars.iter().enumerate() {
                assert_eq!(recompose::<F>(&digits, scalars.len(), i, c), *s, "c = {c}");
            }
            assert!(digits.iter().all(|&d| -half <= d && d < half));
        }
    }

    fn agrees_with_arkworks<P: SWCurveConfig>() {
        let mut rng = test_rng();
        for n in [MIN_TERMS, 3000, 1 << 13] {
            let bases = random_bases::<P>(n);
            // Uniform scalars.
            let s: Vec<P::ScalarField> = (0..n).map(|_| P::ScalarField::rand(&mut rng)).collect();
            check(&bases, &s);
            // Small scalars, as in circuit witnesses: few buckets, long ones.
            let s: Vec<P::ScalarField> = (0..n)
                .map(|_| P::ScalarField::from(rng.gen_range(0u64..8)))
                .collect();
            check(&bases, &s);
            // Negative small scalars (top digits all carry).
            let s: Vec<P::ScalarField> = (0..n)
                .map(|_| -P::ScalarField::from(rng.gen_range(0u64..5)))
                .collect();
            check(&bases, &s);
            // All zero.
            check(&bases, &alloc::vec![P::ScalarField::zero(); n]);
        }
    }

    #[test]
    fn agrees_with_arkworks_on_four_curves() {
        agrees_with_arkworks::<ark_bn254::g1::Config>();
        agrees_with_arkworks::<ark_grumpkin::GrumpkinConfig>();
        agrees_with_arkworks::<ark_pallas::PallasConfig>();
        agrees_with_arkworks::<ark_vesta::VestaConfig>();
    }

    #[test]
    fn special_cases_of_affine_addition() {
        // Repeated bases (equal points meet in a bucket: tangent), opposite
        // bases (they cancel), identity bases, and a sum that is the
        // identity; each pattern is placed so that the same bucket gets
        // them, in every position of the reduction tree.
        type P = ark_pallas::PallasConfig;
        type F = ark_pallas::Fr;
        let mut rng = test_rng();
        let n = 4096;
        let g = Projective::<P>::rand(&mut rng).into_affine();
        let h = Projective::<P>::rand(&mut rng).into_affine();
        let cases: Vec<(Vec<Affine<P>>, Vec<F>)> = alloc::vec![
            // One base everywhere, one scalar: every addition is a doubling.
            (alloc::vec![g; n], alloc::vec![F::from(5u64); n]),
            // g and −g alternating with equal scalars: everything cancels.
            (
                (0..n).map(|i| if i % 2 == 0 { g } else { -g }).collect(),
                alloc::vec![F::from(3u64); n],
            ),
            // g with scalars 3 and −3 alternating: same cancellation by sign.
            (
                alloc::vec![g; n],
                (0..n)
                    .map(|i| if i % 2 == 0 {
                        F::from(3u64)
                    } else {
                        -F::from(3u64)
                    })
                    .collect(),
            ),
            // Identity bases mixed in.
            (
                (0..n)
                    .map(|i| if i % 3 == 0 { Affine::identity() } else { h })
                    .collect(),
                (0..n).map(|_| F::from(rng.gen_range(1u64..4))).collect(),
            ),
            // Random scalars over few distinct bases (g, −g, h, g + h).
            (
                (0..n)
                    .map(|i| match i % 4 {
                        0 => g,
                        1 => -g,
                        2 => h,
                        _ => (g + h).into_affine(),
                    })
                    .collect(),
                (0..n).map(|_| F::rand(&mut rng)).collect(),
            ),
        ];
        for (bases, scalars) in &cases {
            check(bases, scalars);
        }
        // Shorter slices: the common length is used.
        let (bases, scalars) = &cases[4];
        assert_eq!(
            msm(&bases[..3000], scalars),
            Projective::<P>::msm_unchecked(&bases[..3000], &scalars[..3000])
        );
    }
}
