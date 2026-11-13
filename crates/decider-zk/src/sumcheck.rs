//! Multilinear helpers and the sum-check protocol (no FFT anywhere).
//!
//! Convention: tables are indexed big-endian, so the first variable is the
//! most significant bit of the index and is the first one bound.

use crate::fs_transcript::Transcript;
use alloc::vec::Vec;
use ark_ff::PrimeField;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// The Fiat–Shamir interface the sum-check needs, so the same code runs over
/// the SHA-256 transcript of the transparent decider and the Keccak
/// transcript an EVM contract can replay.
pub trait FsTranscript<F> {
    fn absorb_scalars(&mut self, label: &'static [u8], values: &[F]);
    fn challenge_scalar(&mut self) -> F;
}

impl<F: PrimeField> FsTranscript<F> for Transcript {
    fn absorb_scalars(&mut self, label: &'static [u8], values: &[F]) {
        self.absorb(label, &values.to_vec());
    }
    fn challenge_scalar(&mut self) -> F {
        self.challenge()
    }
}

/// `eq(a, b) = Π (a_i·b_i + (1 − a_i)(1 − b_i))` for two points.
pub fn eq_points<F: PrimeField>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b).fold(F::one(), |acc, (x, y)| {
        acc * (*x * y + (F::one() - x) * (F::one() - y))
    })
}

pub use core_r1cs::mle::eq_table;

/// `eq(r, index)` for a single boolean index.
pub fn eq_at<F: PrimeField>(r: &[F], index: usize) -> F {
    let n = r.len();
    (0..n).fold(F::one(), |acc, j| {
        if (index >> (n - 1 - j)) & 1 == 1 {
            acc * r[j]
        } else {
            acc * (F::one() - r[j])
        }
    })
}

/// Tables at least this long are processed in parallel.
#[cfg(feature = "parallel")]
const PARALLEL_FROM: usize = 1 << 12;

/// Binds the first variable of a table to `r`, halving it.
pub fn bind<F: PrimeField>(table: &mut Vec<F>, r: F) {
    let half = table.len() / 2;
    let (lo, hi) = table.split_at_mut(half);
    let fold = |(lo, hi): (&mut F, &F)| *lo += r * (*hi - *lo);
    #[cfg(feature = "parallel")]
    if half >= PARALLEL_FROM {
        lo.par_iter_mut().zip(hi.par_iter()).for_each(fold);
    } else {
        lo.iter_mut().zip(hi.iter()).for_each(fold);
    }
    #[cfg(not(feature = "parallel"))]
    lo.iter_mut().zip(hi.iter()).for_each(fold);
    table.truncate(half);
}

/// One round's partial sums over the indices `range` of the lower half:
/// the evaluations of the round polynomial at `0, 2, …, degree` (index 1 is
/// left at zero).
fn round_sums<F: PrimeField>(
    tables: &[Vec<F>],
    half: usize,
    degree: usize,
    combine: &(impl Fn(&[F]) -> F + Sync),
    range: core::ops::Range<usize>,
) -> Vec<F> {
    let mut evals = alloc::vec![F::zero(); degree + 1];
    let mut scratch = alloc::vec![F::zero(); tables.len()];
    for j in range {
        for (t, eval) in evals.iter_mut().enumerate() {
            if t == 1 {
                continue;
            }
            let t_f = F::from(t as u64);
            for (slot, table) in scratch.iter_mut().zip(tables.iter()) {
                *slot = table[j] + t_f * (table[j + half] - table[j]);
            }
            *eval += combine(&scratch);
        }
    }
    evals
}

/// Evaluates at `r` the polynomial of degree `evals.len() − 1` given by its
/// values at `0, 1, …, d`.
pub fn interpolate<F: PrimeField>(evals: &[F], r: F) -> F {
    let d = evals.len();
    (0..d).fold(F::zero(), |acc, i| {
        let (mut num, mut den) = (F::one(), F::one());
        for j in 0..d {
            if i != j {
                num *= r - F::from(j as u64);
                den *= F::from(i as u64) - F::from(j as u64);
            }
        }
        acc + evals[i] * num * den.inverse().expect("distinct nodes")
    })
}

/// Runs the prover side of a sum-check over `tables`, where the summand at
/// each point is `combine(values of every table)`, a polynomial of degree
/// `degree` in the tables. Each round sends the evaluations at
/// `0, 2, …, degree` (the one at `1` is implied by the running claim).
///
/// Returns the round messages and the challenge point; the tables are left
/// fully bound (length 1).
pub fn prove<F: PrimeField, T: FsTranscript<F>>(
    tables: &mut [Vec<F>],
    degree: usize,
    combine: impl Fn(&[F]) -> F + Sync,
    transcript: &mut T,
) -> (Vec<F>, Vec<F>) {
    let rounds = tables[0].len().trailing_zeros() as usize;
    let mut messages = Vec::with_capacity(rounds * degree);
    let mut point = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let half = tables[0].len() / 2;
        // Field additions are exact, so the sums do not depend on how the
        // range is split: the messages are the same with or without threads.
        #[cfg(feature = "parallel")]
        let evals = if half >= PARALLEL_FROM {
            let chunk = half.div_ceil(rayon::current_num_threads() * 4).max(1024);
            let shared: &[Vec<F>] = tables;
            (0..half.div_ceil(chunk))
                .into_par_iter()
                .map(|c| {
                    let range = c * chunk..((c + 1) * chunk).min(half);
                    round_sums(shared, half, degree, &combine, range)
                })
                .reduce(
                    || alloc::vec![F::zero(); degree + 1],
                    |mut a, b| {
                        a.iter_mut().zip(&b).for_each(|(x, y)| *x += y);
                        a
                    },
                )
        } else {
            round_sums(tables, half, degree, &combine, 0..half)
        };
        #[cfg(not(feature = "parallel"))]
        let evals = round_sums(tables, half, degree, &combine, 0..half);
        let round: Vec<F> = evals
            .iter()
            .enumerate()
            .filter(|(t, _)| *t != 1)
            .map(|(_, e)| *e)
            .collect();
        transcript.absorb_scalars(b"sumcheck-round", &round);
        let r: F = transcript.challenge_scalar();
        for table in tables.iter_mut() {
            bind(table, r);
        }
        messages.extend(round);
        point.push(r);
    }
    // The bound tables hold one value each: give their memory back now, not
    // when the caller's bindings go out of scope.
    for table in tables.iter_mut() {
        table.shrink_to_fit();
    }
    (messages, point)
}

/// Verifier side: reduces `claim` to a claim about the summand at the
/// returned point. Returns `None` if the proof is malformed.
pub fn verify<F: PrimeField, T: FsTranscript<F>>(
    mut claim: F,
    rounds: usize,
    degree: usize,
    messages: &[F],
    transcript: &mut T,
) -> Option<(F, Vec<F>)> {
    if messages.len() != rounds * degree {
        return None;
    }
    let mut point = Vec::with_capacity(rounds);
    for round in messages.chunks(degree) {
        // evals at 0, 1, 2, …, degree with p(1) = claim − p(0).
        let mut evals = Vec::with_capacity(degree + 1);
        evals.push(round[0]);
        evals.push(claim - round[0]);
        evals.extend_from_slice(&round[1..]);
        transcript.absorb_scalars(b"sumcheck-round", round);
        let r: F = transcript.challenge_scalar();
        claim = interpolate(&evals, r);
        point.push(r);
    }
    Some((claim, point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_pallas::Fr;
    use ark_std::test_rng;

    #[test]
    fn sumcheck_round_trip_and_rejection() {
        let mut rng = test_rng();
        let n = 32;
        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let c: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let claim: Fr = (0..n).map(|i| a[i] * b[i] * c[i]).sum();

        let mut tables = [a.clone(), b.clone(), c.clone()];
        let mut tr = Transcript::new(b"test");
        let (msgs, point) = prove(&mut tables, 3, |v| v[0] * v[1] * v[2], &mut tr);

        let mut tr = Transcript::new(b"test");
        let (last, vpoint) = verify(claim, 5, 3, &msgs, &mut tr).unwrap();
        assert_eq!(point, vpoint);
        // The reduced claim is the product of the three MLEs at the point.
        let eq = eq_table(&point);
        let mle = |t: &[Fr]| -> Fr { t.iter().zip(&eq).map(|(x, e)| *x * e).sum() };
        assert_eq!(last, mle(&a) * mle(&b) * mle(&c));
        assert_eq!(tables[0][0], mle(&a));
        assert_eq!(eq_at(&point, 13), eq[13]);

        // A wrong claim or a tampered message ends in a wrong reduced claim.
        let mut tr = Transcript::new(b"test");
        let (bad, _) = verify(claim + Fr::from(1u64), 5, 3, &msgs, &mut tr).unwrap();
        assert_ne!(bad, mle(&a) * mle(&b) * mle(&c));
        let mut tampered = msgs.clone();
        tampered[4] += Fr::from(1u64);
        let mut tr = Transcript::new(b"test");
        let (bad, bad_point) = verify(claim, 5, 3, &tampered, &mut tr).unwrap();
        let eq = eq_table(&bad_point);
        let mle = |t: &[Fr]| -> Fr { t.iter().zip(&eq).map(|(x, e)| *x * e).sum() };
        assert_ne!(bad, mle(&a) * mle(&b) * mle(&c));
        assert!(verify(claim, 5, 3, &msgs[1..], &mut Transcript::new(b"test")).is_none());
    }
}
