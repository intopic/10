//! HyperKZG: evaluation proofs for *multilinear* polynomials committed with
//! plain KZG (Gemini folding + batched univariate openings).
//!
//! A vector `f` of length `2^ℓ` is committed as the univariate polynomial
//! with coefficients `f` — exactly the commitments the folding scheme already
//! produces in EVM mode. To prove `f̃(p) = v` for its multilinear extension:
//!
//! 1. fold `P_0 = f`, `P_{i+1}[j] = P_i[2j] + u_i·(P_i[2j+1] − P_i[2j])`
//!    with `u` = the point in least-significant-variable-first order, so that
//!    `P_ℓ = v`; commit to `P_1, …, P_{ℓ−1}`;
//! 2. for a random `r`, send `P_i(r)`, `P_i(−r)` and `P_i(r²)`; the verifier
//!    checks `2r·P_{i+1}(r²) = r(1−u_i)(P_i(r)+P_i(−r)) + u_i(P_i(r)−P_i(−r))`;
//! 3. open all `P_i` at `r`, `−r`, `r²` with three batched KZG proofs.
//!
//! Several polynomials opened at the same point are first combined with a
//! random challenge. The verifier does not pair: it returns the two G1
//! points `(L, R)` of the equation `e(L, G₂) = e(R, [τ]₂)`, so that all
//! openings of a proof share one pairing check.

use super::transcript::KeccakTranscript;
use crate::kzg;
use alloc::vec::Vec;
use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_ff::{Field, One, Zero};
use llull_folder::CommitmentKey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperKzgProof {
    /// Commitments to `P_1, …, P_{ℓ−1}`.
    pub comms: Vec<G1>,
    /// `P_i(r)` for `i = 0..ℓ`.
    pub y_pos: Vec<Fr>,
    /// `P_i(−r)` for `i = 0..ℓ`.
    pub y_neg: Vec<Fr>,
    /// `P_i(r²)` for `i = 1..ℓ`.
    pub y_sq: Vec<Fr>,
    /// KZG proofs at `r`, `−r`, `r²`.
    pub pi: [G1; 3],
}

fn powers(base: Fr, n: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(n);
    let mut p = Fr::one();
    for _ in 0..n {
        out.push(p);
        p *= base;
    }
    out
}

fn combine(polys: &[&[Fr]], coeffs: &[Fr]) -> Vec<Fr> {
    let len = polys.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut out = alloc::vec![Fr::zero(); len];
    for (p, c) in polys.iter().zip(coeffs) {
        for (o, v) in out.iter_mut().zip(p.iter()) {
            *o += *c * v;
        }
    }
    out
}

/// Proves the evaluations `values[i] = f̃_i(point)` of polynomials given by
/// their evaluation tables (all of length `2^len(point)`, `len(point) ≥ 2`).
/// `point` is in the sum-check's order (first variable = most significant
/// index bit). The caller must have absorbed the commitments.
pub fn prove(
    tr: &mut KeccakTranscript,
    ck: &CommitmentKey<G1>,
    polys: &[&[Fr]],
    point: &[Fr],
    values: &[Fr],
) -> HyperKzgProof {
    let ell = point.len();
    assert!(ell >= 2, "HyperKZG needs at least two variables");
    assert!(polys.iter().all(|p| p.len() == 1 << ell));

    tr.absorb_scalars(point);
    tr.absorb_scalars(values);
    let q = powers(tr.challenge(), polys.len());
    let u: Vec<Fr> = point.iter().rev().copied().collect();

    // Fold.
    let mut layers: Vec<Vec<Fr>> = alloc::vec![combine(polys, &q)];
    for u_i in &u[..ell - 1] {
        let prev = layers.last().expect("non-empty");
        let next = (0..prev.len() / 2)
            .map(|j| prev[2 * j] + *u_i * (prev[2 * j + 1] - prev[2 * j]))
            .collect();
        layers.push(next);
    }
    debug_assert_eq!(
        {
            let last = layers.last().expect("non-empty");
            last[0] + u[ell - 1] * (last[1] - last[0])
        },
        values
            .iter()
            .zip(&q)
            .fold(Fr::zero(), |acc, (v, q)| acc + *v * q),
        "claimed values are not the evaluations at the point"
    );
    let comms: Vec<G1> = layers[1..]
        .iter()
        .map(|p| ck.commit(p, Fr::zero()))
        .collect();
    tr.absorb_points(&comms);

    let r = tr.challenge();
    let y_pos: Vec<Fr> = layers.iter().map(|p| kzg::evaluate(p, r)).collect();
    let y_neg: Vec<Fr> = layers.iter().map(|p| kzg::evaluate(p, -r)).collect();
    let y_sq: Vec<Fr> = layers[1..]
        .iter()
        .map(|p| kzg::evaluate(p, r * r))
        .collect();
    tr.absorb_scalars(&y_pos);
    tr.absorb_scalars(&y_neg);
    tr.absorb_scalars(&y_sq);

    let d = powers(tr.challenge(), ell);
    let all: Vec<&[Fr]> = layers.iter().map(Vec::as_slice).collect();
    let batch = combine(&all, &d);
    let batch_tail = combine(&all[1..], &d[1..]);
    let pi = [
        kzg::open(ck, &batch, r).1,
        kzg::open(ck, &batch, -r).1,
        kzg::open(ck, &batch_tail, r * r).1,
    ];
    tr.absorb_points(&pi);
    // The verifier draws its batching challenge here; stay in sync so that
    // several openings can share one transcript.
    let _ = tr.challenge();
    HyperKzgProof {
        comms,
        y_pos,
        y_neg,
        y_sq,
        pi,
    }
}

/// Verifies the evaluations of the (unblinded) commitments `comms` at
/// `point`, up to the pairing equation `e(L, G₂) = e(R, [τ]₂)` whose two G1
/// points are returned. `None` means the proof is already known to be wrong.
pub fn verify(
    tr: &mut KeccakTranscript,
    comms: &[G1],
    point: &[Fr],
    values: &[Fr],
    proof: &HyperKzgProof,
) -> Option<(G1, G1)> {
    let ell = point.len();
    if ell < 2
        || comms.len() != values.len()
        || proof.comms.len() != ell - 1
        || proof.y_pos.len() != ell
        || proof.y_neg.len() != ell
        || proof.y_sq.len() != ell - 1
    {
        return None;
    }
    tr.absorb_scalars(point);
    tr.absorb_scalars(values);
    let q = powers(tr.challenge(), comms.len());
    let comm = comms
        .iter()
        .zip(&q)
        .fold(G1::zero(), |acc, (c, q)| acc + *c * q);
    let value = values
        .iter()
        .zip(&q)
        .fold(Fr::zero(), |acc, (v, q)| acc + *v * q);
    let u: Vec<Fr> = point.iter().rev().copied().collect();

    tr.absorb_points(&proof.comms);
    let r = tr.challenge();
    if r.is_zero() {
        return None;
    }
    tr.absorb_scalars(&proof.y_pos);
    tr.absorb_scalars(&proof.y_neg);
    tr.absorb_scalars(&proof.y_sq);

    // Folding consistency, ending in the claimed value.
    let two_r = r + r;
    for (i, u_i) in u.iter().enumerate() {
        let next = if i + 1 < ell { proof.y_sq[i] } else { value };
        let (yp, yn) = (proof.y_pos[i], proof.y_neg[i]);
        if two_r * next != r * (Fr::one() - u_i) * (yp + yn) + *u_i * (yp - yn) {
            return None;
        }
    }

    // Batched KZG openings at r, −r and r².
    let d = powers(tr.challenge(), ell);
    let tail = proof
        .comms
        .iter()
        .zip(&d[1..])
        .fold(G1::zero(), |acc, (c, d)| acc + *c * d);
    let dot = |ys: &[Fr], ds: &[Fr]| {
        ys.iter()
            .zip(ds)
            .fold(Fr::zero(), |acc, (y, d)| acc + *y * d)
    };
    let openings = [
        (comm + tail, r, dot(&proof.y_pos, &d), proof.pi[0]),
        (comm + tail, -r, dot(&proof.y_neg, &d), proof.pi[1]),
        (tail, r * r, dot(&proof.y_sq, &d[1..]), proof.pi[2]),
    ];
    tr.absorb_points(&proof.pi);
    let g = powers(tr.challenge(), 3);
    let generator = G1::generator();
    let mut left = G1::zero();
    let mut right = G1::zero();
    for ((c, z, y, pi), g) in openings.iter().zip(&g) {
        left += (*c - generator * y + *pi * z) * g;
        right += *pi * g;
    }
    Some((left, right))
}

/// Evaluates the multilinear extension of `table` at `point` (first variable
/// = most significant index bit).
pub fn mle_eval(table: &[Fr], point: &[Fr]) -> Fr {
    let mut t = table.to_vec();
    for p in point {
        let half = t.len() / 2;
        for j in 0..half {
            t[j] = t[j] + *p * (t[j + half] - t[j]);
        }
        t.truncate(half);
    }
    t[0]
}

/// The final check shared by all openings: `e(L, G₂) = e(R, [τ]₂)`.
pub fn pairing_check(left: G1, right: G1, tau_g2: ark_bn254::G2Affine) -> bool {
    use ark_bn254::{Bn254, G2Affine};
    use ark_ec::{pairing::Pairing, AffineRepr};
    Bn254::multi_pairing([left, -right], [G2Affine::generator(), tau_g2]).0
        == <Bn254 as Pairing>::TargetField::ONE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::Srs;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn hyperkzg_batched_openings() {
        let mut rng = test_rng();
        let srs = Srs::insecure_for_testing(64, &mut rng);
        let ck = srs.commitment_key(b"hyperkzg-test", 64);
        for ell in [2usize, 3, 6] {
            let n = 1 << ell;
            let polys: Vec<Vec<Fr>> = (0..3)
                .map(|_| (0..n).map(|_| Fr::rand(&mut rng)).collect())
                .collect();
            let refs: Vec<&[Fr]> = polys.iter().map(Vec::as_slice).collect();
            let comms: Vec<G1> = polys.iter().map(|p| ck.commit(p, Fr::zero())).collect();
            let point: Vec<Fr> = (0..ell).map(|_| Fr::rand(&mut rng)).collect();
            let values: Vec<Fr> = polys.iter().map(|p| mle_eval(p, &point)).collect();

            let mut tr = KeccakTranscript::new(b"test");
            let proof = prove(&mut tr, &ck, &refs, &point, &values);
            let check = |comms: &[G1], point: &[Fr], values: &[Fr], proof: &HyperKzgProof| {
                let mut tr = KeccakTranscript::new(b"test");
                verify(&mut tr, comms, point, values, proof)
                    .is_some_and(|(l, r)| pairing_check(l, r, srs.tau_g2))
            };
            assert!(check(&comms, &point, &values, &proof));

            // Wrong value, point, commitment and every proof component.
            let mut bad = values.clone();
            bad[1] += Fr::one();
            assert!(!check(&comms, &point, &bad, &proof));
            let mut bad = point.clone();
            bad[0] += Fr::one();
            assert!(!check(&comms, &bad, &values, &proof));
            let mut bad = comms.clone();
            bad[2] += ck.h;
            assert!(!check(&bad, &point, &values, &proof));
            let mut bad = proof.clone();
            bad.comms[0] += ck.h;
            assert!(!check(&comms, &point, &values, &bad));
            for which in 0..3 {
                let mut bad = proof.clone();
                match which {
                    0 => bad.y_pos[ell - 1] += Fr::one(),
                    1 => bad.y_neg[0] += Fr::one(),
                    _ => bad.y_sq[0] += Fr::one(),
                }
                assert!(!check(&comms, &point, &values, &bad));
                let mut bad = proof.clone();
                bad.pi[which] += ck.h;
                assert!(!check(&comms, &point, &values, &bad));
            }
            let mut bad = proof.clone();
            bad.y_sq.pop();
            assert!(!check(&comms, &point, &values, &bad));
        }
    }
}
