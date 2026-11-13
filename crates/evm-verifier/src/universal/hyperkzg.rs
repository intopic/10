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
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A joint opening proof for several evaluation claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperKzgProof {
    /// Per claim: commitments to `P_1, …, P_{ℓ−1}`.
    pub comms: Vec<Vec<G1>>,
    /// Per claim: `P_i(r)` for `i = 0..ℓ`.
    pub y_pos: Vec<Vec<Fr>>,
    /// Per claim: `P_i(−r)` for `i = 0..ℓ`.
    pub y_neg: Vec<Vec<Fr>>,
    /// Per claim: `P_i(r²)` for `i = 1..ℓ`.
    pub y_sq: Vec<Vec<Fr>>,
    /// KZG proofs at `r`, `−r`, `r²`, shared by all claims.
    pub pi: [G1; 3],
}

/// One evaluation claim on the prover side: polynomials (as evaluation
/// tables of length `2^len(point)`) with their values at `point`.
pub struct Claim<'a> {
    pub polys: &'a [&'a [Fr]],
    pub point: &'a [Fr],
    pub values: &'a [Fr],
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

/// Index ranges handled by one task when the `parallel` feature is on.
const CHUNK: usize = 1 << 12;

/// `Σ_k coeffs[k]·polys[k]`, entry by entry (shorter polynomials are
/// zero-padded).
fn combine(polys: &[&[Fr]], coeffs: &[Fr]) -> Vec<Fr> {
    let len = polys.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut out = alloc::vec![Fr::zero(); len];
    let fill = |(c, chunk): (usize, &mut [Fr])| {
        let start = c * CHUNK;
        for (p, coeff) in polys.iter().zip(coeffs) {
            if start < p.len() {
                for (o, v) in chunk.iter_mut().zip(&p[start..]) {
                    *o += *coeff * v;
                }
            }
        }
    };
    #[cfg(feature = "parallel")]
    out.par_chunks_mut(CHUNK).enumerate().for_each(fill);
    #[cfg(not(feature = "parallel"))]
    out.chunks_mut(CHUNK).enumerate().for_each(fill);
    out
}

/// One folding step: `next[j] = prev[2j] + u·(prev[2j+1] − prev[2j])`.
fn fold_layer(prev: &[Fr], u: Fr) -> Vec<Fr> {
    let half = prev.len() / 2;
    let at = |j: usize| prev[2 * j] + u * (prev[2 * j + 1] - prev[2 * j]);
    #[cfg(feature = "parallel")]
    if half >= CHUNK {
        return (0..half).into_par_iter().map(at).collect();
    }
    (0..half).map(at).collect()
}

/// Proves all `claims` jointly: every folded polynomial of every claim is
/// opened at the *same* three points `r, −r, r²`, so the whole batch costs
/// three KZG proofs regardless of the number of claims. Points are in the
/// sum-check's order (first variable = most significant index bit) and need
/// at least two variables. The caller must have absorbed the commitments.
pub fn prove(tr: &mut KeccakTranscript, ck: &CommitmentKey<G1>, claims: &[Claim]) -> HyperKzgProof {
    // Fold every claim and commit to its layers.
    let mut all_layers: Vec<Vec<Vec<Fr>>> = Vec::with_capacity(claims.len());
    let mut comms = Vec::with_capacity(claims.len());
    for claim in claims {
        let ell = claim.point.len();
        assert!(ell >= 2, "HyperKZG needs at least two variables");
        assert!(claim.polys.iter().all(|p| p.len() == 1 << ell));
        tr.absorb_scalars(claim.point);
        tr.absorb_scalars(claim.values);
        let q = powers(tr.challenge(), claim.polys.len());
        let u: Vec<Fr> = claim.point.iter().rev().copied().collect();
        let mut layers: Vec<Vec<Fr>> = alloc::vec![combine(claim.polys, &q)];
        for u_i in &u[..ell - 1] {
            let prev = layers.last().expect("non-empty");
            let next = fold_layer(prev, *u_i);
            layers.push(next);
        }
        debug_assert_eq!(
            {
                let last = layers.last().expect("non-empty");
                last[0] + u[ell - 1] * (last[1] - last[0])
            },
            claim
                .values
                .iter()
                .zip(&q)
                .fold(Fr::zero(), |acc, (v, q)| acc + *v * q),
            "claimed values are not the evaluations at the point"
        );
        let c: Vec<G1> = layers[1..]
            .iter()
            .map(|p| ck.commit(p, Fr::zero()))
            .collect();
        tr.absorb_points(&c);
        comms.push(c);
        all_layers.push(layers);
    }

    // One evaluation point for everything.
    let r = tr.challenge();
    // Every layer of every claim is evaluated independently.
    let evals = |z: Fr, skip: usize| -> Vec<Vec<Fr>> {
        let claim = |layers: &Vec<Vec<Fr>>| -> Vec<Fr> {
            #[cfg(feature = "parallel")]
            return layers[skip..]
                .par_iter()
                .map(|p| kzg::evaluate(p, z))
                .collect();
            #[cfg(not(feature = "parallel"))]
            layers[skip..].iter().map(|p| kzg::evaluate(p, z)).collect()
        };
        all_layers.iter().map(claim).collect()
    };
    let (y_pos, y_neg, y_sq) = (evals(r, 0), evals(-r, 0), evals(r * r, 1));
    for j in 0..claims.len() {
        tr.absorb_scalars(&y_pos[j]);
        tr.absorb_scalars(&y_neg[j]);
        tr.absorb_scalars(&y_sq[j]);
    }

    // Batch all layers with powers of d; the r² batch skips the first layers.
    let total: usize = all_layers.iter().map(Vec::len).sum();
    let d = powers(tr.challenge(), total);
    let mut every: Vec<&[Fr]> = Vec::with_capacity(total);
    let (mut tail, mut tail_d) = (Vec::new(), Vec::new());
    let mut t = 0;
    for layers in &all_layers {
        for (i, layer) in layers.iter().enumerate() {
            every.push(layer);
            if i > 0 {
                tail.push(layer.as_slice());
                tail_d.push(d[t]);
            }
            t += 1;
        }
    }
    let batch = combine(&every, &d);
    let batch_tail = combine(&tail, &tail_d);
    let pi = [
        kzg::open(ck, &batch, r).1,
        kzg::open(ck, &batch, -r).1,
        kzg::open(ck, &batch_tail, r * r).1,
    ];
    tr.absorb_points(&pi);
    // The verifier draws its batching challenge here; stay in sync.
    let _ = tr.challenge();
    HyperKzgProof {
        comms,
        y_pos,
        y_neg,
        y_sq,
        pi,
    }
}

/// Verifies the joint opening of `claims` — each a list of (unblinded)
/// commitments with their claimed values at a point — up to the pairing
/// equation `e(L, G₂) = e(R, [τ]₂)` whose two G1 points are returned.
/// `None` means the proof is already known to be wrong.
pub fn verify(
    tr: &mut KeccakTranscript,
    claims: &[(Vec<G1>, &[Fr], &[Fr])],
    proof: &HyperKzgProof,
) -> Option<(G1, G1)> {
    let n = claims.len();
    if proof.comms.len() != n
        || proof.y_pos.len() != n
        || proof.y_neg.len() != n
        || proof.y_sq.len() != n
    {
        return None;
    }
    let mut combined = Vec::with_capacity(n); // (commitment, value) per claim
    for (j, (comms, point, values)) in claims.iter().enumerate() {
        let ell = point.len();
        if ell < 2
            || comms.len() != values.len()
            || proof.comms[j].len() != ell - 1
            || proof.y_pos[j].len() != ell
            || proof.y_neg[j].len() != ell
            || proof.y_sq[j].len() != ell - 1
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
        tr.absorb_points(&proof.comms[j]);
        combined.push((comm, value));
    }

    let r = tr.challenge();
    if r.is_zero() {
        return None;
    }
    let two_r = r + r;
    for (j, (_, point, _)) in claims.iter().enumerate() {
        tr.absorb_scalars(&proof.y_pos[j]);
        tr.absorb_scalars(&proof.y_neg[j]);
        tr.absorb_scalars(&proof.y_sq[j]);
        // Folding consistency, ending in the claimed value.
        let ell = point.len();
        for (i, u_i) in point.iter().rev().enumerate() {
            let next = if i + 1 < ell {
                proof.y_sq[j][i]
            } else {
                combined[j].1
            };
            let (yp, yn) = (proof.y_pos[j][i], proof.y_neg[j][i]);
            if two_r * next != r * (Fr::one() - u_i) * (yp + yn) + *u_i * (yp - yn) {
                return None;
            }
        }
    }

    // Batched KZG openings at r, −r and r².
    let d_base = tr.challenge();
    let mut d = Fr::one();
    let (mut heads, mut tails) = (G1::zero(), G1::zero());
    let (mut b_pos, mut b_neg, mut b_sq) = (Fr::zero(), Fr::zero(), Fr::zero());
    for (j, (comm, _)) in combined.iter().enumerate() {
        for i in 0..proof.y_pos[j].len() {
            if i == 0 {
                heads += *comm * d;
            } else {
                tails += proof.comms[j][i - 1] * d;
                b_sq += d * proof.y_sq[j][i - 1];
            }
            b_pos += d * proof.y_pos[j][i];
            b_neg += d * proof.y_neg[j][i];
            d *= d_base;
        }
    }
    tr.absorb_points(&proof.pi);
    let g = tr.challenge();
    let g2 = g * g;
    let one = Fr::one();
    // L = (1+g)·heads + (1+g+g²)·tails − (b⁺ + g·b⁻ + g²·b^sq)·G
    //     + r·π₀ − g·r·π₁ + g²·r²·π₂,          R = π₀ + g·π₁ + g²·π₂
    let left = heads * (one + g) + tails * (one + g + g2)
        - G1::generator() * (b_pos + g * b_neg + g2 * b_sq)
        + proof.pi[0] * r
        - proof.pi[1] * (g * r)
        + proof.pi[2] * (g2 * r * r);
    let right = proof.pi[0] + proof.pi[1] * g + proof.pi[2] * g2;
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
    fn hyperkzg_joint_openings() {
        let mut rng = test_rng();
        let srs = Srs::insecure_for_testing(64, &mut rng);
        let ck = srs.commitment_key(b"hyperkzg-test", 64);
        // Three claims of different sizes and arities, opened jointly.
        let shapes = [(2usize, 1usize), (6, 3), (3, 2)];
        let polys: Vec<Vec<Vec<Fr>>> = shapes
            .iter()
            .map(|(ell, count)| {
                (0..*count)
                    .map(|_| (0..1 << ell).map(|_| Fr::rand(&mut rng)).collect())
                    .collect()
            })
            .collect();
        let points: Vec<Vec<Fr>> = shapes
            .iter()
            .map(|(ell, _)| (0..*ell).map(|_| Fr::rand(&mut rng)).collect())
            .collect();
        let values: Vec<Vec<Fr>> = polys
            .iter()
            .zip(&points)
            .map(|(ps, point)| ps.iter().map(|p| mle_eval(p, point)).collect())
            .collect();
        let comms: Vec<Vec<G1>> = polys
            .iter()
            .map(|ps| ps.iter().map(|p| ck.commit(p, Fr::zero())).collect())
            .collect();

        let refs: Vec<Vec<&[Fr]>> = polys
            .iter()
            .map(|ps| ps.iter().map(Vec::as_slice).collect())
            .collect();
        let claims: Vec<Claim> = (0..3)
            .map(|j| Claim {
                polys: &refs[j],
                point: &points[j],
                values: &values[j],
            })
            .collect();
        let mut tr = KeccakTranscript::new(b"test");
        let proof = prove(&mut tr, &ck, &claims);

        let check =
            |comms: &[Vec<G1>], points: &[Vec<Fr>], values: &[Vec<Fr>], proof: &HyperKzgProof| {
                let claims: Vec<(Vec<G1>, &[Fr], &[Fr])> = (0..3)
                    .map(|j| (comms[j].clone(), points[j].as_slice(), values[j].as_slice()))
                    .collect();
                let mut tr = KeccakTranscript::new(b"test");
                verify(&mut tr, &claims, proof)
                    .is_some_and(|(l, r)| pairing_check(l, r, srs.tau_g2))
            };
        assert!(check(&comms, &points, &values, &proof));

        // Wrong value, point or commitment in any claim.
        for j in 0..3 {
            let mut bad = values.clone();
            bad[j][0] += Fr::one();
            assert!(!check(&comms, &points, &bad, &proof));
            let mut bad = points.clone();
            bad[j][0] += Fr::one();
            assert!(!check(&comms, &bad, &values, &proof));
            let mut bad = comms.clone();
            bad[j][0] += ck.h;
            assert!(!check(&bad, &points, &values, &proof));
            // Every proof component of that claim.
            let mut bad = proof.clone();
            bad.comms[j][0] += ck.h;
            assert!(!check(&comms, &points, &values, &bad));
            let mut bad = proof.clone();
            *bad.y_pos[j].last_mut().unwrap() += Fr::one();
            assert!(!check(&comms, &points, &values, &bad));
            let mut bad = proof.clone();
            bad.y_neg[j][0] += Fr::one();
            assert!(!check(&comms, &points, &values, &bad));
            let mut bad = proof.clone();
            bad.y_sq[j][0] += Fr::one();
            assert!(!check(&comms, &points, &values, &bad));
            let mut bad = proof.clone();
            bad.y_sq[j].pop();
            assert!(!check(&comms, &points, &values, &bad));
        }
        for which in 0..3 {
            let mut bad = proof.clone();
            bad.pi[which] += ck.h;
            assert!(!check(&comms, &points, &values, &bad));
        }
        // Moving a value between two claims.
        let mut bad = values.clone();
        bad[0][0] = values[2][0];
        assert!(!check(&comms, &points, &bad, &proof));
    }
}
