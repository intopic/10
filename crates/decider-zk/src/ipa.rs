//! Inner-product argument (Bulletproofs-style) over the engine's own
//! Pedersen generators: proves `⟨a, b⟩ = v` for a public vector `b` and a
//! committed vector `P = ⟨a, G⟩`, with `2·log n` group elements.

use crate::fs_transcript::Transcript;
use alloc::vec::Vec;
use ark_ec::CurveGroup;
use ark_ff::{Field, One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::cfg_into_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct IpaProof<C: CurveGroup> {
    pub l: Vec<C>,
    pub r: Vec<C>,
    pub a: C::ScalarField,
}

fn inner<F: Field>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b).fold(F::zero(), |acc, (x, y)| acc + *x * y)
}

/// Proves `⟨a, b⟩ = v` where `P = ⟨a, gens⟩`. The caller must already have
/// absorbed `P`, `b`'s defining data and `v` into the transcript.
pub fn prove<C: CurveGroup>(
    transcript: &mut Transcript,
    gens: &[C::Affine],
    q_base: C::Affine,
    mut a: Vec<C::ScalarField>,
    mut b: Vec<C::ScalarField>,
) -> IpaProof<C> {
    assert!(a.len().is_power_of_two() && a.len() == b.len() && gens.len() == a.len());
    let q: C = q_base * transcript.challenge::<C::ScalarField>();
    let mut g = gens.to_vec();
    let (mut ls, mut rs) = (Vec::new(), Vec::new());
    while a.len() > 1 {
        let half = a.len() / 2;
        let (a_l, a_r) = a.split_at(half);
        let (b_l, b_r) = b.split_at(half);
        let (g_l, g_r) = g.split_at(half);
        let l = C::msm_unchecked(g_r, a_l) + q * inner(a_l, b_r);
        let r = C::msm_unchecked(g_l, a_r) + q * inner(a_r, b_l);
        transcript.absorb(b"ipa-l", &l);
        transcript.absorb(b"ipa-r", &r);
        // Fold with G' = G_L + x·G_R, a' = a_L + x⁻¹·a_R, b' = b_L + x·b_R,
        // so that P' = P + x·L + x⁻¹·R: one scalar multiplication per pair.
        let x: C::ScalarField = transcript.challenge_128();
        let x_inv = x.inverse().expect("challenge is non-zero");

        let next_a = (0..half).map(|j| a_l[j] + a_r[j] * x_inv).collect();
        let next_b = (0..half).map(|j| b_l[j] + b_r[j] * x).collect();
        let next_g: Vec<C> = cfg_into_iter!(0..half)
            .map(|j| g_r[j] * x + g_l[j])
            .collect();
        g = C::normalize_batch(&next_g);
        a = next_a;
        b = next_b;
        ls.push(l);
        rs.push(r);
    }
    IpaProof {
        l: ls,
        r: rs,
        a: a[0],
    }
}

/// Verifies that the vector committed in `p = ⟨a, gens⟩` satisfies
/// `⟨a, b⟩ = v`. One multi-scalar multiplication of size `n + 2·log n + 2`.
pub fn verify<C: CurveGroup>(
    transcript: &mut Transcript,
    gens: &[C::Affine],
    q_base: C::Affine,
    p: C,
    b: &[C::ScalarField],
    v: C::ScalarField,
    proof: &IpaProof<C>,
) -> bool {
    let n = gens.len();
    let rounds = n.trailing_zeros() as usize;
    if !n.is_power_of_two() || b.len() != n || proof.l.len() != rounds || proof.r.len() != rounds {
        return false;
    }
    let q: C = q_base * transcript.challenge::<C::ScalarField>();
    let mut s = alloc::vec![C::ScalarField::one()];
    let mut lhs = p + q * v;
    for (l, r) in proof.l.iter().zip(&proof.r) {
        transcript.absorb(b"ipa-l", l);
        transcript.absorb(b"ipa-r", r);
        let x: C::ScalarField = transcript.challenge_128();
        let Some(x_inv) = x.inverse() else {
            return false;
        };
        lhs += *l * x + *r * x_inv;
        let mut next = Vec::with_capacity(s.len() * 2);
        for v in &s {
            next.push(*v);
            next.push(*v * x);
        }
        s = next;
    }
    let b_final = inner(&s, b);
    let scalars: Vec<C::ScalarField> = s.iter().map(|si| *si * proof.a).collect();
    let rhs = C::msm_unchecked(gens, &scalars) + q * (proof.a * b_final);
    (lhs - rhs).is_zero()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero};
    use ark_pallas::{Fr, Projective};
    use ark_std::test_rng;
    use llull_folder::CommitmentKey;

    #[test]
    fn ipa_completeness_and_soundness() {
        let mut rng = test_rng();
        for n in [1usize, 2, 8, 64] {
            let ck = CommitmentKey::<Projective>::setup(b"ipa-test", n);
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let p = ck.commit(&a, Fr::zero());
            let v = inner(&a, &b);
            let start = || {
                let mut t = Transcript::new(b"test");
                t.absorb(b"p", &p);
                t.absorb(b"v", &v);
                t
            };
            let proof = prove::<Projective>(&mut start(), &ck.gens, ck.h, a.clone(), b.clone());
            assert_eq!(proof.l.len(), n.trailing_zeros() as usize);
            let check = |p, b: &[Fr], v, proof: &IpaProof<Projective>| {
                verify(&mut start(), &ck.gens, ck.h, p, b, v, proof)
            };
            assert!(check(p, &b, v, &proof));
            // Wrong value, wrong commitment, wrong public vector, wrong proof.
            assert!(!check(p, &b, v + Fr::one(), &proof));
            assert!(!check(p + ck.h, &b, v, &proof));
            let mut b_bad = b.clone();
            b_bad[n - 1] += Fr::one();
            assert!(!check(p, &b_bad, v, &proof));
            let mut bad = proof.clone();
            bad.a += Fr::one();
            assert!(!check(p, &b, v, &bad));
            if n > 1 {
                let mut bad = proof.clone();
                bad.r[0] += ck.h;
                assert!(!check(p, &b, v, &bad));
                let mut bad = proof.clone();
                bad.l.pop();
                assert!(!check(p, &b, v, &bad));
            }
        }
    }
}
