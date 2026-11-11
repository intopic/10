//! KZG polynomial commitments over BN254, used as the folding commitment in
//! EVM mode so that the final accumulator can be opened on-chain with one
//! pairing check.
//!
//! A vector `v` is committed as `Σ v_i·[τ^i]₁ + r·H`: a KZG commitment to the
//! polynomial with coefficients `v`, blinded with an independent generator.
//! It is additively homomorphic, so folding works exactly as with Pedersen
//! generators. The powers `[τ^i]₁` come from a universal structured
//! reference string (e.g. Perpetual Powers of Tau); nothing in it depends on
//! the application circuit.

use alloc::vec::Vec;
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand, Zero};
use ark_std::rand::RngCore;
use llull_folder::{pedersen::hash_to_curve, CommitmentKey};

/// A universal SRS: `[τ^i]₁` for `i < n`, and `[τ]₂`.
#[derive(Clone, Debug)]
pub struct Srs {
    pub powers_g1: Vec<G1Affine>,
    pub tau_g2: G2Affine,
}

impl Srs {
    /// Generates an SRS from a locally sampled `τ`.
    ///
    /// **For tests and development only**: whoever knows `τ` can forge
    /// openings. Production deployments must load the powers from a public
    /// multi-party ceremony instead.
    pub fn insecure_for_testing(n: usize, rng: &mut impl RngCore) -> Self {
        let tau = Fr::rand(rng);
        let g = G1::generator();
        let mut power = Fr::from(1u64);
        let mut powers = Vec::with_capacity(n);
        for _ in 0..n {
            powers.push(g * power);
            power *= tau;
        }
        Self {
            powers_g1: G1::normalize_batch(&powers),
            tau_g2: (G2Projective::generator() * tau).into_affine(),
        }
    }

    /// The folding commitment key over this SRS: the powers as vector
    /// generators plus a transparent blinding generator.
    pub fn commitment_key(&self, label: &[u8], len: usize) -> CommitmentKey<G1> {
        assert!(self.powers_g1.len() >= len, "SRS too short for the circuit");
        CommitmentKey {
            gens: self.powers_g1[..len].to_vec(),
            h: hash_to_curve::<G1>(label, 0),
        }
    }
}

/// Evaluates the polynomial with coefficients `coeffs` at `c`.
pub fn evaluate(coeffs: &[Fr], c: Fr) -> Fr {
    coeffs.iter().rev().fold(Fr::zero(), |acc, a| acc * c + a)
}

/// Opens the polynomial with coefficients `coeffs` at `c`: returns its value
/// and the commitment to the quotient `(p(X) − p(c)) / (X − c)`.
pub fn open(ck: &CommitmentKey<G1>, coeffs: &[Fr], c: Fr) -> (Fr, G1) {
    // Synthetic division, from the leading coefficient down.
    let mut quotient = alloc::vec![Fr::zero(); coeffs.len().saturating_sub(1)];
    let mut carry = Fr::zero();
    for (i, a) in coeffs.iter().enumerate().rev() {
        let value = *a + carry * c;
        if i > 0 {
            quotient[i - 1] = value;
        }
        carry = value;
    }
    let proof = if quotient.iter().all(Zero::is_zero) {
        G1::zero()
    } else {
        G1::msm_unchecked(&ck.gens[..quotient.len()], &quotient)
    };
    (carry, proof)
}

/// Checks, with one pairing equation, that the *unblinded* commitment
/// `comm` opens to `value` at `c`: `e(comm − value·G + c·π, G₂) = e(π, [τ]₂)`.
pub fn verify(comm: G1, c: Fr, value: Fr, proof: G1, tau_g2: G2Affine) -> bool {
    let lhs = comm - G1::generator() * value + proof * c;
    let g2 = G2Affine::generator();
    Bn254::multi_pairing([lhs, -proof], [g2, tau_g2]).0 == <Bn254 as Pairing>::TargetField::ONE
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn kzg_open_and_verify() {
        let mut rng = test_rng();
        let srs = Srs::insecure_for_testing(64, &mut rng);
        let ck = srs.commitment_key(b"kzg-test", 64);
        for len in [1usize, 2, 33, 64] {
            let coeffs: Vec<Fr> = (0..len).map(|_| Fr::rand(&mut rng)).collect();
            let blind = Fr::rand(&mut rng);
            let comm = ck.commit(&coeffs, blind);
            let c = Fr::rand(&mut rng);
            let (value, proof) = open(&ck, &coeffs, c);
            assert_eq!(value, evaluate(&coeffs, c));
            let unblinded = comm - ck.h * blind;
            assert!(verify(unblinded, c, value, proof, srs.tau_g2));
            assert!(!verify(
                unblinded,
                c,
                value + Fr::from(1u64),
                proof,
                srs.tau_g2
            ));
            // A constant polynomial takes the same value everywhere.
            if len > 1 {
                let other = c + Fr::from(1u64);
                assert!(!verify(unblinded, other, value, proof, srs.tau_g2));
            }
            assert!(!verify(comm, c, value, proof, srs.tau_g2));
            assert!(!verify(unblinded, c, value, proof + ck.h, srs.tau_g2));
        }
    }
}
