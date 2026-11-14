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
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand, Zero};
use ark_std::rand::RngCore;
use llull_folder::{msm::ProverMsm, pedersen::hash_to_curve, CommitmentKey};

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
        use ark_ec::scalar_mul::ScalarMul;
        let tau = Fr::rand(rng);
        let mut power = Fr::from(1u64);
        let mut scalars = Vec::with_capacity(n);
        for _ in 0..n {
            scalars.push(power);
            power *= tau;
        }
        // Fixed-base windowed multiplication of the generator: the same
        // points as n separate scalar multiplications, much faster.
        Self {
            powers_g1: G1::generator().batch_mul(&scalars),
            tau_g2: (G2Projective::generator() * tau).into_affine(),
        }
    }

    /// Loads the first `n` powers from a Powers-of-Tau file in snarkjs'
    /// `.ptau` format (e.g. the Perpetual Powers of Tau / Hermez ceremony
    /// files) and checks that they are well-formed:
    ///
    /// * every point is on its curve and `[τ^0]₁` is the generator;
    /// * the powers are consecutive: for a random `ρ`,
    ///   `e(Σ ρ^i·[τ^{i+1}]₁, G₂) = e(Σ ρ^i·[τ^i]₁, [τ]₂)`.
    ///
    /// This validates the structure of the string, not the honesty of the
    /// ceremony that produced it; use a file from a ceremony you trust.
    pub fn from_ptau(bytes: &[u8], n: usize, rng: &mut impl RngCore) -> Result<Self, PtauError> {
        let sections = ptau_sections(bytes)?;
        let find = |kind: u32| {
            sections
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, data)| *data)
                .ok_or(PtauError::Malformed("missing section"))
        };

        let header = find(1)?;
        if header.len() != 44 || header[..4] != 32u32.to_le_bytes() {
            return Err(PtauError::Malformed("unexpected header"));
        }
        if header[4..36] != Fq::MODULUS.to_bytes_le()[..] {
            return Err(PtauError::WrongCurve);
        }
        let power = u32::from_le_bytes(header[36..40].try_into().expect("4 bytes"));
        if power >= 32 || n == 0 || n > (1usize << power) {
            return Err(PtauError::TooShort {
                available: 1usize.checked_shl(power).unwrap_or(0),
            });
        }

        let g1_section = find(2)?;
        let g2_section = find(3)?;
        if g1_section.len() < 64 * n || g2_section.len() < 256 {
            return Err(PtauError::Malformed("truncated point section"));
        }
        let powers_g1 = g1_section[..64 * n]
            .chunks(64)
            .map(|c| {
                let p = G1Affine::new_unchecked(montgomery_fq(&c[..32])?, montgomery_fq(&c[32..])?);
                if p.is_on_curve() {
                    Ok(p)
                } else {
                    Err(PtauError::InvalidPoint)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The second G2 power is [τ]₂; coordinates are stored as (c0, c1).
        let t = &g2_section[128..256];
        let tau_g2 = G2Affine::new_unchecked(
            Fq2::new(montgomery_fq(&t[..32])?, montgomery_fq(&t[32..64])?),
            Fq2::new(montgomery_fq(&t[64..96])?, montgomery_fq(&t[96..])?),
        );
        if !tau_g2.is_on_curve() || !tau_g2.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PtauError::InvalidPoint);
        }
        if powers_g1[0] != G1Affine::generator() {
            return Err(PtauError::Inconsistent);
        }

        // Consecutive powers, checked with one random linear combination.
        if n > 1 {
            let rho = Fr::rand(rng);
            let mut coeffs = Vec::with_capacity(n - 1);
            let mut power = Fr::from(1u64);
            for _ in 0..n - 1 {
                coeffs.push(power);
                power *= rho;
            }
            let low = G1::msm_unchecked(&powers_g1[..n - 1], &coeffs);
            let high = G1::msm_unchecked(&powers_g1[1..], &coeffs);
            let ok = Bn254::multi_pairing([high, -low], [G2Affine::generator(), tau_g2]).0
                == <Bn254 as Pairing>::TargetField::ONE;
            if !ok {
                return Err(PtauError::Inconsistent);
            }
        }
        Ok(Self { powers_g1, tau_g2 })
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

/// Number of `[τ^i]₁` powers a `.ptau` file holds (and [`Srs::from_ptau`]
/// can load), without reading the points.
pub fn ptau_powers(bytes: &[u8]) -> Result<usize, PtauError> {
    let sections = ptau_sections(bytes)?;
    let find = |kind: u32| {
        sections
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, data)| *data)
            .ok_or(PtauError::Malformed("missing section"))
    };
    let header = find(1)?;
    if header.len() != 44 {
        return Err(PtauError::Malformed("unexpected header"));
    }
    let power = u32::from_le_bytes(header[36..40].try_into().expect("4 bytes"));
    if power >= 32 {
        return Err(PtauError::Malformed("unexpected header"));
    }
    Ok((1usize << power).min(find(2)?.len() / 64))
}

/// The same ceremony file cut down to its first `n` powers in G1 and the
/// two first powers in G2 (`[1]₂`, `[τ]₂`): everything a prover of a circuit
/// with `srs_len() ≤ n` needs, a small fraction of the file. The points are
/// copied byte for byte, so the result is a prefix of the same ceremony and
/// gives the same circuit keys; [`Srs::from_ptau`] reads it like the
/// original. Callers should load the result once to check it.
pub fn trim_ptau(bytes: &[u8], n: usize) -> Result<Vec<u8>, PtauError> {
    if n == 0 || ptau_powers(bytes)? < n {
        return Err(PtauError::TooShort {
            available: ptau_powers(bytes)?,
        });
    }
    let sections = ptau_sections(bytes)?;
    let find = |kind: u32| {
        sections
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, data)| *data)
            .ok_or(PtauError::Malformed("missing section"))
    };
    let (header, g1, g2) = (find(1)?, find(2)?, find(3)?);
    if g2.len() < 256 {
        return Err(PtauError::Malformed("truncated point section"));
    }
    let mut header = header.to_vec();
    let power = n.next_power_of_two().trailing_zeros();
    header[36..40].copy_from_slice(&power.to_le_bytes());
    let mut out = Vec::with_capacity(12 + 3 * 12 + 44 + 64 * n + 256);
    out.extend_from_slice(b"ptau");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    for (kind, data) in [(1u32, &header[..]), (2, &g1[..64 * n]), (3, &g2[..256])] {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    Ok(out)
}

/// Errors when loading a `.ptau` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PtauError {
    Malformed(&'static str),
    /// The file is not for BN254.
    WrongCurve,
    /// The ceremony has fewer powers than requested.
    TooShort {
        available: usize,
    },
    /// A point is not on its curve or not in the right subgroup.
    InvalidPoint,
    /// The points are not consecutive powers of one `τ`.
    Inconsistent,
}

impl core::fmt::Display for PtauError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed .ptau file: {what}"),
            Self::WrongCurve => write!(f, ".ptau file is not for BN254"),
            Self::TooShort { available } => {
                write!(f, ".ptau file only has {available} powers")
            }
            Self::InvalidPoint => write!(f, ".ptau file contains an invalid curve point"),
            Self::Inconsistent => write!(f, ".ptau points are not consecutive powers of tau"),
        }
    }
}

/// Splits a `.ptau` container into `(section type, data)` pairs.
fn ptau_sections(bytes: &[u8]) -> Result<Vec<(u32, &[u8])>, PtauError> {
    let err = PtauError::Malformed("unexpected end of file");
    if bytes.len() < 12 || &bytes[..4] != b"ptau" {
        return Err(PtauError::Malformed("bad magic bytes"));
    }
    let mut rest = &bytes[12..];
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 12 {
            return Err(err);
        }
        let kind = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes"));
        let size = u64::from_le_bytes(rest[4..12].try_into().expect("8 bytes"));
        let size = usize::try_from(size).map_err(|_| err.clone())?;
        if rest.len() - 12 < size {
            return Err(err);
        }
        out.push((kind, &rest[12..12 + size]));
        rest = &rest[12 + size..];
    }
    Ok(out)
}

/// A base-field element stored little-endian in Montgomery form.
fn montgomery_fq(bytes: &[u8]) -> Result<Fq, PtauError> {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
    }
    let repr = BigInt::<4>::new(limbs);
    if repr >= Fq::MODULUS {
        return Err(PtauError::InvalidPoint);
    }
    Ok(Fq::new_unchecked(repr))
}

/// Evaluates the polynomial with coefficients `coeffs` at `c`.
pub fn evaluate(coeffs: &[Fr], c: Fr) -> Fr {
    let horner = |block: &[Fr]| block.iter().rev().fold(Fr::zero(), |acc, a| acc * c + a);
    // Long polynomials: Horner on blocks in parallel, then Horner over the
    // blocks' values with c^BLOCK. The value is the same field element.
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        const BLOCK: usize = 1 << 12;
        if coeffs.len() >= 4 * BLOCK {
            let parts: Vec<Fr> = coeffs.par_chunks(BLOCK).map(horner).collect();
            let step = c.pow([BLOCK as u64]);
            return parts.iter().rev().fold(Fr::zero(), |acc, a| acc * step + a);
        }
    }
    horner(coeffs)
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
        // A prover-side MSM (`llull_folder::msm`); verifiers never call this.
        G1::prover_msm(&ck.gens[..quotient.len()], &quotient)
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

    #[test]
    fn loads_and_validates_a_real_ptau_file() {
        // A power-7 ceremony file produced by snarkjs with two contributions.
        const PTAU: &[u8] = include_bytes!("../fixtures/pot7_test.ptau");
        let mut rng = test_rng();
        let srs = Srs::from_ptau(PTAU, 128, &mut rng).unwrap();
        assert_eq!(srs.powers_g1.len(), 128);

        // The loaded string really supports KZG openings.
        let ck = srs.commitment_key(b"ptau-test", 128);
        let coeffs: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect();
        let c = Fr::rand(&mut rng);
        let (value, proof) = open(&ck, &coeffs, c);
        assert!(verify(
            ck.commit(&coeffs, Fr::zero()),
            c,
            value,
            proof,
            srs.tau_g2
        ));

        // Requests beyond the ceremony, corruption and truncation are refused.
        assert_eq!(
            Srs::from_ptau(PTAU, 129, &mut rng).unwrap_err(),
            PtauError::TooShort { available: 128 }
        );
        let g1_start = 80;
        let mut bad = PTAU.to_vec();
        bad[g1_start + 64 * 5] ^= 1; // x of [τ^5]₁: no longer on the curve
        assert_eq!(
            Srs::from_ptau(&bad, 128, &mut rng).unwrap_err(),
            PtauError::InvalidPoint
        );
        // Swapping two valid powers breaks the geometric progression.
        let mut bad = PTAU.to_vec();
        let (a, b) = (g1_start + 64 * 3, g1_start + 64 * 4);
        let tmp = bad[a..a + 64].to_vec();
        bad.copy_within(b..b + 64, a);
        bad[b..b + 64].copy_from_slice(&tmp);
        assert_eq!(
            Srs::from_ptau(&bad, 128, &mut rng).unwrap_err(),
            PtauError::Inconsistent
        );
        for cut in [0, 11, 40, 5000, PTAU.len() - 1] {
            assert!(Srs::from_ptau(&PTAU[..cut], 16, &mut rng).is_err());
        }
        assert!(Srs::from_ptau(b"not a ptau file", 16, &mut rng).is_err());
    }

    #[test]
    fn a_trimmed_ptau_is_a_prefix_of_the_same_ceremony() {
        const PTAU: &[u8] = include_bytes!("../fixtures/pot7_test.ptau");
        let mut rng = test_rng();
        assert_eq!(ptau_powers(PTAU).unwrap(), 128);
        let full = Srs::from_ptau(PTAU, 128, &mut rng).unwrap();
        for n in [1, 20, 64, 128] {
            let trimmed = trim_ptau(PTAU, n).unwrap();
            assert!(trimmed.len() < 64 * n + 400);
            assert_eq!(ptau_powers(&trimmed).unwrap(), n);
            let srs = Srs::from_ptau(&trimmed, n, &mut rng).unwrap();
            assert_eq!(srs.powers_g1, full.powers_g1[..n]);
            assert_eq!(srs.tau_g2, full.tau_g2);
            assert!(Srs::from_ptau(&trimmed, n + 1, &mut rng).is_err());
        }
        assert!(trim_ptau(PTAU, 129).is_err());
        assert!(trim_ptau(PTAU, 0).is_err());
    }
}
