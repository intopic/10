//! Phase 1 acceptance tests (roadmap KPI): after folding `t = 100` steps the
//! accumulator satisfies `(A·Z) ∘ (B·Z) = u·(C·Z) + E` with zero errors.

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use llull_folder::{
    check_accumulator, commit_witness,
    core_r1cs::{R1CSError, RelaxedR1CSInstance, RelaxedR1CSWitness},
    demo_circuit::CubicChain,
    llull_combinator::compute_cross_term,
    nifs_prove, nifs_verify,
    transcript::poseidon_config,
    CommitmentKey, FoldError, PublicParams,
};

#[allow(clippy::type_complexity)]
fn fold_chain<C: CurveGroup>(
    steps: usize,
    rounds: usize,
) -> (
    PublicParams<C>,
    llull_folder::core_r1cs::R1CSShape<C::ScalarField>,
    RelaxedR1CSInstance<C>,
    RelaxedR1CSWitness<C>,
)
where
    C::BaseField: PrimeField + Absorb,
{
    let mut rng = test_rng();
    let mut state = C::ScalarField::from(3u64);
    let (shape, _, _) = CubicChain {
        z_in: state,
        rounds,
    }
    .synthesize()
    .unwrap();
    let pp = PublicParams::<C>::setup(&shape, b"test");
    let mut acc_u = RelaxedR1CSInstance::default_for(&shape);
    let mut acc_w = RelaxedR1CSWitness::default_for(&shape);
    check_accumulator(&pp.ck, &shape, &acc_u, &acc_w).unwrap();
    let mut sizes = Vec::new();

    for _ in 0..steps {
        let circuit = CubicChain {
            z_in: state,
            rounds,
        };
        let (_, w, x) = circuit.synthesize().unwrap();
        shape.is_sat(&w, &x).unwrap();
        state = circuit.output();
        let (u2, w2) = commit_witness(&pp.ck, w, x, &mut rng);
        let (u, w, comm_t) = nifs_prove(&pp, &shape, &acc_u, &acc_w, &u2, &w2, &mut rng).unwrap();
        // The O(1) verifier reaches the same accumulator from public data only.
        assert_eq!(
            nifs_verify(&pp.poseidon, pp.digest, &acc_u, &u2, &comm_t),
            u
        );
        (acc_u, acc_w) = (u, w);
        sizes.push((acc_u.compressed_size(), acc_w.compressed_size()));
    }
    // Zeno invariant: the accumulator never grows with the number of steps.
    assert!(sizes.windows(2).all(|p| p[0] == p[1]));
    (pp, shape, acc_u, acc_w)
}

fn kpi_100_steps<C: CurveGroup>()
where
    C::BaseField: PrimeField + Absorb,
{
    let (pp, shape, u, w) = fold_chain::<C>(100, 16);
    check_accumulator(&pp.ck, &shape, &u, &w).unwrap();
    // A satisfied accumulator after real folds is genuinely relaxed.
    assert!(u.u != C::ScalarField::one());
    assert!(w.e.iter().any(|e| *e != C::ScalarField::from(0u64)));
}

#[test]
fn kpi_fold_100_steps_pallas() {
    kpi_100_steps::<ark_pallas::Projective>();
}

#[test]
fn kpi_fold_100_steps_vesta() {
    kpi_100_steps::<ark_vesta::Projective>();
}

#[test]
fn kpi_fold_100_steps_bn254() {
    kpi_100_steps::<ark_bn254::G1Projective>();
}

#[test]
fn kpi_fold_100_steps_grumpkin() {
    kpi_100_steps::<ark_grumpkin::Projective>();
}

#[test]
fn tampered_accumulator_is_rejected() {
    type C = ark_pallas::Projective;
    let (pp, shape, u, w) = fold_chain::<C>(5, 8);

    let mut bad = w.clone();
    bad.w[0] += ark_pallas::Fr::one();
    assert!(matches!(
        check_accumulator(&pp.ck, &shape, &u, &bad),
        Err(FoldError::R1CS(R1CSError::Unsatisfied { .. }))
    ));

    let mut bad = w.clone();
    bad.r_w += ark_pallas::Fr::one();
    assert_eq!(
        check_accumulator(&pp.ck, &shape, &u, &bad),
        Err(FoldError::WitnessCommitmentMismatch)
    );

    let mut bad = w.clone();
    bad.r_e += ark_pallas::Fr::one();
    assert_eq!(
        check_accumulator(&pp.ck, &shape, &u, &bad),
        Err(FoldError::ErrorCommitmentMismatch)
    );

    let mut bad_u = u.clone();
    bad_u.x[0] += ark_pallas::Fr::one();
    assert!(check_accumulator(&pp.ck, &shape, &bad_u, &w).is_err());
}

#[test]
fn folding_an_invalid_step_poisons_the_accumulator() {
    type C = ark_pallas::Projective;
    let mut rng = test_rng();
    let (pp, shape, u, w) = fold_chain::<C>(3, 8);
    let circuit = CubicChain {
        z_in: ark_pallas::Fr::from(7u64),
        rounds: 8,
    };
    let (_, mut bad_w, x) = circuit.synthesize().unwrap();
    bad_w[1] += ark_pallas::Fr::one();
    assert!(shape.is_sat(&bad_w, &x).is_err());
    let (u2, w2) = commit_witness(&pp.ck, bad_w, x, &mut rng);
    let (u, w, _) = nifs_prove(&pp, &shape, &u, &w, &u2, &w2, &mut rng).unwrap();
    assert!(check_accumulator(&pp.ck, &shape, &u, &w).is_err());
}

#[test]
fn challenge_binds_every_transcript_element() {
    type C = ark_pallas::Projective;
    let mut rng = test_rng();
    let (pp, shape, u, w) = fold_chain::<C>(2, 4);
    let circuit = CubicChain {
        z_in: ark_pallas::Fr::from(9u64),
        rounds: 4,
    };
    let (_, w2, x2) = circuit.synthesize().unwrap();
    let (u2, w2) = commit_witness(&pp.ck, w2, x2, &mut rng);
    let (folded, _, comm_t) = nifs_prove(&pp, &shape, &u, &w, &u2, &w2, &mut rng).unwrap();

    let verify =
        |digest, u1: &RelaxedR1CSInstance<C>, u2, t| nifs_verify(&pp.poseidon, digest, u1, u2, t);
    assert_eq!(verify(pp.digest, &u, &u2, &comm_t), folded);
    // A different vk digest, accumulator, step or cross-term commitment each
    // changes the challenge, hence `u` of the folded instance.
    let other_digest = pp.digest + ark_pallas::Fq::one();
    assert_ne!(verify(other_digest, &u, &u2, &comm_t).u, folded.u);
    let mut u_alt = u.clone();
    u_alt.x[1] += ark_pallas::Fr::one();
    assert_ne!(
        verify(pp.digest, &u_alt, &u2, &comm_t).u - u_alt.u,
        folded.u - u.u
    );
    let mut u2_alt = u2.clone();
    u2_alt.comm_w += pp.ck.h;
    assert_ne!(verify(pp.digest, &u, &u2_alt, &comm_t).u, folded.u);
    assert_ne!(verify(pp.digest, &u, &u2, &(comm_t + pp.ck.h)).u, folded.u);
}

#[test]
fn pedersen_is_additively_homomorphic_and_transparent() {
    type C = ark_bn254::G1Projective;
    type F = ark_bn254::Fr;
    let mut rng = test_rng();
    let ck = CommitmentKey::<C>::setup(b"homomorphism", 32);
    // Deterministic, label-separated and free of repeated generators.
    assert_eq!(ck, CommitmentKey::<C>::setup(b"homomorphism", 32));
    assert_ne!(ck.gens, CommitmentKey::<C>::setup(b"other", 32).gens);
    let mut all = ck.gens.clone();
    all.push(ck.h);
    let unique: std::collections::HashSet<_> = all.iter().collect();
    assert_eq!(unique.len(), all.len());

    let a: Vec<F> = (0..32).map(|_| F::rand(&mut rng)).collect();
    let b: Vec<F> = (0..32).map(|_| F::rand(&mut rng)).collect();
    let (ra, rb, r) = (F::rand(&mut rng), F::rand(&mut rng), F::rand(&mut rng));
    let sum: Vec<F> = a.iter().zip(&b).map(|(x, y)| *x + r * y).collect();
    assert_eq!(
        ck.commit(&a, ra) + ck.commit(&b, rb) * r,
        ck.commit(&sum, ra + r * rb)
    );
}

#[test]
fn cross_term_matches_the_folding_identity() {
    // (A·Z)∘(B·Z) − u·(C·Z) for Z = Z1 + r·Z2 equals E1 + r·T + r²·E2 (eq. 8).
    type F = ark_pallas::Fr;
    let mut rng = test_rng();
    let (shape, _, _) = CubicChain {
        z_in: F::from(2u64),
        rounds: 6,
    }
    .synthesize()
    .unwrap();
    let rand_z = |rng: &mut _| -> Vec<F> { (0..shape.num_cols()).map(|_| F::rand(rng)).collect() };
    let (z1, z2, r) = (rand_z(&mut rng), rand_z(&mut rng), F::rand(&mut rng));
    let residual = |z: &[F]| -> Vec<F> {
        let (az, bz, cz) = shape.mul_z(z);
        let u = z[shape.num_cols() - 1];
        (0..shape.num_constraints)
            .map(|i| az[i] * bz[i] - u * cz[i])
            .collect()
    };
    let (e1, e2) = (residual(&z1), residual(&z2));
    let t = compute_cross_term(&shape, &z1, &z2);
    let z: Vec<F> = z1.iter().zip(&z2).map(|(a, b)| *a + r * b).collect();
    let expected: Vec<F> = (0..shape.num_constraints)
        .map(|i| e1[i] + r * t[i] + r * r * e2[i])
        .collect();
    assert_eq!(residual(&z), expected);
}

#[test]
fn poseidon_sbox_is_a_permutation_on_all_supported_fields() {
    fn check<F: PrimeField>() {
        let cfg = poseidon_config::<F>();
        // gcd(α, p − 1) = 1  ⇔  x ↦ x^α is a bijection.
        let alpha = cfg.alpha;
        let p_minus_one: num_bigint_free::U = num_bigint_free::minus_one::<F>();
        assert_ne!(num_bigint_free::rem(&p_minus_one, alpha), 0);
    }
    mod num_bigint_free {
        use ark_ff::{BigInteger, PrimeField};
        pub type U = Vec<u64>;
        pub fn minus_one<F: PrimeField>() -> U {
            let mut m = F::MODULUS;
            m.sub_with_borrow(&F::BigInt::from(1u64));
            m.as_ref().to_vec()
        }
        pub fn rem(limbs: &U, d: u64) -> u64 {
            limbs
                .iter()
                .rev()
                .fold(0u128, |acc, l| ((acc << 64) | *l as u128) % d as u128) as u64
        }
    }
    check::<ark_pallas::Fq>();
    check::<ark_pallas::Fr>();
    check::<ark_bn254::Fq>();
    check::<ark_bn254::Fr>();
}

#[test]
fn relaxed_relaxed_folding_and_random_masking() {
    use llull_folder::{nifs_prove_relaxed, nifs_verify_relaxed, sample_relaxed};
    type C = ark_pallas::Projective;
    let mut rng = test_rng();
    let (pp, shape, u1, w1) = fold_chain::<C>(4, 8);

    // A random relaxed pair satisfies the relation by construction.
    let (u2, w2) = sample_relaxed(&pp.ck, &shape, &mut rng);
    check_accumulator(&pp.ck, &shape, &u2, &w2).unwrap();

    // Folding two relaxed pairs (r² terms included) preserves satisfaction,
    // and the verifier agrees with the prover.
    let (u, w, comm_t) = nifs_prove_relaxed(&pp, &shape, &u1, &w1, &u2, &w2, &mut rng).unwrap();
    check_accumulator(&pp.ck, &shape, &u, &w).unwrap();
    assert_eq!(
        nifs_verify_relaxed(&pp.poseidon, pp.digest, &u1, &u2, &comm_t),
        u
    );
    // The mask changes every witness coordinate.
    assert!(w.w.iter().zip(&w1.w).all(|(a, b)| a != b));

    // An unsatisfied accumulator stays unsatisfied after masking.
    let mut bad = w1.clone();
    bad.w[0] += ark_pallas::Fr::one();
    let bad_u = RelaxedR1CSInstance {
        comm_w: pp.ck.commit(&bad.w, bad.r_w),
        ..u1.clone()
    };
    let (u, w, _) = nifs_prove_relaxed(&pp, &shape, &bad_u, &bad, &u2, &w2, &mut rng).unwrap();
    assert!(check_accumulator(&pp.ck, &shape, &u, &w).is_err());
}
