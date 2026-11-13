//! Rust-side tests of the EVM folding flow (the contract itself is tested
//! against the same code in `contracts/test`).

use ark_bn254::Fr;
use ark_std::test_rng;
use evm_verifier::{abi, fold_challenge, mask_challenge, verify_final, EvmParams, OnChainFolder};
use llull_folder::{
    check_accumulator, core_r1cs::R1CSInstance, demo_circuit::CubicChain, fold_instance,
    fold_relaxed_instance, FoldError,
};

fn params() -> EvmParams {
    let (shape, _, _) = CubicChain {
        z_in: Fr::from(3u64),
        rounds: 16,
    }
    .synthesize()
    .unwrap();
    EvmParams::setup(shape, b"test")
}

#[test]
fn folding_matches_what_the_contract_recomputes() {
    let mut rng = test_rng();
    let params = params();
    let mut folder = OnChainFolder::new(&params);
    // The contract's view: public data only.
    let mut onchain = folder.acc.clone();
    let mut state = Fr::from(3u64);
    for _ in 0..4 {
        let circuit = CubicChain {
            z_in: state,
            rounds: 16,
        };
        let (_, w, x) = circuit.synthesize().unwrap();
        state = circuit.output();
        let proof = folder.fold_step(&params, w, x, &mut rng).unwrap();
        let step = R1CSInstance {
            comm_w: proof.comm_w,
            x: proof.public_inputs.clone(),
        };
        let r = fold_challenge(&params.vk, &onchain, &step, &proof.comm_t);
        onchain = fold_instance(&onchain, &step, &proof.comm_t, r);
        assert_eq!(onchain, folder.acc);
        check_accumulator(&params.ck, &params.shape, &folder.acc, &folder.witness).unwrap();
    }

    let pre_mask = onchain.clone();
    let (mask, final_acc, snark) = folder.finalize(&params, &mut rng).unwrap();
    let r = mask_challenge(&params.vk, &pre_mask, &mask.mask, &mask.comm_t);
    let onchain = fold_relaxed_instance(&pre_mask, &mask.mask, &mask.comm_t, r);
    assert_eq!(onchain, final_acc);

    // The decider accepts exactly the finalized accumulator.
    assert!(verify_final(&params, &onchain, &snark));
    assert!(!verify_final(&params, &pre_mask, &snark));
    let mut other = onchain.clone();
    other.x[1] += Fr::from(1u64);
    assert!(!verify_final(&params, &other, &snark));
    let other_params = EvmParams::setup(params.shape.clone(), b"other");
    assert!(!verify_final(&other_params, &onchain, &snark));
}

#[test]
fn invalid_steps_are_refused_by_the_prover_library() {
    let mut rng = test_rng();
    let params = params();
    let mut folder = OnChainFolder::new(&params);
    let (_, mut w, x) = CubicChain {
        z_in: Fr::from(3u64),
        rounds: 16,
    }
    .synthesize()
    .unwrap();
    w[0] += Fr::from(1u64);
    assert!(matches!(
        folder.fold_step(&params, w, x, &mut rng),
        Err(FoldError::R1CS(_))
    ));
    assert_eq!(folder.steps, 0);
}

#[test]
fn abi_selectors_and_layout() {
    // Known selector: transfer(address,uint256) = a9059cbb.
    assert_eq!(
        abi::selector("transfer(address,uint256)"),
        [0xa9, 0x05, 0x9c, 0xbb]
    );
    let vk = [7u8; 32];
    let data = abi::open_session(&vk, &[Fr::from(3u64)]);
    assert_eq!(data.len(), 4 + 32 * 4);
    assert_eq!(&data[4..36], &vk);
    assert_eq!(data[4 + 63], 0x40);
    assert_eq!(data[4 + 95], 1);
    assert_eq!(data[4 + 127], 3);
}

#[cfg(feature = "dev-groth16")]
#[test]
fn onchain_decider_groth16_kzg() {
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use evm_verifier::{kzg::Srs, verify_onchain_decider, DeciderError, DeciderKeys};
    let mut rng = StdRng::seed_from_u64(7);
    let rounds = 16;
    let (shape, _, _) = CubicChain {
        z_in: Fr::from(3u64),
        rounds,
    }
    .synthesize()
    .unwrap();
    let srs = Srs::insecure_for_testing(64, &mut rng);
    let params = EvmParams::setup_kzg(shape, b"test", &srs);
    let keys = DeciderKeys::insecure_for_testing(&params, &mut rng).unwrap();

    let run = |rng: &mut StdRng, corrupt: bool| {
        let mut folder = OnChainFolder::new(&params);
        let mut state = Fr::from(3u64);
        for _ in 0..3 {
            let circuit = CubicChain {
                z_in: state,
                rounds,
            };
            let (_, w, x) = circuit.synthesize().unwrap();
            state = circuit.output();
            folder.fold_step(&params, w, x, rng).unwrap();
        }
        if corrupt {
            folder.witness.w[2] += Fr::from(1u64);
        }
        folder.finalize_onchain(&params, &keys, rng)
    };

    let (_, acc, proof) = run(&mut rng, false).unwrap();
    assert!(verify_onchain_decider(&params, &keys.vk, &acc, &proof));

    // Any other accumulator, evaluation, blinding or opening is rejected.
    let mut other = acc.clone();
    other.u += Fr::from(1u64);
    assert!(!verify_onchain_decider(&params, &keys.vk, &other, &proof));
    let mut other = acc.clone();
    other.comm_e += params.ck.h;
    assert!(!verify_onchain_decider(&params, &keys.vk, &other, &proof));
    // The witness digest fixes the evaluation point: any other digest moves
    // the point and invalidates the openings and the Groth16 proof.
    let mut bad = proof.clone();
    bad.digest += Fr::from(1u64);
    assert!(!verify_onchain_decider(&params, &keys.vk, &acc, &bad));
    let mut bad = proof.clone();
    bad.w_eval += Fr::from(1u64);
    assert!(!verify_onchain_decider(&params, &keys.vk, &acc, &bad));
    let mut bad = proof.clone();
    bad.r_e += Fr::from(1u64);
    assert!(!verify_onchain_decider(&params, &keys.vk, &acc, &bad));
    let mut bad = proof.clone();
    bad.pi_w += params.ck.h;
    assert!(!verify_onchain_decider(&params, &keys.vk, &acc, &bad));
    let mut bad = proof.clone();
    bad.groth16.c = (bad.groth16.c + params.ck.h).into();
    assert!(!verify_onchain_decider(&params, &keys.vk, &acc, &bad));

    // An unsatisfied accumulator cannot be decided, and transparent
    // parameters cannot use the on-chain decider.
    assert!(matches!(
        run(&mut rng, true),
        Err(DeciderError::Unsatisfied)
    ));
    let transparent = EvmParams::setup(params.shape.clone(), b"test");
    let folder = OnChainFolder::new(&transparent);
    assert!(matches!(
        folder.finalize_onchain(&transparent, &keys, &mut rng),
        Err(DeciderError::NotKzg)
    ));
}

#[cfg(feature = "dev-groth16")]
#[test]
fn decider_witness_cannot_be_swapped_after_the_point_is_known() {
    // Regression test for the commit-and-prove link. An accumulator whose
    // committed witness is NOT satisfying must not be decidable by feeding
    // the circuit some other, satisfying pair (W', E') for the same (u, x):
    // the evaluation point depends on Poseidon(W', E'), so the pair is fixed
    // before the point at which it is compared with the commitments.
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use evm_verifier::{
        decider_circuit::{witness_digest, DeciderCircuit},
        decider_point,
        kzg::{self, Srs},
    };
    use llull_folder::{sample_relaxed, transcript::poseidon_config};

    let mut rng = StdRng::seed_from_u64(11);
    let (shape, _, _) = CubicChain {
        z_in: Fr::from(3u64),
        rounds: 16,
    }
    .synthesize()
    .unwrap();
    let srs = Srs::insecure_for_testing(64, &mut rng);
    let params = EvmParams::setup_kzg(shape, b"test", &srs);
    let poseidon = poseidon_config::<Fr>();

    // On-chain: commitments to a witness that does not satisfy the relation.
    let (mut acc, mut committed) = sample_relaxed(&params.ck, &params.shape, &mut rng);
    committed.w[0] += Fr::from(1u64);
    acc.comm_w = params.ck.commit(&committed.w, committed.r_w);
    assert!(check_accumulator(&params.ck, &params.shape, &acc, &committed).is_err());

    // The adversary's substitute: any W' with E' := (A·Z)∘(B·Z) − u·(C·Z)
    // satisfies the relaxed relation for the same public (u, x).
    let w_prime: Vec<Fr> = (0..params.shape.num_vars as u64).map(Fr::from).collect();
    let z = params.shape.z(&w_prime, &acc.x, acc.u).unwrap();
    let (az, bz, cz) = params.shape.mul_z(&z);
    let e_prime: Vec<Fr> = (0..params.shape.num_constraints)
        .map(|i| az[i] * bz[i] - acc.u * cz[i])
        .collect();
    params
        .shape
        .is_sat_relaxed(&w_prime, &acc.x, acc.u, &e_prime)
        .unwrap();

    // The point is forced by the substitute's own digest; the contract then
    // compares against the evaluations of the *committed* polynomials.
    let digest = witness_digest(&poseidon, &w_prime, &e_prime);
    let c = decider_point(&params.vk, &acc, &digest);
    let (w_eval, _) = kzg::open(&params.ck, &committed.w, c);
    let (e_eval, _) = kzg::open(&params.ck, &committed.e, c);
    let circuit = |w_eval, e_eval, digest| DeciderCircuit {
        shape: &params.shape,
        poseidon: &poseidon,
        u: Some(acc.u),
        x: Some(acc.x.clone()),
        digest: Some(digest),
        c: Some(c),
        w_eval: Some(w_eval),
        e_eval: Some(e_eval),
        w: Some(w_prime.clone()),
        e: Some(e_prime.clone()),
    };
    let satisfied = |c: DeciderCircuit| {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    };
    // With the committed evaluations the circuit is unsatisfiable…
    assert!(!satisfied(circuit(w_eval, e_eval, digest)));
    // …it is only satisfiable with the substitute's own evaluations, which
    // the KZG check on-chain rejects, and never with a different digest.
    let own = (kzg::evaluate(&w_prime, c), kzg::evaluate(&e_prime, c));
    assert!(satisfied(circuit(own.0, own.1, digest)));
    assert_ne!((w_eval, e_eval), own);
    assert!(!satisfied(circuit(own.0, own.1, digest + Fr::from(1u64))));
}
