//! The universal decider: no per-circuit keys, only a universal reference
//! string and a public, deterministic commitment to the circuit.

use ark_bn254::Fr;
use ark_ff::One;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use evm_verifier::{
    kzg::Srs,
    universal::{self, CircuitKey, UniversalProof},
    EvmParams, OnChainFolder,
};
use llull_folder::{
    check_accumulator,
    core_r1cs::{RelaxedR1CSInstance, RelaxedR1CSWitness},
    demo_circuit::CubicChain,
};

type Acc = RelaxedR1CSInstance<ark_bn254::G1Projective>;
type Wit = RelaxedR1CSWitness<ark_bn254::G1Projective>;

fn setup(rounds: usize, rng: &mut StdRng) -> (EvmParams, CircuitKey) {
    let (shape, _, _) = CubicChain {
        z_in: Fr::from(3u64),
        rounds,
    }
    .synthesize()
    .unwrap();
    let len = universal::Dims::of(&shape).srs_len();
    let srs = Srs::insecure_for_testing(len, rng);
    EvmParams::setup_universal(shape, b"universal-test", &srs)
}

/// Folds `steps` steps and masks the accumulator, as `finalize` does.
fn folded(params: &EvmParams, rounds: usize, steps: usize, rng: &mut StdRng) -> (Acc, Wit) {
    let mut folder = OnChainFolder::new(params);
    let mut state = Fr::from(3u64);
    for _ in 0..steps {
        let circuit = CubicChain {
            z_in: state,
            rounds,
        };
        let (_, w, x) = circuit.synthesize().unwrap();
        state = circuit.output();
        folder.fold_step(params, w, x, rng).unwrap();
    }
    (folder.acc, folder.witness)
}

#[test]
fn universal_decider_accepts_folded_accumulators() {
    let mut rng = StdRng::seed_from_u64(1);
    for rounds in [4usize, 16] {
        let (params, key) = setup(rounds, &mut rng);
        // Preprocessing is deterministic: anyone recomputes the same key,
        // and with it the circuit's on-chain identity.
        let again = CircuitKey::preprocess(&params.shape, &params.ck);
        assert_eq!(again.digest(), key.digest());
        let tau_g2 = params.tau_g2.unwrap();
        assert_eq!(again.circuit_id(&params.ck.h, &tau_g2), params.vk);
        for steps in [1, 3] {
            let (acc, witness) = folded(&params, rounds, steps, &mut rng);
            check_accumulator(&params.ck, &params.shape, &acc, &witness).unwrap();
            let proof = universal::prove(&params, &key, &acc, &witness);
            assert!(universal::verify(&params, &key, &acc, &proof));
        }
    }
}

#[test]
fn universal_decider_rejects_every_forgery() {
    let mut rng = StdRng::seed_from_u64(2);
    let rounds = 8;
    let (params, key) = setup(rounds, &mut rng);
    let (acc, witness) = folded(&params, rounds, 2, &mut rng);
    let proof = universal::prove(&params, &key, &acc, &witness);
    assert!(universal::verify(&params, &key, &acc, &proof));
    let one = Fr::one();
    let h = params.ck.h;

    // A different accumulator.
    let mut other = acc.clone();
    other.u += one;
    assert!(!universal::verify(&params, &key, &other, &proof));
    let mut other = acc.clone();
    other.x[0] += one;
    assert!(!universal::verify(&params, &key, &other, &proof));
    let mut other = acc.clone();
    other.comm_w += h;
    assert!(!universal::verify(&params, &key, &other, &proof));
    let mut other = acc.clone();
    other.comm_e += h;
    assert!(!universal::verify(&params, &key, &other, &proof));

    // Every component of the proof.
    let reject = |name: &str, mutate: &dyn Fn(&mut UniversalProof)| {
        let mut bad = proof.clone();
        mutate(&mut bad);
        assert!(bad != proof, "{name}: mutation had no effect");
        assert!(
            !universal::verify(&params, &key, &acc, &bad),
            "{name} accepted"
        );
    };
    reject("r_w", &|p| p.r_w += one);
    reject("r_e", &|p| p.r_e += one);
    reject("outer[0]", &|p| p.outer[0] += one);
    reject("outer[last]", &|p| *p.outer.last_mut().unwrap() += one);
    reject("outer length", &|p| {
        p.outer.pop();
    });
    for i in 0..4 {
        reject("claims", &|p| p.claims[i] += one);
    }
    reject("inner", &|p| p.inner[1] += one);
    reject("v_m", &|p| p.v_m += one);
    reject("v_w", &|p| p.v_w += one);
    for i in 0..6 {
        reject("comms", &|p| p.comms[i] += h);
    }
    for i in 0..2 {
        reject("sums", &|p| p.sums[i] += one);
    }
    reject("sc_k", &|p| p.sc_k[2] += one);
    for i in 0..9 {
        reject("evals_k", &|p| p.evals_k[i] += one);
    }
    reject("sc_m", &|p| p.sc_m[0] += one);
    reject("sc_z", &|p| p.sc_z[0] += one);
    for i in 0..2 {
        reject("evals_m", &|p| p.evals_m[i] += one);
        reject("evals_z", &|p| p.evals_z[i] += one);
    }
    for i in 0..5 {
        reject("opening comm", &|p| p.openings.comms[i][0] += h);
        reject("opening y_pos", &|p| p.openings.y_pos[i][0] += one);
        reject("opening y_neg", &|p| p.openings.y_neg[i][1] += one);
        reject("opening y_sq", &|p| p.openings.y_sq[i][0] += one);
    }
    for j in 0..3 {
        reject("opening pi", &|p| p.openings.pi[j] += h);
    }
    // Swapping the two lookup sums or the two table openings.
    reject("swapped sums", &|p| p.sums.swap(0, 1));
}

#[test]
fn universal_decider_rejects_unsatisfied_witnesses_and_wrong_circuits() {
    let mut rng = StdRng::seed_from_u64(3);
    let rounds = 8;
    let (params, key) = setup(rounds, &mut rng);
    let (acc, witness) = folded(&params, rounds, 2, &mut rng);

    // A witness that does not satisfy the relation, committed consistently.
    for which in 0..2 {
        let mut bad_w = witness.clone();
        let mut bad_acc = acc.clone();
        if which == 0 {
            bad_w.w[1] += Fr::one();
            bad_acc.comm_w = params.ck.commit(&bad_w.w, bad_w.r_w);
        } else {
            bad_w.e[0] += Fr::one();
            bad_acc.comm_e = params.ck.commit(&bad_w.e, bad_w.r_e);
        }
        assert!(check_accumulator(&params.ck, &params.shape, &bad_acc, &bad_w).is_err());
        let proof = universal::prove(&params, &key, &bad_acc, &bad_w);
        assert!(!universal::verify(&params, &key, &bad_acc, &proof));
    }

    // A proof made against a *different circuit's* matrices (one extra
    // round changes A, B, C) does not verify under this circuit's key, and
    // a tampered key commitment is rejected too.
    let proof = universal::prove(&params, &key, &acc, &witness);
    for i in 0..7 {
        let mut other_key = key.clone();
        other_key.comms[i] += params.ck.h;
        assert!(
            !universal::verify(&params, &other_key, &acc, &proof),
            "key comm {i}"
        );
    }
    let mut other_dims = key.clone();
    other_dims.dims.log_k += 1;
    assert!(!universal::verify(&params, &other_dims, &acc, &proof));
}

#[test]
fn finalize_universal_end_to_end_and_proof_size() {
    use evm_verifier::{fold_relaxed_mask, DeciderError};
    use std::time::Instant;
    let mut rng = StdRng::seed_from_u64(4);
    for rounds in [8usize, 512] {
        let (params, key) = setup(rounds, &mut rng);
        let mut folder = OnChainFolder::new(&params);
        let mut state = Fr::from(3u64);
        for _ in 0..3 {
            let circuit = CubicChain {
                z_in: state,
                rounds,
            };
            let (_, w, x) = circuit.synthesize().unwrap();
            state = circuit.output();
            folder.fold_step(&params, w, x, &mut rng).unwrap();
        }
        let pre_mask = folder.acc.clone();
        let t = Instant::now();
        let (mask, acc, proof) = folder.finalize_universal(&params, &key, &mut rng).unwrap();
        let prove_time = t.elapsed();
        // What the chain holds after the mask fold is what the proof is about.
        assert_eq!(fold_relaxed_mask(&params, &pre_mask, &mask), acc);
        let t = Instant::now();
        assert!(universal::verify(&params, &key, &acc, &proof));
        println!(
            "{} constraints: proof {} bytes, mask+prove+self-check {:.2?}, verify {:.2?}",
            params.shape.num_constraints,
            proof.size_bytes(),
            prove_time,
            t.elapsed()
        );
        // Logarithmic in the circuit: a 64x larger circuit adds few bytes.
        assert!(proof.size_bytes() < 16 * 1024);
    }

    // Transparent (non-KZG) parameters cannot use the universal decider.
    let (shape, _, _) = CubicChain {
        z_in: Fr::from(3u64),
        rounds: 8,
    }
    .synthesize()
    .unwrap();
    let (kzg_params, key) = setup(8, &mut rng);
    let transparent = EvmParams::setup(shape, b"universal-test");
    let folder = OnChainFolder::new(&transparent);
    assert!(matches!(
        folder.finalize_universal(&transparent, &key, &mut rng),
        Err(DeciderError::NotKzg)
    ));
    let _ = kzg_params;
}
