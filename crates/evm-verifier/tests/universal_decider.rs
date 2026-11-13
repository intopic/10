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
        assert_eq!(again.comms, key.comms);
        assert_eq!(again.num_io, params.shape.num_io);
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

/// `out = in² + in` with public inputs `(in, out)` and `extra` further public
/// inputs that no constraint touches.
fn square_step(
    extra: usize,
    z_in: Fr,
    junk: Fr,
) -> (llull_folder::core_r1cs::R1CSShape<Fr>, Vec<Fr>, Vec<Fr>) {
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
    use llull_folder::core_r1cs::ark_bridge::{assignment_from_cs, shape_from_cs};
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });
    let z_out = z_in * z_in + z_in;
    let a = FpVar::new_input(cs.clone(), || Ok(z_in)).unwrap();
    let b = FpVar::new_input(cs.clone(), || Ok(z_out)).unwrap();
    for _ in 0..extra {
        let _ = FpVar::new_input(cs.clone(), || Ok(junk)).unwrap();
    }
    // A few witnesses so that the padded dimensions do not depend on `extra`.
    let mut sq = a.square().unwrap();
    for _ in 0..6 {
        let w = FpVar::new_witness(cs.clone(), || Ok(z_in * z_in)).unwrap();
        w.enforce_equal(&sq).unwrap();
        sq = w;
    }
    (sq + &a).enforce_equal(&b).unwrap();
    let shape = shape_from_cs(&cs).unwrap();
    let (w, x) = assignment_from_cs(&cs).unwrap();
    (shape, w, x)
}

#[test]
fn the_number_of_public_inputs_is_part_of_the_circuit_identity() {
    // Regression test. Public inputs beyond the circuit's own occupy columns
    // of Z that no matrix entry touches, so they are unconstrained. The two
    // circuits below have the same matrices — the same seven commitments and
    // dimensions — and differ only in two such inputs. Before the number of
    // inputs was part of the key, they had the same on-chain identity, and
    // an accumulator with arbitrary extra "state" was decided under the
    // identity of the two-input circuit.
    let mut rng = StdRng::seed_from_u64(9);
    let (shape, _, _) = square_step(0, Fr::from(3u64), Fr::one());
    let (wide_shape, w, x) = square_step(2, Fr::from(3u64), Fr::from(123_456u64));
    assert_eq!((shape.num_io, wide_shape.num_io), (2, 4));
    let srs = Srs::insecure_for_testing(universal::Dims::of(&wide_shape).srs_len(), &mut rng);
    let (params, key) = EvmParams::setup_universal(shape, b"arity", &srs);
    let (wide_params, wide_key) = EvmParams::setup_universal(wide_shape, b"arity", &srs);
    assert_eq!(key.dims, wide_key.dims);
    assert_eq!(key.comms, wide_key.comms, "the matrices are the same");
    assert_ne!(params.vk, wide_params.vk, "but the identities differ");

    // An honest proof for the wide circuit, whose extra inputs are junk.
    let mut folder = OnChainFolder::new(&wide_params);
    folder.fold_step(&wide_params, w, x, &mut rng).unwrap();
    let (acc, witness) = (folder.acc, folder.witness);
    assert_eq!(acc.x.len(), 4);
    let proof = universal::prove(&wide_params, &wide_key, &acc, &witness);
    assert!(universal::verify(&wide_params, &wide_key, &acc, &proof));
    // It is not a proof for the two-input circuit, with either key object.
    assert!(!universal::verify(&params, &key, &acc, &proof));
    assert!(!universal::verify(&params, &wide_key, &acc, &proof));
    assert!(!universal::verify(&wide_params, &key, &acc, &proof));
    // The key's 24th word is the number of inputs.
    let words = wide_key.contract_words(&wide_params.ck.h, &wide_params.tau_g2.unwrap());
    assert_eq!(words.len(), 24);
    assert_eq!(words[23][31], 4);
}
