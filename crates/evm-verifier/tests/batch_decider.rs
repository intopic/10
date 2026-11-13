//! The batched universal decider: several accumulators of different circuits
//! in one argument.

use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_ff::One;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use core_r1cs::{R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness};
use evm_verifier::{
    kzg::Srs,
    universal::{
        self,
        batch::{self, Item},
        CircuitKey, Dims,
    },
    EvmParams, OnChainFolder,
};
use llull_folder::demo_circuit::CubicChain;

/// A change to an otherwise valid proof.
type Forgery = Box<dyn Fn(&mut batch::BatchProof)>;

type Acc = RelaxedR1CSInstance<G1>;
type Wit = RelaxedR1CSWitness<G1>;

fn shape(rounds: usize) -> R1CSShape<Fr> {
    CubicChain {
        z_in: Fr::from(3u64),
        rounds,
    }
    .synthesize()
    .unwrap()
    .0
}

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

fn max_dims(a: Dims, b: Dims) -> Dims {
    Dims {
        log_m: a.log_m.max(b.log_m),
        log_n: a.log_n.max(b.log_n),
        log_k: a.log_k.max(b.log_k),
    }
}

#[allow(clippy::type_complexity)]
fn setup(rng: &mut StdRng) -> ([(EvmParams, CircuitKey); 2], [(Acc, Wit); 2]) {
    let (s1, s2) = (shape(8), shape(64));
    let dims = max_dims(Dims::of(&s1), Dims::of(&s2));
    let srs = Srs::insecure_for_testing(dims.srs_len(), rng);
    let p1 = EvmParams::setup_universal_with_dims(s1, b"batch/one", &srs, dims);
    let p2 = EvmParams::setup_universal_with_dims(s2, b"batch/two", &srs, dims);
    let a1 = folded(&p1.0, 8, 3, rng);
    let a2 = folded(&p2.0, 64, 2, rng);
    ([p1, p2], [a1, a2])
}

#[test]
fn batch_of_two_circuits_and_of_one() {
    let mut rng = StdRng::seed_from_u64(1);
    let ([p1, p2], [a1, a2]) = setup(&mut rng);
    let items = [
        Item {
            params: &p1.0,
            key: &p1.1,
            acc: &a1.0,
        },
        Item {
            params: &p2.0,
            key: &p2.1,
            acc: &a2.0,
        },
    ];
    let proof = batch::prove(&items, &[&a1.1, &a2.1]);
    assert!(batch::verify(&items, &proof));
    let single = universal::prove(&p2.0, &p2.1, &a2.0, &a2.1);
    println!(
        "batched proof for 2 circuits: {} bytes; one single-circuit proof: {} bytes",
        32 * proof.words().len(),
        single.size_bytes()
    );
    assert!(32 * proof.words().len() < single.size_bytes() + single.size_bytes() / 4);

    let one = batch::prove(&items[1..], &[&a2.1]);
    assert!(batch::verify(&items[1..], &one));
    // The two-instance proof is not a proof for one instance, nor reordered.
    assert!(!batch::verify(&items[1..], &proof));
    let swapped = [
        Item {
            params: &p2.0,
            key: &p2.1,
            acc: &a2.0,
        },
        Item {
            params: &p1.0,
            key: &p1.1,
            acc: &a1.0,
        },
    ];
    assert!(!batch::verify(&swapped, &proof));
}

#[test]
fn batch_rejects_forgeries() {
    let mut rng = StdRng::seed_from_u64(2);
    let ([p1, p2], [a1, a2]) = setup(&mut rng);
    let items = [
        Item {
            params: &p1.0,
            key: &p1.1,
            acc: &a1.0,
        },
        Item {
            params: &p2.0,
            key: &p2.1,
            acc: &a2.0,
        },
    ];
    let proof = batch::prove(&items, &[&a1.1, &a2.1]);

    // Another accumulator for either circuit.
    for i in 0..2 {
        let mut other = [a1.0.clone(), a2.0.clone()];
        other[i].u += Fr::one();
        let items = [
            Item {
                params: &p1.0,
                key: &p1.1,
                acc: &other[0],
            },
            Item {
                params: &p2.0,
                key: &p2.1,
                acc: &other[1],
            },
        ];
        assert!(!batch::verify(&items, &proof), "other accumulator {i}");
    }
    // An unsatisfied witness for the second circuit.
    let mut bad = a2.1.clone();
    bad.w[5] += Fr::one();
    let bad_acc = RelaxedR1CSInstance {
        comm_w: p2.0.ck.commit(&bad.w, bad.r_w),
        ..a2.0.clone()
    };
    let bad_items = [
        Item {
            params: &p1.0,
            key: &p1.1,
            acc: &a1.0,
        },
        Item {
            params: &p2.0,
            key: &p2.1,
            acc: &bad_acc,
        },
    ];
    let bad_proof = batch::prove(&bad_items, &[&a1.1, &bad]);
    assert!(!batch::verify(&bad_items, &bad_proof));

    // Every scalar and point of the proof.
    let forgeries: Vec<Forgery> = vec![
        Box::new(|p| p.blinds[1][0] += Fr::one()),
        Box::new(|p| p.outer[3] += Fr::one()),
        Box::new(|p| p.claims[0][2] += Fr::one()),
        Box::new(|p| p.claims[1][3] += Fr::one()),
        Box::new(|p| p.inner[1] += Fr::one()),
        Box::new(|p| p.v[1][0] += Fr::one()),
        Box::new(|p| p.v[0][1] += Fr::one()),
        Box::new(|p| p.comms[1][0] += G1::generator()),
        Box::new(|p| p.comms[0][4] += G1::generator()),
        Box::new(|p| p.sums[1][1] += Fr::one()),
        Box::new(|p| p.sc_k[2] += Fr::one()),
        Box::new(|p| p.evals_k[1][7] += Fr::one()),
        Box::new(|p| p.sc_m[0] += Fr::one()),
        Box::new(|p| p.evals_m[0][1] += Fr::one()),
        Box::new(|p| p.sc_z[4] += Fr::one()),
        Box::new(|p| p.evals_z[1][0] += Fr::one()),
        Box::new(|p| p.openings.pi[1] += G1::generator()),
        Box::new(|p| p.openings.y_pos[2][0] += Fr::one()),
        Box::new(|p| p.openings.comms[4][0] += G1::generator()),
    ];
    for (i, forge) in forgeries.iter().enumerate() {
        let mut bad = proof.clone();
        forge(&mut bad);
        assert!(!batch::verify(&items, &bad), "forgery {i} was accepted");
    }

    // A key of another circuit in place of the second one.
    let p3 = EvmParams::setup_universal_with_dims(
        shape(32),
        b"batch/two",
        &Srs::insecure_for_testing(p1.1.dims.srs_len(), &mut rng),
        p1.1.dims,
    );
    let items = [
        Item {
            params: &p1.0,
            key: &p1.1,
            acc: &a1.0,
        },
        Item {
            params: &p3.0,
            key: &p3.1,
            acc: &a2.0,
        },
    ];
    assert!(!batch::verify(&items, &proof));
}
