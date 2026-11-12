//! The closing circuit decided by the universal decider over 2^20 powers.
//!
//! Heavy (a 2^20-power reference string): run explicitly with
//! `cargo test --release -p evm-verifier --test closing_decider -- --ignored --nocapture`.
//! With `ZENO_PTAU` pointing at a 2^20 Powers-of-Tau file the powers are
//! loaded from it; otherwise a local test SRS is sampled.

use ark_bn254::{Fq, Fr, G1Projective as G1};
use ark_ff::{UniformRand, Zero};
use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
use ark_std::{rand::SeedableRng, test_rng};
use core_r1cs::{
    ark_bridge::{assignment_from_cs, shape_from_cs},
    RelaxedR1CSInstance, RelaxedR1CSWitness,
};
use evm_verifier::{
    kzg::Srs,
    universal::{self, Dims},
    EvmParams,
};
use std::time::Instant;
use zeno_ivc::{
    cyclefold::{
        closing::{closing_scalars, ClosingCircuit},
        CycleFoldAccumulator, CycleFoldParams, CF_COLUMNS,
    },
    CubicStep,
};

type Bn254 = ark_bn254::g1::Config;
type Grumpkin = ark_grumpkin::GrumpkinConfig;

fn peak_rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map(|kib| kib / 1024)
        .unwrap_or(0)
}

#[test]
#[ignore = "needs a 2^20-power reference string; run explicitly"]
fn closing_circuit_is_decided_by_the_universal_decider() {
    let mut rng = test_rng();
    let step = CubicStep { rounds: 1 };
    let params = CycleFoldParams::<Bn254, Grumpkin>::setup(&step, b"closing", CF_COLUMNS).unwrap();
    let mut acc = CycleFoldAccumulator::new(&params, vec![Fr::from(3u64)]).unwrap();
    for _ in 0..2 {
        acc.prove_step(&params, &step, &mut rng).unwrap();
    }
    let point = |rng: &mut _| -> Vec<Fq> { (0..10).map(|_| Fq::rand(rng)).collect() };
    let (r_w, r_e, gamma) = (point(&mut rng), point(&mut rng), Fq::rand(&mut rng));
    let (row_weights, combined, _, _) =
        closing_scalars(&acc.cf.1.w, &acc.cf.1.e, CF_COLUMNS, &r_w, &r_e, gamma);
    let gens = params.cf_key.ck.gens.clone();
    let circuit = ClosingCircuit::<Bn254, Grumpkin> {
        poseidon: &params.poseidon,
        digest: params.digest,
        gens: &gens,
        i: acc.i,
        z0: acc.z0.clone(),
        zi: acc.zi.clone(),
        acc: acc.acc.0.clone(),
        cf_acc: acc.cf.0.clone(),
        row_weights,
        combined,
    };
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });
    circuit.synthesize(cs.clone()).unwrap();
    let shape = shape_from_cs(&cs).unwrap();
    let (w, x) = assignment_from_cs(&cs).unwrap();
    drop(cs);
    let dims = Dims::of(&shape);
    println!(
        "closing circuit: {} constraints, {} public inputs, dims {:?}, reference string 2^{}",
        shape.num_constraints,
        shape.num_io,
        dims,
        dims.srs_len().trailing_zeros()
    );
    assert!(dims.srs_len() <= 1 << 20);

    let t = Instant::now();
    let srs = match std::env::var("ZENO_PTAU") {
        Ok(path) => {
            let bytes = std::fs::read(path).expect("readable .ptau");
            Srs::from_ptau(&bytes, dims.srs_len(), &mut rng).expect("valid .ptau")
        }
        Err(_) => Srs::insecure_for_testing(
            dims.srs_len(),
            &mut ark_std::rand::rngs::StdRng::seed_from_u64(7),
        ),
    };
    println!("reference string: {:.1} s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let (evm, key) = EvmParams::setup_universal(shape, b"zeno-llull/closing", &srs);
    drop(srs);
    println!(
        "preprocessing (circuit key): {:.1} s",
        t.elapsed().as_secs_f64()
    );

    let r_w = Fr::rand(&mut rng);
    let instance = RelaxedR1CSInstance {
        comm_e: G1::zero(),
        u: Fr::from(1u64),
        comm_w: evm.ck.commit(&w, r_w),
        x,
    };
    let witness = RelaxedR1CSWitness {
        e: vec![Fr::zero(); evm.shape.num_constraints],
        r_e: Fr::zero(),
        w,
        r_w,
    };
    let t = Instant::now();
    let proof = universal::prove(&evm, &key, &instance, &witness);
    println!(
        "prove: {:.1} s, proof {} bytes",
        t.elapsed().as_secs_f64(),
        proof.size_bytes()
    );
    let t = Instant::now();
    assert!(universal::verify(&evm, &key, &instance, &proof));
    println!("verify (native): {:.3} s", t.elapsed().as_secs_f64());
    println!("peak memory: {} MiB", peak_rss_mib());
}
