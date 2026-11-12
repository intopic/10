//! The recursive IVC decided end to end: the Rust mirror of
//! `finalizeRecursive`, with forgeries.
//!
//! Heavy (two universal proofs over a 2^20-power reference string): run with
//! `cargo test --release -p evm-verifier --test recursive -- --ignored --nocapture`,
//! with `ZENO_PTAU` pointing at a 2^20 Powers-of-Tau file or, without it, a
//! locally sampled test SRS.

use ark_bn254::{Fq, Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_ff::One;
use ark_std::{rand::SeedableRng, test_rng};
use evm_verifier::{
    kzg::Srs,
    recursive::{self, RecursiveParams},
};
use std::time::Instant;
use zeno_ivc::{cyclefold::CycleFoldAccumulator, CubicStep};

/// A named change to an otherwise valid proof.
type Forgery = Box<dyn Fn(&mut recursive::RecursiveProof)>;

fn srs(n: usize) -> Srs {
    match std::env::var("ZENO_PTAU") {
        Ok(path) => {
            let bytes = std::fs::read(path).expect("readable .ptau");
            Srs::from_ptau(&bytes, n, &mut test_rng()).expect("valid .ptau")
        }
        Err(_) => Srs::insecure_for_testing(n, &mut ark_std::rand::rngs::StdRng::seed_from_u64(7)),
    }
}

#[test]
#[ignore = "needs a 2^20-power reference string; run explicitly"]
fn recursive_ivc_is_decided_and_forgeries_are_rejected() {
    let mut rng = test_rng();
    let step = CubicStep { rounds: 2 };
    let t = Instant::now();
    let srs = srs(1 << 20);
    let params = RecursiveParams::setup(&step, b"recursive-test", &srs).unwrap();
    drop(srs);
    println!(
        "setup: {:.1} s; primary circuit {} constraints (dims {:?}), closing {} (dims {:?}), CycleFold data {} bytes",
        t.elapsed().as_secs_f64(),
        params.primary.shape.num_constraints,
        params.primary_key.dims,
        params.closing.shape.num_constraints,
        params.closing_key.dims,
        params.cf_code.len()
    );

    let mut ivc = CycleFoldAccumulator::new(&params.ivc, vec![Fr::from(3u64)]).unwrap();
    let mut z = Fr::from(3u64);
    for _ in 0..3 {
        ivc.prove_step(&params.ivc, &step, &mut rng).unwrap();
        z = step.eval(z);
    }
    let t = Instant::now();
    let proof = recursive::prove(&params, &ivc, &mut rng).unwrap();
    println!("prove: {:.1} s", t.elapsed().as_secs_f64());
    assert_eq!(proof.zi, vec![z]);
    let t = Instant::now();
    assert!(recursive::verify(&params, &proof));
    println!("verify (native): {:.3} s", t.elapsed().as_secs_f64());

    // Forgeries: the claim, every accumulator, every part of the CycleFold
    // argument and both universal proofs.
    let forged: Vec<(&str, Forgery)> = vec![
        ("z_i", Box::new(|p| p.zi[0] += Fr::one())),
        ("z_0", Box::new(|p| p.z0[0] += Fr::one())),
        ("i", Box::new(|p| p.i += 1)),
        ("U.comm_W", Box::new(|p| p.acc.comm_w += G1::generator())),
        ("U.u", Box::new(|p| p.acc.u += Fr::one())),
        ("u.x", Box::new(|p| p.last.x[0] += Fr::one())),
        ("comm_T", Box::new(|p| p.comm_t += G1::generator())),
        ("mask", Box::new(|p| p.mask.u += Fr::one())),
        (
            "U_cf row",
            Box::new(|p| p.cf_acc.comm_e[3] += ark_grumpkin::Projective::generator()),
        ),
        ("U_cf.u", Box::new(|p| p.cf_acc.u += Fq::one())),
        ("U_cf.x", Box::new(|p| p.cf_acc.x[2] += Fq::one())),
        ("outer sum-check", Box::new(|p| p.cf.outer[4] += Fq::one())),
        ("claims", Box::new(|p| p.cf.claims[3] += Fq::one())),
        ("inner sum-check", Box::new(|p| p.cf.inner[1] += Fq::one())),
        ("W(r_y)", Box::new(|p| p.cf.v_w += Fq::one())),
        ("e'", Box::new(|p| p.cf.e_row[7] += Fq::one())),
        ("w'", Box::new(|p| p.cf.w_row[100] += Fq::one())),
        (
            "closing comm_W",
            Box::new(|p| p.closing_comm_w += G1::generator()),
        ),
        (
            "primary proof",
            Box::new(|p| p.primary_proof.claims[0] += Fr::one()),
        ),
        (
            "closing proof",
            Box::new(|p| p.closing_proof.v_w += Fr::one()),
        ),
    ];
    for (name, forge) in &forged {
        let mut bad = proof.clone();
        forge(&mut bad);
        assert!(
            !recursive::verify(&params, &bad),
            "forged {name} was accepted"
        );
    }
}
