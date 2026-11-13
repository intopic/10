//! Speed of the prover's MSM against arkworks; run with
//! `cargo test --release -p llull-folder --test msm_speed -- --ignored --nocapture`.

use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup, VariableBaseMSM,
};
use ark_ff::UniformRand;
use ark_std::{rand::Rng, test_rng};
use std::time::Instant;

fn bench<P: SWCurveConfig>(name: &str, n: usize, small: bool) {
    let mut rng = test_rng();
    let g = Projective::<P>::rand(&mut rng);
    let mut acc = g;
    let proj: Vec<Projective<P>> = (0..n)
        .map(|_| {
            acc += g;
            acc
        })
        .collect();
    let bases: Vec<Affine<P>> = Projective::normalize_batch(&proj);
    let scalars: Vec<P::ScalarField> = (0..n)
        .map(|_| {
            if small {
                P::ScalarField::from(rng.gen_range(2u64..1 << 20))
            } else {
                P::ScalarField::rand(&mut rng)
            }
        })
        .collect();
    let reps = if n > 1 << 19 { 2 } else { 5 };
    let time = |f: &dyn Fn() -> Projective<P>| {
        let t = Instant::now();
        for _ in 0..reps {
            let _ = std::hint::black_box(f());
        }
        t.elapsed().as_secs_f64() * 1000.0 / reps as f64
    };
    assert_eq!(
        llull_folder::msm::msm(&bases, &scalars),
        Projective::<P>::msm_unchecked(&bases, &scalars)
    );
    let ta = time(&|| Projective::<P>::msm_unchecked(&bases, &scalars));
    let tb = time(&|| llull_folder::msm::msm(&bases, &scalars));
    println!(
        "{name:7} n = {n:8} {}: arkworks {ta:8.1} ms, batch-affine {tb:8.1} ms, {:.2}×",
        if small { "small " } else { "random" },
        ta / tb
    );
}

#[test]
#[ignore = "timing only"]
fn msm_speed() {
    for small in [false, true] {
        bench::<ark_vesta::VestaConfig>("vesta", 11_200, small);
        bench::<ark_pallas::PallasConfig>("pallas", 77_000, small);
        bench::<ark_bn254::g1::Config>("bn254", 66_800, small);
    }
    bench::<ark_bn254::g1::Config>("bn254", 1 << 18, false);
    bench::<ark_bn254::g1::Config>("bn254", 1 << 20, false);
}
