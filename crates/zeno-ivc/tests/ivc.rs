//! End-to-end IVC tests on both supported curve cycles.

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig};
use ark_ff::{One, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use zeno_ivc::{CubicStep, IvcError, IvcParams, ZenoAccumulator};

fn run_ivc<P1, P2>(steps: u64) -> (IvcParams<P1, P2>, ZenoAccumulator<P1, P2>)
where
    P1: SWCurveConfig<BaseField = <P2 as CurveConfig>::ScalarField>,
    P2: SWCurveConfig<BaseField = <P1 as CurveConfig>::ScalarField>,
    P1::BaseField: PrimeField + Absorb,
    P2::BaseField: PrimeField + Absorb,
{
    let mut rng = test_rng();
    let step = CubicStep { rounds: 8 };
    let params = IvcParams::<P1, P2>::setup(&step, b"test").unwrap();
    let z0 = P1::ScalarField::from(3u64);
    let mut acc = ZenoAccumulator::new(&params, vec![z0]).unwrap();
    assert!(matches!(acc.verify(&params), Err(IvcError::NoSteps)));

    let mut expected = z0;
    let mut sizes = Vec::new();
    for _ in 0..steps {
        acc.prove_step(&params, &step, &mut rng).unwrap();
        expected = step.eval(expected);
        acc.verify(&params).unwrap();
        assert_eq!(acc.zi, vec![expected]);
        sizes.push(acc.compressed_size());
    }
    assert_eq!(acc.i, steps);
    // Zeno invariant: the whole proof state is constant-size in the step count.
    assert!(sizes.windows(2).all(|p| p[0] == p[1]));
    (params, acc)
}

#[test]
fn ivc_pallas_vesta() {
    run_ivc::<ark_pallas::PallasConfig, ark_vesta::VestaConfig>(6);
}

#[test]
fn ivc_bn254_grumpkin() {
    run_ivc::<ark_bn254::g1::Config, ark_grumpkin::GrumpkinConfig>(4);
}

#[test]
fn forged_claims_are_rejected() {
    type P1 = ark_pallas::PallasConfig;
    type P2 = ark_vesta::VestaConfig;
    let (params, acc) = run_ivc::<P1, P2>(3);
    let one = ark_pallas::Fr::one();

    // Wrong output, wrong input, wrong step count.
    let mut bad = acc.clone();
    bad.zi[0] += one;
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let mut bad = acc.clone();
    bad.z0[0] += one;
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let mut bad = acc.clone();
    bad.i += 1;
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));

    // Tampered accumulators and witnesses.
    let mut bad = acc.clone();
    bad.acc1.0.u += one;
    assert!(bad.verify(&params).is_err());
    let mut bad = acc.clone();
    bad.acc2.1.w[0] += ark_vesta::Fr::one();
    assert!(bad.verify(&params).is_err());
    let mut bad = acc.clone();
    bad.last2.1.w[0] += ark_vesta::Fr::one();
    assert!(bad.verify(&params).is_err());
    let mut bad = acc.clone();
    bad.acc1.1.e[0] += one;
    assert!(bad.verify(&params).is_err());

    // Parameters for a different step function do not accept the proof.
    let other = IvcParams::<P1, P2>::setup(&CubicStep { rounds: 9 }, b"test").unwrap();
    assert!(acc.verify(&other).is_err());
    let other = IvcParams::<P1, P2>::setup(&CubicStep { rounds: 8 }, b"other-label").unwrap();
    assert!(acc.verify(&other).is_err());
}

#[test]
fn a_cheating_step_cannot_be_folded_in() {
    // A prover that lies about z_{i+1} mid-chain ends with an invalid proof.
    type P1 = ark_pallas::PallasConfig;
    type P2 = ark_vesta::VestaConfig;
    let mut rng = test_rng();
    let step = CubicStep { rounds: 4 };
    let params = IvcParams::<P1, P2>::setup(&step, b"test").unwrap();
    let mut acc = ZenoAccumulator::new(&params, vec![ark_pallas::Fr::from(2u64)]).unwrap();
    acc.prove_step(&params, &step, &mut rng).unwrap();
    acc.zi[0] += ark_pallas::Fr::one();
    acc.prove_step(&params, &step, &mut rng).unwrap();
    acc.prove_step(&params, &step, &mut rng).unwrap();
    assert!(acc.verify(&params).is_err());
}
