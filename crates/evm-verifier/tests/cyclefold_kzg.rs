//! The CycleFold IVC with primary commitments over the powers of a KZG
//! reference string: the commitment layout the universal EVM decider opens.

use ark_bn254::Fr;
use ark_std::test_rng;
use evm_verifier::kzg::Srs;
use zeno_ivc::{
    cyclefold::{CycleFoldAccumulator, CycleFoldParams},
    CubicStep,
};

#[test]
fn cyclefold_ivc_with_kzg_primary_commitments() {
    let mut rng = test_rng();
    let step = CubicStep { rounds: 4 };
    let srs = Srs::insecure_for_testing(1 << 16, &mut rng);
    let params =
        CycleFoldParams::<ark_bn254::g1::Config, ark_grumpkin::GrumpkinConfig>::setup_with_key(
            &step,
            b"kzg-test",
            1024,
            |len| srs.commitment_key(b"kzg-test/primary", len),
        )
        .unwrap();
    assert_eq!(params.ck.gens[..8], srs.powers_g1[..8]);

    let mut acc = CycleFoldAccumulator::new(&params, vec![Fr::from(7u64)]).unwrap();
    let mut z = Fr::from(7u64);
    for _ in 0..3 {
        acc.prove_step(&params, &step, &mut rng).unwrap();
        z = step.eval(z);
        acc.verify(&params).unwrap();
    }
    assert_eq!(acc.zi, vec![z]);
}
