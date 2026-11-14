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
