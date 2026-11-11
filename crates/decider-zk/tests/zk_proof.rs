use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;
use decider_zk::ZkIvcProof;
use zeno_ivc::{CubicStep, IvcError, IvcParams, ZenoAccumulator};

type P1 = ark_pallas::PallasConfig;
type P2 = ark_vesta::VestaConfig;

fn setup(steps: usize) -> (IvcParams<P1, P2>, ZenoAccumulator<P1, P2>) {
    let mut rng = test_rng();
    let step = CubicStep { rounds: 8 };
    let params = IvcParams::<P1, P2>::setup(&step, b"zk-test").unwrap();
    let mut acc = ZenoAccumulator::new(&params, vec![ark_pallas::Fr::from(3u64)]).unwrap();
    for _ in 0..steps {
        acc.prove_step(&params, &step, &mut rng).unwrap();
    }
    (params, acc)
}

#[test]
fn zk_proof_verifies_and_round_trips() {
    let mut rng = test_rng();
    for steps in [1, 4] {
        let (params, acc) = setup(steps);
        let proof = ZkIvcProof::prove(&params, &acc, &mut rng).unwrap();
        proof.verify(&params).unwrap();

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let decoded = ZkIvcProof::<P1, P2>::deserialize_compressed(&bytes[..]).unwrap();
        assert!(decoded == proof);
        decoded.verify(&params).unwrap();
    }
}

#[test]
fn zk_proof_hides_the_accumulated_witness() {
    let mut rng = test_rng();
    let (params, acc) = setup(3);
    let a = ZkIvcProof::prove(&params, &acc, &mut rng).unwrap();
    let b = ZkIvcProof::prove(&params, &acc, &mut rng).unwrap();
    // No coordinate of the opened witness equals the real accumulated one,
    // and two proofs of the same statement share no witness coordinate.
    assert!(a.w1.w.iter().zip(&acc.acc1.1.w).all(|(x, y)| x != y));
    assert!(a.w1.w.iter().zip(&b.w1.w).all(|(x, y)| x != y));
    assert!(a.w2.w.iter().zip(&b.w2.w).all(|(x, y)| x != y));
    assert_ne!(a.w1.r_w, b.w1.r_w);
    assert_ne!(a.w1.r_e, b.w1.r_e);
    a.verify(&params).unwrap();
    b.verify(&params).unwrap();
}

#[test]
fn zk_proof_rejects_forgeries() {
    let mut rng = test_rng();
    let (params, acc) = setup(2);
    assert!(matches!(
        ZkIvcProof::prove(
            &params,
            &ZenoAccumulator::new(&params, acc.z0.clone()).unwrap(),
            &mut rng
        ),
        Err(IvcError::NoSteps)
    ));
    let proof = ZkIvcProof::prove(&params, &acc, &mut rng).unwrap();
    let one = ark_pallas::Fr::one();

    let mut bad = proof.clone();
    bad.statement.zi[0] += one;
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let mut bad = proof.clone();
    bad.statement.i += 1;
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let mut bad = proof.clone();
    bad.w1.w[0] += one;
    assert!(bad.verify(&params).is_err());
    let mut bad = proof.clone();
    bad.w2.e[0] += ark_vesta::Fr::one();
    assert!(bad.verify(&params).is_err());
    let mut bad = proof.clone();
    bad.statement.mask1.u += one;
    assert!(bad.verify(&params).is_err());
    let mut bad = proof.clone();
    bad.statement.comm_t2 += params.pp2.ck.h;
    assert!(bad.verify(&params).is_err());
    let mut bad = proof.clone();
    bad.statement.comm_t_last += params.pp2.ck.h;
    assert!(bad.verify(&params).is_err());
    let mut bad = proof.clone();
    bad.statement.acc1.u += one;
    assert!(bad.verify(&params).is_err());

    // A proof built from a corrupted prover state does not verify.
    let mut corrupt = acc.clone();
    corrupt.acc1.1.w[0] += one;
    let bad = ZkIvcProof::prove(&params, &corrupt, &mut rng).unwrap();
    assert!(bad.verify(&params).is_err());
}

#[test]
fn compressed_proof_is_succinct_and_sound() {
    use decider_zk::CompressedIvcProof;
    let mut rng = test_rng();
    let (params, acc) = setup(3);
    let proof = CompressedIvcProof::prove(&params, &acc, &mut rng).unwrap();
    proof.verify(&params).unwrap();

    // Kilobytes instead of megabytes, and it survives serialization.
    let zk_size = ZkIvcProof::prove(&params, &acc, &mut rng)
        .unwrap()
        .compressed_size();
    let size = proof.compressed_size();
    assert!(size < 16 * 1024, "compressed proof is {size} bytes");
    assert!(size * 50 < zk_size);
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).unwrap();
    let decoded = CompressedIvcProof::<P1, P2>::deserialize_compressed(&bytes[..]).unwrap();
    assert!(decoded == proof);
    decoded.verify(&params).unwrap();

    // Every component of the proof is checked.
    let one = ark_pallas::Fr::one();
    let v_one = ark_vesta::Fr::one();
    let mut bad = proof.clone();
    bad.statement.zi[0] += one;
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let reject = |mutate: &dyn Fn(&mut CompressedIvcProof<P1, P2>)| {
        let mut bad = proof.clone();
        mutate(&mut bad);
        assert!(bad != proof);
        assert!(matches!(bad.verify(&params), Err(IvcError::InvalidSnark)));
    };
    reject(&|bad| bad.snark1.r_w += one);
    reject(&|bad| bad.snark1.r_e += one);
    reject(&|bad| bad.snark1.outer[0] += one);
    reject(&|bad| {
        let k = bad.snark1.outer.len() - 1;
        bad.snark1.outer[k] += one;
    });
    reject(&|bad| bad.snark1.claims[3] += one);
    reject(&|bad| bad.snark1.inner[1] += one);
    reject(&|bad| bad.snark1.eval_w += one);
    reject(&|bad| bad.snark1.ipa_e.a += one);
    reject(&|bad| bad.snark1.ipa_w.l[0] += params.pp1.ck.h);
    reject(&|bad| {
        bad.snark1.ipa_w.r.pop();
    });
    reject(&|bad| {
        bad.snark1.outer.pop();
    });
    reject(&|bad| bad.snark2.claims[0] += v_one);
    reject(&|bad| bad.snark2.ipa_e.r[2] += params.pp2.ck.h);
    reject(&|bad| bad.snark2.eval_w += v_one);
    reject(&|bad| bad.statement.mask1.u += one);
    reject(&|bad| bad.statement.comm_t2 += params.pp2.ck.h);

    // A corrupted prover state cannot be compressed into a valid proof.
    let mut corrupt = acc.clone();
    corrupt.acc1.1.w[5] += one;
    let bad = CompressedIvcProof::prove(&params, &corrupt, &mut rng).unwrap();
    assert!(matches!(bad.verify(&params), Err(IvcError::InvalidSnark)));
    let mut corrupt = acc.clone();
    corrupt.acc2.1.e[3] += v_one;
    let bad = CompressedIvcProof::prove(&params, &corrupt, &mut rng).unwrap();
    assert!(matches!(bad.verify(&params), Err(IvcError::InvalidSnark)));
}
