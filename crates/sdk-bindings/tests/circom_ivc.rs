//! IVC over a real Circom-compiled step circuit (`fixtures/step.circom`):
//! `z_out = z_in³ + z_in + secret`, with witnesses from Circom's generator.

use sdk_bindings::{
    circom::{parse_wtns, CircomR1cs, SdkError},
    CircomIvc, CircomParams, Fr,
};

const R1CS: &[u8] = include_bytes!("../fixtures/step.r1cs");
const WTNS: [&[u8]; 3] = [
    include_bytes!("../fixtures/step0.wtns"),
    include_bytes!("../fixtures/step1.wtns"),
    include_bytes!("../fixtures/step2.wtns"),
];

#[test]
fn parses_circom_files() {
    let r1cs = CircomR1cs::<Fr>::parse(R1CS).unwrap();
    assert_eq!(
        (
            r1cs.num_wires,
            r1cs.num_outputs,
            r1cs.num_public_inputs,
            r1cs.num_private_inputs
        ),
        (5, 1, 1, 1)
    );
    assert_eq!(r1cs.a.len(), 2);
    let step = r1cs.step(None);
    for wtns in WTNS {
        let w = parse_wtns::<Fr>(wtns).unwrap();
        assert_eq!(w.len(), 5);
        assert_eq!(step.first_unsatisfied(&w), None);
    }
    // step_in = 3, secret = 7  →  step_out = 27 + 3 + 7.
    let w = parse_wtns::<Fr>(WTNS[0]).unwrap();
    assert_eq!((w[2], w[1]), (Fr::from(3u64), Fr::from(37u64)));

    // Wrong field, truncation and garbage are rejected, never panicking.
    assert!(matches!(
        CircomR1cs::<ark_grumpkin::Fr>::parse(R1CS),
        Err(SdkError::WrongField)
    ));
    for cut in 0..R1CS.len() {
        assert!(CircomR1cs::<Fr>::parse(&R1CS[..cut]).is_err());
    }
    for cut in 0..WTNS[0].len() {
        assert!(parse_wtns::<Fr>(&WTNS[0][..cut]).is_err());
    }
    assert!(parse_wtns::<Fr>(R1CS).is_err());
}

#[test]
fn circom_ivc_end_to_end_with_zk_proof() {
    let mut rng = rand::rngs::OsRng;
    let mut ivc = CircomIvc::new(R1CS, vec![Fr::from(3u64)]).unwrap();

    // A witness for a later step does not continue from the current state.
    assert!(matches!(
        ivc.prove_step(WTNS[1], &mut rng),
        Err(SdkError::StateMismatch)
    ));
    for wtns in WTNS {
        ivc.prove_step(wtns, &mut rng).unwrap();
        ivc.verify().unwrap();
    }
    assert_eq!(ivc.acc.i, 3);
    assert_eq!(ivc.acc.zi, vec![Fr::from(130308420719099u64)]);

    // A third party verifies the zero-knowledge proof from the circuit alone.
    let proof = ivc.finalize(&mut rng).unwrap();
    let verifier = CircomParams::setup(R1CS).unwrap();
    let statement = verifier.verify_proof(&proof).unwrap();
    assert_eq!(statement.statement.i, 3);
    assert_eq!(statement.statement.z0, vec![Fr::from(3u64)]);
    assert_eq!(statement.statement.zi, ivc.acc.zi);

    // Corrupted or truncated proofs are rejected.
    let mut bad = proof.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    assert!(verifier.verify_proof(&bad).is_err());
    assert!(verifier.verify_proof(&proof[..proof.len() - 1]).is_err());
    assert!(verifier.verify_proof(&[]).is_err());
}

#[test]
fn tampered_circom_witness_is_rejected() {
    let mut rng = rand::rngs::OsRng;
    let mut ivc = CircomIvc::new(R1CS, vec![Fr::from(3u64)]).unwrap();
    // Flip one byte of the output wire: the witness no longer satisfies R1CS.
    let mut bad = WTNS[0].to_vec();
    let last = bad.len() - 4 * 32;
    bad[last] ^= 1;
    assert!(matches!(
        ivc.prove_step(&bad, &mut rng),
        Err(SdkError::UnsatisfiedWitness { .. })
    ));
    assert_eq!(ivc.acc.i, 0);
}
