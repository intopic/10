//! Mode D through the server SDK: a Circom circuit, three steps, one
//! `finalizeRecursive` call (checked by the prover before it is returned).

use sdk_bindings::recursive::{RecursiveCircuit, RecursiveProver, RECURSIVE_POWERS};
use std::sync::Arc;
use zeno_license::{issue, Claims, DEV_PRIVATE_KEY};

const R1CS: &[u8] = include_bytes!("../fixtures/step.r1cs");
const WTNS: [&[u8]; 3] = [
    include_bytes!("../fixtures/step0.wtns"),
    include_bytes!("../fixtures/step1.wtns"),
    include_bytes!("../fixtures/step2.wtns"),
];

#[test]
#[ignore = "needs a 2^20-power reference string (ZENO_PTAU) and about 2 GB; run explicitly"]
fn mode_d_through_the_server_sdk() {
    let ptau = std::fs::read(std::env::var("ZENO_PTAU").expect("ZENO_PTAU")).unwrap();
    let t = std::time::Instant::now();
    let circuit = Arc::new(RecursiveCircuit::from_files(R1CS, &ptau).unwrap());
    drop(ptau);
    println!("circuit prepared in {:.1} s", t.elapsed().as_secs_f64());
    let license = issue(
        &DEV_PRIVATE_KEY,
        &Claims {
            customer: "tests".into(),
            plan: "dev".into(),
            expires_at: sdk_bindings::api::unix_now() + 3600,
            max_steps: Some(3),
        },
    )
    .unwrap();

    let mut p = RecursiveProver::new(&license, circuit.clone(), &["3".to_string()]).unwrap();
    assert!(p.finalize().is_err(), "nothing folded yet");
    assert!(
        p.prove_step(WTNS[1]).is_err(),
        "a witness for another state"
    );
    for wtns in WTNS {
        p.prove_step(wtns).unwrap();
    }
    assert!(
        p.prove_step(WTNS[0]).is_err(),
        "the license quota is 3 steps"
    );
    let t = std::time::Instant::now();
    let call = p.finalize().unwrap();
    println!(
        "finalize: {:.1} s, {} bytes of calldata",
        t.elapsed().as_secs_f64(),
        call.calldata.len()
    );
    assert_eq!(
        (call.steps, call.zi.clone()),
        (3, vec!["130308420719099".to_string()])
    );
    assert_eq!(call.system_id, circuit.system_id());
    let selector = evm_verifier::abi::selector(
        "finalizeRecursive(uint256[],uint256[],uint256[],uint256[],uint256[])",
    );
    assert_eq!(&call.calldata[..4], &selector);
    assert!(call.to_json().contains("\"finalizeRecursive\":\"0x"));
    assert_eq!(RECURSIVE_POWERS, 1 << 20);
}
