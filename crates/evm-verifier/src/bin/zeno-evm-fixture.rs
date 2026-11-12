//! Emits a deterministic end-to-end scenario for the contract tests as JSON:
//! calldata for every call and the accumulator the prover expects on-chain
//! after each of them, plus the off-chain decider's verdict.
//!
//! Usage: `zeno-evm-fixture [--session 0x<64 hex>] [--steps N] [--rounds N]
//!        [--mode transparent|onchain|universal] [--ptau FILE]`
//!
//! `onchain` loads the KZG reference string from a small ceremony-format
//! `.ptau` file, uses locally generated (test-only) Groth16 decider keys and emits the `finalizeWithProof` flow.

use ark_bn254::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use evm_verifier::{
    abi, kzg::Srs, point_words, universal, verify_final, word, DeciderKeys, EvmParams,
    OnChainFolder, Word,
};
use llull_folder::{core_r1cs::RelaxedR1CSInstance, demo_circuit::CubicChain};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn acc_json(acc: &RelaxedR1CSInstance<ark_bn254::G1Projective>) -> String {
    let mut words: Vec<Word> = Vec::new();
    words.extend(point_words(&acc.comm_e));
    words.push(word(&acc.u));
    words.extend(point_words(&acc.comm_w));
    words.extend(acc.x.iter().map(word));
    let items: Vec<String> = words.iter().map(|w| format!("\"{}\"", hex(w))).collect();
    format!("[{}]", items.join(","))
}

fn main() {
    let mut session = [0u8; 32];
    let mut steps = 5usize;
    let mut onchain = false;
    let mut universal_mode = false;
    let mut rounds_override: Option<usize> = None;
    let mut ptau_path: Option<String> = None;
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let value = argv.next().expect("missing value");
        match flag.as_str() {
            "--session" => {
                let v = value.trim_start_matches("0x");
                assert_eq!(v.len(), 64, "session id must be 32 bytes");
                for (i, byte) in session.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&v[2 * i..2 * i + 2], 16).expect("hex");
                }
            }
            "--steps" => steps = value.parse().expect("number"),
            "--rounds" => rounds_override = Some(value.parse().expect("number")),
            "--ptau" => ptau_path = Some(value),
            "--mode" => {
                onchain = value == "onchain";
                universal_mode = value == "universal";
            }
            other => panic!("unknown option {other}"),
        }
    }

    // Fixed seed: the scenario must be reproducible across invocations.
    let mut rng = StdRng::seed_from_u64(0x5eed);
    // The universal mode commits to the matrices too; a smaller circuit
    // keeps it within the 128 powers of the test ceremony file.
    let rounds = rounds_override.unwrap_or(if universal_mode { 8 } else { 64 });
    let z0 = Fr::from(3u64);
    let (shape, _, _) = CubicChain { z_in: z0, rounds }
        .synthesize()
        .expect("synthesis");
    // A real ceremony-format file (snarkjs, power 7, two contributions).
    const PTAU: &[u8] = include_bytes!("../../fixtures/pot7_test.ptau");
    let label = b"zeno-llull/evm-fixture";
    let mut circuit_key = None;
    let params = if universal_mode {
        let len = universal::Dims::of(&shape).srs_len();
        // The test ceremony file has 128 powers; larger circuits (gas
        // scaling measurements only) fall back to a locally sampled string.
        let srs = if let Some(path) = &ptau_path {
            // A public ceremony file, e.g. Perpetual Powers of Tau.
            let bytes = std::fs::read(path).expect("readable .ptau file");
            Srs::from_ptau(&bytes, len, &mut rng).expect("valid .ptau")
        } else if len <= 128 {
            Srs::from_ptau(PTAU, len, &mut rng).expect("valid .ptau")
        } else {
            Srs::insecure_for_testing(len, &mut rng)
        };
        let (params, key) = EvmParams::setup_universal(shape, label, &srs);
        circuit_key = Some(key);
        params
    } else if onchain {
        let len = shape
            .num_vars
            .max(shape.num_constraints)
            .next_power_of_two();
        let srs = Srs::from_ptau(PTAU, len, &mut rng).expect("valid .ptau");
        EvmParams::setup_kzg(shape, label, &srs)
    } else {
        EvmParams::setup(shape, label)
    };
    let mut folder = OnChainFolder::new(&params);

    let mut state = z0;
    let mut step_items = Vec::new();
    for _ in 0..steps {
        let circuit = CubicChain {
            z_in: state,
            rounds,
        };
        let (_, w, x) = circuit.synthesize().expect("synthesis");
        state = circuit.output();
        let proof = folder.fold_step(&params, w, x, &mut rng).expect("fold");
        step_items.push(format!(
            "{{\"calldata\":\"{}\",\"accumulator\":{},\"state\":\"{}\"}}",
            hex(&abi::verify_folded_proof(&session, &proof)),
            acc_json(&folder.acc),
            hex(&word(&state))
        ));
    }
    let open = hex(&abi::open_session(&params.vk, &[z0]));
    let get = hex(&abi::get_accumulator(&session));
    if universal_mode {
        // No keys to generate: the circuit key is a public commitment.
        let key = circuit_key.expect("universal mode");
        let key_words = abi::universal_key(&params, &key);
        let (mask, final_acc, proof) = folder
            .finalize_universal(&params, &key, &mut rng)
            .expect("universal proof");
        let proof_words = proof.words();
        println!(
            "{{\"vk\":\"{}\",\"open\":\"{open}\",\"announce\":\"{}\",\"steps\":[{}],\"finalizeUniversal\":{{\"calldata\":\"{}\",\"accumulator\":{},\"proofBytes\":{},\"proofWords\":{},\"keyWords\":{}}},\"getAccumulator\":\"{get}\"}}",
            hex(&params.vk),
            hex(&abi::announce_circuit(&key_words)),
            step_items.join(","),
            hex(&abi::finalize_universal(&session, &mask, &key_words, &proof_words)),
            acc_json(&final_acc),
            32 * proof_words.len(),
            proof_words.len(),
            key_words.len(),
        );
        return;
    }
    if onchain {
        let keys = DeciderKeys::insecure_for_testing(&params, &mut rng).expect("decider keys");
        let key = abi::decider_key(&params, &keys.vk);
        let (mask, final_acc, proof) = folder
            .finalize_onchain(&params, &keys, &mut rng)
            .expect("decider proof");
        let proof_bytes = 32 * abi::decider_proof_words(&proof).len();
        println!(
            "{{\"vk\":\"{}\",\"open\":\"{open}\",\"register\":\"{}\",\"steps\":[{}],\"finalizeWithProof\":{{\"calldata\":\"{}\",\"accumulator\":{},\"proofBytes\":{proof_bytes}}},\"getAccumulator\":\"{get}\"}}",
            hex(&params.vk),
            hex(&abi::register_circuit(&params.vk, &key)),
            step_items.join(","),
            hex(&abi::finalize_with_proof(&session, &mask, &proof, &key)),
            acc_json(&final_acc),
        );
        return;
    }

    let (mask, final_acc, snark) = folder.finalize(&params, &mut rng).expect("finalize");
    let snark_ok = verify_final(&params, &final_acc, &snark);
    // The decider must reject any other accumulator.
    let mut other = final_acc.clone();
    other.u += Fr::from(1u64);
    let snark_rejects_other = !verify_final(&params, &other, &snark);

    println!(
        "{{\"vk\":\"{}\",\"open\":\"{open}\",\"steps\":[{}],\"finalize\":{{\"calldata\":\"{}\",\"accumulator\":{}}},\"getAccumulator\":\"{get}\",\"deciderAccepts\":{},\"deciderRejectsOther\":{}}}",
        hex(&params.vk),
        step_items.join(","),
        hex(&abi::finalize(&session, &mask)),
        acc_json(&final_acc),
        snark_ok,
        snark_rejects_other
    );
}
