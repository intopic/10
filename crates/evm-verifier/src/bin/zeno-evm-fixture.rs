//! Emits a deterministic end-to-end scenario for the contract tests as JSON:
//! calldata for every call and the accumulator the prover expects on-chain
//! after each of them, plus the off-chain decider's verdict.
//!
//! Usage: `zeno-evm-fixture [--session 0x<64 hex>] [--steps N]`

use ark_bn254::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use evm_verifier::{abi, point_words, verify_final, word, EvmParams, OnChainFolder, Word};
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
            other => panic!("unknown option {other}"),
        }
    }

    // Fixed seed: the scenario must be reproducible across invocations.
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let rounds = 64;
    let z0 = Fr::from(3u64);
    let (shape, _, _) = CubicChain { z_in: z0, rounds }
        .synthesize()
        .expect("synthesis");
    let params = EvmParams::setup(shape, b"zeno-llull/evm-fixture");
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
    let (mask, final_acc, snark) = folder.finalize(&params, &mut rng).expect("finalize");
    let snark_ok = verify_final(&params, &final_acc, &snark);
    // The decider must reject any other accumulator.
    let mut other = final_acc.clone();
    other.u += Fr::from(1u64);
    let snark_rejects_other = !verify_final(&params, &other, &snark);

    println!(
        "{{\"vk\":\"{}\",\"open\":\"{}\",\"steps\":[{}],\"finalize\":{{\"calldata\":\"{}\",\"accumulator\":{}}},\"getAccumulator\":\"{}\",\"deciderAccepts\":{},\"deciderRejectsOther\":{}}}",
        hex(&params.vk),
        hex(&abi::open_session(&params.vk, &[z0])),
        step_items.join(","),
        hex(&abi::finalize(&session, &mask)),
        acc_json(&final_acc),
        hex(&abi::get_accumulator(&session)),
        snark_ok,
        snark_rejects_other
    );
}
