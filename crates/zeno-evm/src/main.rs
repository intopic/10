//! `zeno-evm` — proves a Circom step circuit for the on-chain verifiers.
//!
//! The same `.r1cs` / `.wtns` files as the SDK,
//! turned into calldata for the contracts:
//!
//! ```text
//! zeno-evm key       --r1cs STEP.r1cs --ptau FILE.ptau
//! zeno-evm universal --r1cs STEP.r1cs --ptau FILE.ptau --z0 3[,5…] --session 0x<32 bytes>
//!                    --wtns STEP0.wtns STEP1.wtns …
//! zeno-evm recursive --r1cs STEP.r1cs --ptau FILE.ptau --z0 3[,5…]
//!                    --wtns STEP0.wtns STEP1.wtns …
//! zeno-evm trim-ptau --r1cs STEP.r1cs --ptau FILE.ptau --out STEP.ptau
//! ```
//!
//! * `key` — mode B: the circuit's universal key and `vk` (what a session is
//!   opened with), and the `openSession` / `announceCircuit` calldata.
//! * `universal` — mode B: folds every step as the contract will
//!   (`verifyFoldedProofBatch`) and proves the final accumulator for
//!   `finalizeUniversal`. Open the session first with the `vk` of `key`
//!   (the contract returns its id), then pass that id as `--session`.
//! * `trim-ptau` — mode B on devices: the prefix of a ceremony file that
//!   the circuit needs (often a few MB instead of hundreds), with its SHA-256
//!   and the circuit's `vk` to publish next to it. Proving from the trimmed
//!   file gives the same `vk` as from the full one.
//! * `recursive` — mode D: runs the CycleFold IVC over the steps off-chain
//!   and emits one `finalizeRecursive` call (needs a reference string of
//!   2^20 powers, e.g. the public `ppot_0080_20.ptau`).
//!
//! Every witness must continue from the current state (`step_in` = the
//! previous `step_out`, the first one `--z0`) and satisfy the circuit; the
//! tool refuses anything else before proving. The output is one JSON object
//! on stdout. Randomness comes from the operating system: the proofs are
//! zero-knowledge (unlike `zeno-evm-fixture`, a test tool).

use ark_bn254::Fr;
use evm_verifier::{
    abi,
    kzg::Srs,
    recursive::{self, RecursiveParams},
    word, EvmParams, OnChainFolder, Word,
};
use rand::rngs::OsRng;
use sdk_bindings::circom::{parse_wtns, CircomR1cs};
use std::{process::ExitCode, str::FromStr};
use zeno_ivc::cyclefold::CycleFoldAccumulator;

use evm_verifier::{
    CIRCOM_RECURSIVE_LABEL as RECURSIVE_LABEL, CIRCOM_UNIVERSAL_LABEL as UNIVERSAL_LABEL,
};

const USAGE: &str = "\
zeno-evm — Circom step circuits on the EVM verifiers

USAGE:
    zeno-evm key       --r1cs FILE --ptau FILE
    zeno-evm universal --r1cs FILE --ptau FILE --z0 A[,B…] --session 0x<64 hex> --wtns FILE…
    zeno-evm recursive --r1cs FILE --ptau FILE --z0 A[,B…] --wtns FILE…
    zeno-evm trim-ptau --r1cs FILE --ptau FILE --out FILE
";

struct Args {
    command: String,
    r1cs: Vec<u8>,
    ptau: String,
    z0: Vec<Fr>,
    session: Option<Word>,
    wtns: Vec<String>,
    out: Option<String>,
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    let command = argv.next().ok_or("missing command")?;
    let (mut r1cs, mut ptau, mut z0, mut session, mut wtns) =
        (None, None, Vec::new(), None, Vec::new());
    let mut out = None;
    let mut flag: Option<String> = None;
    for arg in argv {
        if arg.starts_with("--") {
            flag = Some(arg);
            continue;
        }
        match flag.as_deref() {
            Some("--r1cs") => r1cs = Some(read(&arg)?),
            Some("--ptau") => ptau = Some(arg),
            Some("--out") => out = Some(arg),
            Some("--z0") => {
                z0 = arg
                    .split(',')
                    .map(|s| {
                        Fr::from_str(s.trim())
                            .map_err(|_| format!("--z0: `{s}` is not a field element"))
                    })
                    .collect::<Result<_, _>>()?
            }
            Some("--session") => {
                let hex = arg.trim_start_matches("0x");
                if hex.len() != 64 {
                    return Err("--session must be 32 bytes of hex".into());
                }
                let mut id = [0u8; 32];
                for (i, byte) in id.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                        .map_err(|_| "--session: not hex")?;
                }
                session = Some(id);
            }
            // `--wtns` takes every following file.
            Some("--wtns") => {
                wtns.push(arg);
                continue;
            }
            Some(other) => return Err(format!("unknown option {other}")),
            None => return Err(format!("unexpected argument {arg}")),
        }
        flag = None;
    }
    Ok(Args {
        command,
        r1cs: r1cs.ok_or("missing --r1cs")?,
        ptau: ptau.ok_or("missing --ptau")?,
        z0,
        session,
        wtns,
        out,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * bytes.len());
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_words(words: &[Word]) -> String {
    let items: Vec<String> = words.iter().map(|w| format!("\"{}\"", hex(w))).collect();
    format!("[{}]", items.join(","))
}

fn strings(z: &[Fr]) -> String {
    let items: Vec<String> = z.iter().map(|f| format!("\"{f}\"")).collect();
    format!("[{}]", items.join(","))
}

fn srs(path: &str, len: usize) -> Result<Srs, String> {
    let bytes = read(path)?;
    Srs::from_ptau(&bytes, len, &mut OsRng).map_err(|e| format!("{path}: {e:?}"))
}

/// The witnesses of the steps, each checked to continue from the state
/// before it and to satisfy the circuit.
fn steps(r1cs: &CircomR1cs<Fr>, z0: &[Fr], paths: &[String]) -> Result<Vec<Vec<Fr>>, String> {
    if paths.is_empty() {
        return Err("no --wtns given".into());
    }
    if z0.len() != r1cs.num_outputs {
        return Err(format!(
            "--z0 has {} elements, the circuit's state has {}",
            z0.len(),
            r1cs.num_outputs
        ));
    }
    let k = r1cs.num_outputs;
    let mut state = z0.to_vec();
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let wires = parse_wtns::<Fr>(&read(path)?).map_err(|e| format!("{path}: {e}"))?;
        let step = r1cs.step(Some(wires));
        let wires = step.assignment.as_ref().expect("just set");
        if wires.len() != r1cs.num_wires {
            return Err(format!(
                "{path}: {} wires, the circuit has {}",
                wires.len(),
                r1cs.num_wires
            ));
        }
        if wires[k + 1..=2 * k] != state[..] {
            return Err(format!("{path}: step_in is not the current state"));
        }
        if let Some(row) = step.first_unsatisfied(wires) {
            return Err(format!("{path}: the witness violates constraint {row}"));
        }
        state = wires[1..=k].to_vec();
        out.push(wires.clone());
    }
    Ok(out)
}

fn key(args: &Args, r1cs: &CircomR1cs<Fr>) -> Result<String, String> {
    let shape = r1cs.folding_shape();
    let srs = srs(
        &args.ptau,
        evm_verifier::universal::Dims::of(&shape).srs_len(),
    )?;
    let (params, key) = EvmParams::setup_universal(shape, UNIVERSAL_LABEL, &srs);
    let key_words = abi::universal_key(&params, &key);
    let mut out = format!(
        "\"vk\":\"{}\",\"keyWords\":{},\"announce\":\"{}\"",
        hex(&params.vk),
        hex_words(&key_words),
        hex(&abi::announce_circuit(&key_words)),
    );
    if !args.z0.is_empty() {
        out.push_str(&format!(
            ",\"open\":\"{}\"",
            hex(&abi::open_session(&params.vk, &args.z0))
        ));
    }
    Ok(format!("{{{out}}}"))
}

fn universal(args: &Args, r1cs: &CircomR1cs<Fr>) -> Result<String, String> {
    let session = args
        .session
        .ok_or("missing --session (open the session first, see `key`)")?;
    let witnesses = steps(r1cs, &args.z0, &args.wtns)?;
    let shape = r1cs.folding_shape();
    let srs = srs(
        &args.ptau,
        evm_verifier::universal::Dims::of(&shape).srs_len(),
    )?;
    let (params, key) = EvmParams::setup_universal(shape, UNIVERSAL_LABEL, &srs);
    drop(srs);
    let mut folder = OnChainFolder::new(&params);
    let mut proofs = Vec::with_capacity(witnesses.len());
    let mut state = args.z0.clone();
    for wires in &witnesses {
        let (w, x) = r1cs.folding_assignment(wires).map_err(|e| e.to_string())?;
        state = x[x.len() / 2..].to_vec();
        proofs.push(
            folder
                .fold_step(&params, w, x, &mut OsRng)
                .map_err(|e| e.to_string())?,
        );
    }
    let steps = folder.steps;
    let (mask, _, proof) = folder
        .finalize_universal(&params, &key, &mut OsRng)
        .map_err(|e| e.to_string())?;
    let key_words = abi::universal_key(&params, &key);
    let proof_words = proof.words();
    let fold_calls: Vec<String> = proofs
        .iter()
        .map(|p| format!("\"{}\"", hex(&abi::verify_folded_proof(&session, p))))
        .collect();
    Ok(format!(
        "{{\"vk\":\"{}\",\"steps\":{steps},\"z0\":{},\"zi\":{},\"open\":\"{}\",\"verifyFoldedProof\":[{}],\"verifyFoldedProofBatch\":\"{}\",\"finalizeUniversal\":\"{}\",\"proofBytes\":{}}}",
        hex(&params.vk),
        strings(&args.z0),
        strings(&state),
        hex(&abi::open_session(&params.vk, &args.z0)),
        fold_calls.join(","),
        hex(&abi::verify_folded_proof_batch(&session, &proofs)),
        hex(&abi::finalize_universal(&session, &mask, &key_words, &proof_words)),
        32 * proof_words.len(),
    ))
}

fn recursive(args: &Args, r1cs: &CircomR1cs<Fr>) -> Result<String, String> {
    let witnesses = steps(r1cs, &args.z0, &args.wtns)?;
    let srs = srs(&args.ptau, 1 << 20)?;
    let params = RecursiveParams::setup(&r1cs.step(None), RECURSIVE_LABEL, &srs)
        .map_err(|e| e.to_string())?;
    drop(srs);
    let mut ivc =
        CycleFoldAccumulator::new(&params.ivc, args.z0.clone()).map_err(|e| e.to_string())?;
    for wires in witnesses {
        ivc.prove_step(&params.ivc, &r1cs.step(Some(wires)), &mut OsRng)
            .map_err(|e| e.to_string())?;
    }
    let proof = recursive::prove(&params, &ivc, &mut OsRng).map_err(|e| e.to_string())?;
    if !recursive::verify(&params, &proof) {
        return Err("the recursive proof does not verify".into());
    }
    let (calldata, _) = recursive::calldata(&params, &proof);
    let claim: Vec<Word> = core::iter::once(word(&Fr::from(proof.i)))
        .chain(proof.z0.iter().chain(&proof.zi).map(word))
        .collect();
    Ok(format!(
        "{{\"systemId\":\"{}\",\"decidedKey\":\"{}\",\"steps\":{},\"z0\":{},\"zi\":{},\"claim\":\"{}\",\"finalizeRecursive\":\"{}\",\"primaryConstraints\":{}}}",
        hex(&params.system_id()),
        hex(&params.decided_key(&proof)),
        proof.i,
        strings(&proof.z0),
        strings(&proof.zi),
        hex(&claim.concat()),
        hex(&calldata),
        params.primary.shape.num_constraints,
    ))
}

fn trim(args: &Args, r1cs: &CircomR1cs<Fr>) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let out = args.out.as_deref().ok_or("missing --out")?;
    let shape = r1cs.folding_shape();
    let n = evm_verifier::universal::Dims::of(&shape).srs_len();
    let full = read(&args.ptau)?;
    let trimmed =
        evm_verifier::kzg::trim_ptau(&full, n).map_err(|e| format!("{}: {e}", args.ptau))?;
    drop(full);
    // Load what was written, with all the checks a prover will run.
    let srs = Srs::from_ptau(&trimmed, n, &mut OsRng).map_err(|e| e.to_string())?;
    let (params, _) = EvmParams::setup_universal(shape, UNIVERSAL_LABEL, &srs);
    std::fs::write(out, &trimmed).map_err(|e| format!("{out}: {e}"))?;
    Ok(format!(
        "{{\"out\":\"{out}\",\"powers\":{n},\"bytes\":{},\"sha256\":\"{}\",\"vk\":\"{}\"}}",
        trimmed.len(),
        hex(&Sha256::digest(&trimmed)),
        hex(&params.vk),
    ))
}

fn run() -> Result<String, String> {
    let args = parse_args()?;
    let r1cs = CircomR1cs::<Fr>::parse(&args.r1cs).map_err(|e| format!("--r1cs: {e}"))?;
    match args.command.as_str() {
        "key" => key(&args, &r1cs),
        "universal" => universal(&args, &r1cs),
        "recursive" => recursive(&args, &r1cs),
        "trim-ptau" => trim(&args, &r1cs),
        other => Err(format!("unknown command {other}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}
