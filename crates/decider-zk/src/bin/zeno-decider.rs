//! Phase 3 CLI: runs IVC, then compresses the result into a succinct
//! zero-knowledge proof and reports its size and timings.

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use decider_zk::{CompressedIvcProof, ZkIvcProof};
use std::{process::ExitCode, time::Instant};
use zeno_ivc::{CubicStep, IvcParams, ZenoAccumulator};

const USAGE: &str = "\
zeno-decider — succinct zero-knowledge finalization of a Zeno–Llull IVC run

USAGE:
    zeno-decider [--steps N] [--log-constraints K] [--cycle pasta|bn254]
                 [--max-proof-bytes B]

OPTIONS:
    --steps N              number of IVC steps before finalizing  [default: 10]
    --log-constraints K    step function has 2^K constraints      [default: 10]
    --cycle NAME           pasta | bn254                          [default: pasta]
    --max-proof-bytes B    fail if the compressed proof exceeds B bytes
";

struct Args {
    steps: u64,
    log_constraints: u32,
    cycle: String,
    max_proof_bytes: Option<usize>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        steps: 10,
        log_constraints: 10,
        cycle: "pasta".into(),
        max_proof_bytes: None,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || argv.next().ok_or(format!("missing value for `{flag}`"));
        let bad = |e: &dyn std::fmt::Display| format!("{flag}: {e}");
        match flag.as_str() {
            "--steps" => args.steps = value()?.parse().map_err(|e| bad(&e))?,
            "--log-constraints" => args.log_constraints = value()?.parse().map_err(|e| bad(&e))?,
            "--cycle" => args.cycle = value()?,
            "--max-proof-bytes" => {
                args.max_proof_bytes = Some(value()?.parse().map_err(|e| bad(&e))?)
            }
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    if !(1..=24).contains(&args.log_constraints) || args.steps == 0 {
        return Err("--log-constraints must be in 1..=24 and --steps at least 1".into());
    }
    Ok(args)
}

fn run<P1, P2>(args: &Args) -> Result<(), String>
where
    P1: SWCurveConfig<BaseField = <P2 as CurveConfig>::ScalarField>,
    P2: SWCurveConfig<BaseField = <P1 as CurveConfig>::ScalarField>,
    P1::BaseField: PrimeField + Absorb,
    P2::BaseField: PrimeField + Absorb,
{
    let mut rng = rand::rngs::OsRng;
    let step = CubicStep {
        rounds: 1 << (args.log_constraints - 1),
    };
    let err = |e: zeno_ivc::IvcError| e.to_string();
    let params = IvcParams::<P1, P2>::setup(&step, b"zeno-llull/cli").map_err(err)?;
    let mut acc = ZenoAccumulator::new(&params, vec![P1::ScalarField::from(3u64)]).map_err(err)?;
    for _ in 0..args.steps {
        acc.prove_step(&params, &step, &mut rng).map_err(err)?;
    }
    println!(
        "IVC                  : {} steps, primary circuit {} constraints, secondary {}",
        args.steps, params.shape1.num_constraints, params.shape2.num_constraints
    );
    println!("prover state         : {} bytes", acc.compressed_size());

    let t = Instant::now();
    let zk = ZkIvcProof::prove(&params, &acc, &mut rng).map_err(err)?;
    println!(
        "ZK masking           : {:.2?}, uncompressed proof {} bytes",
        t.elapsed(),
        zk.compressed_size()
    );
    let t = Instant::now();
    let proof = zk.compress(&params).map_err(err)?;
    println!("compression          : {:.2?}", t.elapsed());

    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| e.to_string())?;
    let decoded = CompressedIvcProof::<P1, P2>::deserialize_compressed(&bytes[..])
        .map_err(|e| e.to_string())?;
    let t = Instant::now();
    decoded.verify(&params).map_err(err)?;
    println!("verification         : OK in {:.2?}", t.elapsed());
    println!(
        "compressed proof     : {} bytes ({:.2} KiB), independent of step count",
        bytes.len(),
        bytes.len() as f64 / 1024.0
    );
    if let Some(limit) = args.max_proof_bytes {
        if bytes.len() > limit {
            return Err(format!("KPI failed: proof {} bytes > {limit}", bytes.len()));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("error: {msg}\n");
            }
            eprint!("{USAGE}");
            return if msg.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };
    let result = match args.cycle.as_str() {
        "pasta" => run::<ark_pallas::PallasConfig, ark_vesta::VestaConfig>(&args),
        "bn254" => run::<ark_bn254::g1::Config, ark_grumpkin::GrumpkinConfig>(&args),
        other => Err(format!("unknown cycle `{other}`")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
