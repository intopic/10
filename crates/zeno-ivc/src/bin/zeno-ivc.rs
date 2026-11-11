//! Phase 2 CLI: runs full IVC (recursive folding over a 2-cycle of curves)
//! and reports per-step time, proof-state size and peak memory.

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use std::{process::ExitCode, time::Instant};
use zeno_ivc::{CubicStep, IvcParams, ZenoAccumulator};

const USAGE: &str = "\
zeno-ivc — Zeno–Llull recursive IVC over a 2-cycle of curves (Phase 2)

USAGE:
    zeno-ivc prove [--steps N] [--log-constraints K] [--cycle pasta|bn254]
                   [--max-step-ms T] [--max-rss-mib M]

OPTIONS:
    --steps N              number of IVC steps                    [default: 100]
    --log-constraints K    step function has 2^K constraints      [default: 10]
    --cycle NAME           pasta (Pallas/Vesta) | bn254 (BN254/Grumpkin) [default: pasta]
    --max-step-ms T        fail if the mean step time exceeds T milliseconds
    --max-rss-mib M        fail if peak resident memory exceeds M MiB
";

struct Args {
    steps: u64,
    log_constraints: u32,
    cycle: String,
    max_step_ms: Option<f64>,
    max_rss_mib: Option<f64>,
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    match argv.next().as_deref() {
        Some("prove") => {}
        Some("-h") | Some("--help") | None => return Err(String::new()),
        Some(other) => return Err(format!("unknown command `{other}`")),
    }
    let mut args = Args {
        steps: 100,
        log_constraints: 10,
        cycle: "pasta".into(),
        max_step_ms: None,
        max_rss_mib: None,
    };
    while let Some(flag) = argv.next() {
        let mut value = || argv.next().ok_or(format!("missing value for `{flag}`"));
        let bad = |e: &dyn std::fmt::Display| format!("{flag}: {e}");
        match flag.as_str() {
            "--steps" => args.steps = value()?.parse().map_err(|e| bad(&e))?,
            "--log-constraints" => args.log_constraints = value()?.parse().map_err(|e| bad(&e))?,
            "--cycle" => args.cycle = value()?,
            "--max-step-ms" => args.max_step_ms = Some(value()?.parse().map_err(|e| bad(&e))?),
            "--max-rss-mib" => args.max_rss_mib = Some(value()?.parse().map_err(|e| bad(&e))?),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    if !(1..=24).contains(&args.log_constraints) {
        return Err("--log-constraints must be in 1..=24".into());
    }
    if args.steps == 0 {
        return Err("--steps must be at least 1".into());
    }
    Ok(args)
}

/// Peak resident set size of this process in MiB (Linux only).
fn peak_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kb: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024.0)
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

    let t = Instant::now();
    let params = IvcParams::<P1, P2>::setup(&step, b"zeno-llull/cli").map_err(|e| e.to_string())?;
    println!("step function        : {} constraints", 2 * step.rounds);
    println!(
        "primary circuit      : {} constraints ({} of recursion overhead)",
        params.shape1.num_constraints,
        params.shape1.num_constraints - 2 * step.rounds
    );
    println!(
        "secondary circuit    : {} constraints",
        params.shape2.num_constraints
    );
    println!("setup (transparent)  : {:.2?}", t.elapsed());

    let z0 = P1::ScalarField::from(3u64);
    let mut acc = ZenoAccumulator::new(&params, vec![z0]).map_err(|e| e.to_string())?;
    let mut expected = z0;
    let mut first_size = None;
    let t = Instant::now();
    for i in 0..args.steps {
        acc.prove_step(&params, &step, &mut rng)
            .map_err(|e| format!("step {i}: {e}"))?;
        expected = step.eval(expected);
        let size = acc.compressed_size();
        if *first_size.get_or_insert(size) != size {
            return Err(format!("step {i}: proof state changed size"));
        }
    }
    let step_ms = 1e3 * t.elapsed().as_secs_f64() / args.steps as f64;
    if acc.zi != vec![expected] {
        return Err("IVC output differs from native execution".into());
    }

    let t = Instant::now();
    acc.verify(&params).map_err(|e| e.to_string())?;
    println!("IVC steps            : {}", args.steps);
    println!("prover               : {step_ms:.1} ms / step");
    println!(
        "verifier             : {:.2?} (independent of step count)",
        t.elapsed()
    );
    println!(
        "proof state          : {} bytes (constant in step count)",
        acc.compressed_size()
    );
    let rss = peak_rss_mib();
    if let Some(rss) = rss {
        println!("peak RSS             : {rss:.1} MiB");
    }
    println!("verification         : OK");

    if let Some(limit) = args.max_step_ms {
        if step_ms > limit {
            return Err(format!("KPI failed: {step_ms:.1} ms/step > {limit} ms"));
        }
    }
    if let (Some(limit), Some(rss)) = (args.max_rss_mib, rss) {
        if rss > limit {
            return Err(format!("KPI failed: peak RSS {rss:.1} MiB > {limit} MiB"));
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
