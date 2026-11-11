//! Phase 1 CLI: folds `t` steps of a demo circuit into one constant-size
//! accumulator and verifies `(A·Z) ∘ (B·Z) = u·(C·Z) + E` with zero residual.

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use llull_folder::{
    check_accumulator, commit_witness,
    core_r1cs::{RelaxedR1CSInstance, RelaxedR1CSWitness},
    demo_circuit::CubicChain,
    nifs_prove, nifs_verify, PublicParams,
};
use std::{process::ExitCode, time::Instant};

const USAGE: &str = "\
llull-folder — Zeno–Llull NIFS folding engine (Phase 1)

USAGE:
    llull-folder fold [--steps N] [--log-constraints K] [--curve pallas|bn254]

OPTIONS:
    --steps N              number of steps to fold           [default: 100]
    --log-constraints K    step circuit has 2^K constraints  [default: 10]
    --curve NAME           pallas | bn254                    [default: pallas]
";

struct Args {
    steps: usize,
    log_constraints: u32,
    curve: String,
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    match argv.next().as_deref() {
        Some("fold") => {}
        Some("-h") | Some("--help") | None => return Err(String::new()),
        Some(other) => return Err(format!("unknown command `{other}`")),
    }
    let mut args = Args {
        steps: 100,
        log_constraints: 10,
        curve: "pallas".into(),
    };
    while let Some(flag) = argv.next() {
        let mut value = || argv.next().ok_or(format!("missing value for `{flag}`"));
        match flag.as_str() {
            "--steps" => args.steps = value()?.parse().map_err(|e| format!("--steps: {e}"))?,
            "--log-constraints" => {
                args.log_constraints = value()?
                    .parse()
                    .map_err(|e| format!("--log-constraints: {e}"))?
            }
            "--curve" => args.curve = value()?,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    if !(1..=24).contains(&args.log_constraints) {
        return Err("--log-constraints must be in 1..=24".into());
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

fn run<C: CurveGroup>(args: &Args) -> Result<(), String>
where
    C::BaseField: PrimeField + Absorb,
{
    let rounds = 1usize << (args.log_constraints - 1);
    let mut rng = rand::rngs::OsRng;

    let mut state = C::ScalarField::from(3u64);
    let (shape, _, _) = CubicChain {
        z_in: state,
        rounds,
    }
    .synthesize()
    .map_err(|e| e.to_string())?;

    let t0 = Instant::now();
    let pp = PublicParams::<C>::setup(&shape, b"zeno-llull/cli");
    println!(
        "circuit: {} constraints, {} variables, {} public inputs",
        shape.num_constraints, shape.num_vars, shape.num_io
    );
    println!("setup (transparent, hash-to-curve): {:.2?}", t0.elapsed());

    let mut acc_u = RelaxedR1CSInstance::<C>::default_for(&shape);
    let mut acc_w = RelaxedR1CSWitness::<C>::default_for(&shape);
    let mut verifier_u = acc_u.clone();
    let (mut prove_time, mut verify_time) = (0f64, 0f64);

    for step in 0..args.steps {
        let circuit = CubicChain {
            z_in: state,
            rounds,
        };
        let (_, w, x) = circuit.synthesize().map_err(|e| e.to_string())?;
        state = circuit.output();
        let (u2, w2) = commit_witness(&pp.ck, w, x, &mut rng);

        let t = Instant::now();
        let (u, w, comm_t) = nifs_prove(&pp, &shape, &acc_u, &acc_w, &u2, &w2, &mut rng)
            .map_err(|e| format!("step {step}: {e}"))?;
        prove_time += t.elapsed().as_secs_f64();

        let t = Instant::now();
        verifier_u = nifs_verify(&pp.poseidon, pp.digest, &verifier_u, &u2, &comm_t);
        verify_time += t.elapsed().as_secs_f64();

        if verifier_u != u {
            return Err(format!("step {step}: prover and verifier disagree"));
        }
        (acc_u, acc_w) = (u, w);
    }

    let t = Instant::now();
    check_accumulator(&pp.ck, &shape, &acc_u, &acc_w).map_err(|e| e.to_string())?;
    let n = args.steps as f64;
    println!("folded {} steps", args.steps);
    println!("  prover   : {:.3} ms / step", 1e3 * prove_time / n);
    println!("  verifier : {:.3} ms / step", 1e3 * verify_time / n);
    println!(
        "  accumulator instance U: {} bytes (constant in t)",
        acc_u.compressed_size()
    );
    println!(
        "  accumulator witness  W: {} bytes (constant in t)",
        acc_w.compressed_size()
    );
    if let Some(rss) = peak_rss_mib() {
        println!("  peak RSS : {rss:.1} MiB");
    }
    println!(
        "final check (A·Z)∘(B·Z) == u·(C·Z) + E with 0 errors: OK ({:.2?})",
        t.elapsed()
    );
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
    let result = match args.curve.as_str() {
        "pallas" => run::<ark_pallas::Projective>(&args),
        "bn254" => run::<ark_bn254::G1Projective>(&args),
        other => Err(format!("unknown curve `{other}`")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
