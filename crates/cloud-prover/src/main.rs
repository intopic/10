//! ZenoLlull-Cloud-Prover server.
//!
//! Configuration (environment):
//! * `ZENO_LICENSE_PUBLIC_KEY` — vendor public key (hex), required;
//! * `ZENO_BIND` — listen address, default `0.0.0.0:8080`;
//! * `ZENO_USAGE_LOG` — path of the hash-chained usage log (optional; without
//!   it usage is only counted in memory);
//! * `ZENO_MAX_JOBS`, `ZENO_MAX_WIRES`, `ZENO_MAX_CONSTRAINTS`,
//!   `ZENO_MAX_SESSIONS` — override the default [`Limits`];
//! * `ZENO_PROOF_RETENTION_SECS` — how long a delivered proof can be
//!   fetched again (default 600);
//! * `ZENO_PTAU_PATH` — a Powers-of-Tau file of a public ceremony: enables
//!   the EVM modes (`universal`; `recursive` with 2^20 powers). It is loaded
//!   and checked once, at start, and shared by every session;
//! * `ZENO_MAX_RECURSIVE_JOBS` — recursive proofs at the same time
//!   (default 1, each about 2 GB of memory).
//!
//! Idle sessions and expired proofs are swept every minute.
//!
//! The API carries the license key as a bearer credential: run it behind a
//! TLS-terminating proxy.

use cloud_prover::{app, metering::Meter, spawn_sweeper, AppState, Limits};
use evm_verifier::kzg::{ptau_powers, Srs};
use std::{path::Path, process::ExitCode, sync::Arc, time::Duration};

async fn run() -> Result<(), String> {
    let key = std::env::var("ZENO_LICENSE_PUBLIC_KEY")
        .map_err(|_| "ZENO_LICENSE_PUBLIC_KEY is not set".to_string())?;
    let key = zeno_license::parse_key_hex(&key).map_err(|e| e.to_string())?;
    let bind = std::env::var("ZENO_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let meter = match std::env::var("ZENO_USAGE_LOG") {
        Ok(path) => Meter::with_log(Path::new(&path)).map_err(|e| format!("usage log: {e}"))?,
        Err(_) => Meter::in_memory(),
    };

    let mut limits = Limits::default();
    let number = |name: &str, target: &mut usize| -> Result<(), String> {
        if let Ok(v) = std::env::var(name) {
            *target = v.parse().map_err(|_| format!("{name}: not a number"))?;
        }
        Ok(())
    };
    number("ZENO_MAX_JOBS", &mut limits.max_parallel_jobs)?;
    number("ZENO_MAX_WIRES", &mut limits.max_wires)?;
    number("ZENO_MAX_CONSTRAINTS", &mut limits.max_constraints)?;
    number("ZENO_MAX_SESSIONS", &mut limits.max_sessions_per_customer)?;
    number("ZENO_MAX_RECURSIVE_JOBS", &mut limits.max_recursive_jobs)?;
    let mut retention = limits.proof_retention.as_secs() as usize;
    number("ZENO_PROOF_RETENTION_SECS", &mut retention)?;
    limits.proof_retention = Duration::from_secs(retention as u64);
    if std::env::var("ZENO_USAGE_LOG").is_err() {
        eprintln!("warning: ZENO_USAGE_LOG is not set; usage is counted in memory only");
    }
    eprintln!(
        "limits: {} parallel jobs, {} wires, {} constraints, {} sessions per license",
        limits.max_parallel_jobs,
        limits.max_wires,
        limits.max_constraints,
        limits.max_sessions_per_customer
    );

    let srs = match std::env::var("ZENO_PTAU_PATH") {
        Ok(path) => {
            let bytes = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
            let powers = ptau_powers(&bytes).map_err(|e| format!("{path}: {e}"))?;
            let srs = Srs::from_ptau(&bytes, powers, &mut rand::rngs::OsRng)
                .map_err(|e| format!("{path}: {e}"))?;
            eprintln!(
                "EVM modes enabled: {powers} powers of tau from {path} (mode recursive {})",
                if powers >= cloud_prover::provers::RECURSIVE_POWERS {
                    "available"
                } else {
                    "needs 2^20"
                }
            );
            Some(Arc::new(srs))
        }
        Err(_) => None,
    };
    let state = AppState::with_reference_string(key, limits, meter, srs);
    spawn_sweeper(state.clone(), Duration::from_secs(60));
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| format!("cannot bind {bind}: {e}"))?;
    eprintln!("zenollull-cloud-prover listening on {bind}");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
