//! ZenoLlull-Cloud-Prover server.
//!
//! Configuration (environment):
//! * `ZENO_LICENSE_PUBLIC_KEY` — vendor public key (hex), required;
//! * `ZENO_BIND` — listen address, default `0.0.0.0:8080`;
//! * `ZENO_USAGE_LOG` — path of the hash-chained usage log (optional).

use cloud_prover::{app, metering::Meter, AppState, Limits};
use std::{path::Path, process::ExitCode};

async fn run() -> Result<(), String> {
    let key = std::env::var("ZENO_LICENSE_PUBLIC_KEY")
        .map_err(|_| "ZENO_LICENSE_PUBLIC_KEY is not set".to_string())?;
    let key = zeno_license::parse_key_hex(&key).map_err(|e| e.to_string())?;
    let bind = std::env::var("ZENO_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let meter = match std::env::var("ZENO_USAGE_LOG") {
        Ok(path) => Meter::with_log(Path::new(&path)).map_err(|e| format!("usage log: {e}"))?,
        Err(_) => Meter::in_memory(),
    };

    let state = AppState::new(key, Limits::default(), meter);
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
