//! End-to-end tests of the HTTP API, driven in-process.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use cloud_prover::{
    app,
    metering::{verify_log, Meter},
    AppState, Limits,
};
use http_body_util::BodyExt;
use sdk_bindings::CircomParams;
use tower::ServiceExt;
use zeno_license::{generate_keypair, issue, Claims};

const R1CS: &[u8] = include_bytes!("../../sdk-bindings/fixtures/step.r1cs");
const WTNS: [&[u8]; 3] = [
    include_bytes!("../../sdk-bindings/fixtures/step0.wtns"),
    include_bytes!("../../sdk-bindings/fixtures/step1.wtns"),
    include_bytes!("../../sdk-bindings/fixtures/step2.wtns"),
];

fn license(private: &[u8; 32], customer: &str, expires_at: u64) -> String {
    issue(
        private,
        &Claims {
            customer: customer.into(),
            plan: "pay-per-proof".into(),
            expires_at,
        },
    )
    .unwrap()
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: &[u8],
) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_vec())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    (
        status,
        res.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
}

fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn pay_per_proof_flow_with_metering() {
    let (private, public) = generate_keypair();
    let log = std::env::temp_dir().join(format!("zeno-usage-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&log);
    let state = AppState::new(public, Limits::default(), Meter::with_log(&log).unwrap());
    let app = app(state);
    let far = 4_000_000_000;
    let acme = license(&private, "acme", far);
    let other = license(&private, "other", far);

    assert_eq!(
        call(&app, "GET", "/healthz", None, b"").await.0,
        StatusCode::OK
    );

    // --- Authentication -----------------------------------------------------
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=3", None, R1CS).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=3", Some("garbage"), R1CS).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let expired = license(&private, "acme", 1);
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=3", Some(&expired), R1CS).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (rogue, _) = generate_keypair();
    let forged = license(&rogue, "acme", far);
    let (status, _) = call(&app, "GET", "/v1/usage", Some(&forged), b"").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- Input validation ---------------------------------------------------
    let (status, _) = call(&app, "POST", "/v1/sessions", Some(&acme), R1CS).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=abc", Some(&acme), R1CS).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=3", Some(&acme), b"not r1cs").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // --- Session, steps, proof ----------------------------------------------
    let (status, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(&acme), R1CS).await;
    assert_eq!(status, StatusCode::CREATED);
    let session = json(&body)["session_id"].as_str().unwrap().to_string();
    let step_uri = format!("/v1/fold-step?session={session}");
    let fin_uri = format!("/v1/finalize-snark?session={session}");

    // Another customer cannot see or use the session.
    let (status, _) = call(&app, "POST", &step_uri, Some(&other), WTNS[0]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&app, "POST", &fin_uri, Some(&other), b"").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A witness for the wrong state is refused and not billed.
    let (status, _) = call(&app, "POST", &step_uri, Some(&acme), WTNS[1]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(&app, "POST", &step_uri, Some(&acme), b"junk").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    for (i, wtns) in WTNS.iter().enumerate() {
        let (status, body) = call(&app, "POST", &step_uri, Some(&acme), wtns).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["steps"], i as u64 + 1);
    }
    let (_, body) = call(&app, "POST", &step_uri, Some(&acme), WTNS[2]).await;
    assert!(json(&body)["error"].is_string());

    let (status, proof) = call(&app, "POST", &fin_uri, Some(&acme), b"").await;
    assert_eq!(status, StatusCode::OK);
    // The customer verifies the proof locally, without trusting the service.
    let statement = CircomParams::setup(R1CS)
        .unwrap()
        .verify_proof(&proof)
        .unwrap()
        .statement;
    assert_eq!(statement.i, 3);
    assert_eq!(statement.zi[0].to_string(), "130308420719099");
    // The session is gone after finalization.
    let (status, _) = call(&app, "POST", &step_uri, Some(&acme), WTNS[0]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- Metering -------------------------------------------------------------
    let (_, body) = call(&app, "GET", "/v1/usage", Some(&acme), b"").await;
    let usage = json(&body);
    assert_eq!(
        (&usage["sessions"], &usage["fold_steps"], &usage["proofs"]),
        (&1.into(), &3.into(), &1.into())
    );
    let (_, body) = call(&app, "GET", "/v1/usage", Some(&other), b"").await;
    assert_eq!(json(&body)["fold_steps"], 0);

    // The log is a valid hash chain, survives a restart, and detects edits.
    let (totals, _) = verify_log(&log).unwrap();
    assert_eq!(totals["acme"].fold_steps, 3);
    assert_eq!(Meter::with_log(&log).unwrap().usage("acme").proofs, 1);
    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5);
    std::fs::write(&log, text.replacen("fold-step", "session", 1)).unwrap();
    assert!(verify_log(&log).is_err());
    std::fs::write(&log, [&lines[..1], &lines[2..]].concat().join("\n")).unwrap();
    assert!(verify_log(&log).is_err());
    assert!(Meter::with_log(&log).is_err());
    let _ = std::fs::remove_file(&log);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_limit_per_license() {
    let (private, public) = generate_keypair();
    let limits = Limits {
        max_sessions_per_customer: 1,
        ..Limits::default()
    };
    let app = app(AppState::new(public, limits, Meter::in_memory()));
    let token = license(&private, "acme", 4_000_000_000);
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
