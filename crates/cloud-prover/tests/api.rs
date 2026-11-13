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
            max_steps: None,
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
    let (totals, head) = verify_log(&log).unwrap();
    // The head of the chain is what an auditor anchors elsewhere: a log cut
    // short is a valid chain, but with another head.
    assert_eq!(usage["log_head"], head.as_str());
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

/// A minimal `.r1cs` container that only declares its sizes.
fn r1cs_header(wires: u32, constraints: u32) -> Vec<u8> {
    use ark_ff::{BigInteger, PrimeField};
    let mut header = Vec::new();
    header.extend(32u32.to_le_bytes());
    header.extend(sdk_bindings::Fr::MODULUS.to_bytes_le());
    for v in [wires, 1, 1, 0] {
        header.extend(v.to_le_bytes());
    }
    header.extend(0u64.to_le_bytes());
    header.extend(constraints.to_le_bytes());
    let mut out = b"r1cs".to_vec();
    out.extend(1u32.to_le_bytes());
    out.extend(2u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out.extend((header.len() as u64).to_le_bytes());
    out.extend(header);
    out.extend(2u32.to_le_bytes());
    out.extend(0u64.to_le_bytes());
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn declared_circuit_sizes_are_bounded_before_allocation() {
    let (private, public) = generate_keypair();
    let state = AppState::new(public, Limits::default(), Meter::in_memory());
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);
    // A hundred bytes declaring four billion wires: refused, nothing built.
    let huge = r1cs_header(u32::MAX, 0);
    assert!(huge.len() < 128);
    let (status, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), &huge).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{:?}", json(&body));
    let (status, _) = call(
        &app,
        "POST",
        "/v1/sessions?z0=3",
        Some(&token),
        &r1cs_header(4, u32::MAX),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(state.session_count(), 0);
    // The service's own limit, below the size of a real circuit.
    let small = Limits {
        max_constraints: 1,
        ..Limits::default()
    };
    let app = cloud_prover::app(AppState::new(public, small, Meter::in_memory()));
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_body_is_not_read_without_a_license() {
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        sync::Arc,
        task::{Context, Poll},
    };
    /// A body that records whether anyone asked for its data.
    struct Tracked(Arc<AtomicBool>);
    impl http_body::Body for Tracked {
        type Data = axum::body::Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            self.0.store(true, Ordering::SeqCst);
            Poll::Ready(None)
        }
    }
    let (private, public) = generate_keypair();
    let app = app(AppState::new(public, Limits::default(), Meter::in_memory()));
    let send = |token: Option<String>| {
        let app = app.clone();
        async move {
            let read = Arc::new(AtomicBool::new(false));
            let mut req = Request::builder().method("POST").uri("/v1/sessions?z0=3");
            if let Some(token) = token {
                req = req.header("authorization", format!("Bearer {token}"));
            }
            let res = app
                .oneshot(req.body(Body::new(Tracked(read.clone()))).unwrap())
                .await
                .unwrap();
            (res.status(), read.load(Ordering::SeqCst))
        }
    };
    assert_eq!(send(None).await, (StatusCode::UNAUTHORIZED, false));
    assert_eq!(
        send(Some("garbage".into())).await,
        (StatusCode::UNAUTHORIZED, false)
    );
    // With a license the body is read (and is not a circuit).
    let token = license(&private, "acme", 4_000_000_000);
    assert_eq!(send(Some(token)).await, (StatusCode::BAD_REQUEST, true));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_session_limit_holds_under_concurrent_requests() {
    let (private, public) = generate_keypair();
    let limits = Limits {
        max_sessions_per_customer: 2,
        max_parallel_jobs: 64,
        ..Limits::default()
    };
    let state = AppState::new(public, limits, Meter::in_memory());
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);
    let mut handles = Vec::new();
    for _ in 0..12 {
        let (app, token) = (app.clone(), token.clone());
        handles.push(tokio::spawn(async move {
            call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS)
                .await
                .0
        }));
    }
    let mut created = 0;
    for h in handles {
        match h.await.unwrap() {
            StatusCode::CREATED => created += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(created, 2);
    assert_eq!(state.session_count(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_jobs_are_bounded() {
    let (private, public) = generate_keypair();
    let limits = Limits {
        max_parallel_jobs: 1,
        ..Limits::default()
    };
    let state = AppState::new(public, limits, Meter::in_memory());
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);
    let request = || call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS);
    let (a, b) = tokio::join!(request(), request());
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::CREATED, StatusCode::SERVICE_UNAVAILABLE]
    );
    // The refused request left no reserved slot behind.
    assert_eq!(state.session_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_delivered_when_usage_cannot_be_recorded() {
    let (private, public) = generate_keypair();
    let token = license(&private, "acme", 4_000_000_000);

    // The session record fails: no session.
    let state = AppState::new(public, Limits::default(), Meter::failing_for_tests(0));
    let app = cloud_prover::app(state.clone());
    let (status, _) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(state.session_count(), 0);

    // The step record fails: the folded step is not delivered, its session
    // is closed, and it is not counted.
    let state = AppState::new(public, Limits::default(), Meter::failing_for_tests(1));
    let app = cloud_prover::app(state.clone());
    let (status, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    assert_eq!(status, StatusCode::CREATED);
    let session = json(&body)["session_id"].as_str().unwrap().to_string();
    let step_uri = format!("/v1/fold-step?session={session}");
    let (status, _) = call(&app, "POST", &step_uri, Some(&token), WTNS[0]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = call(&app, "POST", &step_uri, Some(&token), WTNS[1]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(state.session_count(), 0);
    assert_eq!(state.meter.lock().unwrap().usage("acme").fold_steps, 0);

    // The proof record fails: no proof.
    let state = AppState::new(public, Limits::default(), Meter::failing_for_tests(2));
    let app = cloud_prover::app(state.clone());
    let (_, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    let session = json(&body)["session_id"].as_str().unwrap().to_string();
    let (status, _) = call(
        &app,
        "POST",
        &format!("/v1/fold-step?session={session}"),
        Some(&token),
        WTNS[0],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(
        &app,
        "POST",
        &format!("/v1/finalize-snark?session={session}"),
        Some(&token),
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(json(&body)["error"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_step_is_billed_even_if_the_client_disconnects() {
    let (private, public) = generate_keypair();
    let state = AppState::new(public, Limits::default(), Meter::in_memory());
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);
    let (_, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    let session = json(&body)["session_id"].as_str().unwrap().to_string();
    let step_uri = format!("/v1/fold-step?session={session}");

    // Send the step and hang up before the answer: the request future is
    // dropped while the prover works.
    let hung_up = tokio::time::timeout(
        std::time::Duration::from_millis(1),
        call(&app, "POST", &step_uri, Some(&token), WTNS[0]),
    )
    .await;
    assert!(hung_up.is_err(), "the step finished before the client left");

    // The step is folded and billed all the same.
    let mut billed = 0;
    for _ in 0..600 {
        billed = state.meter.lock().unwrap().usage("acme").fold_steps;
        if billed == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(billed, 1);
    // And the session moved on: the next witness is step 1.
    let mut status = StatusCode::CONFLICT;
    for _ in 0..100 {
        status = call(&app, "POST", &step_uri, Some(&token), WTNS[1]).await.0;
        if status != StatusCode::CONFLICT {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(status, StatusCode::OK);
}
