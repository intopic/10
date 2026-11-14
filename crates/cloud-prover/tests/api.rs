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

#[tokio::test(flavor = "multi_thread")]
async fn the_license_step_quota_holds_on_the_server() {
    let (private, public) = generate_keypair();
    let app = app(AppState::new(public, Limits::default(), Meter::in_memory()));
    let token = issue(
        &private,
        &Claims {
            customer: "acme".into(),
            plan: "pay-per-proof".into(),
            expires_at: 4_000_000_000,
            max_steps: Some(2),
        },
    )
    .unwrap();
    let (_, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    let session = json(&body)["session_id"].as_str().unwrap().to_string();
    let step_uri = format!("/v1/fold-step?session={session}");
    for wtns in &WTNS[..2] {
        assert_eq!(
            call(&app, "POST", &step_uri, Some(&token), wtns).await.0,
            StatusCode::OK
        );
    }
    let (status, body) = call(&app, "POST", &step_uri, Some(&token), WTNS[2]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(json(&body)["error"]
        .as_str()
        .unwrap()
        .contains("quota of 2 steps"));
    // The proof of the steps within the quota is still delivered.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/v1/finalize-snark?session={session}"),
        Some(&token),
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_proof_can_be_fetched_again_without_being_billed_twice() {
    let (private, public) = generate_keypair();
    let state = AppState::new(public, Limits::default(), Meter::in_memory());
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);
    let other = license(&private, "other", 4_000_000_000);
    let (_, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    let session = json(&body)["session_id"].as_str().unwrap().to_string();
    let step = format!("/v1/fold-step?session={session}");
    assert_eq!(
        call(&app, "POST", &step, Some(&token), WTNS[0]).await.0,
        StatusCode::OK
    );
    let fin = format!("/v1/finalize-snark?session={session}");

    // The client hangs up while the proof is computed: it is billed...
    let hung_up = tokio::time::timeout(
        std::time::Duration::from_millis(1),
        call(&app, "POST", &fin, Some(&token), b""),
    )
    .await;
    assert!(
        hung_up.is_err(),
        "the proof finished before the client left"
    );
    let mut retained = 0;
    for _ in 0..600 {
        retained = state.retained_proofs();
        if retained == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(retained, 1);
    assert_eq!(state.meter.lock().unwrap().usage("acme").proofs, 1);

    // ...and repeating the request returns the proof, unbilled.
    let (status, proof) = call(&app, "POST", &fin, Some(&token), b"").await;
    assert_eq!(status, StatusCode::OK);
    let (status, again) = call(&app, "POST", &fin, Some(&token), b"").await;
    assert_eq!((status, &again), (StatusCode::OK, &proof));
    assert_eq!(state.meter.lock().unwrap().usage("acme").proofs, 1);
    let statement = CircomParams::setup(R1CS)
        .unwrap()
        .verify_proof(&proof)
        .unwrap()
        .statement;
    assert_eq!(statement.i, 1);
    // Nobody else can fetch it, and the session itself is closed.
    assert_eq!(
        call(&app, "POST", &fin, Some(&other), b"").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "POST", &step, Some(&token), WTNS[1]).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_sessions_and_old_proofs_are_swept_and_circuits_are_shared() {
    let (private, public) = generate_keypair();
    let limits = Limits {
        session_idle_timeout: std::time::Duration::from_millis(300),
        proof_retention: std::time::Duration::from_millis(300),
        ..Limits::default()
    };
    let state = AppState::new(public, limits, Meter::in_memory());
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);
    let other = license(&private, "other", 4_000_000_000);

    // Two customers, three sessions, one circuit: its parameters are derived
    // once and shared.
    let mut sessions = Vec::new();
    for t in [&token, &token, &other] {
        let (status, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(t), R1CS).await;
        assert_eq!(status, StatusCode::CREATED);
        sessions.push(json(&body)["session_id"].as_str().unwrap().to_string());
    }
    assert_eq!((state.session_count(), state.circuit_count()), (3, 1));
    let fin = format!("/v1/finalize-snark?session={}", sessions[0]);
    call(
        &app,
        "POST",
        &format!("/v1/fold-step?session={}", sessions[0]),
        Some(&token),
        WTNS[0],
    )
    .await;
    assert_eq!(
        call(&app, "POST", &fin, Some(&token), b"").await.0,
        StatusCode::OK
    );

    let (status, metrics) = call(&app, "GET", "/metrics", None, b"").await;
    assert_eq!(status, StatusCode::OK);
    let metrics = String::from_utf8(metrics).unwrap();
    for line in [
        "zeno_sessions 2",
        "zeno_circuits_cached 1",
        "zeno_proofs_retained 1",
        "zeno_jobs_running 0",
        "zeno_jobs_capacity 2",
    ] {
        assert!(metrics.contains(line), "{line} missing in\n{metrics}");
    }

    // The background sweeper closes idle sessions, drops the proof and
    // forgets the circuit once no session uses it.
    let sweeper = cloud_prover::spawn_sweeper(state.clone(), std::time::Duration::from_millis(100));
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    sweeper.abort();
    assert_eq!(
        (
            state.session_count(),
            state.retained_proofs(),
            state.circuit_count()
        ),
        (0, 0, 0)
    );
    assert_eq!(
        call(&app, "POST", &fin, Some(&token), b"").await.0,
        StatusCode::NOT_FOUND
    );
}

async fn call_full(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: &[u8],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_vec()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    (
        status,
        headers,
        res.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn evm_modes_need_a_reference_string() {
    let (private, public) = generate_keypair();
    let app = app(AppState::new(public, Limits::default(), Meter::in_memory()));
    let token = license(&private, "acme", 4_000_000_000);
    for mode in ["universal", "recursive"] {
        let uri = format!("/v1/sessions?z0=3&mode={mode}");
        let (status, body) = call(&app, "POST", &uri, Some(&token), R1CS).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json(&body)["error"].as_str().unwrap().contains("EVM modes"));
    }
    let (status, _) = call(
        &app,
        "POST",
        "/v1/sessions?z0=3&mode=other",
        Some(&token),
        R1CS,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn mode_b_through_the_api() {
    use std::sync::Arc;
    const PTAU: &[u8] = include_bytes!("../../evm-verifier/fixtures/pot7_test.ptau");
    let srs = evm_verifier::kzg::Srs::from_ptau(PTAU, 128, &mut rand::rngs::OsRng).unwrap();
    let (private, public) = generate_keypair();
    let state = AppState::with_reference_string(
        public,
        Limits::default(),
        Meter::in_memory(),
        Some(Arc::new(srs)),
    );
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);

    let (status, body) = call(
        &app,
        "POST",
        "/v1/sessions?z0=3&mode=universal",
        Some(&token),
        R1CS,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created = json(&body);
    assert_eq!(created["mode"], "universal");
    let session = created["session_id"].as_str().unwrap().to_string();
    // The same vk as the SDK computes on a device from the same ceremony.
    let device = sdk_bindings::onchain::OnChainProver::new(
        &issue(
            &zeno_license::DEV_PRIVATE_KEY,
            &Claims {
                customer: "x".into(),
                plan: "y".into(),
                expires_at: 4_000_000_000,
                max_steps: None,
            },
        )
        .unwrap(),
        R1CS,
        PTAU,
        &["3".to_string()],
    )
    .unwrap();
    assert_eq!(
        created["vk"],
        sdk_bindings::onchain::to_hex(&device.vk()).as_str()
    );
    assert!(created["open_session"].as_str().unwrap().starts_with("0x"));

    for wtns in WTNS {
        let uri = format!("/v1/fold-step?session={session}");
        assert_eq!(
            call(&app, "POST", &uri, Some(&token), wtns).await.0,
            StatusCode::OK
        );
    }
    // Not a mode-A session; and mode B needs the on-chain session id.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/v1/finalize-snark?session={session}"),
        Some(&token),
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let fin = format!("/v1/finalize-evm?session={session}");
    assert_eq!(
        call(&app, "POST", &fin, Some(&token), b"").await.0,
        StatusCode::BAD_REQUEST
    );
    let fin = format!("{fin}&onchain=0x{}", "cd".repeat(32));
    let (status, headers, body) = call_full(&app, "POST", &fin, &token, b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-zeno-repeated"], "false");
    let answer = json(&body);
    assert_eq!(
        (answer["steps"].as_u64(), answer["batch_steps"].as_u64()),
        (Some(3), Some(3))
    );
    // Send the batch with stepFee × batch_steps, the decision with decisionFee.
    assert_eq!(answer["decision_fees"], 1);
    assert_eq!(answer["zi"][0], "130308420719099");
    let selector = |sig: &str| sdk_bindings::onchain::to_hex(&evm_verifier::abi::selector(sig));
    assert!(answer["verifyFoldedProofBatch"]
        .as_str()
        .unwrap()
        .starts_with(&selector("verifyFoldedProofBatch(bytes32,uint256[])")));
    assert!(answer["finalizeUniversal"]
        .as_str()
        .unwrap()
        .starts_with(&selector(
            "finalizeUniversal(bytes32,bytes,uint256[],uint256[])"
        )));
    // Repeated: the same answer, billed once.
    let (status, headers, again) = call_full(&app, "POST", &fin, &token, b"").await;
    assert_eq!((status, &again), (StatusCode::OK, &body));
    assert_eq!(headers["x-zeno-repeated"], "true");
    let usage = state.meter.lock().unwrap().usage("acme");
    assert_eq!((usage.sessions, usage.fold_steps, usage.proofs), (1, 3, 1));

    let (status, metrics) = call(&app, "GET", "/metrics", None, b"").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(metrics)
        .unwrap()
        .contains("zeno_evm_modes 1"));
}

/// Mode D through the API: needs `ZENO_PTAU` (2^20 powers) and about 2 GB.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a 2^20-power reference string (ZENO_PTAU); run explicitly"]
async fn mode_d_through_the_api() {
    use std::sync::Arc;
    let path = std::env::var("ZENO_PTAU").expect("ZENO_PTAU");
    let bytes = std::fs::read(path).unwrap();
    let srs = evm_verifier::kzg::Srs::from_ptau(&bytes, 1 << 20, &mut rand::rngs::OsRng).unwrap();
    drop(bytes);
    let (private, public) = generate_keypair();
    let state = AppState::with_reference_string(
        public,
        Limits::default(),
        Meter::in_memory(),
        Some(Arc::new(srs)),
    );
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);
    let (status, body) = call(
        &app,
        "POST",
        "/v1/sessions?z0=3&mode=recursive",
        Some(&token),
        R1CS,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{:?}", json(&body));
    let session = json(&body)["session_id"].as_str().unwrap().to_string();
    for wtns in &WTNS[..2] {
        let uri = format!("/v1/fold-step?session={session}");
        assert_eq!(
            call(&app, "POST", &uri, Some(&token), wtns).await.0,
            StatusCode::OK
        );
    }
    let fin = format!("/v1/finalize-evm?session={session}");
    let t = std::time::Instant::now();
    let (status, _) = call(&app, "POST", &fin, Some(&token), b"").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    // While it runs: 202, and the session takes no more steps.
    let (status, _) = call(&app, "POST", &fin, Some(&token), b"").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let uri = format!("/v1/fold-step?session={session}");
    assert_eq!(
        call(&app, "POST", &uri, Some(&token), WTNS[2]).await.0,
        StatusCode::CONFLICT
    );
    let body = loop {
        let (status, body) = call(&app, "POST", &fin, Some(&token), b"").await;
        if status != StatusCode::ACCEPTED {
            assert_eq!(status, StatusCode::OK, "{:?}", json(&body));
            break body;
        }
        assert!(
            t.elapsed().as_secs() < 900,
            "the recursive proof took too long"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    println!("mode D through the API: {:.1} s", t.elapsed().as_secs_f64());
    let answer = json(&body);
    assert_eq!(answer["steps"], 2);
    let selector = sdk_bindings::onchain::to_hex(&evm_verifier::abi::selector(
        "finalizeRecursive(uint256[],uint256[],uint256[],uint256[],uint256[])",
    ));
    assert!(answer["finalizeRecursive"]
        .as_str()
        .unwrap()
        .starts_with(&selector));
    let usage = state.meter.lock().unwrap().usage("acme");
    assert_eq!((usage.proofs, usage.recursive_proofs), (0, 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn with_no_retention_nothing_is_kept_after_the_answer() {
    let (private, public) = generate_keypair();
    let limits = Limits {
        proof_retention: std::time::Duration::ZERO,
        ..Limits::default()
    };
    let state = AppState::new(public, limits, Meter::in_memory());
    let app = app(state.clone());
    let token = license(&private, "acme", 4_000_000_000);
    let (_, body) = call(&app, "POST", "/v1/sessions?z0=3", Some(&token), R1CS).await;
    let session = json(&body)["session_id"].as_str().unwrap().to_string();
    let step = format!("/v1/fold-step?session={session}");
    assert_eq!(
        call(&app, "POST", &step, Some(&token), WTNS[0]).await.0,
        StatusCode::OK
    );
    let fin = format!("/v1/finalize-snark?session={session}");
    assert_eq!(
        call(&app, "POST", &fin, Some(&token), b"").await.0,
        StatusCode::OK
    );
    // The session is gone and its answer is not kept.
    assert_eq!(
        call(&app, "POST", &fin, Some(&token), b"").await.0,
        StatusCode::NOT_FOUND
    );
    state.sweep();
    assert_eq!(
        (
            state.session_count(),
            state.retained_proofs(),
            state.circuit_count()
        ),
        (0, 0, 0)
    );
}
