//! `cloud-prover` — the ZenoLlull-Cloud-Prover service (spec Paketa B).
//!
//! | Method | Path | Body | Result |
//! |---|---|---|---|
//! | `POST` | `/v1/sessions?z0=3,5` | Circom `.r1cs` | `{"session_id", "arity"}` |
//! | `POST` | `/v1/fold-step?session=ID` | Circom `.wtns` of the step | `{"steps", "state"}` |
//! | `POST` | `/v1/finalize-snark?session=ID` | — | succinct ZK proof (binary) |
//! | `GET` | `/v1/usage` | — | metered usage of the caller |
//! | `GET` | `/healthz` | — | `ok` |
//!
//! Every `/v1` call carries `Authorization: Bearer <license key>`; the key is
//! verified against the vendor's public key (see `zeno-license`), so the
//! service keeps no credential database. Each folded step and each finalized
//! proof is billed to the license's customer and appended to a hash-chained
//! usage log.
#![forbid(unsafe_code)]

pub mod metering;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use metering::{Event, Meter};
use rand::RngCore;
use sdk_bindings::{circom::SdkError, CircomIvc, Fr};
use serde_json::json;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use zeno_license::Claims;

/// Service limits.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_sessions_per_customer: usize,
    pub session_idle_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 << 20,
            max_sessions_per_customer: 16,
            session_idle_timeout: Duration::from_secs(30 * 60),
        }
    }
}

struct Session {
    customer: String,
    last_used: Instant,
    ivc: CircomIvc,
}

/// Shared service state.
pub struct AppState {
    vendor_public_key: [u8; 32],
    limits: Limits,
    sessions: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
    pub meter: Mutex<Meter>,
}

impl AppState {
    pub fn new(vendor_public_key: [u8; 32], limits: Limits, meter: Meter) -> Arc<Self> {
        Arc::new(Self {
            vendor_public_key,
            limits,
            sessions: Mutex::new(HashMap::new()),
            meter: Mutex::new(meter),
        })
    }
}

/// An API error: HTTP status plus a JSON `{"error": …}` body.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<SdkError> for ApiError {
    fn from(e: SdkError) -> Self {
        let status = match e {
            SdkError::StateMismatch => StatusCode::CONFLICT,
            SdkError::Ivc(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::BAD_REQUEST,
        };
        Self(status, e.to_string())
    }
}

fn bad_request(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Authenticates the request with its license key.
fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Claims, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError(
                StatusCode::UNAUTHORIZED,
                "missing bearer license key".into(),
            )
        })?;
    zeno_license::verify(token, &state.vendor_public_key, unix_now())
        .map_err(|e| ApiError(StatusCode::UNAUTHORIZED, e.to_string()))
}

/// Runs CPU-bound proving work off the async executor.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work).await.map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "prover task failed".into(),
        )
    })?
}

fn find_session(
    state: &AppState,
    claims: &Claims,
    query: &HashMap<String, String>,
) -> Result<(String, Arc<Mutex<Session>>), ApiError> {
    let id = query
        .get("session")
        .ok_or_else(|| bad_request("missing `session` query parameter"))?;
    let sessions = state.sessions.lock().expect("sessions lock");
    // A session of another customer is indistinguishable from a missing one.
    sessions
        .get(id)
        .filter(|s| s.lock().expect("session lock").customer == claims.customer)
        .map(|s| (id.clone(), s.clone()))
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown session".into()))
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let z0 = query
        .get("z0")
        .ok_or_else(|| bad_request("missing `z0` query parameter"))?
        .split(',')
        .map(|s| {
            Fr::from_str(s.trim()).map_err(|_| bad_request("`z0` must be decimal field elements"))
        })
        .collect::<Result<Vec<Fr>, _>>()?;

    {
        let mut sessions = state.sessions.lock().expect("sessions lock");
        let timeout = state.limits.session_idle_timeout;
        sessions.retain(|_, s| s.lock().expect("session lock").last_used.elapsed() < timeout);
        let owned = sessions
            .values()
            .filter(|s| s.lock().expect("session lock").customer == claims.customer)
            .count();
        if owned >= state.limits.max_sessions_per_customer {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many open sessions for this license".into(),
            ));
        }
    }

    let arity = z0.len();
    let ivc = blocking(move || Ok(CircomIvc::new(&body, z0)?)).await?;
    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let id: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let session = Session {
        customer: claims.customer.clone(),
        last_used: Instant::now(),
        ivc,
    };
    state
        .sessions
        .lock()
        .expect("sessions lock")
        .insert(id.clone(), Arc::new(Mutex::new(session)));
    state
        .meter
        .lock()
        .expect("meter lock")
        .record(&claims.customer, Event::Session, unix_now());
    Ok((
        StatusCode::CREATED,
        Json(json!({ "session_id": id, "arity": arity })),
    )
        .into_response())
}

async fn fold_step(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let (_, session) = find_session(&state, &claims, &query)?;
    let (steps, zi) = blocking(move || {
        let mut s = session.lock().expect("session lock");
        s.ivc.prove_step(&body, &mut rand::rngs::OsRng)?;
        s.last_used = Instant::now();
        Ok((s.ivc.acc.i, s.ivc.acc.zi.clone()))
    })
    .await?;
    // Bill only steps that were actually folded.
    state
        .meter
        .lock()
        .expect("meter lock")
        .record(&claims.customer, Event::FoldStep, unix_now());
    let state_strings: Vec<String> = zi.iter().map(|z| z.to_string()).collect();
    Ok(Json(json!({ "steps": steps, "state": state_strings })).into_response())
}

async fn finalize_snark(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let (id, session) = find_session(&state, &claims, &query)?;
    let (steps, proof) = blocking(move || {
        let s = session.lock().expect("session lock");
        Ok((s.ivc.acc.i, s.ivc.finalize(&mut rand::rngs::OsRng)?))
    })
    .await?;
    state.sessions.lock().expect("sessions lock").remove(&id);
    state
        .meter
        .lock()
        .expect("meter lock")
        .record(&claims.customer, Event::Proof, unix_now());
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::HeaderName::from_static("x-zeno-steps"),
                steps.to_string(),
            ),
        ],
        proof,
    )
        .into_response())
}

async fn usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = authenticate(&state, &headers)?;
    let usage = state
        .meter
        .lock()
        .expect("meter lock")
        .usage(&claims.customer);
    Ok(Json(json!({
        "customer": claims.customer,
        "plan": claims.plan,
        "license_expires_at": claims.expires_at,
        "sessions": usage.sessions,
        "fold_steps": usage.fold_steps,
        "proofs": usage.proofs,
    }))
    .into_response())
}

/// Builds the HTTP application.
pub fn app(state: Arc<AppState>) -> Router {
    let body_limit = state.limits.max_body_bytes;
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/sessions", post(create_session))
        .route("/v1/fold-step", post(fold_step))
        .route("/v1/finalize-snark", post(finalize_snark))
        .route("/v1/usage", get(usage))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}
