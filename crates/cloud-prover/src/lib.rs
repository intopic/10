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
//! service keeps no credential database. The key is a long-lived bearer
//! credential: serve this API only behind TLS.
//!
//! How the service protects itself and its billing:
//!
//! * the license is checked **before** the request body is read;
//! * a circuit's declared size is bounded ([`Limits::max_wires`],
//!   [`Limits::max_constraints`]) before anything is allocated for it;
//! * proving runs on blocking threads, at most [`Limits::max_parallel_jobs`]
//!   at a time (further requests get `503`), and a panic in a job is caught
//!   and costs only the session it ran for;
//! * request handlers never wait on a lock held by a running job: a second
//!   request for a busy session gets `409`;
//! * a session slot is reserved before the session is built, so the limit
//!   per license holds under concurrent requests;
//! * every folded step, proof and session is recorded in the usage log
//!   **inside** the job that produced it, so a client that disconnects early
//!   is still billed; if the record cannot be written, the step's session is
//!   closed and no proof is returned — nothing is given away unbilled.
#![forbid(unsafe_code)]

pub mod metering;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Extension, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use metering::{Event, Meter};
use rand::RngCore;
use sdk_bindings::{
    circom::{CircuitLimits, SdkError},
    CircomIvc, Fr,
};
use serde_json::json;
use std::{
    collections::HashMap,
    panic::{catch_unwind, AssertUnwindSafe},
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::Semaphore;
use zeno_license::Claims;

/// Service limits.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_sessions_per_customer: usize,
    pub session_idle_timeout: Duration,
    /// Proving jobs (session setup, step, proof) running at the same time.
    pub max_parallel_jobs: usize,
    /// Largest number of wires a step circuit may declare.
    pub max_wires: usize,
    /// Largest number of constraints a step circuit may declare.
    pub max_constraints: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 << 20,
            max_sessions_per_customer: 16,
            session_idle_timeout: Duration::from_secs(30 * 60),
            max_parallel_jobs: 2,
            max_wires: 1 << 20,
            max_constraints: 1 << 20,
        }
    }
}

/// A session slot. `ivc` is `None` while the session is being built: the
/// slot already counts against the customer's limit.
struct Entry {
    customer: String,
    last_used: Instant,
    ivc: Option<Arc<Mutex<CircomIvc>>>,
}

/// Shared service state.
pub struct AppState {
    vendor_public_key: [u8; 32],
    limits: Limits,
    /// Held only for map operations, never while proving and never while
    /// waiting for a session.
    sessions: Mutex<HashMap<String, Entry>>,
    pub meter: Mutex<Meter>,
    jobs: Arc<Semaphore>,
}

impl AppState {
    pub fn new(vendor_public_key: [u8; 32], limits: Limits, meter: Meter) -> Arc<Self> {
        Arc::new(Self {
            vendor_public_key,
            jobs: Arc::new(Semaphore::new(limits.max_parallel_jobs.max(1))),
            limits,
            sessions: Mutex::new(HashMap::new()),
            meter: Mutex::new(meter),
        })
    }

    /// Number of session slots (ready or being built), for tests and
    /// monitoring.
    pub fn session_count(&self) -> usize {
        lock(&self.sessions).len()
    }
}

/// Locks a mutex whose critical sections cannot leave it inconsistent (map
/// operations, one log append): a panic elsewhere must not take the service
/// down with a poisoned lock.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
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
            SdkError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
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

/// Runs before any `/v1` handler and before the body is read: a request
/// without a valid license is answered from its headers alone.
async fn require_license(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    match authenticate(&state, request.headers()) {
        Ok(claims) => {
            request.extensions_mut().insert(claims);
            next.run(request).await
        }
        Err(e) => e.into_response(),
    }
}

/// Runs CPU-bound proving work off the async executor, within the global
/// limit of parallel jobs. The work runs to completion even if the client
/// disconnects; a panic in it becomes an error response.
async fn job<T: Send + 'static>(
    state: &Arc<AppState>,
    work: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    let permit = state.jobs.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "the prover is at capacity; retry shortly".into(),
        )
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(|_| {
            Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "prover task failed".into(),
            ))
        })
    })
    .await
    .map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "prover task failed".into(),
        )
    })?
}

/// Records a billable event; an event that cannot be recorded is an error.
fn bill(state: &AppState, customer: &str, event: Event) -> Result<(), ApiError> {
    lock(&state.meter)
        .record(customer, event, unix_now())
        .map_err(|e| {
            eprintln!("usage log write failed: {e}");
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "usage could not be recorded; nothing was delivered".into(),
            )
        })
}

fn remove_session(state: &AppState, id: &str) {
    lock(&state.sessions).remove(id);
}

/// The session `id` of this customer, if it exists and is ready.
fn find_session(
    state: &AppState,
    claims: &Claims,
    query: &HashMap<String, String>,
) -> Result<(String, Arc<Mutex<CircomIvc>>), ApiError> {
    let id = query
        .get("session")
        .ok_or_else(|| bad_request("missing `session` query parameter"))?;
    let mut sessions = lock(&state.sessions);
    // A session of another customer is indistinguishable from a missing one.
    let entry = sessions
        .get_mut(id)
        .filter(|e| e.customer == claims.customer)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown session".into()))?;
    let ivc = entry.ivc.clone().ok_or_else(|| {
        ApiError(
            StatusCode::CONFLICT,
            "the session is still being created".into(),
        )
    })?;
    entry.last_used = Instant::now();
    Ok((id.clone(), ivc))
}

/// Runs `work` on a session inside a job. The session is never waited for
/// (a busy one is a `409`), and a panic while it is being modified closes
/// it: its state can no longer be trusted.
fn with_session<T>(
    state: &AppState,
    id: &str,
    ivc: &Mutex<CircomIvc>,
    work: impl FnOnce(&mut CircomIvc) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let mut guard = match ivc.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "the session is busy with another request".into(),
            ))
        }
        Err(TryLockError::Poisoned(_)) => {
            remove_session(state, id);
            return Err(ApiError(StatusCode::NOT_FOUND, "unknown session".into()));
        }
    };
    match catch_unwind(AssertUnwindSafe(|| work(&mut guard))) {
        Ok(result) => result,
        Err(_) => {
            drop(guard);
            remove_session(state, id);
            Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "prover task failed; the session was closed".into(),
            ))
        }
    }
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let z0 = query
        .get("z0")
        .ok_or_else(|| bad_request("missing `z0` query parameter"))?
        .split(',')
        .map(|s| {
            Fr::from_str(s.trim()).map_err(|_| bad_request("`z0` must be decimal field elements"))
        })
        .collect::<Result<Vec<Fr>, _>>()?;
    let arity = z0.len();

    // Reserve a slot first: the count and the reservation are one step.
    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let id: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();
    {
        let mut sessions = lock(&state.sessions);
        let timeout = state.limits.session_idle_timeout;
        sessions.retain(|_, e| e.last_used.elapsed() < timeout);
        let owned = sessions
            .values()
            .filter(|e| e.customer == claims.customer)
            .count();
        if owned >= state.limits.max_sessions_per_customer {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many open sessions for this license".into(),
            ));
        }
        sessions.insert(
            id.clone(),
            Entry {
                customer: claims.customer.clone(),
                last_used: Instant::now(),
                ivc: None,
            },
        );
    }

    let limits = CircuitLimits {
        max_wires: state.limits.max_wires,
        max_constraints: state.limits.max_constraints,
    };
    let (shared, session_id) = (state.clone(), id.clone());
    let built = job(&state, move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let ivc = CircomIvc::new_with_limits(&body, z0, limits)?;
            bill(&shared, &claims.customer, Event::Session)?;
            Ok(ivc)
        }))
        .unwrap_or_else(|_| {
            Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "prover task failed".into(),
            ))
        });
        let mut sessions = lock(&shared.sessions);
        match result {
            Ok(ivc) => {
                // The slot may have been evicted meanwhile; then the session
                // simply does not exist.
                if let Some(entry) = sessions.get_mut(&session_id) {
                    entry.ivc = Some(Arc::new(Mutex::new(ivc)));
                    entry.last_used = Instant::now();
                }
                Ok(())
            }
            Err(e) => {
                sessions.remove(&session_id);
                Err(e)
            }
        }
    })
    .await;
    if let Err(e) = built {
        // Also when the job never started (no capacity).
        remove_session(&state, &id);
        return Err(e);
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({ "session_id": id, "arity": arity })),
    )
        .into_response())
}

async fn fold_step(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (id, session) = find_session(&state, &claims, &query)?;
    let shared = state.clone();
    let (steps, zi) = job(&state, move || {
        with_session(&shared, &id, &session, |ivc| {
            ivc.prove_step(&body, &mut rand::rngs::OsRng)?;
            Ok(())
        })?;
        // The step is folded: it is billed here, in the job, whether or not
        // the client is still connected. A step that cannot be billed is not
        // delivered: its session is closed.
        if let Err(e) = bill(&shared, &claims.customer, Event::FoldStep) {
            remove_session(&shared, &id);
            return Err(e);
        }
        with_session(&shared, &id, &session, |ivc| {
            Ok((ivc.acc.i, ivc.acc.zi.clone()))
        })
    })
    .await?;
    let state_strings: Vec<String> = zi.iter().map(|z| z.to_string()).collect();
    Ok(Json(json!({ "steps": steps, "state": state_strings })).into_response())
}

async fn finalize_snark(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let (id, session) = find_session(&state, &claims, &query)?;
    let shared = state.clone();
    let (steps, proof) = job(&state, move || {
        let out = with_session(&shared, &id, &session, |ivc| {
            Ok((ivc.acc.i, ivc.finalize(&mut rand::rngs::OsRng)?))
        })?;
        // No proof leaves the service unbilled; the session stays open so
        // that the request can be repeated.
        bill(&shared, &claims.customer, Event::Proof)?;
        remove_session(&shared, &id);
        Ok(out)
    })
    .await?;
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
    Extension(claims): Extension<Claims>,
) -> Result<Response, ApiError> {
    let (usage, head) = {
        let meter = lock(&state.meter);
        (meter.usage(&claims.customer), meter.head().to_string())
    };
    Ok(Json(json!({
        "customer": claims.customer,
        "plan": claims.plan,
        "license_expires_at": claims.expires_at,
        "sessions": usage.sessions,
        "fold_steps": usage.fold_steps,
        "proofs": usage.proofs,
        "log_head": head,
    }))
    .into_response())
}

/// Builds the HTTP application.
pub fn app(state: Arc<AppState>) -> Router {
    let body_limit = state.limits.max_body_bytes;
    let v1 = Router::new()
        .route("/v1/sessions", post(create_session))
        .route("/v1/fold-step", post(fold_step))
        .route("/v1/finalize-snark", post(finalize_snark))
        .route("/v1/usage", get(usage))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_license,
        ));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(v1)
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}
