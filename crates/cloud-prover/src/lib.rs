//! `cloud-prover` — the ZenoLlull-Cloud-Prover service (spec Paketa B).
//!
//! | Method | Path | Body | Result |
//! |---|---|---|---|
//! | `POST` | `/v1/sessions?z0=3,5[&mode=M]` | Circom `.r1cs` | `{"session_id", "arity", "mode"}` (+ `vk`, `open_session` in mode `universal`) |
//! | `POST` | `/v1/fold-step?session=ID` | Circom `.wtns` of the step | `{"steps", "state"}` |
//! | `POST` | `/v1/finalize-snark?session=ID` | — | mode `transparent`: succinct ZK proof (binary) |
//! | `POST` | `/v1/finalize-evm?session=ID[&onchain=0x…]` | — | modes `universal` / `recursive`: the calldata to send (JSON) |
//! | `GET` | `/v1/usage` | — | metered usage of the caller |
//! | `GET` | `/healthz` | — | `ok` |
//! | `GET` | `/metrics` | — | Prometheus text: sessions, jobs, caches |
//!
//! Modes (see [`provers`]): `transparent` (default, mode A, off-chain proof),
//! `universal` (mode B: the contract folds the steps; `finalize-evm` with the
//! on-chain session id returns `verifyFoldedProofBatch` and
//! `finalizeUniversal`), `recursive` (mode D: `finalize-evm` starts the
//! recursive proof in the background and answers `202` until it returns the
//! `finalizeRecursive` call). Modes B and D need a reference string loaded at
//! start (`ZENO_PTAU_PATH`, 2^20 powers for mode D).
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
//! * nothing a client sends is written to disk: circuits, witnesses and
//!   prover states live in memory for the session only. When a session ends
//!   (finalized, failed, or idle for [`Limits::session_idle_timeout`]) its
//!   prover is dropped and every witness in it is overwritten with zeros; a
//!   step's wire values are wiped as soon as the step is folded. What stays
//!   for [`Limits::proof_retention`] is only the answer (a zero-knowledge
//!   proof or public calldata), and `ZENO_PROOF_RETENTION_SECS=0` keeps
//!   nothing at all. The usage log holds customer, time and event only;
//! * a session slot is reserved before the session is built, so the limit
//!   per license holds under concurrent requests;
//! * every folded step, proof and session is recorded in the usage log
//!   **inside** the job that produced it, so a client that disconnects early
//!   is still billed; if the record cannot be written, the step's session is
//!   closed and no proof is returned — nothing is given away unbilled;
//! * the license's step quota (`max_steps`) holds per session (`403`);
//! * a finished proof stays available for [`Limits::proof_retention`]:
//!   repeating `finalize-snark` for the session returns it again, unbilled,
//!   so a client that lost the connection does not lose what it paid for;
//! * sessions of the same circuit share its parameters (by SHA-256 of the
//!   `.r1cs`), and a background task ([`spawn_sweeper`]) closes idle
//!   sessions and drops expired proofs.
//!
//! `/metrics` and `/healthz` carry no customer data and need no license;
//! expose them to the operator's network only.
#![forbid(unsafe_code)]

pub mod metering;
pub mod provers;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Extension, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use evm_verifier::kzg::Srs;
use metering::{Event, Meter};
use provers::{Cached, Mode, Params, Prover};
use rand::RngCore;
use sdk_bindings::{
    circom::{CircuitLimits, SdkError},
    onchain::{parse_session, to_hex},
    Fr,
};
use serde_json::json;
use sha2::{Digest, Sha256};
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
    /// How long a finished proof can be fetched again (unbilled) by
    /// repeating `finalize-snark` / `finalize-evm` for its session.
    pub proof_retention: Duration,
    /// Recursive (mode D) proofs running at the same time; each takes
    /// about 2 GB of memory and tens of seconds.
    pub max_recursive_jobs: usize,
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
            proof_retention: Duration::from_secs(10 * 60),
            max_recursive_jobs: 1,
        }
    }
}

/// A session slot. `ivc` is `None` while the session is being built: the
/// slot already counts against the customer's limit.
struct Entry {
    customer: String,
    last_used: Instant,
    ivc: Option<Arc<Mutex<Prover>>>,
    /// A recursive proof of this session is running in the background.
    proving: bool,
}

/// The answer of a finalization (a proof, or the calldata to send; or why
/// it failed), kept for a while so that it can be fetched again unbilled.
struct Finished {
    customer: String,
    steps: u64,
    status: StatusCode,
    /// `application/octet-stream` (mode A proof) or JSON.
    json: bool,
    body: Arc<Vec<u8>>,
    at: Instant,
}

/// Shared service state.
pub struct AppState {
    vendor_public_key: [u8; 32],
    limits: Limits,
    /// Held only for map operations, never while proving and never while
    /// waiting for a session.
    sessions: Mutex<HashMap<String, Entry>>,
    /// Answers of finished sessions, by session id.
    finished: Mutex<HashMap<String, Finished>>,
    /// Parameters of the circuits in use, by SHA-256 of the `.r1cs` and
    /// mode. Weak: they live as long as one of their sessions does.
    circuits: Mutex<HashMap<([u8; 32], Mode), Cached>>,
    pub meter: Mutex<Meter>,
    jobs: Arc<Semaphore>,
    recursive_jobs: Arc<Semaphore>,
    /// The reference string of modes B and D, loaded once at start.
    srs: Option<Arc<Srs>>,
}

impl AppState {
    /// A service for mode A only.
    pub fn new(vendor_public_key: [u8; 32], limits: Limits, meter: Meter) -> Arc<Self> {
        Self::with_reference_string(vendor_public_key, limits, meter, None)
    }

    /// A service that also runs the EVM modes over `srs` (shared by every
    /// session; mode D needs 2^20 powers).
    pub fn with_reference_string(
        vendor_public_key: [u8; 32],
        limits: Limits,
        meter: Meter,
        srs: Option<Arc<Srs>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            vendor_public_key,
            jobs: Arc::new(Semaphore::new(limits.max_parallel_jobs.max(1))),
            recursive_jobs: Arc::new(Semaphore::new(limits.max_recursive_jobs.max(1))),
            limits,
            sessions: Mutex::new(HashMap::new()),
            finished: Mutex::new(HashMap::new()),
            circuits: Mutex::new(HashMap::new()),
            meter: Mutex::new(meter),
            srs,
        })
    }

    /// Recursive proofs running now.
    pub fn running_recursive_jobs(&self) -> usize {
        self.limits
            .max_recursive_jobs
            .max(1)
            .saturating_sub(self.recursive_jobs.available_permits())
    }

    /// Number of session slots (ready or being built), for tests and
    /// monitoring.
    pub fn session_count(&self) -> usize {
        lock(&self.sessions).len()
    }

    /// Number of circuits whose parameters are in memory.
    pub fn circuit_count(&self) -> usize {
        lock(&self.circuits).values().filter(|c| c.alive()).count()
    }

    /// Number of finished proofs still available for fetching again.
    pub fn retained_proofs(&self) -> usize {
        lock(&self.finished).len()
    }

    /// Proving jobs running now.
    pub fn running_jobs(&self) -> usize {
        self.limits
            .max_parallel_jobs
            .max(1)
            .saturating_sub(self.jobs.available_permits())
    }

    /// Closes idle sessions, drops expired proofs and forgets the
    /// parameters of circuits no session uses any more. Runs every minute
    /// in the background ([`spawn_sweeper`]) and before a session is
    /// created.
    pub fn sweep(&self) {
        let timeout = self.limits.session_idle_timeout;
        // A slot still being built, or with a proof running, is never idle.
        lock(&self.sessions)
            .retain(|_, e| e.ivc.is_none() || e.proving || e.last_used.elapsed() < timeout);
        let retention = self.limits.proof_retention;
        lock(&self.finished).retain(|_, f| f.at.elapsed() < retention);
        lock(&self.circuits).retain(|_, c| c.alive());
    }

    /// The parameters of a circuit for `mode`, shared with every session of
    /// the same `.r1cs` and mode, or derived (and remembered).
    fn circuit(&self, mode: Mode, r1cs: &[u8], limits: CircuitLimits) -> Result<Params, SdkError> {
        let id: [u8; 32] = Sha256::digest(r1cs).into();
        if let Some(params) = lock(&self.circuits)
            .get(&(id, mode))
            .and_then(Params::from_cache)
        {
            return Ok(params);
        }
        // Derived without holding the lock; two first sessions of the same
        // circuit at once may both derive it, and the later one is kept.
        let params = Params::derive(mode, r1cs, limits, self.srs.as_deref())?;
        lock(&self.circuits).insert((id, mode), params.cache());
        Ok(params)
    }
}

/// Runs [`AppState::sweep`] every `every` on the Tokio runtime.
pub fn spawn_sweeper(state: Arc<AppState>, every: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            state.sweep();
        }
    })
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
            SdkError::QuotaExceeded { .. } => StatusCode::FORBIDDEN,
            SdkError::Evm(_) => StatusCode::UNPROCESSABLE_ENTITY,
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
) -> Result<(String, Arc<Mutex<Prover>>), ApiError> {
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
    if entry.proving {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "the session's recursive proof is running".into(),
        ));
    }
    entry.last_used = Instant::now();
    Ok((id.clone(), ivc))
}

/// Runs `work` on a session inside a job. The session is never waited for
/// (a busy one is a `409`), and a panic while it is being modified closes
/// it: its state can no longer be trusted.
fn with_session<T>(
    state: &AppState,
    id: &str,
    ivc: &Mutex<Prover>,
    work: impl FnOnce(&mut Prover) -> Result<T, ApiError>,
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
    let mode = Mode::parse(query.get("mode").map(String::as_str)).map_err(|e| bad_request(&e))?;
    if mode != Mode::Transparent && state.srs.is_none() {
        return Err(bad_request(
            "EVM modes are not enabled on this service (it has no reference string)",
        ));
    }

    // Reserve a slot first: the count and the reservation are one step.
    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let id: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();
    state.sweep();
    {
        let mut sessions = lock(&state.sessions);
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
                proving: false,
            },
        );
    }

    let limits = CircuitLimits {
        max_wires: state.limits.max_wires,
        max_constraints: state.limits.max_constraints,
    };
    let (shared, session_id) = (state.clone(), id.clone());
    let built: Result<Option<(String, String)>, ApiError> = job(&state, move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let prover = shared.circuit(mode, &body, limits)?.start(z0)?;
            bill(&shared, &claims.customer, Event::Session)?;
            Ok(prover)
        }))
        .unwrap_or_else(|_| {
            Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "prover task failed".into(),
            ))
        });
        let mut sessions = lock(&shared.sessions);
        match result {
            Ok(prover) => {
                // Mode B: what the client needs to open the session on-chain.
                let onchain = match &prover {
                    Prover::Universal(p) => {
                        Some((to_hex(&p.vk()), to_hex(&p.open_session_calldata())))
                    }
                    _ => None,
                };
                // The slot may have been evicted meanwhile; then the session
                // simply does not exist.
                if let Some(entry) = sessions.get_mut(&session_id) {
                    entry.ivc = Some(Arc::new(Mutex::new(prover)));
                    entry.last_used = Instant::now();
                }
                Ok(onchain)
            }
            Err(e) => {
                sessions.remove(&session_id);
                Err(e)
            }
        }
    })
    .await;
    let onchain = match built {
        Ok(onchain) => onchain,
        Err(e) => {
            // Also when the job never started (no capacity).
            remove_session(&state, &id);
            return Err(e);
        }
    };
    let mut body = json!({ "session_id": id, "arity": arity, "mode": mode.name() });
    if let Some((vk, open)) = onchain {
        body["vk"] = vk.into();
        body["open_session"] = open.into();
    }
    Ok((StatusCode::CREATED, Json(body)).into_response())
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
            // The license's quota: steps one prover (session) may fold.
            if let Some(max_steps) = claims.max_steps {
                if ivc.steps() >= max_steps {
                    return Err(SdkError::QuotaExceeded { max_steps }.into());
                }
            }
            ivc.prove_step(&body)?;
            Ok(())
        })?;
        // The step is folded: it is billed here, in the job, whether or not
        // the client is still connected. A step that cannot be billed is not
        // delivered: its session is closed.
        if let Err(e) = bill(&shared, &claims.customer, Event::FoldStep) {
            remove_session(&shared, &id);
            return Err(e);
        }
        with_session(&shared, &id, &session, |ivc| Ok((ivc.steps(), ivc.state())))
    })
    .await?;
    Ok(Json(json!({ "steps": steps, "state": zi })).into_response())
}

async fn finalize_snark(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    // A proof already delivered for this session is handed out again,
    // unbilled, while it is retained.
    if let Some(response) = retained(&state, &claims, &query, false) {
        return Ok(response);
    }
    let (id, session) = find_session(&state, &claims, &query)?;
    let shared = state.clone();
    let customer = claims.customer.clone();
    let (steps, proof) = job(&state, move || {
        let (steps, proof) = with_session(&shared, &id, &session, |prover| match prover {
            Prover::Transparent(ivc) => Ok((ivc.acc.i, ivc.finalize(&mut rand::rngs::OsRng)?)),
            other => Err(ApiError(
                StatusCode::CONFLICT,
                format!(
                    "a {} session is finalized with /v1/finalize-evm",
                    other.mode().name()
                ),
            )),
        })?;
        // No proof leaves the service unbilled; the session stays open so
        // that the request can be repeated.
        bill(&shared, &customer, Event::Proof)?;
        // Billed: from now on the proof is the customer's. It is kept for a
        // while, so that a client that lost the answer can fetch it again,
        // and the session is closed.
        let proof = Arc::new(proof);
        retain(
            &shared,
            &id,
            customer,
            steps,
            StatusCode::OK,
            false,
            proof.clone(),
        );
        remove_session(&shared, &id);
        Ok((steps, proof))
    })
    .await?;
    Ok(answer(StatusCode::OK, steps, false, &proof, false))
}

/// Keeps a finalization's answer for [`Limits::proof_retention`].
fn retain(
    state: &AppState,
    id: &str,
    customer: String,
    steps: u64,
    status: StatusCode,
    json: bool,
    body: Arc<Vec<u8>>,
) {
    lock(&state.finished).insert(
        id.to_string(),
        Finished {
            customer,
            steps,
            status,
            json,
            body,
            at: Instant::now(),
        },
    );
}

/// The retained answer of the session in `query`, if any (of the right
/// kind: a binary proof, or JSON calldata).
fn retained(
    state: &AppState,
    claims: &Claims,
    query: &HashMap<String, String>,
    json: bool,
) -> Option<Response> {
    let id = query.get("session")?;
    let finished = lock(&state.finished);
    let retention = state.limits.proof_retention;
    let f = finished
        .get(id)
        .filter(|f| f.customer == claims.customer && f.json == json)
        .filter(|f| f.at.elapsed() < retention)?;
    Some(answer(f.status, f.steps, f.json, &f.body, true))
}

fn answer(status: StatusCode, steps: u64, json: bool, body: &[u8], repeated: bool) -> Response {
    let content_type = if json {
        "application/json"
    } else {
        "application/octet-stream"
    };
    (
        status,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::HeaderName::from_static("x-zeno-steps"),
                steps.to_string(),
            ),
            (
                header::HeaderName::from_static("x-zeno-repeated"),
                repeated.to_string(),
            ),
        ],
        body.to_vec(),
    )
        .into_response()
}

/// `POST /v1/finalize-evm?session=ID[&onchain=0x…]`: the calldata that
/// decides a mode-B or mode-D session on-chain (JSON, see [`provers`]).
///
/// * `universal`: needs `onchain`, the id the contract returned from
///   `openSession`; answers at once with `verifyFoldedProofBatch` (the steps
///   not yet on-chain) and `finalizeUniversal`.
/// * `recursive`: starts the proof in the background and answers `202`;
///   repeating the request answers `202` while it runs, then the
///   `finalizeRecursive` call.
///
/// The answer is billed once and retained like a proof.
async fn finalize_evm(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    if let Some(response) = retained(&state, &claims, &query, true) {
        return Ok(response);
    }
    let running = |id: &str| Json(json!({ "session_id": id, "status": "running" }));
    // A recursive proof already running for this session.
    if let Some(id) = query.get("session") {
        let proving = lock(&state.sessions)
            .get(id)
            .filter(|e| e.customer == claims.customer)
            .is_some_and(|e| e.proving);
        if proving {
            return Ok((StatusCode::ACCEPTED, running(id)).into_response());
        }
    }
    let (id, session) = find_session(&state, &claims, &query)?;
    let mode = match session.try_lock() {
        Ok(prover) => prover.mode(),
        Err(_) => {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "the session is busy with another request".into(),
            ))
        }
    };
    let customer = claims.customer.clone();
    match mode {
        Mode::Transparent => Err(ApiError(
            StatusCode::CONFLICT,
            "a transparent session is finalized with /v1/finalize-snark".into(),
        )),
        Mode::Universal => {
            let onchain = query.get("onchain").ok_or_else(|| {
                bad_request(
                    "missing `onchain`: the session id the contract returned from openSession",
                )
            })?;
            let onchain = parse_session(onchain)?;
            let shared = state.clone();
            let (steps, body) = job(&state, move || {
                let answer = with_session(&shared, &id, &session, |prover| {
                    Ok((prover.steps(), prover.finalize_universal(&onchain)?))
                })?;
                bill(&shared, &customer, Event::Proof)?;
                let body = Arc::new(answer.1.to_string().into_bytes());
                retain(
                    &shared,
                    &id,
                    customer,
                    answer.0,
                    StatusCode::OK,
                    true,
                    body.clone(),
                );
                remove_session(&shared, &id);
                Ok((answer.0, body))
            })
            .await?;
            Ok(answer(StatusCode::OK, steps, true, &body, false))
        }
        Mode::Recursive => {
            let permit = state
                .recursive_jobs
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    ApiError(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "the recursive prover is at capacity; retry shortly".into(),
                    )
                })?;
            if let Some(entry) = lock(&state.sessions).get_mut(&id) {
                entry.proving = true;
            }
            let shared = state.clone();
            let session_id = id.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mut prover = session.lock().unwrap_or_else(|e| e.into_inner());
                    let Prover::Recursive(s) = &mut *prover else {
                        unreachable!("the mode was checked");
                    };
                    s.finalize()
                        .map(|v| (v["steps"].as_u64().unwrap_or_default(), v))
                }))
                .unwrap_or_else(|_| Err(SdkError::Evm("prover task failed".into())));
                let id = session_id;
                match result {
                    Ok((steps, value)) => {
                        let body = Arc::new(value.to_string().into_bytes());
                        match bill(&shared, &customer, Event::RecursiveProof) {
                            Ok(()) => {
                                retain(&shared, &id, customer, steps, StatusCode::OK, true, body);
                                remove_session(&shared, &id);
                            }
                            // Not billed, not delivered: the session stays,
                            // the client may ask again.
                            Err(_) => {
                                if let Some(entry) = lock(&shared.sessions).get_mut(&id) {
                                    entry.proving = false;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Not billed. The error is kept like an answer; the
                        // session is closed (its state cannot be proven).
                        let status = ApiError::from(e);
                        let body = json!({ "error": status.1 }).to_string().into_bytes();
                        retain(&shared, &id, customer, 0, status.0, true, Arc::new(body));
                        remove_session(&shared, &id);
                    }
                }
            });
            Ok((StatusCode::ACCEPTED, running(&id)).into_response())
        }
    }
}

/// Operator metrics in the Prometheus text format. No customer data.
async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let gauges = [
        (
            "zeno_sessions",
            "Session slots (ready or being built).",
            state.session_count(),
        ),
        (
            "zeno_jobs_running",
            "Proving jobs running now.",
            state.running_jobs(),
        ),
        (
            "zeno_jobs_capacity",
            "Proving jobs allowed at the same time.",
            state.limits.max_parallel_jobs.max(1),
        ),
        (
            "zeno_circuits_cached",
            "Circuits whose parameters are in memory.",
            state.circuit_count(),
        ),
        (
            "zeno_proofs_retained",
            "Finished proofs available for fetching again.",
            state.retained_proofs(),
        ),
        (
            "zeno_recursive_jobs_running",
            "Recursive (mode D) proofs running now.",
            state.running_recursive_jobs(),
        ),
        (
            "zeno_evm_modes",
            "1 if a reference string is loaded (modes universal and recursive).",
            usize::from(state.srs.is_some()),
        ),
    ];
    let mut body = String::new();
    for (name, help, value) in gauges {
        body.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
        ));
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
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
        "recursive_proofs": usage.recursive_proofs,
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
        .route("/v1/finalize-evm", post(finalize_evm))
        .route("/v1/usage", get(usage))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_license,
        ));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .merge(v1)
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}
