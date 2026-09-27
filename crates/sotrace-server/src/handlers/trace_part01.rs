// Trace import and query handlers

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use sotrace_core::models::instruction_trace::InstructionTrace;
use sotrace_core::models::jni_call::JNICall;
use sotrace_core::models::call_trace::CallTrace;
use sotrace_core::models::register_delta::RegisterDelta;
use sotrace_core::models::thread::{
    ThreadInfo, ThreadSyncEvent, ContextSwitch, ThreadStateChange,
};
use sotrace_engine::TraceEngine;

use crate::app::AppState;
use crate::handlers::error::ApiError;

/// Trace import request — batches multiple trace event types into one import
///
/// All events are inserted into the TraceEngine for the given trace_id.
/// The engine is created on first import if it doesn't exist.
#[derive(Debug, Deserialize)]
pub struct TraceImportRequest {
    /// Trace ID
    pub trace_id: u64,
    /// SO file ID whose function table should be registered into the engine
    /// for function-name resolution in analysis results (race locations, JNI
    /// native addresses, thread-function associations). 0/absent = no SO
    /// (names stay None). Mirrors CLI `load_engine`'s so_file_id handling.
    #[serde(default)]
    pub so_file_id: Option<u64>,
    /// Threads to register (metadata)
    #[serde(default)]
    pub threads: Vec<ThreadInfo>,
    /// Instruction traces (must be in seq order)
    #[serde(default)]
    pub instructions: Vec<InstructionTrace>,
    /// Synchronization events
    #[serde(default)]
    pub sync_events: Vec<ThreadSyncEvent>,
    /// Context switches
    #[serde(default)]
    pub context_switches: Vec<ContextSwitch>,
    /// Thread state changes
    #[serde(default)]
    pub state_changes: Vec<ThreadStateChange>,
    /// Memory writes (address + data + thread)
    #[serde(default)]
    pub memory_writes: Vec<MemoryWriteInput>,
    /// Memory reads (address + size + thread) — fed to the analyzer for
    /// write→read race detection. Reads are not persisted into the memory
    /// store (only writes affect memory state), so they only matter during
    /// import for live analysis.
    #[serde(default)]
    pub memory_reads: Vec<MemoryReadInput>,
    /// JNI boundary-crossing calls (Java↔native)
    #[serde(default)]
    pub jni_calls: Vec<JNICall>,
    /// ARM64 register-change deltas (change_mask + new values at a step)
    #[serde(default)]
    pub register_deltas: Vec<RegisterDelta>,
    /// Function call/return events (CallTrace) for call-stack reconstruction
    #[serde(default)]
    pub calls: Vec<CallTrace>,
}

/// Memory write input (matches MemoryWrite but with serde-friendly shape)
#[derive(Debug, Deserialize)]
pub struct MemoryWriteInput {
    pub step: u64,
    pub thread_id: u32,
    pub address: u64,
    pub data: Vec<u8>,
}

/// Memory read input (serde-friendly shape for import). Reads are forwarded
/// to the analyzer for race detection; they are not stored as memory state.
#[derive(Debug, Deserialize)]
pub struct MemoryReadInput {
    pub step: u64,
    pub thread_id: u32,
    pub address: u64,
    pub size: usize,
}

/// Import result summary
#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub trace_id: u64,
    pub threads_imported: usize,
    pub instructions_imported: usize,
    pub sync_events_imported: usize,
    pub context_switches_imported: usize,
    pub state_changes_imported: usize,
    pub memory_writes_imported: usize,
    pub memory_reads_imported: usize,
    pub jni_calls_imported: usize,
    pub register_deltas_imported: usize,
    pub calls_imported: usize,
}

/// Query parameters for instruction queries
#[derive(Debug, Deserialize)]
pub struct InstructionQueryParams {
    pub start_step: Option<u64>,
    pub end_step: Option<u64>,
    pub thread_id: Option<u32>,
    pub address: Option<u64>,
    pub limit: Option<u64>,
}

/// Request body for `POST /traces/:id/save` (all fields optional).
#[derive(Debug, Default, Deserialize)]
pub struct SaveTraceRequest {
    pub so_file_id: Option<u64>,
    pub source: Option<String>,
}

/// Feed a single normalized event into an engine (used by import_trace and
/// load_trace to replay an event stream). Thin wrapper over the engine's own
/// `feed_event` dispatch table so all entry paths share one source of truth.
fn feed_event(engine: &mut TraceEngine, event: sotrace_core::adapters::TraceEvent) -> Result<(), String> {
    engine.feed_event(event).map_err(|e| e.to_string())
}

/// Load the persisted SO file `so_file_id` and register its function table
/// into `engine`, so analysis results resolve function names instead of bare
/// offsets. Mirrors CLI `load_engine`'s SO-registration step.
///
/// `so_file_id == 0` is the "no SO" sentinel and skips registration (the
/// caller passes `Option<u64>`; `None`/`0` are equivalent). A load failure
/// (e.g. the so_id is unknown) is logged and swallowed — the trace is still
/// usable, just with `None` function names — matching CLI's `.ok()` graceful
/// degradation. `SoRepository::load` is synchronous `std::fs` I/O, so it runs
/// in `spawn_blocking`; `register_parsed_so` is pure memory work done under
/// the engine lock.
async fn register_so_for_engine(state: &AppState, so_file_id: u64, engine: &tokio::sync::RwLock<TraceEngine>) {
    if so_file_id == 0 {
        return;
    }
    let data_dir = state.data_dir.clone();
    let parsed = tokio::task::spawn_blocking(move || {
        sotrace_engine::persistence::SoRepository::open(&data_dir)
            .and_then(|repo| repo.load(so_file_id))
    })
    .await;
    match parsed {
        Ok(Ok(parsed)) => {
            engine.write().await.register_parsed_so(&parsed);
        }
        Ok(Err(e)) => {
            eprintln!(
                "so-trace: warning: failed to load so_file_id {} for function-name resolution ({}); \
                 analysis will show bare offsets",
                so_file_id, e
            );
        }
        Err(e) => {
            eprintln!(
                "so-trace: warning: so load task for so_file_id {} join failed ({}); \
                 analysis will show bare offsets",
                so_file_id, e
            );
        }
    }
}

/// Persist the event stream of an in-memory trace to disk.
///
/// `POST /api/v1/traces/:id/save` with optional `{so_file_id, source}` body.
/// Returns the assigned persisted trace ID.
async fn save_trace(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
    Json(req): Json<SaveTraceRequest>,
) -> impl IntoResponse {
    let events = match state.take_event_buffer(trace_id).await {
        Some(e) => e,
        None => {
            state.record_save_failure();
            return ApiError::not_found(
                "no in-memory trace",
                format!("no event buffer for trace id {} (import first)", trace_id),
            ).into_response();
        }
    };
    let so_file_id = req.so_file_id.unwrap_or(0);
    let source = req.source.unwrap_or_else(|| "http".to_string());
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let trace = sotrace_engine::persistence::PersistedTrace {
        trace_id: 0,
        so_file_id,
        source,
        base_addr: 0,
        events,
        created_at,
    };
    let data_dir = state.data_dir.clone();
    let saved = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)?;
        repo.save(trace)
    })
    .await;
    match saved {
        Ok(Ok(persisted_id)) => Json(serde_json::json!({
            "status": "ok",
            "persisted_id": persisted_id,
            "source_trace_id": trace_id,
        })).into_response(),
        Ok(Err(e)) => {
            state.record_save_failure();
            ApiError::internal(
                "failed to persist trace",
                format!("trace id {}: {}", trace_id, e),
            ).into_response()
        }
        Err(e) => {
            state.record_save_failure();
            ApiError::internal(
                "save task join failed",
                e.to_string(),
            ).into_response()
        }
    }
}

/// List all persisted traces (summaries only).
async fn list_persisted_traces(State(state): State<AppState>) -> impl IntoResponse {
    let data_dir = state.data_dir.clone();
    let result = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)?;
        repo.list()
    })
    .await;
    match result {
        Ok(Ok(summaries)) => {
            let traces: Vec<serde_json::Value> = summaries.iter().map(|s| serde_json::json!({
                "trace_id": s.trace_id,
                "so_file_id": s.so_file_id,
                "source": s.source,
                "base_addr": s.base_addr,
                "event_count": s.event_count,
                "created_at": s.created_at,
            })).collect();
            Json(serde_json::json!({
                "trace_count": traces.len(),
                "traces": traces,
            })).into_response()
        }
        Ok(Err(e)) => ApiError::internal(
            "failed to list persisted traces",
            e.to_string(),
        ).into_response(),
        Err(e) => ApiError::internal(
            "list task join failed",
            e.to_string(),
        ).into_response(),
    }
}

/// Get a single persisted trace summary by ID.
async fn get_persisted_trace(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let data_dir = state.data_dir.clone();
    let result = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)?;
        repo.summary(trace_id)
    })
    .await;
    match result {
        Ok(Ok(Some(s))) => Json(serde_json::json!({
            "trace_id": s.trace_id,
            "so_file_id": s.so_file_id,
            "source": s.source,
            "base_addr": s.base_addr,
            "event_count": s.event_count,
            "created_at": s.created_at,
        })).into_response(),
        Ok(Ok(None)) => ApiError::not_found(
            "not found",
            format!("no persisted trace with id {}", trace_id),
        ).into_response(),
        Ok(Err(e)) => ApiError::internal(
            "failed to load trace summary",
            format!("trace id {}: {}", trace_id, e),
        ).into_response(),
        Err(e) => ApiError::internal(
            "task join failed",
            e.to_string(),
        ).into_response(),
    }
}

/// Replay a persisted trace into the in-memory engine pool by its persisted ID.
///
/// `POST /api/v1/traces/persisted/:id/load`. The replayed trace becomes
/// available for all query/analyze endpoints under the same persisted ID.
async fn load_trace(
    State(state): State<AppState>,
    Path(persisted_id): Path<u64>,
) -> impl IntoResponse {
    let data_dir = state.data_dir.clone();
    let loaded = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)?;
        // Distinguish "missing" (404) from a real I/O / deserialize failure
        // (500): `TraceRepository::load` returns Err for both, so probe with
        // `summary` (which returns Option) before attempting the heavier load.
        match repo.summary(persisted_id)? {
            None => Ok::<_, anyhow::Error>(None),
            Some(_) => Ok(Some(repo.load(persisted_id)?)),
        }
    })
    .await;
    let persisted = match loaded {
        Ok(Ok(Some(p))) => p,
        Ok(Ok(None)) => return ApiError::not_found(
            "not found",
            format!("no persisted trace with id {}", persisted_id),
        ).into_response(),
        Ok(Err(e)) => return ApiError::internal(
            "failed to load persisted trace",
            format!("persisted id {}: {}", persisted_id, e),
        ).into_response(),
        Err(e) => return ApiError::internal(
            "load task join failed",
            e.to_string(),
        ).into_response(),
    };
    let event_count = persisted.events.len();
    let so_file_id = persisted.so_file_id;
    let engine = state.get_or_create_engine(persisted_id).await;
    let mut guard = engine.write().await;
    let mut sorted = persisted.events;
    sorted.sort_by_key(|e| e.step());
    for ev in sorted {
        if let Err(detail) = feed_event(&mut guard, ev) {
            return ApiError::internal(
                "failed to replay event",
                format!("persisted id {}: {}", persisted_id, detail),
            ).into_response();
        }
    }
    drop(guard);

    // Register the SO function table the persisted trace references, so
    // analysis after load resolves function names (parity with CLI load_engine,
    // which loads so_file_id from the persisted trace and registers it).
    register_so_for_engine(&state, so_file_id, &engine).await;

    state.store_event_buffer(persisted_id, Vec::new()).await;
    Json(serde_json::json!({
        "status": "ok",
        "persisted_id": persisted_id,
        "so_file_id": so_file_id,
        "event_count": event_count,
    })).into_response()
}

/// Delete a persisted trace by ID.
async fn delete_persisted_trace(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let data_dir = state.data_dir.clone();
    let result = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)?;
        repo.delete(trace_id)
    })
    .await;
    match result {
        Ok(Ok(true)) => Json(serde_json::json!({
            "status": "deleted",
            "trace_id": trace_id,
        })).into_response(),
        Ok(Ok(false)) => ApiError::not_found(
            "not found",
            format!("no persisted trace with id {} to delete", trace_id),
        ).into_response(),
        Ok(Err(e)) => ApiError::internal(
            "failed to delete persisted trace",
            format!("trace id {}: {}", trace_id, e),
        ).into_response(),
        Err(e) => ApiError::internal(
            "delete task join failed",
            e.to_string(),
        ).into_response(),
    }
}

/// Trace routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/api/v1/traces/import", axum::routing::post(import_trace))
        .route("/api/v1/traces", axum::routing::get(list_traces))
        .route("/api/v1/traces/:id/instructions", axum::routing::get(query_instructions))
        // Persistence: save/load/list/delete persisted trace event streams.
        .route("/api/v1/traces/:id/save", axum::routing::post(save_trace))
        .route("/api/v1/traces/persisted", axum::routing::get(list_persisted_traces))
        .route(
            "/api/v1/traces/persisted/:id",
            axum::routing::get(get_persisted_trace).delete(delete_persisted_trace),
        )
        .route("/api/v1/traces/persisted/:id/load", axum::routing::post(load_trace))
}
