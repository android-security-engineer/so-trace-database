
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::handlers::error::ApiError;
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadSummary {
    pub thread_id: u32,
    pub name: Option<String>,
    pub parent_thread_id: u32,
    pub create_step: u64,
    pub exit_step: Option<u64>,
    pub is_jni_attached: bool,
    pub stack_base: u64,
    pub stack_size: u64,
}

impl From<sotrace_core::models::thread::ThreadInfo> for ThreadSummary {
    fn from(info: sotrace_core::models::thread::ThreadInfo) -> Self {
        Self {
            thread_id: info.thread_id,
            name: info.name,
            parent_thread_id: info.parent_thread_id,
            create_step: info.create_step,
            exit_step: info.exit_step,
            is_jni_attached: info.is_jni_attached,
            stack_base: info.stack_base,
            stack_size: info.stack_size,
        }
    }
}

/// Query parameters for listing threads
#[derive(Debug, Deserialize)]
pub struct ListThreadsQuery {
    /// Include statistics
    pub include_stats: Option<bool>,
}

/// Query parameters for sync event queries
#[derive(Debug, Deserialize)]
pub struct SyncEventQuery {
    pub thread_id: Option<u32>,
    pub sync_object_addr: Option<u64>,
    pub start_step: Option<u64>,
    pub end_step: Option<u64>,
}

/// Query parameters for context switch queries
#[derive(Debug, Deserialize)]
pub struct ContextSwitchQueryParams {
    pub start_step: Option<u64>,
    pub end_step: Option<u64>,
    pub thread_id: Option<u32>,
}

/// Query parameters for thread timeline
#[derive(Debug, Deserialize)]
pub struct ThreadTimelineQuery {
    pub start_step: Option<u64>,
    pub end_step: Option<u64>,
}

/// Build the thread analysis routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        // Thread listing and info
        .route("/api/v1/traces/:id/threads", axum::routing::get(list_threads))
        .route("/api/v1/traces/:id/threads/:thread_id", axum::routing::get(get_thread))
        .route("/api/v1/traces/:id/threads/:thread_id/timeline", axum::routing::get(get_thread_timeline))
        .route("/api/v1/traces/:id/threads/:thread_id/sync-events", axum::routing::get(get_thread_sync_events))
        // Sync event and context switch queries
        .route("/api/v1/traces/:id/threads/sync-events", axum::routing::get(query_sync_events))
        .route("/api/v1/traces/:id/threads/context-switches", axum::routing::get(query_context_switches))
        // Analysis endpoints
        .route("/api/v1/traces/:id/analyze/threads", axum::routing::post(analyze_threads))
        .route("/api/v1/traces/:id/analyze/threads/races", axum::routing::get(detect_races))
        .route("/api/v1/traces/:id/analyze/threads/deadlocks", axum::routing::get(detect_deadlocks))
        .route("/api/v1/traces/:id/analyze/threads/contentions", axum::routing::get(analyze_contentions))
        .route("/api/v1/traces/:id/analyze/threads/function-safety", axum::routing::get(classify_function_safety))
        .route("/api/v1/traces/:id/analyze/threads/function-assoc", axum::routing::get(analyze_function_assoc))
        .route("/api/v1/traces/:id/analyze/threads/data-flows", axum::routing::get(analyze_data_flows))
        .route("/api/v1/traces/:id/analyze/threads/producer-consumer", axum::routing::get(detect_producer_consumer))
        .route("/api/v1/traces/:id/analyze/threads/scheduling", axum::routing::get(analyze_scheduling))
        .route("/api/v1/traces/:id/analyze/threads/lifecycle", axum::routing::get(analyze_thread_lifecycle))
        .route("/api/v1/traces/:id/analyze/threads/states", axum::routing::get(analyze_thread_states))
        .route("/api/v1/traces/:id/analyze/threads/critical-sections", axum::routing::get(analyze_critical_sections))
        .route("/api/v1/traces/:id/analyze/threads/jni-boundary", axum::routing::get(analyze_jni_boundary))
}

/// List all threads in a trace
async fn list_threads(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
    Query(params): Query<ListThreadsQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let threads: Vec<ThreadSummary> = engine.all_thread_ids()
        .into_iter()
        .filter_map(|tid| engine.get_thread_info(tid).cloned())
        .map(ThreadSummary::from)
        .collect();

    let thread_count = threads.len();

    let mut response = serde_json::json!({
        "trace_id": trace_id,
        "thread_count": thread_count,
        "threads": threads,
    });

    if params.include_stats.unwrap_or(false) {
        response["stats"] = serde_json::to_value(engine.all_thread_stats()).unwrap_or(serde_json::Value::Null);
    }

    Json(response)
}

/// Get a single thread's info
async fn get_thread(
    State(state): State<AppState>,
    Path((trace_id, thread_id)): Path<(u64, u32)>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    match engine.get_thread_info(thread_id) {
        Some(info) => {
            let summary = ThreadSummary::from(info.clone());
            Json(serde_json::json!({
                "trace_id": trace_id,
                "thread": summary,
            })).into_response()
        }
        None => ApiError::not_found(
            "thread not found",
            format!("trace {} has no thread {}", trace_id, thread_id),
        ).into_response(),
    }
}

/// Get a thread's timeline (state changes + sync events + context switches)
async fn get_thread_timeline(
    State(state): State<AppState>,
    Path((trace_id, thread_id)): Path<(u64, u32)>,
    Query(params): Query<ThreadTimelineQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let start = params.start_step.unwrap_or(0);
    let end = params.end_step.unwrap_or(u64::MAX);

    let timeline = engine.query_thread_timeline(thread_id, start, end);

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_id": thread_id,
        "timeline": timeline,
    }))
}

/// Get sync events for a specific thread
async fn get_thread_sync_events(
    State(state): State<AppState>,
    Path((trace_id, thread_id)): Path<(u64, u32)>,
    Query(params): Query<ThreadTimelineQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let start = params.start_step.unwrap_or(0);
    let end = params.end_step.unwrap_or(u64::MAX);

    let events: Vec<_> = engine.query_thread_sync_events(thread_id, start, end)
        .into_iter()
        .cloned()
        .collect();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_id": thread_id,
        "event_count": events.len(),
        "events": events,
    }))
}

/// Query sync events with optional filters (thread_id, sync_object_addr, step range)
async fn query_sync_events(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
    Query(params): Query<SyncEventQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let start = params.start_step.unwrap_or(0);
    let end = params.end_step.unwrap_or(u64::MAX);

    let events: Vec<_> = if let Some(lock_addr) = params.sync_object_addr {
        engine.query_lock_contentions(lock_addr, start, end)
            .into_iter()
            .filter(|e| params.thread_id.map_or(true, |tid| e.thread_id == tid))
            .cloned()
            .collect()
    } else if let Some(tid) = params.thread_id {
        engine.query_thread_sync_events(tid, start, end)
            .into_iter()
            .cloned()
            .collect()
    } else {
        // All sync events in range
        let mut all = Vec::new();
        for tid in engine.all_thread_ids() {
            all.extend(engine.query_thread_sync_events(tid, start, end).into_iter().cloned());
        }
        all.sort_by_key(|e| e.step);
        all
    };

    let count = events.len();
    Json(serde_json::json!({
        "trace_id": trace_id,
        "event_count": count,
        "events": events,
    }))
}

/// Query context switches with optional filters
async fn query_context_switches(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
    Query(params): Query<ContextSwitchQueryParams>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let start = params.start_step.unwrap_or(0);
    let end = params.end_step.unwrap_or(u64::MAX);

    let switches: Vec<_> = engine.query_context_switches(start, end)
        .into_iter()
        .filter(|s| params.thread_id.map_or(true, |tid| s.from_thread == tid || s.to_thread == tid))
        .cloned()
        .collect();

    let count = switches.len();
    Json(serde_json::json!({
        "trace_id": trace_id,
        "switch_count": count,
        "context_switches": switches,
    }))
}

/// Run comprehensive thread analysis (all analysis passes)
async fn analyze_threads(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let result = engine.analyze_threads();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "analysis": result,
    }))
}

/// Detect race conditions only
async fn detect_races(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let races = engine.detect_race_conditions();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "race_count": races.len(),
        "races": races,
    }))
}

/// Detect deadlock risks only
async fn detect_deadlocks(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let deadlocks = engine.detect_deadlocks();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "deadlock_count": deadlocks.len(),
        "deadlocks": deadlocks,
    }))
}

/// Analyze lock contentions only
async fn analyze_contentions(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let contentions = engine.analyze_lock_contention();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "contention_count": contentions.len(),
        "contentions": contentions,
    }))
}

/// Classify function thread safety only
async fn classify_function_safety(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let safety = engine.classify_function_thread_safety();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "function_count": safety.len(),
        "function_safety": safety,
    }))
}

/// Analyze thread-function associations only
async fn analyze_function_assoc(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let assocs = engine.analyze_thread_function_assoc();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "assoc_count": assocs.len(),
        "thread_function_assocs": assocs,
    }))
}

/// Analyze inter-thread data flows only
async fn analyze_data_flows(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let flows = engine.analyze_data_flows();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "flow_count": flows.len(),
        "data_flows": flows,
    }))
}

/// Detect producer-consumer patterns only
async fn detect_producer_consumer(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let patterns = engine.detect_producer_consumer();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "pattern_count": patterns.len(),
        "producer_consumer_patterns": patterns,
    }))
}

/// GET per-thread scheduling / context-switch statistics.
async fn analyze_scheduling(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let scheduling = engine.analyze_scheduling();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_count": scheduling.len(),
        "scheduling": scheduling,
    }))
}

/// GET per-thread lifecycle / spawn tree.
async fn analyze_thread_lifecycle(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let lifecycle = engine.analyze_thread_lifecycle();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_count": lifecycle.len(),
        "lifecycle": lifecycle,
    }))
}

/// GET per-thread state residency / transitions.
async fn analyze_thread_states(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let state_stats = engine.analyze_thread_states();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_count": state_stats.len(),
        "state_stats": state_stats,
    }))
}
