//! Thread analysis handlers — race detection, deadlock detection, contention analysis
//!
//! These endpoints expose the ThreadAnalyzer's capabilities via HTTP.
//! Analysis is performed on the TraceEngine associated with each trace_id.
//!
//! # Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET  | `/api/v1/traces/{id}/threads` | List all threads (metadata + stats) |
//! | GET  | `/api/v1/traces/{id}/threads/{thread_id}` | Get a single thread's info |
//! | GET  | `/api/v1/traces/{id}/threads/{thread_id}/timeline` | Get a thread's timeline |
//! | GET  | `/api/v1/traces/{id}/threads/{thread_id}/sync-events` | Get sync events for a thread |
//! | GET  | `/api/v1/traces/{id}/threads/sync-events` | Query sync events (filterable) |
//! | GET  | `/api/v1/traces/{id}/threads/context-switches` | Query context switches |
//! | POST | `/api/v1/traces/{id}/analyze/threads` | Run full thread analysis |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/races` | Detect race conditions only |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/deadlocks` | Detect deadlocks only |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/contentions` | Analyze lock contentions only |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/function-safety` | Classify function thread safety |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/function-assoc` | Analyze thread-function associations |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/data-flows` | Analyze inter-thread data flows |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/producer-consumer` | Detect producer-consumer patterns |

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
    let engine = engine.lock().await;

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
    let engine = engine.lock().await;

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
    let engine = engine.lock().await;

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
    let engine = engine.lock().await;

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
    let engine = engine.lock().await;

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
    let engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

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
    let mut engine = engine.lock().await;

    let state_stats = engine.analyze_thread_states();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_count": state_stats.len(),
        "state_stats": state_stats,
    }))
}

/// GET per-lock critical-section / hold-time statistics.
async fn analyze_critical_sections(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;

    let critical_sections = engine.analyze_critical_sections();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "lock_count": critical_sections.len(),
        "critical_sections": critical_sections,
    }))
}

/// `GET /api/v1/traces/:id/analyze/threads/jni-boundary`
async fn analyze_jni_boundary(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;

    let jni_boundary = engine.analyze_jni_boundary();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_count": jni_boundary.len(),
        "jni_boundary": jni_boundary,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{build_app_with_state, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sotrace_core::models::instruction_trace::InstructionTrace;
    use sotrace_core::models::jni_call::{JNICall, JNICallDirection};
    use sotrace_core::models::thread::{
        ThreadInfo, ThreadSyncEvent, SyncEventType, SyncResult, ContextSwitch, SwitchReason,
        ThreadStateChange, ThreadState,
    };
    use sotrace_engine::TraceEngine;
    use sotrace_engine::trace_store::memory_store::MemoryWrite;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// 0xABCD0000 in decimal — used as a query parameter
    const LOCK_ADDR: u64 = 0xABCD0000;

    /// Build an AppState pre-populated with a trace engine containing test data
    async fn make_app() -> axum::Router {
        let mut engine = TraceEngine::new(42, Default::default());

        // Register two threads
        for tid in [1, 2] {
            engine.register_thread(ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: Some(format!("worker-{}", tid)),
                stack_base: 0x7FFF0000, stack_size: 0x80000, tls_addr: 0, is_jni_attached: false,
            }).unwrap();
        }

        // Instructions on thread 1
        for i in 0..10 {
            engine.import_instruction(InstructionTrace {
                seq: i, thread_id: 1, address: 0x4000 + i * 4,
                timestamp: None, is_branch: false, branch_taken: false, opcode: None,
            }).unwrap();
        }

        // Memory write by thread 1 (race candidate vs thread 2 read)
        engine.import_memory_write(MemoryWrite {
            step: 5, thread_id: 1, address: 0x1000, data: vec![0xFF; 4],
        }).unwrap();
        engine.feed_memory_read(7, 2, 0x1000, 4);

        // Sync events on a shared lock
        engine.record_sync_event(ThreadSyncEvent {
            step: 3, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 6, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR,
            result: SyncResult::Success,
            wait_duration_ns: Some(1500),
        }).unwrap();

        // Context switch
        engine.record_context_switch(ContextSwitch {
            step: 4, from_thread: 1, to_thread: 2,
            switch_reason: SwitchReason::Preemption,
            cpu_core: Some(0),
        }).unwrap();

        // Thread 1 state changes: Running 0→30, then WaitingForLock (trailing,
        // unbounded → contributes nothing). Gives a measurable Running interval.
        engine.record_thread_state_change(ThreadStateChange {
            step: 0, thread_id: 1, new_state: ThreadState::Running,
            prev_state: None, prev_running_thread: None,
        }).unwrap();
        engine.record_thread_state_change(ThreadStateChange {
            step: 30, thread_id: 1, new_state: ThreadState::WaitingForLock,
            prev_state: Some(ThreadState::Running), prev_running_thread: None,
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        state.engines.lock().await.insert(42, Arc::new(tokio::sync::Mutex::new(engine)));
        build_app_with_state(state)
    }

    async fn send(router: axum::Router, method: &str, uri: &str) -> (StatusCode, String) {
        let resp = router
            .oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap())
            .await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn test_list_threads() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread_count"], 2);
        let threads = json["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 2);
        // Both worker names should be present (order is nondeterministic)
        let names: Vec<&str> = threads.iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"worker-1"));
        assert!(names.contains(&"worker-2"));
    }

    #[tokio::test]
    async fn test_list_threads_with_stats() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads?include_stats=true").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["stats"].is_array(), "stats should be present when include_stats=true");
        // #114: lock_release_count is present alongside lock_acquire_count.
        // make_app seeds two MutexLock acquires and no unlock → release_count 0,
        // acquire_count 2 (acquire ≫ release would flag a leak).
        let stats = &json["stats"].as_array().unwrap()[0];
        assert!(stats["lock_acquire_count"].is_u64());
        assert!(stats["lock_release_count"].is_u64());
        assert_eq!(stats["lock_release_count"], 0);
        // #118: max_lock_wait_ns is null (seed acquires had no real wait) but
        // present as a field.
        assert!(stats["max_lock_wait_ns"].is_null());
    }

    #[tokio::test]
    async fn test_get_thread_found() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/1").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread"]["thread_id"], 1);
        assert_eq!(json["thread"]["name"], "worker-1");
    }

    #[tokio::test]
    async fn test_get_thread_not_found() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["error"], "thread not found");
    }

    #[tokio::test]
    async fn test_query_sync_events_by_lock() {
        let app = make_app().await;
        let uri = format!("/api/v1/traces/42/threads/sync-events?sync_object_addr={}&start_step=0&end_step=100", LOCK_ADDR);
        let (status, body) = send(app, "GET", &uri).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["event_count"], 2, "two mutex lock events on this lock");
    }

    #[tokio::test]
    async fn test_query_sync_events_by_thread() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/sync-events?thread_id=1&start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["event_count"], 1, "thread 1 has 1 sync event");
    }

    #[tokio::test]
    async fn test_query_context_switches() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/context-switches?start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["switch_count"], 1);
        assert_eq!(json["context_switches"][0]["from_thread"], 1);
        assert_eq!(json["context_switches"][0]["to_thread"], 2);
    }

    #[tokio::test]
    async fn test_query_context_switches_thread_filter() {
        let app = make_app().await;
        // Thread 1 is involved
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/context-switches?thread_id=1&start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["switch_count"], 1);
    }

    #[tokio::test]
    async fn test_query_context_switches_unrelated_thread() {
        let app = make_app().await;
        // Thread 99 is not involved
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/context-switches?thread_id=99&start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["switch_count"], 0);
    }

    #[tokio::test]
    async fn test_analyze_threads() {
        let app = make_app().await;
        let (status, body) = send(app, "POST", "/api/v1/traces/42/analyze/threads").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["analysis"].is_object());
        assert!(json["analysis"]["race_conditions"].is_array());
        assert!(json["analysis"]["deadlock_risks"].is_array());
        assert!(json["analysis"]["lock_contentions"].is_array());
    }

    #[tokio::test]
    async fn test_detect_races() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/races").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["trace_id"], 42);
        assert!(json["races"].is_array());
        // Thread 1 wrote at step 5, thread 2 read at step 7 with no sync → race
        assert!(!json["races"].as_array().unwrap().is_empty(), "should detect a race");
        // #112: access sizes and overlap range are present in the JSON
        let race = &json["races"].as_array().unwrap()[0];
        assert!(race["first_access_size"].is_u64());
        assert!(race["second_access_size"].is_u64());
        assert!(race["overlap_address"].is_u64());
        assert!(race["overlap_size"].is_u64());
    }

    #[tokio::test]
    async fn test_analyze_contentions() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/contentions").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let contentions = json["contentions"].as_array().unwrap();
        assert!(contentions.iter().any(|c| c["lock_address"]["addr"] == LOCK_ADDR));
    }

    #[tokio::test]
    async fn test_detect_deadlocks() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/deadlocks").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["deadlocks"].is_array());
    }

    #[tokio::test]
    async fn test_classify_function_safety() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/function-safety").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["function_safety"].is_array());
    }

    #[tokio::test]
    async fn test_analyze_function_assoc() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/function-assoc").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["thread_function_assocs"].is_array());
    }

    #[tokio::test]
    async fn test_analyze_data_flows() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/data-flows").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["data_flows"].is_array());
        assert!(!json["data_flows"].as_array().unwrap().is_empty(), "should detect a data flow");
        // #113: transfer sizes and overlap range are present in the JSON
        let flow = &json["data_flows"].as_array().unwrap()[0];
        assert!(flow["write_size"].is_u64());
        assert!(flow["read_size"].is_u64());
        assert!(flow["overlap_address"].is_u64());
        assert!(flow["overlap_size"].is_u64());
    }

    #[tokio::test]
    async fn test_detect_producer_consumer() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/producer-consumer").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["producer_consumer_patterns"].is_array());
    }

    /// The typed `sync_mechanism` must surface the primitive kind through the
    /// JSON envelope — the field is now an object `{addr, kind}`, not a bare
    /// number. A mutex producer-consumer rendezvous must report `kind: "Mutex"`.
    #[tokio::test]
    async fn test_detect_producer_consumer_sync_mechanism_typed() {
        let mut engine = TraceEngine::new(44, Default::default());
        for tid in [1, 2] {
            engine.register_thread(ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: Some(format!("worker-{}", tid)),
                stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
            }).unwrap();
        }
        // Two produce→consume cycles sharing one mutex so detect_producer_consumer
        // (which needs >=2 cycles) reports a pattern with the typed sync mechanism.
        engine.import_memory_write(MemoryWrite {
            step: 100, thread_id: 1, address: 0x5000, data: vec![0xFF; 4],
        }).unwrap();
        engine.feed_memory_read(130, 2, 0x5000, 4);
        engine.import_memory_write(MemoryWrite {
            step: 200, thread_id: 1, address: 0x6000, data: vec![0xFF; 4],
        }).unwrap();
        engine.feed_memory_read(230, 2, 0x6000, 4);
        engine.record_sync_event(ThreadSyncEvent {
            step: 110, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 120, thread_id: 2, sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: Some(1000),
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 210, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 220, thread_id: 2, sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: Some(1000),
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        state.engines.lock().await.insert(44, Arc::new(tokio::sync::Mutex::new(engine)));
        let app = build_app_with_state(state);

        let (status, body) = send(app, "GET", "/api/v1/traces/44/analyze/threads/producer-consumer").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let patterns = json["producer_consumer_patterns"].as_array().unwrap();
        assert!(!patterns.is_empty(), "producer-consumer pattern must be detected");
        let pc = patterns.iter()
            .find(|p| p["producer_thread"] == 1 && p["consumer_thread"] == 2)
            .unwrap();
        assert_eq!(pc["sync_mechanism"]["addr"], LOCK_ADDR);
        assert_eq!(pc["sync_mechanism"]["kind"], "Mutex");
        // #116: shared_addresses entries are objects with address + sizes
        let slots = pc["shared_addresses"].as_array().unwrap();
        assert!(!slots.is_empty(), "shared_addresses must list the slots");
        let slot = slots.iter().find(|s| s["address"] == 0x6000).unwrap();
        assert_eq!(slot["access_size"], 4);
        assert_eq!(slot["overlap_size"], 4);
        // #120: max_latency_steps surfaces the slowest cycle. Both cycles here
        // have equal latency (100→130, 200→230 = 30 each), so max == avg.
        assert_eq!(pc["avg_latency_steps"], 30);
        assert_eq!(pc["max_latency_steps"], 30);
    }

    #[tokio::test]
    async fn test_analyze_scheduling() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/scheduling").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["scheduling"].is_array());
        // #117: each row carries core_residency as an array of [core, steps].
        let sched = json["scheduling"].as_array().unwrap();
        assert!(sched.iter().all(|s| s["core_residency"].is_array()));
    }

    #[tokio::test]
    async fn test_analyze_thread_lifecycle() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/lifecycle").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let life = json["lifecycle"].as_array().unwrap();
        assert_eq!(life.len(), 2);
        assert_eq!(json["thread_count"], 2);
        // Both fixture threads are roots (parent 0), alive, at depth 0.
        for l in life {
            assert_eq!(l["parent_thread_id"], 0);
            assert_eq!(l["tree_depth"], 0);
            assert_eq!(l["is_alive"], true);
        }
    }

    #[tokio::test]
    async fn test_analyze_thread_states() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/states").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let stats = json["state_stats"].as_array().unwrap();
        // Only thread 1 has state changes in the fixture.
        let t1 = stats.iter().find(|s| s["thread_id"] == 1).expect("thread 1 state stats");
        // Running interval 0→30 is bounded; the trailing WaitingForLock is open.
        assert_eq!(t1["running_steps"], 30);
        assert_eq!(t1["total_measured_steps"], 30);
        assert_eq!(t1["final_state"], "WaitingForLock");
        assert_eq!(t1["transition_count"], 2);
    }

    #[tokio::test]
    async fn test_analyze_critical_sections() {
        // Self-contained trace (not the shared fixture, whose locks are never
        // released): thread 1 holds LOCK_ADDR from step 10 to 40 (hold = 30).
        let mut engine = TraceEngine::new(43, Default::default());
        engine.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some("worker".into()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 40, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        state.engines.lock().await.insert(43, Arc::new(tokio::sync::Mutex::new(engine)));
        let app = build_app_with_state(state);

        let (status, body) = send(app, "GET", "/api/v1/traces/43/analyze/threads/critical-sections").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["lock_count"], 1);
        let cs = json["critical_sections"].as_array().unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0]["lock_address"]["addr"], LOCK_ADDR);
        assert_eq!(cs[0]["hold_count"], 1);
        assert_eq!(cs[0]["total_hold_steps"], 30);
        assert_eq!(cs[0]["max_hold_steps"], 30);
        assert_eq!(cs[0]["longest_hold_thread"], 1);
    }

    #[tokio::test]
    async fn test_analyze_jni_boundary() {
        // Self-contained trace: thread 1 (JNI-attached) makes two crossings.
        let mut engine = TraceEngine::new(44, Default::default());
        engine.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some("jni-worker".into()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: true,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 1, seq: 10, thread_id: 1, direction: JNICallDirection::JavaToNative,
            java_class: "com.app.Foo".into(), java_method: "doWork".into(),
            java_signature: "()V".into(), native_func_id: None,
            native_address: 8192, jni_env_address: None,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 2, seq: 20, thread_id: 1, direction: JNICallDirection::NativeToJava,
            java_class: "com.app.Bar".into(), java_method: "callback".into(),
            java_signature: "()V".into(), native_func_id: None,
            native_address: 8192, jni_env_address: None,
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        state.engines.lock().await.insert(44, Arc::new(tokio::sync::Mutex::new(engine)));
        let app = build_app_with_state(state);

        let (status, body) = send(app, "GET", "/api/v1/traces/44/analyze/threads/jni-boundary").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread_count"], 1);
        let stats = json["jni_boundary"].as_array().unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0]["thread_id"], 1);
        assert_eq!(stats[0]["is_jni_attached"], true);
        assert_eq!(stats[0]["total_crossings"], 2);
        assert_eq!(stats[0]["java_to_native_count"], 1);
        assert_eq!(stats[0]["native_to_java_count"], 1);
        assert_eq!(stats[0]["native_addresses"], serde_json::json!([8192]));
        assert_eq!(stats[0]["java_methods"], serde_json::json!(["com.app.Bar.callback", "com.app.Foo.doWork"]));
        // #119: first/last crossing step locate the JNI activity window (seq 10..20).
        assert_eq!(stats[0]["first_crossing_step"], 10);
        assert_eq!(stats[0]["last_crossing_step"], 20);
    }

    #[tokio::test]
    async fn test_get_thread_timeline() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/1/timeline?start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread_id"], 1);
        assert!(json["timeline"].is_object());
    }

    #[tokio::test]
    async fn test_get_thread_sync_events() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/1/sync-events?start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["event_count"], 1);
    }

    #[tokio::test]
    async fn test_empty_trace_list_threads() {
        // A trace with no data should return an empty thread list
        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        let app = build_app_with_state(state);
        let (status, body) = send(app, "GET", "/api/v1/traces/999/threads").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread_count"], 0);
    }
}
