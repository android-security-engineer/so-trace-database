//! Call chain query handlers
//!
//! Expose the CallStore's call/return records over HTTP:
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/api/v1/traces/{id}/call-chain` | List call events (optionally filtered by `func_id` and/or step range) |
//! | GET | `/api/v1/traces/{id}/call-stack/{seq}` | Reconstruct a thread's live call stack at `seq` (requires `thread_id`) |

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::app::AppState;

/// Call chain routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/api/v1/traces/:id/call-chain", axum::routing::get(query_call_chain))
        .route("/api/v1/traces/:id/call-stack/:seq", axum::routing::get(rebuild_call_stack))
}

/// Query parameters for the call-chain listing.
#[derive(Debug, Deserialize)]
pub struct CallChainQuery {
    /// Restrict to a single callee function (foreign key → SOFunction).
    pub func_id: Option<u64>,
    /// Start step (inclusive). Default 0.
    pub start_step: Option<u64>,
    /// End step (inclusive). Default u64::MAX.
    pub end_step: Option<u64>,
}

/// Query parameters for call-stack reconstruction.
#[derive(Debug, Deserialize)]
pub struct CallStackQuery {
    /// Thread whose stack to reconstruct (required).
    pub thread_id: u32,
}

/// List call events for a trace.
///
/// With `func_id`, returns the calls targeting that function (via the function
/// index). Otherwise returns all call events. Both are filtered to the
/// `[start_step, end_step]` range.
async fn query_call_chain(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
    Query(params): Query<CallChainQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;
    let store = engine.call_store();

    let start = params.start_step.unwrap_or(0);
    let end = params.end_step.unwrap_or(u64::MAX);

    let calls: Vec<_> = if let Some(func_id) = params.func_id {
        // Function index yields the seqs; hydrate each to its full record(s).
        // A seq can carry multiple calls — but they may target *different*
        // functions (two threads calling different functions at the same step,
        // or one thread calling several). The index only pinpoints the seq, so
        // `get_at_step` results must be filtered by `callee_func_id` to keep
        // this function's calls from leaking the others' — the same step-vs-
        // record granularity gap as instruction_store's `query_by_thread_range`.
        store
            .query_function_calls(func_id)
            .iter()
            .filter(|&&seq| seq >= start && seq <= end)
            .flat_map(|&seq| store.get_at_step(seq).into_iter().cloned())
            .filter(|c| c.callee_func_id == Some(func_id as u32))
            .collect()
    } else {
        store
            .all_calls()
            .into_iter()
            .filter(|c| c.seq >= start && c.seq <= end)
            .collect()
    };

    Json(serde_json::json!({
        "trace_id": trace_id,
        "func_id": params.func_id,
        "call_count": calls.len(),
        "calls": calls,
    }))
}

/// Reconstruct a thread's live call stack at a given step.
async fn rebuild_call_stack(
    State(state): State<AppState>,
    Path((trace_id, seq)): Path<(u64, u64)>,
    Query(params): Query<CallStackQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let frames = engine.rebuild_call_stack(params.thread_id, seq);

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_id": params.thread_id,
        "step": seq,
        "depth": frames.len(),
        "frames": frames,
    }))
}

#[cfg(test)]
mod tests {
    use crate::app::{build_app_with_state, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sotrace_core::models::call_trace::{CallEventType, CallTrace};
    use sotrace_engine::TraceEngine;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Build an app whose trace 7 holds a small call tree on thread 1:
    /// f(0x1000) calls g(0x2000); g returns at seq 3.
    async fn make_app() -> axum::Router {
        let mut engine = TraceEngine::new(7, Default::default());
        let mk = |id: u64, seq: u64, et: CallEventType, callee: u64, func: Option<u32>, depth: u16| CallTrace {
            id, thread_id: 1, event_type: et,
            caller_address: 0x100, callee_address: callee,
            callee_func_id: func, seq, depth, return_seq: None,
        };
        engine.import_call_trace(mk(1, 1, CallEventType::Call, 0x1000, Some(100), 0)).unwrap();
        engine.import_call_trace(mk(2, 2, CallEventType::Call, 0x2000, Some(200), 1)).unwrap();
        engine.import_call_trace(mk(3, 3, CallEventType::Return, 0, None, 1)).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test-callchain"));
        state.engines.lock().await.insert(7, Arc::new(tokio::sync::RwLock::new(engine)));
        build_app_with_state(state)
    }

    async fn send(router: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = router
            .oneshot(Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap())
            .await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn test_call_chain_all() {
        let (status, json) = send(make_app().await, "/api/v1/traces/7/call-chain").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["call_count"], 3);
    }

    #[tokio::test]
    async fn test_call_chain_by_func() {
        let (status, json) = send(make_app().await, "/api/v1/traces/7/call-chain?func_id=200").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["call_count"], 1);
        assert_eq!(json["calls"][0]["callee_address"], 0x2000);
    }

    /// Two calls at the same `seq` targeting *different* functions must not
    /// leak into each other when filtered by `func_id`. The function index
    /// pinpoints the seq, but `get_at_step` returns every call at that seq, so
    /// without a `callee_func_id` filter the other function's call would be
    /// returned too — the call-side twin of the instruction_store thread-leak.
    #[tokio::test]
    async fn test_call_chain_by_func_excludes_other_func_at_same_seq() {
        let mut engine = TraceEngine::new(7, Default::default());
        let mk = |id: u64, seq: u64, callee: u64, func: Option<u32>| CallTrace {
            id, thread_id: 1, event_type: CallEventType::Call,
            caller_address: 0x100, callee_address: callee,
            callee_func_id: func, seq, depth: 0, return_seq: None,
        };
        // Same seq 5, two different functions (300 and 400).
        engine.import_call_trace(mk(1, 5, 0x3000, Some(300))).unwrap();
        engine.import_call_trace(mk(2, 5, 0x4000, Some(400))).unwrap();
        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test-callchain"));
        state.engines.lock().await.insert(7, Arc::new(tokio::sync::RwLock::new(engine)));
        let router = build_app_with_state(state);

        let (status, json) = send(router, "/api/v1/traces/7/call-chain?func_id=300").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["call_count"], 1, "must not leak func 400's call at the same seq");
        assert_eq!(json["calls"][0]["callee_address"], 0x3000);
    }

    #[tokio::test]
    async fn test_call_chain_step_range() {
        // Only seqs 0..=1 → the outer call.
        let (status, json) = send(make_app().await, "/api/v1/traces/7/call-chain?start_step=0&end_step=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["call_count"], 1);
        assert_eq!(json["calls"][0]["callee_address"], 0x1000);
    }

    #[tokio::test]
    async fn test_call_stack_before_return() {
        // At seq 2 both frames are live.
        let (status, json) = send(make_app().await, "/api/v1/traces/7/call-stack/2?thread_id=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["depth"], 2);
        assert_eq!(json["frames"][0]["entry_address"], 0x1000);
        assert_eq!(json["frames"][1]["entry_address"], 0x2000);
    }

    #[tokio::test]
    async fn test_call_stack_after_return() {
        // At seq 3 the inner call returned; only f remains.
        let (status, json) = send(make_app().await, "/api/v1/traces/7/call-stack/3?thread_id=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["depth"], 1);
        assert_eq!(json["frames"][0]["entry_address"], 0x1000);
    }
}
