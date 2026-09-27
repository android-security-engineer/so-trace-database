//! Instruction query handlers
//!
//! Expose the InstructionStore's AddressIndex over HTTP:
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/api/v1/traces/{id}/threads-at-address/{address}` | Which threads executed at `address`, and at which steps |
//!
//! The `address_index` is maintained on every `import_instruction`. This
//! endpoint surfaces the cross-thread view ("who touches this code location?")
//! that the CLI `address` subcommand already exposes but HTTP/MCP lacked.

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;

use crate::app::AppState;

/// Instruction query routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/api/v1/traces/:id/threads-at-address/:address", axum::routing::get(query_threads_at_address))
}

/// List which threads executed at a given address, and at which steps.
///
/// Returns `(thread_id, step)` pairs — each entry means "thread T executed
/// this address at step S". Same-step instructions from multiple threads all
/// survive (two threads sharing a `seq`). This is the cross-thread view; for a
/// single thread's instructions use the thread-scoped query.
async fn query_threads_at_address(
    State(state): State<AppState>,
    Path((trace_id, address)): Path<(u64, u64)>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let accesses = engine.query_threads_at_address(address);
    let step_count = engine.query_instructions_by_address(address).len();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "address": address,
        "step_count": step_count,
        // Each entry is (thread_id, step) — the step at which that thread
        // executed the address, NOT an access count.
        "thread_accesses": accesses.iter().map(|(t, s)| serde_json::json!({"thread_id": t, "step": s})).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use crate::app::{build_app_with_state, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sotrace_core::models::instruction_trace::InstructionTrace;
    use sotrace_engine::TraceEngine;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Build an app whose trace 14 has two threads sharing seq 7 at address
    /// 0x1000 (so both survive), plus thread 1 again at seq 9.
    async fn make_app() -> axum::Router {
        let mut engine = TraceEngine::new(14, Default::default());
        engine.register_thread(sotrace_core::models::thread::ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        engine.register_thread(sotrace_core::models::thread::ThreadInfo {
            thread_id: 2, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        engine.import_instruction(InstructionTrace {
            seq: 7, thread_id: 1, address: 0x1000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();
        engine.import_instruction(InstructionTrace {
            seq: 7, thread_id: 2, address: 0x1000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();
        engine.import_instruction(InstructionTrace {
            seq: 9, thread_id: 1, address: 0x1000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test-instruction"));
        state.engines.lock().await.insert(14, Arc::new(tokio::sync::RwLock::new(engine)));
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
    async fn test_threads_at_address_keeps_both_threads_at_shared_step() {
        // 0x1000 = 4096: two threads at seq 7 + thread 1 at seq 9 → 3 accesses.
        let (status, json) = send(make_app().await, "/api/v1/traces/14/threads-at-address/4096").await;
        assert_eq!(status, StatusCode::OK);
        // find_by_address dedups (address, step): seq 7 shared by two threads
        // collapses to one entry, plus seq 9 → [7, 9].
        assert_eq!(json["step_count"], 2);
        let accesses = json["thread_accesses"].as_array().unwrap();
        assert_eq!(accesses.len(), 3);
        // Each entry carries `step`, not a mislabeled `count`.
        let mut pairs: Vec<(u64, u64)> = accesses.iter()
            .map(|a| (a["thread_id"].as_u64().unwrap(), a["step"].as_u64().unwrap()))
            .collect();
        pairs.sort();
        assert_eq!(pairs, vec![(1, 7), (1, 9), (2, 7)]);
    }

    #[tokio::test]
    async fn test_threads_at_address_unknown_returns_empty() {
        let (status, json) = send(make_app().await, "/api/v1/traces/14/threads-at-address/99999").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["step_count"], 0);
        assert!(json["thread_accesses"].as_array().unwrap().is_empty());
    }
}
