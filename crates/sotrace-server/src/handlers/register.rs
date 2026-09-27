//! Register query handlers
//!
//! Expose the RegisterStore's reconstructed values over HTTP:
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/api/v1/traces/{id}/register/{register_id}` | Value of one register at `step` (query param) |
//! | GET | `/api/v1/traces/{id}/register-state/{step}` | Full ARM64 register file at `step` |
//! | GET | `/api/v1/traces/{id}/register-history/{register_id}` | Steps at which a register changed (`start`/`end` optional) |
//!
//! `register_id` follows the ARM64 layout: 0-30 = x0-x30, 31 = SP, 32 = PC,
//! 33 = NZCV.

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::app::AppState;

/// Register query routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/api/v1/traces/:id/register/:register_id", axum::routing::get(query_register))
        .route("/api/v1/traces/:id/register-state/:step", axum::routing::get(reconstruct_register_state))
        .route("/api/v1/traces/:id/register-history/:register_id", axum::routing::get(query_register_history))
}

/// Query parameters for a single-register lookup.
#[derive(Debug, Deserialize)]
pub struct RegisterQuery {
    /// Step to reconstruct the value at (required).
    pub step: u64,
}

/// Query parameters for a register-history lookup.
#[derive(Debug, Deserialize)]
pub struct RegisterHistoryQuery {
    /// Start step (inclusive). Default 0.
    pub start: Option<u64>,
    /// End step (inclusive). Default u64::MAX = to the end.
    pub end: Option<u64>,
}

/// Reconstruct a single register's value at a given step.
///
/// Returns the value the register held as of the last delta that touched it at
/// or before `step`, or `null` if it was never recorded.
async fn query_register(
    State(state): State<AppState>,
    Path((trace_id, register_id)): Path<(u64, usize)>,
    Query(params): Query<RegisterQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let value = engine.query_register(register_id, params.step);

    Json(serde_json::json!({
        "trace_id": trace_id,
        "register_id": register_id,
        "step": params.step,
        "value": value,
        "value_hex": value.map(|v| format!("0x{v:x}")),
    }))
}

/// Reconstruct the full ARM64 register file at a given step.
///
/// Returns every register's value (x0-x30, SP, PC, NZCV) in one snapshot;
/// `state` is `null` when no register delta exists at or before `step`.
async fn reconstruct_register_state(
    State(state): State<AppState>,
    Path((trace_id, step)): Path<(u64, u64)>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let reg_state = engine.reconstruct_register_state(step);

    Json(serde_json::json!({
        "trace_id": trace_id,
        "step": step,
        "state": reg_state,
    }))
}

/// List the steps at which a register was modified.
///
/// Exposes the per-register index that `query_register` uses internally —
/// answers "when did register X change?" in O(log K + R) via the index, not a
/// full-log scan. `start`/`end` are optional (inclusive).
async fn query_register_history(
    State(state): State<AppState>,
    Path((trace_id, register_id)): Path<(u64, usize)>,
    Query(params): Query<RegisterHistoryQuery>,
) -> impl IntoResponse {
    let start = params.start.unwrap_or(0);
    let end = params.end.unwrap_or(u64::MAX);
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let steps = engine.query_register_history(register_id, start, end);

    Json(serde_json::json!({
        "trace_id": trace_id,
        "register_id": register_id,
        "start": start,
        "end": end,
        "change_count": steps.len(),
        "steps": steps,
    }))
}

#[cfg(test)]
mod tests {
    use crate::app::{build_app_with_state, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sotrace_core::models::register_delta::RegisterDelta;
    use sotrace_engine::TraceEngine;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Build an app whose trace 9 holds two register deltas:
    /// x0 = 0x1000 at seq 5; then x0 = 0x2000 and x2 = 0x12345678 at seq 10.
    async fn make_app() -> axum::Router {
        let mut engine = TraceEngine::new(9, Default::default());
        engine
            .import_register_delta(RegisterDelta { seq: 5, change_mask: 1, values: vec![0x1000] })
            .unwrap();
        engine
            .import_register_delta(RegisterDelta {
                seq: 10,
                change_mask: (1 << 0) | (1 << 2),
                values: vec![0x2000, 0x12345678],
            })
            .unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test-register"));
        state.engines.lock().await.insert(9, Arc::new(tokio::sync::RwLock::new(engine)));
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
    async fn test_query_register_before_first_delta_is_null() {
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register/0?step=3").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["value"].is_null());
    }

    #[tokio::test]
    async fn test_query_register_between_deltas() {
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register/0?step=7").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["value"], 0x1000);
        assert_eq!(json["value_hex"], "0x1000");
    }

    #[tokio::test]
    async fn test_query_register_multi_register_extraction() {
        // At step 12, x2 was set by the multi-register delta at seq 10.
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register/2?step=12").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["value"], 0x12345678);
    }

    #[tokio::test]
    async fn test_register_state_full_file() {
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register-state/12").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["state"]["seq"], 12);
        assert_eq!(json["state"]["gp_regs"][0], 0x2000);
        assert_eq!(json["state"]["gp_regs"][2], 0x12345678);
        assert_eq!(json["state"]["gp_regs"][1], 0); // never written
    }

    #[tokio::test]
    async fn test_register_state_before_any_delta_is_null() {
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register-state/2").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["state"].is_null());
    }

    #[tokio::test]
    async fn test_register_history_lists_change_steps() {
        // x0 changed at seq 5 and 10.
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register-history/0").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["change_count"], 2);
        assert_eq!(json["steps"], serde_json::json!([5, 10]));
    }

    #[tokio::test]
    async fn test_register_history_range_filter() {
        // x0 in [6, max] → only 10.
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register-history/0?start=6").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["steps"], serde_json::json!([10]));
    }

    #[tokio::test]
    async fn test_register_history_never_changed_register() {
        // x1 never changed → empty list.
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register-history/1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["change_count"], 0);
    }

    #[tokio::test]
    async fn test_register_history_out_of_range_id() {
        // register_id 999 is out of range → empty, not an error.
        let (status, json) = send(make_app().await, "/api/v1/traces/9/register-history/999").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["change_count"], 0);
    }
}
