//! JNI query handlers
//!
//! Expose the JNIStore's AddressIndex over HTTP:
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/api/v1/traces/{id}/jni-calls/{address}` | JNI boundary calls reaching `native_address` (`start`/`end` step range optional) |
//!
//! The `address_index` is maintained on every `import_jni_call` but was
//! previously not queryable — this endpoint surfaces it. Same-step calls that
//! target different native addresses are filtered out server-side so a sibling
//! call sharing a `seq` cannot leak into the result (the #94 pattern, JNI-side).

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::app::AppState;

/// JNI query routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/api/v1/traces/:id/jni-calls/:address", axum::routing::get(query_jni_calls_by_address))
}

/// Query parameters for a JNI-by-address lookup.
#[derive(Debug, Deserialize)]
pub struct JniCallsQuery {
    /// Start step (inclusive). Default 0.
    pub start: Option<u64>,
    /// End step (inclusive). Default u64::MAX = to the end.
    pub end: Option<u64>,
}

/// List JNI boundary calls reaching a given native function address.
async fn query_jni_calls_by_address(
    State(state): State<AppState>,
    Path((trace_id, address)): Path<(u64, u64)>,
    Query(params): Query<JniCallsQuery>,
) -> impl IntoResponse {
    let start = params.start.unwrap_or(0);
    let end = params.end.unwrap_or(u64::MAX);
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let calls: Vec<_> = engine
        .query_jni_calls_by_address(address, start, end)
        .into_iter()
        .cloned()
        .collect();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "native_address": address,
        "start": start,
        "end": end,
        "count": calls.len(),
        "jni_calls": calls,
    }))
}

#[cfg(test)]
mod tests {
    use crate::app::{build_app_with_state, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sotrace_core::models::jni_call::{JNICall, JNICallDirection};
    use sotrace_engine::TraceEngine;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Build an app whose trace 12 has three JNI calls: two reach 0x4000
    /// (seq 10 and 30) and one reaches 0x6000 at the SAME seq 10 — the latter
    /// must not leak into a 0x4000 query despite sharing the step.
    async fn make_app() -> axum::Router {
        let mut engine = TraceEngine::new(12, Default::default());
        engine.import_jni_call(JNICall {
            id: 1, seq: 10, thread_id: 1, direction: JNICallDirection::JavaToNative,
            java_class: "com.app.Foo".to_string(), java_method: "doWork".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x4000, jni_env_address: None,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 2, seq: 10, thread_id: 2, direction: JNICallDirection::JavaToNative,
            java_class: "com.app.Bar".to_string(), java_method: "other".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x6000, jni_env_address: None,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 3, seq: 30, thread_id: 1, direction: JNICallDirection::NativeToJava,
            java_class: "com.app.Bar".to_string(), java_method: "callback".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x4000, jni_env_address: None,
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test-jni"));
        state.engines.lock().await.insert(12, Arc::new(tokio::sync::RwLock::new(engine)));
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
    async fn test_jni_calls_by_address_excludes_same_step_sibling() {
        // 0x4000 has two calls (seq 10 + 30); the 0x6000 sibling at seq 10
        // shares the step but must not appear in the 0x4000 result.
        let (status, json) = send(make_app().await, "/api/v1/traces/12/jni-calls/16384").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["count"], 2);
        let calls = json["jni_calls"].as_array().unwrap();
        assert_eq!(calls[0]["seq"], 10);
        assert_eq!(calls[1]["seq"], 30);
        assert!(calls.iter().all(|c| c["native_address"] == 16384));
    }

    #[tokio::test]
    async fn test_jni_calls_by_address_range_filter() {
        // Range [0,20] keeps only the seq-10 call.
        let (status, json) = send(make_app().await, "/api/v1/traces/12/jni-calls/16384?start=0&end=20").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["count"], 1);
        assert_eq!(json["jni_calls"][0]["java_method"], "doWork");
    }

    #[tokio::test]
    async fn test_jni_calls_by_address_sibling_reachable_via_own_address() {
        // The 0x6000 sibling is reachable via its own address (0x6000 = 24576).
        let (status, json) = send(make_app().await, "/api/v1/traces/12/jni-calls/24576").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["count"], 1);
        assert_eq!(json["jni_calls"][0]["thread_id"], 2);
    }

    #[tokio::test]
    async fn test_jni_calls_by_address_unknown_returns_empty() {
        // An address nobody called returns 200 with an empty list, not an error.
        let (status, json) = send(make_app().await, "/api/v1/traces/12/jni-calls/99999").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["count"], 0);
    }
}
