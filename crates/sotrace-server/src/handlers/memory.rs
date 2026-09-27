//! Memory query handlers
//!
//! Expose the MemoryStore's reconstructed state over HTTP:
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/api/v1/traces/{id}/memory/{address}` | Value at `address` (`step` required, `size` optional) |
//! | GET | `/api/v1/traces/{id}/memory-page/{page_addr}` | Full reconstructed page bytes at `step` |
//!
//! Both reconstruct state by replaying byte-level deltas up to `step`, so the
//! result is memory *as of* that step, not the final state.

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::app::AppState;

/// Memory query routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/api/v1/traces/:id/memory/:address", axum::routing::get(query_memory_value))
        .route("/api/v1/traces/:id/memory-page/:page_addr", axum::routing::get(query_memory_page))
}

/// Query parameters for a value lookup at an address.
#[derive(Debug, Deserialize)]
pub struct MemoryValueQuery {
    /// Step to reconstruct at (required).
    pub step: u64,
    /// Number of bytes to read. Default 8.
    pub size: Option<usize>,
}

/// Query parameters for a page reconstruction.
#[derive(Debug, Deserialize)]
pub struct MemoryPageQuery {
    /// Step to reconstruct the page at (required).
    pub step: u64,
}

/// Reconstruct the value at an address as of a given step.
async fn query_memory_value(
    State(state): State<AppState>,
    Path((trace_id, address)): Path<(u64, u64)>,
    Query(params): Query<MemoryValueQuery>,
) -> impl IntoResponse {
    let size = params.size.unwrap_or(8);
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let result = engine.query_memory_value(address, size, params.step);
    let value_hex = result.as_ref().map(|r| hex(&r.value));

    Json(serde_json::json!({
        "trace_id": trace_id,
        "address": address,
        "step": params.step,
        "size": size,
        "result": result,
        "value_hex": value_hex,
    }))
}

/// Reconstruct a full page as of a given step.
async fn query_memory_page(
    State(state): State<AppState>,
    Path((trace_id, page_addr)): Path<(u64, u64)>,
    Query(params): Query<MemoryPageQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let bytes = engine.rebuild_memory_page(page_addr, params.step);

    Json(serde_json::json!({
        "trace_id": trace_id,
        "page_address": page_addr,
        "step": params.step,
        "length": bytes.as_ref().map(|b| b.len()),
        "bytes_hex": bytes.as_ref().map(|b| hex(b)),
    }))
}

/// Lowercase hex encoding of a byte slice.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use crate::app::{build_app_with_state, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sotrace_engine::trace_store::memory_store::MemoryWrite;
    use sotrace_engine::TraceEngine;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Build an app whose trace 11 has a 4-byte write of 0xDEADBEEF (LE) at
    /// address 0x1000, step 5, then an overwrite of the first byte at step 10.
    async fn make_app() -> axum::Router {
        let mut engine = TraceEngine::new(11, Default::default());
        engine.import_memory_write(MemoryWrite {
            step: 5, thread_id: 1, address: 0x1000, data: vec![0xEF, 0xBE, 0xAD, 0xDE],
        }).unwrap();
        engine.import_memory_write(MemoryWrite {
            step: 10, thread_id: 1, address: 0x1000, data: vec![0x11],
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test-memory"));
        state.engines.lock().await.insert(11, Arc::new(tokio::sync::RwLock::new(engine)));
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
    async fn test_memory_value_at_write_step() {
        // At step 5 the 4 bytes read back as written (little-endian 0xDEADBEEF).
        let (status, json) = send(make_app().await, "/api/v1/traces/11/memory/4096?step=5&size=4").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["value_hex"], "efbeadde");
        assert_eq!(json["result"]["page_address"], 4096);
    }

    #[tokio::test]
    async fn test_memory_value_reflects_later_overwrite() {
        // At step 10 byte 0 was overwritten to 0x11; the other three bytes are
        // folded from step 5, so a 4-byte read shows the merged page state.
        let (status, json) = send(make_app().await, "/api/v1/traces/11/memory/4096?step=10&size=4").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["value_hex"], "11beadde");
        // Before the overwrite the byte still reads as the original 0xEF.
        let (_, before) = send(make_app().await, "/api/v1/traces/11/memory/4096?step=5&size=1").await;
        assert_eq!(before["value_hex"], "ef");
    }

    #[tokio::test]
    async fn test_memory_value_default_size() {
        // No size param → default 8 bytes (trailing bytes are zero-filled page).
        let (status, json) = send(make_app().await, "/api/v1/traces/11/memory/4096?step=5").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["size"], 8);
        assert!(json["result"]["value"].is_array());
    }

    #[tokio::test]
    async fn test_memory_page_reconstruction() {
        // The page containing 0x1000 reconstructs with our bytes at offset 0.
        let (status, json) = send(make_app().await, "/api/v1/traces/11/memory-page/4096?step=5").await;
        assert_eq!(status, StatusCode::OK);
        let hex = json["bytes_hex"].as_str().unwrap();
        assert!(hex.starts_with("efbeadde"), "page starts with the write: {hex}");
    }

    #[tokio::test]
    async fn test_memory_value_straddling_page_boundary() {
        // #80 end-to-end at the HTTP layer: a single GET spanning a 4KB page
        // boundary returns the full stitched value, not a truncated tail.
        // PAGE_SIZE = 4096 = 0x1000; write 6 bytes from 0x1FFD → [0x1FFD,0x3003)
        // straddles the 0x1000/0x2000 boundary (0x1FFD sits in page 0x1000).
        let mut engine = TraceEngine::new(12, Default::default());
        engine.import_memory_write(MemoryWrite {
            step: 5, thread_id: 1, address: 0x1FFD,
            data: vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
        }).unwrap();
        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test-memory-straddle"));
        state.engines.lock().await.insert(12, Arc::new(tokio::sync::RwLock::new(engine)));
        let app = build_app_with_state(state);

        let (status, json) = send(app, "/api/v1/traces/12/memory/8189?step=5&size=6").await;
        assert_eq!(status, StatusCode::OK, "straddling read failed");
        assert_eq!(json["size"], 6);
        // Full 6 bytes across the boundary (not truncated to the first 3).
        assert_eq!(json["value_hex"], "102030405060");
        assert_eq!(json["result"]["page_address"], 0x1000);
    }
}
