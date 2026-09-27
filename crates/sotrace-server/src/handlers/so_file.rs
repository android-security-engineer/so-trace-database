//! SO file management handlers.
//!
//! `POST /api/v1/so-files` accepts the raw ELF bytes (`Content-Type:
//! application/octet-stream`), parses them, and persists the SO to the data
//! directory (deduplicated by SHA-256). `GET` endpoints list/inspect persisted
//! SOs.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::response::IntoResponse;
use axum::{Json, Router};

use crate::app::AppState;
use crate::handlers::error::ApiError;

/// SO file routes
pub fn routes() -> Router<AppState> {
    // SO binaries can be large (tens of MB for stripped libc variants); raise
    // the default 2 MiB body limit to 256 MiB for the upload endpoint only.
    const MAX_SO_BYTES: usize = 256 * 1024 * 1024;
    Router::new()
        .route("/api/v1/so-files", axum::routing::post(create_so_file))
        .route("/api/v1/so-files", axum::routing::get(list_so_files))
        .route("/api/v1/so-files/:id", axum::routing::get(get_so_file).delete(delete_so_file))
        .layer(DefaultBodyLimit::max(MAX_SO_BYTES))
}

/// Upload + parse + persist an SO file.
///
/// The request body is the raw ELF bytes. The optional `?path=<label>` query
/// param sets the recorded `path` metadata (defaults to "upload").
async fn create_so_file(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<UploadQuery>,
    body: Bytes,
) -> impl IntoResponse {
    if body.is_empty() {
        return ApiError::bad_request(
            "empty body",
            "expected raw ELF bytes in the request body",
        ).into_response();
    }

    // Parsing is potentially CPU-heavy for large SOs; run on a blocking
    // thread so we don't stall the async runtime.
    let data = body.to_vec();
    let path_label = q.path.unwrap_or_else(|| "upload".to_string());
    let parsed = tokio::task::spawn_blocking(move || {
        sotrace_engine::elf::parse_elf_bytes(&data, &path_label)
    })
    .await;

    let parsed = match parsed {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            return ApiError::bad_request(
                "failed to parse ELF",
                e.to_string(),
            ).into_response();
        }
        Err(e) => {
            return ApiError::internal(
                "parse task join failed",
                e.to_string(),
            ).into_response();
        }
    };

    // Persist to the data directory (dedup by SHA-256).
    let parsed_for_save = parsed.clone();
    let data_dir = state.data_dir.clone();
    let save = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)?;
        let outcome = repo.save(&parsed_for_save)?;
        let summary = repo.summary(outcome.id)?
            .ok_or_else(|| anyhow::anyhow!("SO id {} missing from index after save", outcome.id))?;
        Ok::<_, anyhow::Error>((outcome, summary))
    })
    .await;

    match save {
        Ok(Ok((outcome, summary))) => {
            // deduped is the authoritative signal from save's index lookup —
            // no second-grained created_at heuristic (which broke on same-second
            // re-imports).
            Json(serde_json::json!({
                "so_id": outcome.id,
                "deduped": outcome.deduped,
                "summary": summary_summary_json(&summary),
            })).into_response()
        }
        Ok(Err(e)) => ApiError::internal(
            "failed to persist SO",
            e.to_string(),
        ).into_response(),
        Err(e) => ApiError::internal(
            "save task join failed",
            e.to_string(),
        ).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct UploadQuery {
    /// Optional label for the recorded SO path metadata.
    path: Option<String>,
}

async fn list_so_files(State(state): State<AppState>) -> impl IntoResponse {
    let data_dir = state.data_dir.clone();
    let res = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)?;
        Ok::<_, anyhow::Error>(repo.list()?)
    })
    .await;
    match res {
        Ok(Ok(list)) => Json(serde_json::json!({
            "so_files": list.iter().map(summary_summary_json).collect::<Vec<_>>(),
            "count": list.len(),
        })).into_response(),
        Ok(Err(e)) => ApiError::internal(
            "failed to list SOs",
            e.to_string(),
        ).into_response(),
        Err(e) => ApiError::internal(
            "list task join failed",
            e.to_string(),
        ).into_response(),
    }
}

async fn get_so_file(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    let data_dir = state.data_dir.clone();
    let res = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)?;
        match repo.summary(id)? {
            Some(summary) => Ok::<_, anyhow::Error>(Some(summary)),
            None => Ok(None),
        }
    })
    .await;
    match res {
        Ok(Ok(Some(summary))) => Json(serde_json::json!({
            "so_file": summary_summary_json(&summary),
        })).into_response(),
        Ok(Ok(None)) => ApiError::not_found(
            "not found",
            format!("no SO file with id {}", id),
        ).into_response(),
        Ok(Err(e)) => ApiError::internal(
            "failed to load SO",
            e.to_string(),
        ).into_response(),
        Err(e) => ApiError::internal(
            "load task join failed",
            e.to_string(),
        ).into_response(),
    }
}

/// Delete a persisted SO file by ID. Closes the CRUD symmetry with the MCP
/// `delete_so` tool and the CLI `so-delete` command.
async fn delete_so_file(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    let data_dir = state.data_dir.clone();
    let res = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)?;
        repo.delete(id)
    })
    .await;
    match res {
        Ok(Ok(true)) => Json(serde_json::json!({
            "status": "deleted",
            "so_id": id,
        })).into_response(),
        Ok(Ok(false)) => ApiError::not_found(
            "not found",
            format!("no SO file with id {}", id),
        ).into_response(),
        Ok(Err(e)) => ApiError::internal(
            "failed to delete SO",
            e.to_string(),
        ).into_response(),
        Err(e) => ApiError::internal(
            "delete task join failed",
            e.to_string(),
        ).into_response(),
    }
}

/// Render a SoSummary as a JSON object (id + key metadata).
fn summary_summary_json(s: &sotrace_engine::persistence::SoSummary) -> serde_json::Value {
    serde_json::json!({
        "id": s.id,
        "path": s.path,
        "arch": s.arch,
        "file_size": s.file_size,
        "sha256": s.sha256,
        "build_id": s.build_id,
        "function_count": s.function_count,
        "jni_function_count": s.jni_function_count,
        "exported_function_count": s.exported_function_count,
        "created_at": s.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{build_app_with_state, AppState};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    /// A minimal valid ELF (aarch64 shared object) — too small to be a real SO,
    /// but the `object` crate will reject it, which is enough to test the
    /// error path. For the success path we use the test SO on disk if present.
    fn empty_body() -> Body {
        Body::empty()
    }

    async fn app() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (AppState::new(dir.path().to_path_buf()), dir)
    }

    #[tokio::test]
    async fn test_create_so_empty_body_rejected() {
        let (state, _dir) = app().await;
        let app = build_app_with_state(state);
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/so-files")
                    .body(empty_body())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST); // empty body is a client error
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "empty body");
    }

    #[tokio::test]
    async fn test_list_empty_returns_zero() {
        let (state, _dir) = app().await;
        let app = build_app_with_state(state);
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/so-files")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["count"], 0);
    }

    #[tokio::test]
    async fn test_get_missing_so_returns_not_found() {
        let (state, _dir) = app().await;
        let app = build_app_with_state(state);
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/so-files/999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "not found");
        // detail carries the missing id; the bare id is no longer a top-level field.
        assert!(v["detail"].as_str().unwrap().contains("999"));
    }

    #[tokio::test]
    async fn test_create_so_from_bytes_roundtrip() {
        let so_path = std::path::Path::new("/tmp/sotest/libtest.so");
        if !so_path.exists() {
            eprintln!("skipping: {} not present", so_path.display());
            return;
        }
        let bytes = std::fs::read(so_path).unwrap();
        let (state, _dir) = app().await;
        let app = build_app_with_state(state.clone());
        // POST the raw bytes.
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/so-files?path=/tmp/sotest/libtest.so")
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v.get("so_id").is_some(), "response has so_id: {:?}", v);
        let id = v["so_id"].as_u64().unwrap();
        assert_eq!(v["summary"]["function_count"].as_u64().unwrap(), 486);

        // GET list should now show 1 SO.
        let app = build_app_with_state(state.clone());
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/so-files")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 1);

        // GET by id.
        let app = build_app_with_state(state);
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/v1/so-files/{}", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["so_file"]["id"].as_u64().unwrap(), id);
        assert_eq!(v["so_file"]["path"], "/tmp/sotest/libtest.so");
    }

    /// #107: DELETE /api/v1/so-files/:id closes the CRUD symmetry with the MCP
    /// `delete_so` tool and CLI `so-delete`. Seed an SO directly via the
    /// repository (bypassing parse), then DELETE → 200, re-DELETE → 404.
    #[tokio::test]
    async fn test_delete_so_roundtrip() {
        let (state, _dir) = app().await;

        // Seed a minimal ParsedSoFile directly through the repository.
        let so_id = {
            use sotrace_core::elf::ParsedSoFile;
            use sotrace_core::models::so_file::{Architecture, SOFile};
            let parsed = ParsedSoFile {
                so_file: SOFile {
                    id: 0, path: "/fake/libdelete.so".into(), build_id: None,
                    arch: Architecture::AArch64, file_size: 16, md5: [0; 16], sha256: [9; 32],
                    loaded_base_address: 0, created_at: 1_700_000_000,
                },
                segments: vec![], symbols: vec![], functions: vec![],
            };
            let repo = sotrace_engine::persistence::SoRepository::open(&state.data_dir).unwrap();
            repo.save(&parsed).unwrap().id
        };

        // DELETE → 200 deleted.
        let app = build_app_with_state(state.clone());
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/v1/so-files/{}", so_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "deleted");
        assert_eq!(v["so_id"], so_id);

        // Re-DELETE → 404 not_found.
        let app = build_app_with_state(state.clone());
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/v1/so-files/{}", so_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "not found");
        assert!(v["detail"].as_str().unwrap().contains(&so_id.to_string()));

        // List now empty.
        let app = build_app_with_state(state);
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/so-files")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["count"], 0);
    }
}
