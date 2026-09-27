//! API error type — uniform error responses with correct HTTP status codes.
//!
//! Before this module, handlers returned errors as `Json({"error": ...})` with
//! the default 200 OK. That broke HTTP semantics: a client could not tell
//! success from failure by status code and had to parse the body for an
//! `"error"` field. `ApiError` centralizes the mapping from a logical error
//! kind to the right status code, with a consistent JSON body shape, so every
//! error route returns a real 4xx/5xx.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// A uniform API error carrying the HTTP status it should produce.
///
/// Construct with [`ApiError::bad_request`] / [`ApiError::not_found`] /
/// [`ApiError::internal`] (or [`ApiError::new`] for an arbitrary status). The
/// `detail` is the lower-level cause (e.g. the engine error's `to_string`),
/// surfaced to the caller for diagnostics; keep it free of secrets.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    error: &'static str,
    detail: String,
}

impl ApiError {
    /// Build an error with an explicit status and label.
    pub fn new(status: StatusCode, error: &'static str, detail: impl Into<String>) -> Self {
        Self { status, error, detail: detail.into() }
    }

    /// 400 — the request body or referenced resource is malformed / missing
    /// (empty body, unparseable ELF, an import that failed on bad input).
    pub fn bad_request(error: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error, detail)
    }

    /// 404 — the referenced trace / thread / SO does not exist (in-memory or
    /// on disk).
    pub fn not_found(error: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, error, detail)
    }

    /// 500 — an internal failure the caller can't fix (persistence I/O, a
    /// spawn_blocking join failure, an unexpected engine error).
    pub fn internal(error: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error, detail)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.error,
            "detail": self.detail,
        }));
        (self.status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn bad_request_maps_to_400() {
        let resp = ApiError::bad_request("empty body", "expected ELF bytes").into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_json(resp).await;
        assert_eq!(v["error"], "empty body");
        assert_eq!(v["detail"], "expected ELF bytes");
    }

    #[tokio::test]
    async fn not_found_maps_to_404() {
        let resp = ApiError::not_found("not found", "no trace with id 7").into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let v = body_json(resp).await;
        assert_eq!(v["error"], "not found");
        assert!(v["detail"].as_str().unwrap().contains('7'));
    }

    #[tokio::test]
    async fn internal_maps_to_500() {
        let resp = ApiError::internal("task join failed", "join error").into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let v = body_json(resp).await;
        assert_eq!(v["error"], "task join failed");
    }
}
