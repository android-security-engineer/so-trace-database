//! Authentication middleware for the release HTTP edge.
//!
//! Import and instruction query require `Authorization: Bearer <token>`.
//! The token is the process credential (`SOTRACE_AUTH_TOKEN` in `main`,
//! or the test fixture on `AppState` in unit tests). Health and metrics
//! stay open. A request is never forwarded just because a header is present.

use axum::extract::{Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::app::AppState;

/// Bearer token installed on `AppState::new` so in-process tests can
/// authenticate. `main` does not use this value unless the operator sets
/// `SOTRACE_AUTH_TOKEN` to it explicitly.
pub const TEST_BEARER_TOKEN: &str = "sotrace-test-credential";

/// Paths that require a validated bearer token.
pub fn protected_path(path: &str) -> bool {
    if path == "/api/v1/traces/import" {
        return true;
    }
    let mut parts = path.split('/');
    // ["", "api", "v1", "traces", "{id}", "instructions"]
    parts.next();
    parts.next() == Some("api")
        && parts.next() == Some("v1")
        && parts.next() == Some("traces")
        && parts.next().map(|id| !id.is_empty()).unwrap_or(false)
        && parts.next() == Some("instructions")
        && parts.next().is_none()
}

fn bearer_matches(expected: &str, header: Option<&str>) -> bool {
    if expected.is_empty() {
        return false;
    }
    let Some(header) = header else {
        return false;
    };
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    if presented.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.as_bytes().iter().zip(presented.as_bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Reject missing and invalid credentials on the protected import and
/// instruction-query routes. Every other route, including health, proceeds.
pub async fn auth_fn(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !protected_path(request.uri().path()) {
        return Ok(next.run(request).await);
    }
    let header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if bearer_matches(&state.auth_token, header) {
        return Ok(next.run(request).await);
    }
    if request.uri().path() == "/api/v1/traces/import" {
        state.record_import_failure();
    }
    Err(StatusCode::UNAUTHORIZED)
}
