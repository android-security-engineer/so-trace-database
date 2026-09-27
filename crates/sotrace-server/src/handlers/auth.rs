//! Auth handlers — setup, login, refresh

use axum::{Router, routing::post, extract::State, Json};
use serde::{Deserialize, Serialize};
use crate::app::AppState;

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Auth routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/setup", post(setup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(refresh))
}

/// First-time setup: configure admin credentials
async fn setup(
    State(_state): State<AppState>,
    Json(_req): Json<SetupRequest>,
) -> Json<AuthResponse> {
    // TODO: Implement setup logic
    Json(AuthResponse {
        access_token: "todo".to_string(),
        refresh_token: "todo".to_string(),
        expires_in: 86400,
    })
}

/// Login with credentials
async fn login(
    State(_state): State<AppState>,
    Json(_req): Json<LoginRequest>,
) -> Json<AuthResponse> {
    // TODO: Implement login logic
    Json(AuthResponse {
        access_token: "todo".to_string(),
        refresh_token: "todo".to_string(),
        expires_in: 86400,
    })
}

/// Refresh access token
async fn refresh() -> Json<AuthResponse> {
    // TODO: Implement token refresh
    Json(AuthResponse {
        access_token: "todo".to_string(),
        refresh_token: "todo".to_string(),
        expires_in: 86400,
    })
}
