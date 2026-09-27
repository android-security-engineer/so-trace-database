//! HTTP handlers for UI command bus.
//!
//! Endpoints:
//!   POST /api/v1/ui/command  — agent sends a command (enqueued, broadcast to SSE subscribers)
//!   GET  /api/v1/ui/events   — browser subscribes via SSE; receives commands in real time
//!   GET  /api/v1/ui/state    — agent reads the latest UI state reported by the browser
//!   POST /api/v1/ui/state    — browser reports its current page/tab/trace state

use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Duration};

use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Json,
    },
};
use futures::stream::{self, Stream, StreamExt};
use serde::{Deserialize, Serialize};

use crate::{
    app::AppState,
    ui_bus::{UiBus, UiState},
};

// ─── Request / response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendCommandRequest {
    pub command: String,
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct SendCommandResponse {
    pub id: u64,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /api/v1/ui/command
///
/// An agent sends a UI command (e.g. navigate to a page, switch a tab).
/// The command is broadcast to all currently-connected SSE subscribers.
pub async fn send_command(
    State(state): State<AppState>,
    Json(req): Json<SendCommandRequest>,
) -> Json<SendCommandResponse> {
    let id = state.ui_bus.send(req.command, req.params);
    Json(SendCommandResponse { id })
}

/// GET /api/v1/ui/events
///
/// The browser frontend subscribes here via SSE and receives `command` events
/// as they arrive. A `ping` event is sent every 15 s to keep the connection alive.
pub async fn subscribe_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.ui_bus.subscribe();

    // Command stream: yield one SSE event per received UiCommand.
    let cmd_stream = stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(cmd) => {
                    let data = serde_json::to_string(&cmd).unwrap_or_default();
                    let event = Event::default().event("command").data(data);
                    return Some((Ok(event), rx));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Missed some messages — skip and continue
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return None;
                }
            }
        }
    });

    Sse::new(cmd_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

/// GET /api/v1/ui/state
///
/// Returns the latest UI state that the browser reported via POST /ui/state.
pub async fn get_state(State(state): State<AppState>) -> Json<UiState> {
    Json(state.ui_bus.get_state().await)
}

/// POST /api/v1/ui/state
///
/// The browser frontend calls this whenever its navigation state changes,
/// so agents can always query the current page/tab/trace.
pub async fn report_state(
    State(state): State<AppState>,
    Json(ui_state): Json<UiState>,
) -> StatusCode {
    state.ui_bus.update_state(ui_state).await;
    StatusCode::OK
}

// ─── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/v1/ui/command", post(send_command))
        .route("/api/v1/ui/events", get(subscribe_events))
        .route("/api/v1/ui/state", get(get_state).post(report_state))
}
