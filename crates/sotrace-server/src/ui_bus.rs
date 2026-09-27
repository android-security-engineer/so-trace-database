//! UI command bus — lets agents send UI navigation/state commands to the
//! browser frontend via SSE (Server-Sent Events).

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};

/// A command sent from an agent to the browser UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiCommand {
    /// Monotonically increasing ID, assigned by the bus.
    pub id: u64,
    /// Command verb: "navigate", "select_trace", "switch_tab", "refresh", "close_modal".
    pub command: String,
    /// Free-form parameters (e.g. `{"page":"thread-analysis","trace_id":42,"tab":"races"}`).
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

/// Current UI state as reported by the browser frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiState {
    /// Current page name (e.g. "dashboard", "thread-analysis", "traces").
    pub page: String,
    /// Currently selected trace ID, if any.
    pub trace_id: Option<u64>,
    /// Active tab within the current page, if any.
    pub tab: Option<String>,
    /// Unix timestamp (ms) of the last state report.
    pub updated_at: u64,
    /// ID of the last command acknowledged by the browser frontend (0 = none yet).
    #[serde(default)]
    pub last_acked_command_id: u64,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            page: "dashboard".into(),
            trace_id: None,
            tab: None,
            updated_at: 0,
            last_acked_command_id: 0,
        }
    }
}

/// Shared command bus used both by the HTTP handler (sender) and the SSE
/// stream endpoint (receiver).
pub struct UiBus {
    tx: broadcast::Sender<UiCommand>,
    next_id: AtomicU64,
    state: RwLock<UiState>,
}

impl UiBus {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(64);
        Arc::new(Self {
            tx,
            next_id: AtomicU64::new(1),
            state: RwLock::new(UiState::default()),
        })
    }

    /// Enqueue a command. Returns the assigned command ID.
    /// If no frontend is subscribed the command is silently dropped.
    pub fn send(&self, command: String, params: HashMap<String, serde_json::Value>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let _ = self.tx.send(UiCommand { id, command, params });
        id
    }

    /// Create a new broadcast receiver for the SSE stream.
    pub fn subscribe(&self) -> broadcast::Receiver<UiCommand> {
        self.tx.subscribe()
    }

    pub async fn get_state(&self) -> UiState {
        self.state.read().await.clone()
    }

    pub async fn update_state(&self, state: UiState) {
        *self.state.write().await = state;
    }
}
