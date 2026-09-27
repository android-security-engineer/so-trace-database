//! Axum application builder

use anyhow::{Context, Result};
use axum::Router;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sotrace_core::adapters::TraceEvent;
use sotrace_engine::TraceEngine;

use crate::handlers;
use crate::middleware::auth::{auth_fn, TEST_BEARER_TOKEN};
use crate::ui_bus::UiBus;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub data_dir: PathBuf,
    /// Trace engine pool — maps trace_id → TraceEngine
    ///
    /// Each trace session has its own TraceEngine, behind a tokio `RwLock`
    /// rather than a `Mutex`: the vast majority of endpoints (instruction,
    /// register, memory, call-chain, JNI, and most thread queries) call
    /// `&self` query methods and can run fully concurrently under a shared
    /// read lock. Only mutation (import/load/save) and the handful of
    /// `analyze_*`/`detect_*` methods that lazily build indexes on first call
    /// take `&mut self` and need the exclusive write lock. This is the
    /// concurrency-scaling primitive for high-QPS Agent script access against
    /// the same trace_id.
    pub engines: Arc<tokio::sync::Mutex<HashMap<u64, Arc<tokio::sync::RwLock<TraceEngine>>>>>,
    /// Event stream buffer: trace_id → normalized events from the most recent
    /// import. Kept so `save` can persist the original event stream (the engine
    /// stores page-deltas, not raw MemoryWrite events).
    pub event_buffers: Arc<tokio::sync::Mutex<HashMap<u64, Vec<TraceEvent>>>>,
    /// UI command bus — lets agents send navigation/control commands to the
    /// browser frontend via SSE.
    pub ui_bus: Arc<UiBus>,
    /// Bearer token checked on import and instruction query.
    pub auth_token: String,
    /// Import attempts that did not apply (auth reject or handler error).
    pub import_failures: Arc<AtomicU64>,
    /// Save attempts that did not persist.
    pub save_failures: Arc<AtomicU64>,
}

impl AppState {
    /// Create a new empty AppState
    pub fn new(data_dir: PathBuf) -> Self {
        Self::with_auth_token(data_dir, TEST_BEARER_TOKEN.to_string())
    }

    /// Build state with an explicit bearer token. `main` passes
    /// `SOTRACE_AUTH_TOKEN`. Unit tests use [`Self::new`], which installs
    /// [`TEST_BEARER_TOKEN`].
    pub fn with_auth_token(data_dir: PathBuf, auth_token: String) -> Self {
        Self {
            data_dir,
            engines: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_buffers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            ui_bus: UiBus::new(),
            auth_token,
            import_failures: Arc::new(AtomicU64::new(0)),
            save_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_import_failure(&self) {
        self.import_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_save_failure(&self) {
        self.save_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn import_failure_count(&self) -> u64 {
        self.import_failures.load(Ordering::Relaxed)
    }

    pub fn save_failure_count(&self) -> u64 {
        self.save_failures.load(Ordering::Relaxed)
    }

    /// Get or create a TraceEngine for the given trace ID
    pub async fn get_or_create_engine(&self, trace_id: u64) -> Arc<tokio::sync::RwLock<TraceEngine>> {
        let mut engines = self.engines.lock().await;
        engines.entry(trace_id)
            .or_insert_with(|| {
                Arc::new(tokio::sync::RwLock::new(
                    TraceEngine::new(trace_id, Default::default())
                ))
            })
            .clone()
    }

    /// Store the normalized event stream for a trace (called by import_trace).
    pub async fn store_event_buffer(&self, trace_id: u64, events: Vec<TraceEvent>) {
        self.event_buffers.lock().await.insert(trace_id, events);
    }

    /// Take the stored event stream for a trace (called by save_trace).
    pub async fn take_event_buffer(&self, trace_id: u64) -> Option<Vec<TraceEvent>> {
        self.event_buffers.lock().await.remove(&trace_id)
    }
}

/// Build the Axum application from a data directory
pub fn build_app(data_dir: PathBuf) -> Result<Router> {
    let token = std::env::var("SOTRACE_AUTH_TOKEN")
        .context("SOTRACE_AUTH_TOKEN is required; the server will not start with an open import")?;
    if token.is_empty() {
        anyhow::bail!("SOTRACE_AUTH_TOKEN is empty");
    }
    Ok(build_app_with_state(AppState::with_auth_token(data_dir, token)))
}

/// Build the Axum application from a pre-constructed AppState
///
/// Exposed for testing: tests can inject a state pre-populated with
/// TraceEngine instances containing test data.
pub fn build_app_with_state(state: AppState) -> Router {
    Router::new()
        .merge(handlers::routes())
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_fn))
        .with_state(state)
}
