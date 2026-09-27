//! API handlers

pub mod auth;
pub mod call_chain;
pub mod error;
pub mod instruction;
pub mod jni;
pub mod memory;
pub mod register;
pub mod so_file;
pub mod performance_analysis;
pub mod thread_analysis;
pub mod trace;
pub mod ui_control;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::Router;
use crate::app::AppState;

/// Build the API routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Health check
        .route("/api/v1/health", axum::routing::get(health_check))
        .route("/api/v1/metrics", axum::routing::get(metrics))
        // Auth routes
        .merge(auth::routes())
        // SO file routes
        .merge(so_file::routes())
        // Trace routes
        .merge(trace::routes())
        // Memory query routes
        .merge(memory::routes())
        // JNI query routes
        .merge(jni::routes())
        // Call chain routes
        .merge(call_chain::routes())
        // Instruction query routes
        .merge(instruction::routes())
        // Register query routes
        .merge(register::routes())
        // Thread analysis routes
        .merge(thread_analysis::routes())
        // Performance analysis routes (hot-paths, branches, address range)
        .merge(performance_analysis::routes())
        // UI command bus routes
        .merge(ui_control::routes())
}

async fn health_check() -> &'static str {
    "OK"
}

/// Prometheus text exposition of import and save failures.
///
/// Open like health: the counts are operational, not trace contents.
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = format!(
        "# TYPE sotrace_import_failures_total counter\nsotrace_import_failures_total {}\n# TYPE sotrace_save_failures_total counter\nsotrace_save_failures_total {}\n",
        state.import_failure_count(),
        state.save_failure_count(),
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}
