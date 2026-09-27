//! SO Trace Database — HTTP API Server

use anyhow::Result;
use axum::Router;
use std::path::PathBuf;

mod app;
mod handlers;
mod middleware;
mod ui_bus;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse configuration
    let data_dir = std::env::var("SOTRACE_DATA_DIR")
        .unwrap_or_else(|_| "./data".to_string());
    let bind_addr = std::env::var("SOTRACE_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    // Build and run the server
    let app = app::build_app(PathBuf::from(data_dir))?;

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("SO Trace Server listening on {}", bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
