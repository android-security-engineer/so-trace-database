//! SO Trace Database — MCP Server for AI Agent integration
//!
//! Implements the Model Context Protocol (JSON-RPC 2.0 over stdio) to allow
//! AI agents (such as Claude) to import trace data and run thread analysis.
//!
//! # Usage
//!
//! Run the server as a stdio MCP server:
//! ```sh
//! sotrace-mcp                           # in-memory only (no persistence)
//! SOTRACE_DATA_DIR=./.sotrace sotrace-mcp  # persistence enabled
//! ```
//! The server reads JSON-RPC requests from stdin (one per line) and writes
//! responses to stdout. Set `SOTRACE_DATA_DIR` to enable trace/SO persistence
//! across sessions; without it, the `save_trace` / `load_trace` / persistence
//! tools return an error.
//!
//! # MCP Tools Provided
//!
//! - `import_trace` — Import trace events (threads, instructions, memory, sync, switches)
//! - `list_traces` — List imported trace IDs
//! - `list_threads` — List threads in a trace
//! - `query_instructions` — Query instruction traces with filters
//! - `query_sync_events` — Query synchronization events
//! - `query_context_switches` — Query context switches
//! - `analyze_threads` — Full thread analysis (races, deadlocks, contentions, ...)
//! - `detect_races` / `detect_deadlocks` / `analyze_contentions` / `classify_function_safety`
//! - `analyze_function_assoc` / `analyze_data_flows` / `detect_producer_consumer`
//! - `analyze_scheduling` — per-thread scheduling / context-switch stats
//! - `analyze_thread_lifecycle` — per-thread lifecycle / spawn tree
//! - `analyze_thread_states` — per-thread state residency / transitions
//! - `analyze_critical_sections` — per-lock critical-section / hold-time stats
//! - `analyze_jni_boundary` — per-thread JNI boundary-crossing stats (Java↔native)
//! - `save_trace` / `load_trace` / `list_persisted_traces` / `delete_persisted_trace`
//!   — persist & replay trace event streams (requires `SOTRACE_DATA_DIR`)
//!
//! # MCP Resources Provided
//!
//! - `sotrace://traces` — Trace listing
//! - `sotrace://traces/{id}/summary` — Trace summary

use anyhow::Result;
use std::path::PathBuf;

/// MCP server implementation
mod server;
/// MCP tools (AI-callable operations)
mod tools;
/// MCP resources
mod resources;

#[tokio::main]
async fn main() -> Result<()> {
    // Persistence is enabled when SOTRACE_DATA_DIR is set; otherwise the server
    // runs in pure in-memory mode and persistence tools return an error.
    let data_dir = std::env::var_os("SOTRACE_DATA_DIR").map(PathBuf::from);
    let server = server::McpServer::new_with_data_dir(data_dir);
    server.run_stdio().await
}
