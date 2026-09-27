//! MCP Resources — AI-readable data sources
//!
//! Resources in MCP are read-only URIs that an AI agent can list and read.
//! Unlike tools (which are actions), resources are passive snapshots of data.
//!
//! # URI scheme
//!
//! - `sotrace://traces` — list of all imported traces
//! - `sotrace://traces/{id}/summary` — high-level summary of a trace
//! - `sotrace://traces/{id}/threads` — list of threads in a trace
//! - `sotrace://traces/{id}/stats` — per-thread statistics for a trace

use serde_json::{json, Value};

use crate::server::McpServer;

/// Resource URI patterns (also used for documentation)
pub const TRACES_LIST: &str = "sotrace://traces";
pub const TRACE_SUMMARY: &str = "sotrace://traces/{id}/summary";
pub const TRACE_THREADS: &str = "sotrace://traces/{id}/threads";
pub const TRACE_STATS: &str = "sotrace://traces/{id}/stats";

/// Error returned by a resource read
#[derive(Debug)]
pub struct ResourceError {
    pub message: String,
}

impl ResourceError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

/// A single resource descriptor (for `resources/list`)
fn resource_template(uri: &str, name: &str, description: &str, mime_type: &str) -> Value {
    json!({
        "uri": uri,
        "name": name,
        "description": description,
        "mimeType": mime_type,
    })
}

/// Return the static list of resource templates for `resources/list`.
///
/// Note: in MCP, `resources/list` typically returns concrete (non-templated)
/// resources. We list the per-trace resources dynamically, but since traces
/// are imported at runtime via `import_trace`, the client can discover them
/// via the `sotrace://traces` resource instead. Here we return the static
/// entry points.
pub fn resource_definitions() -> Vec<Value> {
    vec![
        resource_template(
            TRACES_LIST,
            "traces",
            "List of all imported trace IDs with basic counts",
            "application/json",
        ),
        resource_template(
            TRACE_SUMMARY,
            "trace-summary",
            "High-level summary of a trace: step count, thread count, event counts",
            "application/json",
        ),
        resource_template(
            TRACE_THREADS,
            "trace-threads",
            "List of threads in a trace with metadata (name, stack, TLS, ...)",
            "application/json",
        ),
        resource_template(
            TRACE_STATS,
            "trace-stats",
            "Per-thread statistics: switches, running time, wait time, ...",
            "application/json",
        ),
    ]
}

/// Read a resource by URI, returning its JSON content and mime type.
///
/// Supported URIs:
/// - `sotrace://traces`
/// - `sotrace://traces/{id}/summary`
/// - `sotrace://traces/{id}/threads`
/// - `sotrace://traces/{id}/stats`
pub async fn read_resource(
    server: &McpServer,
    uri: &str,
) -> Result<(Value, &'static str), ResourceError> {
    let (content, mime) = if uri == TRACES_LIST {
        (read_traces_list(server).await?, "application/json")
    } else if let Some(trace_id) = match_trace_resource(uri, "summary") {
        (read_trace_summary(server, trace_id).await?, "application/json")
    } else if let Some(trace_id) = match_trace_resource(uri, "threads") {
        (read_trace_threads(server, trace_id).await?, "application/json")
    } else if let Some(trace_id) = match_trace_resource(uri, "stats") {
        (read_trace_stats(server, trace_id).await?, "application/json")
    } else {
        return Err(ResourceError::new(format!("unknown resource URI: {}", uri)));
    };
    Ok((content, mime))
}

/// Match `sotrace://traces/{id}/{suffix}` and return the parsed trace_id
fn match_trace_resource(uri: &str, suffix: &str) -> Option<u64> {
    let prefix = "sotrace://traces/";
    let rest = uri.strip_prefix(prefix)?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() == 2 && parts[1] == suffix {
        parts[0].parse::<u64>().ok()
    } else {
        None
    }
}

async fn read_traces_list(server: &McpServer) -> Result<Value, ResourceError> {
    let engines = server.engines_for_read().await;
    let traces: Vec<Value> = engines.keys().map(|&id| {
        // Note: we only have the lock guard here; reading deeper stats would
        // require acquiring the per-engine lock, which would deadlock against
        // this outer lock. We return the trace_id and let the client fetch
        // the summary resource for details.
        json!({ "trace_id": id })
    }).collect();
    Ok(json!({
        "trace_count": traces.len(),
        "traces": traces,
    }))
}

async fn read_trace_summary(server: &McpServer, trace_id: u64) -> Result<Value, ResourceError> {
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let stats = engine.all_thread_stats();
    let total_switches: u64 = stats.iter().map(|s| s.context_switch_count).sum();
    Ok(json!({
        "trace_id": trace_id,
        "so_file_id": engine.so_file_id(),
        "total_steps": engine.total_steps(),
        "current_step": engine.current_step(),
        "thread_count": engine.thread_count(),
        "total_context_switches": total_switches,
    }))
}

async fn read_trace_threads(server: &McpServer, trace_id: u64) -> Result<Value, ResourceError> {
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let threads: Vec<Value> = engine.all_thread_ids()
        .into_iter()
        .filter_map(|tid| engine.get_thread_info(tid))
        .map(|info| serde_json::to_value(info).unwrap_or(Value::Null))
        .collect();
    Ok(json!({
        "trace_id": trace_id,
        "thread_count": threads.len(),
        "threads": threads,
    }))
}

async fn read_trace_stats(server: &McpServer, trace_id: u64) -> Result<Value, ResourceError> {
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let stats = engine.all_thread_stats();
    let stats_json: Vec<Value> = stats.iter()
        .map(|s| serde_json::to_value(s).unwrap_or(Value::Null))
        .collect();
    Ok(json!({
        "trace_id": trace_id,
        "thread_count": stats_json.len(),
        "stats": stats_json,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::McpServer;
    use serde_json::json;

    /// Import a minimal trace so resources have data to read
    async fn setup(server: &McpServer) {
        let args = json!({
            "trace_id": 42,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "sync_events": [
                {"step": 3, "thread_id": 1, "sync_type": "MutexLock",
                 "sync_object_addr": 2882338816u64, "result": "Success", "wait_duration_ns": null},
            ],
            "context_switches": [
                {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0},
            ],
        });
        // Use the tool dispatcher to import (avoids duplicating parsing logic)
        crate::tools::dispatch_tool(server, "import_trace", &args).await.unwrap();
    }

    #[test]
    fn test_resource_definitions_have_required_fields() {
        let defs = resource_definitions();
        assert!(!defs.is_empty());
        for d in &defs {
            assert!(d["uri"].is_string(), "resource missing uri");
            assert!(d["name"].is_string(), "resource missing name");
            assert!(d["mimeType"].is_string(), "resource missing mimeType");
        }
    }

    #[test]
    fn test_match_trace_resource() {
        assert_eq!(match_trace_resource("sotrace://traces/42/summary", "summary"), Some(42));
        assert_eq!(match_trace_resource("sotrace://traces/42/threads", "threads"), Some(42));
        assert_eq!(match_trace_resource("sotrace://traces/42/stats", "stats"), Some(42));
        assert_eq!(match_trace_resource("sotrace://traces/42/summary", "threads"), None);
        assert_eq!(match_trace_resource("sotrace://traces/abc/summary", "summary"), None);
        assert_eq!(match_trace_resource("sotrace://traces/42", "summary"), None);
        assert_eq!(match_trace_resource("sotrace://other/42/summary", "summary"), None);
    }

    #[tokio::test]
    async fn test_read_traces_list() {
        let server = McpServer::new();
        setup(&server).await;
        let (content, mime) = read_resource(&server, TRACES_LIST).await.unwrap();
        assert_eq!(mime, "application/json");
        assert_eq!(content["trace_count"], 1);
        assert_eq!(content["traces"][0]["trace_id"], 42);
    }

    #[tokio::test]
    async fn test_read_trace_summary() {
        let server = McpServer::new();
        setup(&server).await;
        let (content, _) = read_resource(&server, "sotrace://traces/42/summary").await.unwrap();
        assert_eq!(content["trace_id"], 42);
        assert_eq!(content["thread_count"], 1);
        assert!(content["total_context_switches"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn test_read_trace_threads() {
        let server = McpServer::new();
        setup(&server).await;
        let (content, _) = read_resource(&server, "sotrace://traces/42/threads").await.unwrap();
        assert_eq!(content["thread_count"], 1);
        assert_eq!(content["threads"][0]["name"], "main");
    }

    #[tokio::test]
    async fn test_read_trace_stats() {
        let server = McpServer::new();
        setup(&server).await;
        let (content, _) = read_resource(&server, "sotrace://traces/42/stats").await.unwrap();
        assert_eq!(content["thread_count"], 1);
        assert!(content["stats"].is_array());
    }

    #[tokio::test]
    async fn test_read_unknown_resource_returns_error() {
        let server = McpServer::new();
        let result = read_resource(&server, "sotrace://bogus").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("unknown resource"));
    }
}
