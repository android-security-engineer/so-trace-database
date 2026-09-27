// MCP server — JSON-RPC 2.0 over stdio implementation of the Model Context Protocol
//
// This module implements a minimal but complete MCP server that allows AI agents
// (such as Claude) to import trace data and run thread analysis.
//
// # Protocol
//
// MCP uses JSON-RPC 2.0 over stdio: one JSON object per line.
// Supported methods:
// - `initialize` — handshake, returns server capabilities
// - `notifications/initialized` — client ack (no response)
// - `tools/list` — returns the list of available tools
// - `tools/call` — executes a tool by name
//
// # Transport
//
// Reads line-delimited JSON from stdin, writes responses to stdout.
// Notifications (no `id`) get no response.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sotrace_core::adapters::TraceEvent;
use sotrace_engine::TraceEngine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::tools::{tool_definitions, dispatch_tool, ToolError};
use crate::resources::{resource_definitions, read_resource, ResourceError};

/// MCP server — holds the trace engine pool and handles JSON-RPC requests
pub struct McpServer {
    /// Trace engine pool: trace_id → TraceEngine
    engines: Arc<tokio::sync::Mutex<HashMap<u64, Arc<tokio::sync::Mutex<TraceEngine>>>>>,
    /// Event stream buffer: trace_id → normalized events from the most recent
    /// `import_trace`. Kept so `save_trace` can persist the original event
    /// stream (the engine stores page-deltas, not raw MemoryWrite events).
    event_buffers: Arc<tokio::sync::Mutex<HashMap<u64, Vec<TraceEvent>>>>,
    /// Optional data directory for persistence (SO + trace repositories).
    /// When None, persistence tools return an error.
    data_dir: Option<PathBuf>,
    /// Server name (reported in initialize)
    server_name: String,
    /// Server version
    server_version: String,
    /// HTTP API server URL for GUI control tools (read from SOTRACE_SERVER_URL)
    pub(crate) server_url: Option<String>,
}

/// JSON-RPC 2.0 request
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error object
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// -32600: Invalid request
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self { code: -32600, message: msg.into(), data: None }
    }
    /// -32601: Method not found
    pub fn method_not_found(method: &str) -> Self {
        Self { code: -32601, message: format!("method not found: {}", method), data: None }
    }
    /// -32602: Invalid params
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self { code: -32602, message: msg.into(), data: None }
    }
    /// -32603: Internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self { code: -32603, message: msg.into(), data: None }
    }
}

impl McpServer {
    /// Create a new MCP server with no data directory (persistence disabled).
    pub fn new() -> Self {
        Self::new_with_data_dir(None)
    }

    /// Create a new MCP server with an optional data directory. When set,
    /// trace/SO persistence tools are available.
    pub fn new_with_data_dir(data_dir: Option<PathBuf>) -> Self {
        let server_url = std::env::var("SOTRACE_SERVER_URL").ok()
            .map(|u| u.trim_end_matches('/').to_string());
        Self {
            engines: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            event_buffers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            data_dir,
            server_name: "so-trace-database".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            server_url,
        }
    }

    /// The configured data directory, if persistence is enabled.
    pub(crate) fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref()
    }

    /// Get or create a TraceEngine for the given trace ID
    pub async fn get_or_create_engine(&self, trace_id: u64) -> Arc<tokio::sync::Mutex<TraceEngine>> {
        let mut engines = self.engines.lock().await;
        engines.entry(trace_id)
            .or_insert_with(|| {
                Arc::new(tokio::sync::Mutex::new(
                    TraceEngine::new(trace_id, Default::default())
                ))
            })
            .clone()
    }

    /// Read access to the engine pool (for listing traces)
    pub(crate) async fn engines_for_read(&self) -> tokio::sync::MutexGuard<'_, HashMap<u64, Arc<tokio::sync::Mutex<TraceEngine>>>> {
        self.engines.lock().await
    }

    /// Store the normalized event stream for a trace (called by import_trace).
    pub(crate) async fn store_event_buffer(&self, trace_id: u64, events: Vec<TraceEvent>) {
        self.event_buffers.lock().await.insert(trace_id, events);
    }

    /// Take the stored event stream for a trace (called by save_trace).
    pub(crate) async fn take_event_buffer(&self, trace_id: u64) -> Option<Vec<TraceEvent>> {
        self.event_buffers.lock().await.remove(&trace_id)
    }

    /// Run the MCP server over stdio
    ///
    /// Reads JSON-RPC requests line-by-line from stdin, writes responses to stdout.
    pub async fn run_stdio(&self) -> anyhow::Result<()> {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut stdout = tokio::io::stdout();
        let mut line = String::new();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                // EOF — client closed stdin
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Parse JSON-RPC request
            let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    // Could not parse — if there's an id, send a parse error
                    let id = serde_json::from_str::<Value>(trimmed)
                        .ok()
                        .and_then(|v| v.get("id").cloned())
                        .unwrap_or(Value::Null);
                    let resp = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32700,
                            message: format!("parse error: {}", e),
                            data: None,
                        }),
                    };
                    let mut out = serde_json::to_string(&resp)?;
                    out.push('\n');
                    stdout.write_all(out.as_bytes()).await?;
                    stdout.flush().await?;
                    continue;
                }
            };

            // Notifications (no id) get no response
            let is_notification = req.id.is_none();

            let response = self.handle_method(&req).await;

            if is_notification {
                continue;
            }

            let (result, error) = match response {
                Ok(v) => (Some(v), None),
                Err(e) => (None, Some(match e {
                    HandlerError::Rpc(e) => e,
                    HandlerError::Tool(te) => JsonRpcError {
                        code: -32603,
                        message: te.message,
                        data: te.data,
                    },
                    HandlerError::Resource(re) => JsonRpcError {
                        code: -32602,
                        message: re.message,
                        data: None,
                    },
                })),
            };

            let resp = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id.clone().unwrap_or(Value::Null),
                result,
                error,
            };

            let mut out = serde_json::to_string(&resp)?;
            out.push('\n');
            stdout.write_all(out.as_bytes()).await?;
            stdout.flush().await?;
        }

        Ok(())
    }

    /// Handle a single JSON-RPC method, returning a result value or an error
    async fn handle_method(&self, req: &JsonRpcRequest) -> Result<Value, HandlerError> {
        match req.method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {}
                },
                "serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version,
                },
            })),
            "notifications/initialized" => {
                // No-op acknowledgement
                Ok(Value::Null)
            }
            "tools/list" => Ok(json!({
                "tools": tool_definitions(),
            })),
            "resources/list" => Ok(json!({
                "resources": resource_definitions(),
            })),
            "resources/read" => {
                let uri = req.params.get("uri")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| HandlerError::Rpc(JsonRpcError::invalid_params("missing 'uri'")))?;
                let (content, mime_type) = read_resource(self, uri).await?;
                Ok(json!({
                    "contents": [{
                        "uri": uri,
                        "mimeType": mime_type,
                        "text": serde_json::to_string(&content)
                            .map_err(|e| HandlerError::Rpc(JsonRpcError::internal(e.to_string())))?,
                    }],
                }))
            }
            "tools/call" => {
                let name = req.params.get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| HandlerError::Rpc(JsonRpcError::invalid_params("missing 'name'")))?
                    .to_string();
                let arguments = req.params.get("arguments").cloned().unwrap_or(Value::Null);
                let result = dispatch_tool(self, &name, &arguments).await?;
                Ok(result)
            }
            "ping" => Ok(json!({})),
            other => Err(HandlerError::Rpc(JsonRpcError::method_not_found(other))),
        }
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Error from handling a JSON-RPC method
#[derive(Debug)]
pub enum HandlerError {
    /// A JSON-RPC level error (method not found, invalid params, etc.)
    Rpc(JsonRpcError),
    /// An error from a tool execution
    Tool(ToolError),
    /// An error from a resource read
    Resource(ResourceError),
}

impl From<ToolError> for HandlerError {
    fn from(e: ToolError) -> Self {
        HandlerError::Tool(e)
    }
}

impl From<ResourceError> for HandlerError {
    fn from(e: ResourceError) -> Self {
        HandlerError::Resource(e)
    }
}
