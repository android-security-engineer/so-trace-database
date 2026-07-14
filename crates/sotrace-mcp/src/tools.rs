//! MCP Tools — AI-callable operations for trace analysis
//!
//! Each tool has:
//! - A JSON Schema definition (name, description, input schema) for `tools/list`
//! - A dispatch handler that executes against the TraceEngine pool
//!
//! # Available Tools
//!
//! - `import_trace` — Import a batch of trace events (threads, instructions, memory, sync, switches)
//! - `list_traces` — List imported trace IDs
//! - `list_threads` — List threads in a trace
//! - `query_instructions` — Query instructions with filters
//! - `query_sync_events` — Query synchronization events
//! - `query_context_switches` — Query context switches
//! - `analyze_threads` — Run full thread analysis (races, deadlocks, contentions, ...)
//! - `detect_races` — Detect race conditions only
//! - `detect_deadlocks` — Detect deadlock risks only
//! - `analyze_contentions` — Analyze lock contentions only
//! - `classify_function_safety` — Classify function thread safety
//! - `analyze_function_assoc` — Analyze thread-function associations only
//! - `analyze_data_flows` — Analyze inter-thread data flows only
//! - `detect_producer_consumer` — Detect producer-consumer patterns only
//! - `analyze_scheduling` — Per-thread scheduling / context-switch stats only

use serde_json::{json, Value};
use sotrace_core::models::call_trace::CallTrace;
use sotrace_core::models::instruction_trace::InstructionTrace;
use sotrace_core::models::jni_call::JNICall;
use sotrace_core::models::register_delta::RegisterDelta;
use sotrace_core::models::thread::{
    ContextSwitch, ThreadInfo, ThreadStateChange, ThreadSyncEvent,
};
use sotrace_engine::TraceEngine;

use crate::server::McpServer;

/// Error returned by a tool execution
#[derive(Debug)]
pub struct ToolError {
    pub message: String,
    pub data: Option<Value>,
}

impl ToolError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into(), data: None }
    }
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// Return the list of tool definitions (JSON Schema) for `tools/list`
pub fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "import_trace",
            "description": "Import a batch of trace events into the engine. Creates the trace if it doesn't exist. All events are inserted atomically.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer", "description": "Trace ID (unique identifier for this trace session)" },
                    "so_file_id": { "type": "integer", "description": "SO file ID to register into the engine for function-name resolution in analysis results (race locations, JNI native addresses, thread-function associations). 0/absent = no SO (names stay None). Upload the SO via create_so_file first to obtain this ID. Mirrors CLI load_engine." },
                    "threads": { "type": "array", "description": "Thread metadata to register", "items": { "type": "object" } },
                    "instructions": { "type": "array", "description": "Instruction trace records (in seq order)", "items": { "type": "object" } },
                    "memory_writes": { "type": "array", "description": "Memory write events", "items": { "type": "object" } },
                    "memory_reads": { "type": "array", "description": "Memory read events (fed to the analyzer for write→read race detection; not stored as memory state)", "items": { "type": "object" } },
                    "sync_events": { "type": "array", "description": "Synchronization events (mutex/futex/condvar)", "items": { "type": "object" } },
                    "context_switches": { "type": "array", "description": "Context switch records", "items": { "type": "object" } },
                    "state_changes": { "type": "array", "description": "Thread state change records", "items": { "type": "object" } },
                    "jni_calls": { "type": "array", "description": "JNI boundary-crossing call records (Java↔native)", "items": { "type": "object" } },
                    "register_deltas": { "type": "array", "description": "ARM64 register-change deltas (change_mask + new values at a step)", "items": { "type": "object" } },
                    "calls": { "type": "array", "description": "Function call/return events (CallTrace) for call-stack reconstruction", "items": { "type": "object" } },
                },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "list_traces",
            "description": "List all imported trace IDs.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "list_threads",
            "description": "List all threads in a trace with metadata. Set include_stats=true to also return per-thread statistics (lock acquire/release counts, contentions, etc.) alongside the thread metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "include_stats": { "type": "boolean", "default": false, "description": "If true, include a top-level `stats` array of ThreadStats (lock_acquire_count, lock_release_count, contention, …) alongside `threads`." }
                },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "query_instructions",
            "description": "Query instruction traces with optional filters.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "start_step": { "type": "integer" },
                    "end_step": { "type": "integer" },
                    "thread_id": { "type": "integer" },
                    "address": { "type": "integer", "description": "Exact instruction address to match" },
                    "limit": { "type": "integer" }
                },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "query_sync_events",
            "description": "Query synchronization events (mutex/futex/condvar) with filters. Filter by thread_id, sync_object_addr, or step range.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "thread_id": { "type": "integer" },
                    "sync_object_addr": { "type": "integer", "description": "Lock/condvar address" },
                    "start_step": { "type": "integer" },
                    "end_step": { "type": "integer" }
                },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "query_context_switches",
            "description": "Query context switch records, optionally filtered by thread involvement.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "thread_id": { "type": "integer", "description": "Filter to switches involving this thread (as from or to)" },
                    "start_step": { "type": "integer" },
                    "end_step": { "type": "integer" }
                },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_threads",
            "description": "Run comprehensive thread analysis: race conditions, deadlock risks, lock contentions, thread-function associations, function thread safety, data flows, producer-consumer patterns. Returns all results.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "detect_races",
            "description": "Detect race conditions: cross-thread memory access without synchronization. Returns list of detected races with confidence and steps.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "detect_deadlocks",
            "description": "Detect deadlock risks via lock-ordering cycle detection. Returns list of potential deadlocks with the lock cycle and involved threads.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_contentions",
            "description": "Analyze lock contention: acquisition counts, contention ratios, wait times, contending threads per lock.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "classify_function_safety",
            "description": "Classify each function's thread safety: ThreadSafe / PotentiallyUnsafe / Unsafe / Unknown, based on calling threads, sync events, and detected races.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_function_assoc",
            "description": "Analyze which threads called which functions: per (thread, function) call counts and first/last call steps. Function names are back-filled from ELF symbols when available.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_data_flows",
            "description": "Analyze inter-thread data flows: each write→read transfer across threads with the address, steps, and whether the transfer was synchronized.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "detect_producer_consumer",
            "description": "Detect producer-consumer patterns between threads: producer/consumer threads, shared addresses, cycle counts, average latency, and the synchronization mechanism used.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_scheduling",
            "description": "Summarize per-thread scheduling from the context-switch stream: how often each thread was scheduled on/off CPU, whether it left willingly (yield/blocking) or was preempted, migration count, and the CPU cores it ran on.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_thread_lifecycle",
            "description": "Reconstruct each thread's lifecycle and the spawn tree: its parent, the child threads it spawned, its create/exit steps and lifespan, whether it is still alive, and its depth in the spawn tree. Useful for understanding thread topology and liveness at a glance.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_thread_states",
            "description": "Summarize per-thread state residency from the thread-state-change stream: how many steps each thread spent Running vs waiting/blocked (WaitingForLock/Futex/Condvar/IO, Blocked, Sleeping), its transition count, blocked ratio, and final state. Useful for spotting contention (mostly WaitingForLock) or I/O bottlenecks (mostly WaitingForIO) at a glance.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_critical_sections",
            "description": "Summarize per-lock critical-section hold time: how long each lock was actually held once acquired (acquire→release span), across how many hold intervals, the average and longest hold, which thread held it longest, and all holding threads. Where analyze_contentions measures how long threads WAITED for a lock, this measures how long it was HELD — the root cause of that waiting. Useful for finding the critical section to shorten.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "analyze_jni_boundary",
            "description": "Summarize per-thread JNI boundary-crossing behavior: how many Java→Native and Native→Java crossings each thread made, the distinct native addresses reached from Java (reverse-engineering entry points), and the Java methods on the other side of each crossing. Threads marked JNI-attached in metadata are surfaced even with zero crossings (attached-but-idle). Useful for mapping the Java↔native attack surface of an Android SO.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "save_trace",
            "description": "Persist the event stream of an in-memory trace to disk so it survives across MCP sessions. Requires the server to be started with a data directory. Returns the assigned persisted trace ID (use it with load_trace).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer", "description": "In-memory trace ID to persist (from import_trace)" },
                    "so_file_id": { "type": "integer", "description": "SO file ID to associate (default 0)" },
                    "source": { "type": "string", "description": "Source label (default 'mcp')" }
                },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "load_trace",
            "description": "Replay a persisted trace from disk into the in-memory engine pool by its persisted ID. Requires a data directory. The replayed trace is available for all query/analyze tools under its persisted ID.",
            "inputSchema": {
                "type": "object",
                "properties": { "persisted_id": { "type": "integer", "description": "Persisted trace ID (from save_trace / list_persisted_traces)" } },
                "required": ["persisted_id"]
            }
        }),
        json!({
            "name": "list_persisted_traces",
            "description": "List all traces persisted in the data directory (summaries only). Requires a data directory.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "delete_persisted_trace",
            "description": "Delete a persisted trace by ID. Requires a data directory.",
            "inputSchema": {
                "type": "object",
                "properties": { "trace_id": { "type": "integer" } },
                "required": ["trace_id"]
            }
        }),
        json!({
            "name": "import_so",
            "description": "Upload + parse + persist an SO (ELF) file so analysis can resolve function names instead of bare offsets. The ELF bytes travel base64-encoded inside `bytes` (JSON-RPC args cannot carry raw bytes). Optional `path` labels the recorded metadata (default 'upload'). Returns the assigned so_id (use it with import_trace's so_file_id), whether the upload was deduplicated by SHA-256, and a summary. Requires a data directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "bytes": { "type": "string", "description": "Base64-encoded ELF bytes of the SO file" },
                    "path": { "type": "string", "description": "Optional label for the recorded SO path metadata (default 'upload')" }
                },
                "required": ["bytes"]
            }
        }),
        json!({
            "name": "list_so_files",
            "description": "List all SO files persisted in the data directory (summaries only). Requires a data directory.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "get_so_file",
            "description": "Get a single persisted SO file's summary by ID. Requires a data directory.",
            "inputSchema": {
                "type": "object",
                "properties": { "so_id": { "type": "integer" } },
                "required": ["so_id"]
            }
        }),
        json!({
            "name": "delete_so",
            "description": "Delete a persisted SO file by ID. Requires a data directory.",
            "inputSchema": {
                "type": "object",
                "properties": { "so_id": { "type": "integer" } },
                "required": ["so_id"]
            }
        }),
        json!({
            "name": "query_register",
            "description": "Query a single ARM64 register's value at a given step (0-30=x0-x30, 31=SP, 32=PC, 33=NZCV). Returns the last value written to that register at or before the step, or null if none.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "register_id": { "type": "integer", "description": "ARM64 register index (0-30 GPR, 31 SP, 32 PC, 33 NZCV)" },
                    "step": { "type": "integer" }
                },
                "required": ["trace_id", "register_id", "step"]
            }
        }),
        json!({
            "name": "query_register_state",
            "description": "Reconstruct the full ARM64 register file (all GPRs + SP + PC + NZCV) as of a given step by replaying every delta up to that step. Returns null if no delta exists at or before the step.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "step": { "type": "integer" }
                },
                "required": ["trace_id", "step"]
            }
        }),
        json!({
            "name": "query_register_history",
            "description": "List the steps at which a register was modified, in ascending order. Answers \"when did register X change?\" — the list form of query_register. Uses the per-register index (O(log K + R)). register_id: 0-30 = x0-x30, 31 = SP, 32 = PC, 33 = NZCV. Optionally restrict to a step range.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "register_id": { "type": "integer", "description": "0-30 = x0-x30, 31 = SP, 32 = PC, 33 = NZCV" },
                    "start": { "type": "integer", "description": "Start step (inclusive). Default 0." },
                    "end": { "type": "integer", "description": "End step (inclusive). Default max." }
                },
                "required": ["trace_id", "register_id"]
            }
        }),
        json!({
            "name": "query_memory_value",
            "description": "Query a memory value at a given address and step, reading `size` bytes (default 8). Replays page deltas up to the step to reconstruct the bytes present at that point in time.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "address": { "type": "integer" },
                    "step": { "type": "integer" },
                    "size": { "type": "integer", "description": "Bytes to read (default 8)" }
                },
                "required": ["trace_id", "address", "step"]
            }
        }),
        json!({
            "name": "query_memory_page",
            "description": "Reconstruct a full memory page as of a given step. Returns the page bytes (hex-encoded) and length, or null if the page was never written at or before the step.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "page_address": { "type": "integer" },
                    "step": { "type": "integer" }
                },
                "required": ["trace_id", "page_address", "step"]
            }
        }),
        json!({
            "name": "query_call_stack",
            "description": "Rebuild a thread's call stack at a given step by replaying its call/return events. Returns the active frames outermost-first, or an empty array if the thread has no active call at that step.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "thread_id": { "type": "integer" },
                    "step": { "type": "integer" }
                },
                "required": ["trace_id", "thread_id", "step"]
            }
        }),
        json!({
            "name": "query_jni_calls",
            "description": "Query JNI boundary calls reaching a given native function address. Answers \"which Java methods called into this native entry point, and when?\" — the JNI analogue of querying instructions by address. Optionally restrict to a step range. Same-step calls targeting a different native address are excluded.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "address": { "type": "integer", "description": "Native function address" },
                    "start": { "type": "integer", "description": "Start step (inclusive). Default 0." },
                    "end": { "type": "integer", "description": "End step (inclusive). Default max." }
                },
                "required": ["trace_id", "address"]
            }
        }),
        json!({
            "name": "query_threads_at_address",
            "description": "List which threads executed at a given address, and at which steps. Returns (thread_id, step) pairs — each entry means \"thread T executed this address at step S\". Same-step instructions from multiple threads all survive. The cross-thread view of \"who touches this code location?\".",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "address": { "type": "integer", "description": "Instruction address" }
                },
                "required": ["trace_id", "address"]
            }
        }),
    ]
}

/// Dispatch a tool call to its handler
pub async fn dispatch_tool(
    server: &McpServer,
    name: &str,
    args: &Value,
) -> Result<Value, ToolError> {
    match name {
        "import_trace" => tool_import_trace(server, args).await,
        "list_traces" => tool_list_traces(server).await,
        "list_threads" => tool_list_threads(server, args).await,
        "query_instructions" => tool_query_instructions(server, args).await,
        "query_sync_events" => tool_query_sync_events(server, args).await,
        "query_context_switches" => tool_query_context_switches(server, args).await,
        "analyze_threads" => tool_analyze_threads(server, args).await,
        "detect_races" => tool_detect_races(server, args).await,
        "detect_deadlocks" => tool_detect_deadlocks(server, args).await,
        "analyze_contentions" => tool_analyze_contentions(server, args).await,
        "classify_function_safety" => tool_classify_function_safety(server, args).await,
        "analyze_function_assoc" => tool_analyze_function_assoc(server, args).await,
        "analyze_data_flows" => tool_analyze_data_flows(server, args).await,
        "detect_producer_consumer" => tool_detect_producer_consumer(server, args).await,
        "analyze_scheduling" => tool_analyze_scheduling(server, args).await,
        "analyze_thread_lifecycle" => tool_analyze_thread_lifecycle(server, args).await,
        "analyze_thread_states" => tool_analyze_thread_states(server, args).await,
        "analyze_critical_sections" => tool_analyze_critical_sections(server, args).await,
        "analyze_jni_boundary" => tool_analyze_jni_boundary(server, args).await,
        "save_trace" => tool_save_trace(server, args).await,
        "load_trace" => tool_load_trace(server, args).await,
        "list_persisted_traces" => tool_list_persisted_traces(server).await,
        "delete_persisted_trace" => tool_delete_persisted_trace(server, args).await,
        "import_so" => tool_import_so(server, args).await,
        "list_so_files" => tool_list_so_files(server).await,
        "get_so_file" => tool_get_so_file(server, args).await,
        "delete_so" => tool_delete_so(server, args).await,
        "query_register" => tool_query_register(server, args).await,
        "query_register_state" => tool_query_register_state(server, args).await,
        "query_register_history" => tool_query_register_history(server, args).await,
        "query_memory_value" => tool_query_memory_value(server, args).await,
        "query_memory_page" => tool_query_memory_page(server, args).await,
        "query_call_stack" => tool_query_call_stack(server, args).await,
        "query_jni_calls" => tool_query_jni_calls(server, args).await,
        "query_threads_at_address" => tool_query_threads_at_address(server, args).await,
        other => Err(ToolError::new(format!("unknown tool: {}", other))),
    }
}

// --- Helper: extract trace_id from args ---
fn get_trace_id(args: &Value) -> Result<u64, ToolError> {
    args.get("trace_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'trace_id' (expected integer)"))
}

// --- Helper: extract so_id from args ---
fn get_so_id(args: &Value) -> Result<u64, ToolError> {
    args.get("so_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'so_id' (expected integer)"))
}

// ===========================================================================
// Tool handlers
// ===========================================================================

async fn tool_import_trace(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    use sotrace_core::adapters::TraceEvent;
    let trace_id = get_trace_id(args)?;

    // Phase 1: parse every category into a uniform `TraceEvent` stream WITHOUT
    // touching the engine. Ingestion order used to follow category order
    // (threads, then instructions, then memory_writes, …) rather than step
    // order, so a `state_change` at step 50 fed after a `state_change` at step
    // 100 would leave `thread_states`/`current_thread` stamped with the older
    // state — the very fields #91/#92 made order-sensitive. Sorting the whole
    // stream by step before ingestion (mirroring CLI `feed_events`) keeps the
    // engine's order-dependent state consistent regardless of how the caller
    // arranged the JSON arrays.
    let mut events: Vec<TraceEvent> = Vec::new();

    // Threads
    if let Some(threads) = args.get("threads").and_then(|v| v.as_array()) {
        for t in threads {
            let info: ThreadInfo = serde_json::from_value(t.clone())
                .map_err(|e| ToolError::new(format!("invalid thread: {}", e)))?;
            events.push(TraceEvent::Thread(info));
        }
    }

    // Instructions
    if let Some(instrs) = args.get("instructions").and_then(|v| v.as_array()) {
        for i in instrs {
            let trace: InstructionTrace = serde_json::from_value(i.clone())
                .map_err(|e| ToolError::new(format!("invalid instruction: {}", e)))?;
            events.push(TraceEvent::Instruction(trace));
        }
    }

    // Memory writes
    if let Some(writes) = args.get("memory_writes").and_then(|v| v.as_array()) {
        for w in writes {
            let step = w.get("step").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_write missing 'step'"))?;
            let thread_id = w.get("thread_id").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_write missing 'thread_id'"))? as u32;
            let address = w.get("address").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_write missing 'address'"))?;
            let data: Vec<u8> = w.get("data")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            events.push(TraceEvent::MemoryWrite { step, thread_id, address, data });
        }
    }

    // Memory reads — fed to the analyzer for write→read race detection.
    // Reads are not persisted into the memory store (only writes affect
    // memory state), but are kept in the event stream so save/load replays
    // them into the analyzer on reload.
    if let Some(reads) = args.get("memory_reads").and_then(|v| v.as_array()) {
        for r in reads {
            let step = r.get("step").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_read missing 'step'"))?;
            let thread_id = r.get("thread_id").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_read missing 'thread_id'"))? as u32;
            let address = r.get("address").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_read missing 'address'"))?;
            let size = r.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            events.push(TraceEvent::MemoryRead { step, thread_id, address, size });
        }
    }

    // Sync events
    if let Some(events_arr) = args.get("sync_events").and_then(|v| v.as_array()) {
        for e in events_arr {
            let event: ThreadSyncEvent = serde_json::from_value(e.clone())
                .map_err(|err| ToolError::new(format!("invalid sync_event: {}", err)))?;
            events.push(TraceEvent::Sync(event));
        }
    }

    // Context switches
    if let Some(switches) = args.get("context_switches").and_then(|v| v.as_array()) {
        for s in switches {
            let switch: ContextSwitch = serde_json::from_value(s.clone())
                .map_err(|e| ToolError::new(format!("invalid context_switch: {}", e)))?;
            events.push(TraceEvent::ContextSwitch(switch));
        }
    }

    // State changes
    if let Some(changes) = args.get("state_changes").and_then(|v| v.as_array()) {
        for c in changes {
            let change: ThreadStateChange = serde_json::from_value(c.clone())
                .map_err(|e| ToolError::new(format!("invalid state_change: {}", e)))?;
            events.push(TraceEvent::StateChange(change));
        }
    }

    // JNI calls
    if let Some(calls) = args.get("jni_calls").and_then(|v| v.as_array()) {
        for c in calls {
            let call: JNICall = serde_json::from_value(c.clone())
                .map_err(|e| ToolError::new(format!("invalid jni_call: {}", e)))?;
            events.push(TraceEvent::JniCall(call));
        }
    }

    // Register deltas
    if let Some(deltas) = args.get("register_deltas").and_then(|v| v.as_array()) {
        for d in deltas {
            let delta: RegisterDelta = serde_json::from_value(d.clone())
                .map_err(|e| ToolError::new(format!("invalid register_delta: {}", e)))?;
            events.push(TraceEvent::Register(delta));
        }
    }

    // Call traces (call/return events for call-stack reconstruction)
    if let Some(calls) = args.get("calls").and_then(|v| v.as_array()) {
        for c in calls {
            let call: CallTrace = serde_json::from_value(c.clone())
                .map_err(|e| ToolError::new(format!("invalid call: {}", e)))?;
            events.push(TraceEvent::Call(call));
        }
    }

    // Phase 2: sort by step (stable, to preserve relative order within a step)
    // and feed the engine in step order — the same contract as CLI `feed_events`.
    events.sort_by_key(|e| e.step());

    let engine = server.get_or_create_engine(trace_id).await;
    let mut guard = engine.lock().await;

    let mut counts = json!({
        "threads": 0, "instructions": 0, "memory_writes": 0, "memory_reads": 0,
        "sync_events": 0, "context_switches": 0, "state_changes": 0, "jni_calls": 0,
        "register_deltas": 0, "calls": 0,
    });

    for ev in &events {
        guard.feed_event(ev.clone()).map_err(|e| ToolError::new(e.to_string()))?;
        match ev {
            TraceEvent::Thread(_) => {
                counts["threads"] = json!(counts["threads"].as_u64().unwrap() + 1);
            }
            TraceEvent::Instruction(_) => {
                counts["instructions"] = json!(counts["instructions"].as_u64().unwrap() + 1);
            }
            TraceEvent::MemoryWrite { .. } => {
                counts["memory_writes"] = json!(counts["memory_writes"].as_u64().unwrap() + 1);
            }
            TraceEvent::MemoryRead { .. } => {
                counts["memory_reads"] = json!(counts["memory_reads"].as_u64().unwrap() + 1);
            }
            TraceEvent::Sync(_) => {
                counts["sync_events"] = json!(counts["sync_events"].as_u64().unwrap() + 1);
            }
            TraceEvent::ContextSwitch(_) => {
                counts["context_switches"] = json!(counts["context_switches"].as_u64().unwrap() + 1);
            }
            TraceEvent::StateChange(_) => {
                counts["state_changes"] = json!(counts["state_changes"].as_u64().unwrap() + 1);
            }
            TraceEvent::JniCall(_) => {
                counts["jni_calls"] = json!(counts["jni_calls"].as_u64().unwrap() + 1);
            }
            TraceEvent::Register(_) => {
                counts["register_deltas"] = json!(counts["register_deltas"].as_u64().unwrap() + 1);
            }
            TraceEvent::Call(_) => {
                counts["calls"] = json!(counts["calls"].as_u64().unwrap() + 1);
            }
        }
    }

    drop(guard);
    let so_file_id = args.get("so_file_id").and_then(|v| v.as_u64()).unwrap_or(0);
    // so_file_id == 0 → no SO requested, returns Ok(()) without requiring
    // data_dir. A real load failure is warned + swallowed (trace stays usable).
    register_so_for_engine(server, so_file_id, &engine).await?;
    server.store_event_buffer(trace_id, events).await;

    Ok(json!({
        "status": "ok",
        "trace_id": trace_id,
        "imported": counts,
    }))
}

async fn tool_list_traces(server: &McpServer) -> Result<Value, ToolError> {
    let engines = server.engines_for_read().await;
    let trace_ids: Vec<u64> = engines.keys().copied().collect();
    Ok(json!({
        "trace_count": trace_ids.len(),
        "traces": trace_ids,
    }))
}

async fn tool_list_threads(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let include_stats = args.get("include_stats").and_then(|v| v.as_bool()).unwrap_or(false);
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let threads: Vec<Value> = engine.all_thread_ids()
        .into_iter()
        .filter_map(|tid| engine.get_thread_info(tid).cloned())
        .map(|info| serde_json::to_value(&info).unwrap_or(Value::Null))
        .collect();

    // #115: mirror HTTP's `?include_stats=true` so the MCP path can surface
    // ThreadStats (lock_acquire_count / lock_release_count / …) — keeping the
    // three access paths (CLI / HTTP / MCP) symmetric. Default false preserves
    // the prior response shape for callers that don't request stats.
    let mut response = serde_json::json!({
        "trace_id": trace_id,
        "thread_count": threads.len(),
        "threads": threads,
    });
    if include_stats {
        response["stats"] = serde_json::to_value(engine.all_thread_stats())
            .unwrap_or(serde_json::Value::Null);
    }

    Ok(response)
}

async fn tool_query_instructions(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let start = args.get("start_step").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end_step").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    let thread_id = args.get("thread_id").and_then(|v| v.as_u64()).map(|v| v as u32);
    let address = args.get("address").and_then(|v| v.as_u64());
    let limit = args.get("limit").and_then(|v| v.as_u64());

    let mut results: Vec<InstructionTrace> = engine.query_instructions_range(start, end)
        .into_iter()
        .filter(|t| thread_id.map_or(true, |tid| t.thread_id == tid))
        .filter(|t| address.map_or(true, |addr| t.address == addr))
        .cloned()
        .collect();

    if let Some(lim) = limit {
        results.truncate(lim as usize);
    }

    Ok(json!({
        "trace_id": trace_id,
        "instruction_count": results.len(),
        "instructions": results,
    }))
}

async fn tool_query_sync_events(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let start = args.get("start_step").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end_step").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    let thread_id = args.get("thread_id").and_then(|v| v.as_u64()).map(|v| v as u32);
    let sync_addr = args.get("sync_object_addr").and_then(|v| v.as_u64());

    let events: Vec<ThreadSyncEvent> = if let Some(addr) = sync_addr {
        engine.query_lock_contentions(addr, start, end)
            .into_iter()
            .filter(|e| thread_id.map_or(true, |tid| e.thread_id == tid))
            .cloned()
            .collect()
    } else if let Some(tid) = thread_id {
        engine.query_thread_sync_events(tid, start, end)
            .into_iter()
            .cloned()
            .collect()
    } else {
        let mut all = Vec::new();
        for tid in engine.all_thread_ids() {
            all.extend(engine.query_thread_sync_events(tid, start, end).into_iter().cloned());
        }
        all.sort_by_key(|e| e.step);
        all
    };

    let count = events.len();
    Ok(json!({
        "trace_id": trace_id,
        "event_count": count,
        "events": events,
    }))
}

async fn tool_query_context_switches(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let start = args.get("start_step").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end_step").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    let thread_id = args.get("thread_id").and_then(|v| v.as_u64()).map(|v| v as u32);

    let switches: Vec<ContextSwitch> = engine.query_context_switches(start, end)
        .into_iter()
        .filter(|s| thread_id.map_or(true, |tid| s.from_thread == tid || s.to_thread == tid))
        .cloned()
        .collect();

    let count = switches.len();
    Ok(json!({
        "trace_id": trace_id,
        "switch_count": count,
        "context_switches": switches,
    }))
}

async fn tool_analyze_threads(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let result = engine.analyze_threads();
    Ok(json!({ "trace_id": trace_id, "analysis": result }))
}

async fn tool_detect_races(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let races = engine.detect_race_conditions();
    Ok(json!({ "trace_id": trace_id, "race_count": races.len(), "races": races }))
}

async fn tool_detect_deadlocks(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let deadlocks = engine.detect_deadlocks();
    Ok(json!({ "trace_id": trace_id, "deadlock_count": deadlocks.len(), "deadlocks": deadlocks }))
}

async fn tool_analyze_contentions(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let contentions = engine.analyze_lock_contention();
    Ok(json!({ "trace_id": trace_id, "contention_count": contentions.len(), "contentions": contentions }))
}

async fn tool_classify_function_safety(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let safety = engine.classify_function_thread_safety();
    Ok(json!({ "trace_id": trace_id, "function_count": safety.len(), "function_safety": safety }))
}

async fn tool_analyze_function_assoc(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let assocs = engine.analyze_thread_function_assoc();
    Ok(json!({ "trace_id": trace_id, "assoc_count": assocs.len(), "thread_function_assocs": assocs }))
}

async fn tool_analyze_data_flows(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let flows = engine.analyze_data_flows();
    Ok(json!({ "trace_id": trace_id, "flow_count": flows.len(), "data_flows": flows }))
}

async fn tool_detect_producer_consumer(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let patterns = engine.detect_producer_consumer();
    Ok(json!({ "trace_id": trace_id, "pattern_count": patterns.len(), "producer_consumer_patterns": patterns }))
}

async fn tool_analyze_scheduling(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let scheduling = engine.analyze_scheduling();
    Ok(json!({ "trace_id": trace_id, "thread_count": scheduling.len(), "scheduling": scheduling }))
}

async fn tool_analyze_thread_lifecycle(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let lifecycle = engine.analyze_thread_lifecycle();
    Ok(json!({ "trace_id": trace_id, "thread_count": lifecycle.len(), "lifecycle": lifecycle }))
}

async fn tool_analyze_thread_states(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let state_stats = engine.analyze_thread_states();
    Ok(json!({ "trace_id": trace_id, "thread_count": state_stats.len(), "state_stats": state_stats }))
}

async fn tool_analyze_critical_sections(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let critical_sections = engine.analyze_critical_sections();
    Ok(json!({ "trace_id": trace_id, "lock_count": critical_sections.len(), "critical_sections": critical_sections }))
}

async fn tool_analyze_jni_boundary(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let jni_boundary = engine.analyze_jni_boundary();
    Ok(json!({ "trace_id": trace_id, "thread_count": jni_boundary.len(), "jni_boundary": jni_boundary }))
}

// ===========================================================================
// Persistence tools
// ===========================================================================

/// Feed a single normalized event into an engine. Used by load_trace to replay
/// a persisted event stream. Thin wrapper over the engine's own `feed_event`
/// dispatch table so all entry paths share one source of truth.
fn feed_event(engine: &mut TraceEngine, event: sotrace_core::adapters::TraceEvent) -> Result<(), ToolError> {
    engine.feed_event(event).map_err(|e| ToolError::new(e.to_string()))
}

/// Require a data directory; return it or an error if persistence is disabled.
fn require_data_dir(server: &McpServer) -> Result<std::path::PathBuf, ToolError> {
    server.data_dir()
        .map(std::path::PathBuf::from)
        .ok_or_else(|| ToolError::new("persistence is disabled: server was not started with a data directory (set SOTRACE_DATA_DIR)"))
}

/// Load the persisted SO file `so_file_id` and register its function table
/// into `engine`, so analysis resolves function names instead of bare offsets.
/// Mirrors CLI `load_engine` and the HTTP `register_so_for_engine` helper.
///
/// `so_file_id == 0` is the "no SO" sentinel and skips registration. A load
/// failure is logged and swallowed (the trace is still usable, just with
/// `None` function names) — matching CLI's `.ok()` graceful degradation.
/// Requires `data_dir`; returns a `ToolError` if persistence is disabled and a
/// SO was actually requested.
async fn register_so_for_engine(
    server: &McpServer,
    so_file_id: u64,
    engine: &tokio::sync::Mutex<TraceEngine>,
) -> Result<(), ToolError> {
    if so_file_id == 0 {
        return Ok(());
    }
    let data_dir = require_data_dir(server)?;
    let parsed = tokio::task::spawn_blocking(move || {
        sotrace_engine::persistence::SoRepository::open(&data_dir)
            .and_then(|repo| repo.load(so_file_id))
    })
    .await;
    match parsed {
        Ok(Ok(parsed)) => {
            engine.lock().await.register_parsed_so(&parsed);
        }
        Ok(Err(e)) => {
            eprintln!(
                "so-trace: warning: failed to load so_file_id {} for function-name resolution ({}); \
                 analysis will show bare offsets",
                so_file_id, e
            );
        }
        Err(e) => {
            eprintln!(
                "so-trace: warning: so load task for so_file_id {} join failed ({}); \
                 analysis will show bare offsets",
                so_file_id, e
            );
        }
    }
    Ok(())
}

async fn tool_save_trace(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let data_dir = require_data_dir(server)?;
    let so_file_id = args.get("so_file_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("mcp").to_string();

    let events = server.take_event_buffer(trace_id).await
        .ok_or_else(|| ToolError::new(format!("no in-memory trace with id {} to save (import_trace first)", trace_id)))?;

    // spawn_blocking: bincode serialization + file I/O shouldn't block the async runtime.
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let trace = sotrace_engine::persistence::PersistedTrace {
        trace_id: 0, // auto-assigned
        so_file_id,
        source,
        base_addr: 0,
        events,
        created_at,
    };
    let persisted_id = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.save(trace).map_err(|e| ToolError::new(e.to_string()))
    }).await
        .map_err(|e| ToolError::new(format!("save task failed: {}", e)))??;

    Ok(json!({
        "status": "ok",
        "persisted_id": persisted_id,
        "source_trace_id": trace_id,
    }))
}

async fn tool_load_trace(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let persisted_id = args.get("persisted_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'persisted_id'"))?;
    let data_dir = require_data_dir(server)?;

    let persisted = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.load(persisted_id).map_err(|e| ToolError::new(e.to_string()))
    }).await
        .map_err(|e| ToolError::new(format!("load task failed: {}", e)))??;

    let event_count = persisted.events.len();
    let so_file_id = persisted.so_file_id;
    let engine = server.get_or_create_engine(persisted_id).await;
    let mut guard = engine.lock().await;
    // Replay in chronological order.
    let mut sorted = persisted.events;
    sorted.sort_by_key(|e| e.step());
    for ev in sorted {
        feed_event(&mut guard, ev)?;
    }
    drop(guard);
    // After replay, load the SO function table (if the trace references one)
    // so analysis resolves function names instead of bare offsets. Mirrors CLI
    // load_engine and import_trace's post-feed registration.
    register_so_for_engine(server, so_file_id, &engine).await?;
    server.store_event_buffer(persisted_id, Vec::new()).await;

    Ok(json!({
        "status": "ok",
        "persisted_id": persisted_id,
        "so_file_id": so_file_id,
        "event_count": event_count,
    }))
}

async fn tool_list_persisted_traces(server: &McpServer) -> Result<Value, ToolError> {
    let data_dir = require_data_dir(server)?;
    let summaries = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.list().map_err(|e| ToolError::new(e.to_string()))
    }).await
        .map_err(|e| ToolError::new(format!("list task failed: {}", e)))??;

    let traces: Vec<Value> = summaries.iter().map(|s| json!({
        "trace_id": s.trace_id,
        "so_file_id": s.so_file_id,
        "source": s.source,
        "base_addr": s.base_addr,
        "event_count": s.event_count,
        "created_at": s.created_at,
    })).collect();

    Ok(json!({
        "trace_count": traces.len(),
        "traces": traces,
    }))
}

async fn tool_delete_persisted_trace(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let data_dir = require_data_dir(server)?;

    let deleted = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.delete(trace_id).map_err(|e| ToolError::new(e.to_string()))
    }).await
        .map_err(|e| ToolError::new(format!("delete task failed: {}", e)))??;

    Ok(json!({
        "status": if deleted { "deleted" } else { "not_found" },
        "trace_id": trace_id,
    }))
}

// ===========================================================================
// SO management tools — mirror the HTTP /so-files endpoints and CLI
// import-so/so-list/so-show/so-delete so all three access paths expose the
// same CRUD. The ELF bytes travel base64-encoded inside JSON-RPC args (raw
// bytes cannot be carried in JSON).
// ===========================================================================

/// Upload + parse + persist an SO file (base64 ELF bytes).
///
/// Mirrors HTTP `POST /api/v1/so-files`. Parses, saves (dedup by SHA-256), and
/// returns the assigned `so_id` plus a summary. The `deduped` flag is true when
/// the saved summary differs from the freshly parsed bytes (existing copy
/// reused) — matching the HTTP handler's byte-for-byte logic.
async fn tool_import_so(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    use base64::Engine;
    let data_dir = require_data_dir(server)?;

    let bytes_str = args.get("bytes")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::new("missing or invalid 'bytes' (expected base64 string)"))?;
    let path_label = args.get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("upload")
        .to_string();

    let data = base64::engine::general_purpose::STANDARD
        .decode(bytes_str)
        .map_err(|e| ToolError::new(format!("invalid base64: {}", e)))?;
    if data.is_empty() {
        return Err(ToolError::new("empty body: expected base64-encoded ELF bytes in 'bytes'"));
    }

    // Parse + save + summary all on one blocking task: parsing is CPU-heavy and
    // save/summary do file I/O, so keep them off the async runtime together.
    let result = tokio::task::spawn_blocking(move || -> Result<_, ToolError> {
        let parsed = sotrace_engine::elf::parse_elf_bytes(&data, &path_label)
            .map_err(|e| ToolError::new(format!("failed to parse ELF: {}", e)))?;
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        let outcome = repo.save(&parsed).map_err(|e| ToolError::new(e.to_string()))?;
        let summary = repo.summary(outcome.id)
            .map_err(|e| ToolError::new(e.to_string()))?
            .ok_or_else(|| ToolError::new(format!("SO id {} missing from index after save", outcome.id)))?;
        Ok((outcome, summary))
    })
    .await
    .map_err(|e| ToolError::new(format!("import_so task failed: {}", e)))??;

    let (outcome, summary) = result;
    // deduped is the authoritative signal from save's index lookup — no
    // second-grained created_at heuristic (which broke on same-second
    // re-imports). Mirrors HTTP so_file.rs.
    Ok(json!({
        "so_id": outcome.id,
        "deduped": outcome.deduped,
        "summary": serde_json::to_value(&summary)
            .map_err(|e| ToolError::new(format!("summary serialization failed: {}", e)))?,
    }))
}

/// List all persisted SO files (summaries only). Mirrors HTTP
/// `GET /api/v1/so-files`.
async fn tool_list_so_files(server: &McpServer) -> Result<Value, ToolError> {
    let data_dir = require_data_dir(server)?;
    let list = tokio::task::spawn_blocking(move || -> Result<_, ToolError> {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.list().map_err(|e| ToolError::new(e.to_string()))
    })
    .await
    .map_err(|e| ToolError::new(format!("list_so_files task failed: {}", e)))??;

    let so_files: Vec<Value> = list.iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();
    Ok(json!({
        "so_files": so_files,
        "count": list.len(),
    }))
}

/// Get a single persisted SO file's summary by ID. Mirrors HTTP
/// `GET /api/v1/so-files/:id`.
async fn tool_get_so_file(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let so_id = get_so_id(args)?;
    let data_dir = require_data_dir(server)?;
    let summary = tokio::task::spawn_blocking(move || -> Result<_, ToolError> {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.summary(so_id).map_err(|e| ToolError::new(e.to_string()))
    })
    .await
    .map_err(|e| ToolError::new(format!("get_so_file task failed: {}", e)))??;

    match summary {
        Some(summary) => Ok(json!({
            "so_file": serde_json::to_value(&summary)
                .map_err(|e| ToolError::new(format!("summary serialization failed: {}", e)))?,
        })),
        None => Err(ToolError::new(format!("not found: no SO file with id {}", so_id))),
    }
}

/// Delete a persisted SO file by ID. Mirrors HTTP `DELETE /api/v1/so-files/:id`
/// (added together with this tool to close the CRUD symmetry).
async fn tool_delete_so(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let so_id = get_so_id(args)?;
    let data_dir = require_data_dir(server)?;
    let deleted = tokio::task::spawn_blocking(move || -> Result<_, ToolError> {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.delete(so_id).map_err(|e| ToolError::new(e.to_string()))
    })
    .await
    .map_err(|e| ToolError::new(format!("delete_so task failed: {}", e)))??;

    Ok(json!({
        "status": if deleted { "deleted" } else { "not_found" },
        "so_id": so_id,
    }))
}

/// Lowercase hex encoding of a byte slice, matching the HTTP memory handler.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

async fn tool_query_register(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let register_id = args.get("register_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'register_id' (expected integer)"))?
        as usize;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let value = engine.query_register(register_id, step);

    Ok(json!({
        "trace_id": trace_id,
        "register_id": register_id,
        "step": step,
        "value": value,
        "value_hex": value.map(|v| format!("0x{:x}", v)),
    }))
}

async fn tool_query_register_state(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let state = engine.reconstruct_register_state(step);

    Ok(json!({
        "trace_id": trace_id,
        "step": step,
        "state": state,
    }))
}

async fn tool_query_register_history(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let register_id = args.get("register_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'register_id' (expected integer)"))?
        as usize;
    let start = args.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let steps = engine.query_register_history(register_id, start, end);

    Ok(json!({
        "trace_id": trace_id,
        "register_id": register_id,
        "start": start,
        "end": end,
        "change_count": steps.len(),
        "steps": steps,
    }))
}

async fn tool_query_memory_value(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let address = args.get("address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'address' (expected integer)"))?;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(8) as usize;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let result = engine.query_memory_value(address, size, step);
    let value_hex = result.as_ref().map(|r| hex(&r.value));

    Ok(json!({
        "trace_id": trace_id,
        "address": address,
        "step": step,
        "size": size,
        "result": result,
        "value_hex": value_hex,
    }))
}

async fn tool_query_memory_page(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let page_address = args.get("page_address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'page_address' (expected integer)"))?;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let page = engine.rebuild_memory_page(page_address, step);

    Ok(json!({
        "trace_id": trace_id,
        "page_address": page_address,
        "step": step,
        "length": page.as_ref().map(|p| p.len()).unwrap_or(0),
        "bytes_hex": page.as_ref().map(|p| hex(p)),
    }))
}

async fn tool_query_call_stack(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let thread_id = args.get("thread_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'thread_id' (expected integer)"))?
        as u32;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let frames = engine.rebuild_call_stack(thread_id, step);

    Ok(json!({
        "trace_id": trace_id,
        "thread_id": thread_id,
        "step": step,
        "frame_count": frames.len(),
        "frames": frames,
    }))
}

async fn tool_query_jni_calls(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let address = args.get("address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'address' (expected integer)"))?;
    let start = args.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let calls: Vec<_> = engine
        .query_jni_calls_by_address(address, start, end)
        .into_iter()
        .cloned()
        .collect();
    let count = calls.len();

    Ok(json!({
        "trace_id": trace_id,
        "native_address": address,
        "start": start,
        "end": end,
        "count": count,
        "jni_calls": calls,
    }))
}

async fn tool_query_threads_at_address(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let address = args.get("address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'address' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let accesses = engine.query_threads_at_address(address);
    let step_count = engine.query_instructions_by_address(address).len();

    Ok(json!({
        "trace_id": trace_id,
        "address": address,
        "step_count": step_count,
        // Each entry is (thread_id, step) — the step at which that thread
        // executed the address, NOT an access count.
        "thread_accesses": accesses.iter().map(|(t, s)| json!({"thread_id": t, "step": s})).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::McpServer;
    use serde_json::json;

    const LOCK_ADDR: u64 = 0xABCD0000;

    /// Import a trace with two threads, a memory write, sync events, and a context switch
    async fn import_test_data(server: &McpServer) {
        let args = json!({
            "trace_id": 7,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "worker-1",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "worker-2",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "instructions": [
                {"seq": 0, "thread_id": 1, "address": 0x4000, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 1, "thread_id": 1, "address": 0x4004, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 2, "thread_id": 2, "address": 0x5000, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
            ],
            "memory_writes": [
                {"step": 5, "thread_id": 1, "address": 0x1000, "data": [255, 255, 255, 255]},
            ],
            "sync_events": [
                {"step": 3, "thread_id": 1, "sync_type": "MutexLock",
                 "sync_object_addr": LOCK_ADDR, "result": "Success", "wait_duration_ns": null},
                {"step": 6, "thread_id": 2, "sync_type": "MutexLock",
                 "sync_object_addr": LOCK_ADDR, "result": "Success", "wait_duration_ns": 1500},
            ],
            "context_switches": [
                {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0},
            ],
        });
        let result = dispatch_tool(server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["imported"]["threads"], 2);
        assert_eq!(result["imported"]["instructions"], 3);
        assert_eq!(result["imported"]["sync_events"], 2);
        assert_eq!(result["imported"]["context_switches"], 1);
    }

    #[tokio::test]
    async fn test_import_and_list_traces() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "list_traces", &json!({})).await.unwrap();
        assert_eq!(result["trace_count"], 1);
        assert_eq!(result["traces"][0], 7);
    }

    #[tokio::test]
    async fn test_list_threads() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "list_threads", &json!({"trace_id": 7})).await.unwrap();
        assert_eq!(result["thread_count"], 2);
        let names: Vec<&str> = result["threads"].as_array().unwrap().iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"worker-1"));
        assert!(names.contains(&"worker-2"));
    }

    /// #115: list_threads with include_stats=true surfaces ThreadStats
    /// (lock_acquire_count / lock_release_count / …), matching HTTP's
    /// `?include_stats=true`. Without the flag, `stats` is absent.
    #[tokio::test]
    async fn test_list_threads_include_stats() {
        let server = McpServer::new();
        import_test_data(&server).await;

        // Without the flag: no stats key in the response.
        let result = dispatch_tool(&server, "list_threads", &json!({"trace_id": 7})).await.unwrap();
        assert!(result.get("stats").is_none(), "stats should be absent without include_stats");

        // With include_stats=true: stats array present, with #114's fields.
        let result = dispatch_tool(&server, "list_threads", &json!({"trace_id": 7, "include_stats": true})).await.unwrap();
        assert!(result["stats"].is_array(), "stats should be present when include_stats=true");
        let stats = &result["stats"].as_array().unwrap()[0];
        assert!(stats["lock_acquire_count"].is_u64());
        assert!(stats["lock_release_count"].is_u64());
        // #118: max_lock_wait_ns is null (seed acquires had no real wait) but present.
        assert!(stats["max_lock_wait_ns"].is_null());
    }

    #[tokio::test]
    async fn test_query_instructions_all() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_instructions", &json!({"trace_id": 7})).await.unwrap();
        assert_eq!(result["instruction_count"], 3);
    }

    #[tokio::test]
    async fn test_query_instructions_by_thread() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_instructions",
            &json!({"trace_id": 7, "thread_id": 1})).await.unwrap();
        assert_eq!(result["instruction_count"], 2);
        assert!(result["instructions"].as_array().unwrap().iter()
            .all(|i| i["thread_id"] == 1));
    }

    #[tokio::test]
    async fn test_query_sync_events_by_lock() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_sync_events",
            &json!({"trace_id": 7, "sync_object_addr": LOCK_ADDR, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["event_count"], 2);
    }

    #[tokio::test]
    async fn test_query_sync_events_by_thread() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_sync_events",
            &json!({"trace_id": 7, "thread_id": 1, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["event_count"], 1);
    }

    #[tokio::test]
    async fn test_query_context_switches() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_context_switches",
            &json!({"trace_id": 7, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["switch_count"], 1);
        assert_eq!(result["context_switches"][0]["from_thread"], 1);
        assert_eq!(result["context_switches"][0]["to_thread"], 2);
    }

    #[tokio::test]
    async fn test_query_context_switches_thread_filter() {
        let server = McpServer::new();
        import_test_data(&server).await;

        // Thread 1 is involved
        let result = dispatch_tool(&server, "query_context_switches",
            &json!({"trace_id": 7, "thread_id": 1, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["switch_count"], 1);

        // Thread 99 is not
        let result = dispatch_tool(&server, "query_context_switches",
            &json!({"trace_id": 7, "thread_id": 99, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["switch_count"], 0);
    }

    #[tokio::test]
    async fn test_analyze_threads_full() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "analyze_threads", &json!({"trace_id": 7})).await.unwrap();
        assert_eq!(result["trace_id"], 7);
        assert!(result["analysis"].is_object());
        assert!(result["analysis"]["race_conditions"].is_array());
        assert!(result["analysis"]["deadlock_risks"].is_array());
        assert!(result["analysis"]["lock_contentions"].is_array());
        assert!(result["analysis"]["thread_function_assocs"].is_array());
        assert!(result["analysis"]["function_safety"].is_array());
    }

    /// `import_trace` must ingest events in step order even when the caller's
    /// JSON arrays are out of order. `ThreadStore.thread_states` (the live
    /// HashMap, not the replayed `query_thread_state`) is stamped by each
    /// `record_thread_state_change` in ingestion order — so feeding step 100
    /// (Blocked) before step 50 (Running) would leave it stuck at Running,
    /// the older state. #91/#92 made that field matter (exit `prev_state`,
    /// `current_thread` clearing). The fix sorts the whole event stream by
    /// step before feeding the engine, mirroring CLI `feed_events`.
    #[tokio::test]
    async fn test_import_trace_sorts_state_changes_by_step() {
        let server = McpServer::new();
        let args = json!({
            "trace_id": 9,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t1",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            // Deliberately out of step order: step 100 before step 50.
            "state_changes": [
                {"step": 100, "thread_id": 1, "new_state": "Blocked",
                 "prev_state": "Running", "prev_running_thread": 1},
                {"step": 50, "thread_id": 1, "new_state": "Running",
                 "prev_state": "Runnable", "prev_running_thread": null},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["imported"]["state_changes"], 2);

        // Probe the live `thread_states` map — NOT the replayed query, which
        // re-sorts by step itself and would hide the bug. After a step-ordered
        // feed, the largest step (100, Blocked) is the last applied.
        let engine = server.get_or_create_engine(9).await;
        let engine = engine.lock().await;
        let states = engine.thread_store().all_thread_states();
        let final_state = states.get(&1).expect("thread 1 registered");
        assert_eq!(*final_state, sotrace_core::models::thread::ThreadState::Blocked,
            "step 100 (Blocked) must be the last-applied state, not step 50 (Running)");
    }

    #[tokio::test]
    async fn test_detect_races() {
        let server = McpServer::new();
        import_test_data(&server).await;

        // Feed a cross-thread read to create a race (thread 2 reads what thread 1 wrote)
        let engine = server.get_or_create_engine(7).await;
        engine.lock().await.feed_memory_read(8, 2, 0x1000, 4);

        let result = dispatch_tool(&server, "detect_races", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["race_count"].as_u64().unwrap() >= 1);
        assert!(result["races"].as_array().unwrap().iter()
            .any(|r| r["address"] == 0x1000));
        // #112: access sizes and overlap range are present in the JSON
        let race = &result["races"].as_array().unwrap()[0];
        assert!(race["first_access_size"].is_u64());
        assert!(race["second_access_size"].is_u64());
        assert!(race["overlap_address"].is_u64());
        assert!(race["overlap_size"].is_u64());
    }

    #[tokio::test]
    async fn test_import_trace_memory_reads_feeds_race_detection() {
        // #81: import_trace must accept `memory_reads` and feed them to the
        // analyzer — otherwise detect_races has no read end and reports
        // nothing even though T2 reads an unsynchronized T1 write. Before
        // #81, memory_reads could only reach the analyzer via a direct
        // `engine.feed_memory_read` call (as test_detect_races above does),
        // bypassing import entirely.
        let server = McpServer::new();
        let args = json!({
            "trace_id": 15,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t1",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t2",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 5, "thread_id": 1, "address": 0x1000, "data": [255, 255, 255, 255]},
            ],
            "memory_reads": [
                {"step": 8, "thread_id": 2, "address": 0x1000, "size": 4},
            ],
            "context_switches": [
                {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0},
            ],
        });
        let imp = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(imp["imported"]["memory_reads"], 1);

        let result = dispatch_tool(&server, "detect_races", &json!({"trace_id": 15})).await.unwrap();
        assert!(result["race_count"].as_u64().unwrap() >= 1);
        assert!(result["races"].as_array().unwrap().iter()
            .any(|r| r["address"] == 0x1000));
    }

    #[tokio::test]
    async fn test_analyze_contentions() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "analyze_contentions", &json!({"trace_id": 7})).await.unwrap();
        let contentions = result["contentions"].as_array().unwrap();
        assert!(contentions.iter().any(|c| c["lock_address"]["addr"] == LOCK_ADDR));
    }

    #[tokio::test]
    async fn test_detect_deadlocks() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "detect_deadlocks", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["deadlocks"].is_array());
    }

    #[tokio::test]
    async fn test_classify_function_safety() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "classify_function_safety", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["function_safety"].is_array());
    }

    #[tokio::test]
    async fn test_analyze_function_assoc() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "analyze_function_assoc", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["thread_function_assocs"].is_array());
    }

    #[tokio::test]
    async fn test_analyze_data_flows() {
        let server = McpServer::new();
        import_test_data(&server).await;
        // Cross-thread read of the write at 0x1000 creates an inter-thread data flow.
        let engine = server.get_or_create_engine(7).await;
        engine.lock().await.feed_memory_read(8, 2, 0x1000, 4);

        let result = dispatch_tool(&server, "analyze_data_flows", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["data_flows"].is_array());
        assert!(result["data_flows"].as_array().unwrap().iter()
            .any(|f| f["address"] == 0x1000));
        // #113: transfer sizes and overlap range are present in the JSON
        let flow = &result["data_flows"].as_array().unwrap()[0];
        assert!(flow["write_size"].is_u64());
        assert!(flow["read_size"].is_u64());
        assert!(flow["overlap_address"].is_u64());
        assert!(flow["overlap_size"].is_u64());
    }

    #[tokio::test]
    async fn test_detect_producer_consumer() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "detect_producer_consumer", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["producer_consumer_patterns"].is_array());
    }

    /// The typed `sync_mechanism` must surface the primitive kind through the
    /// JSON envelope — the field is now an object `{addr, kind}`, not a bare
    /// number. A mutex producer-consumer rendezvous must report `kind: "Mutex"`.
    #[tokio::test]
    async fn test_detect_producer_consumer_sync_mechanism_typed() {
        let server = McpServer::new();
        const PC_LOCK: u64 = 0xABCD0000;
        let args = json!({
            "trace_id": 7,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "producer",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "consumer",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 100, "thread_id": 1, "address": 0x5000, "data": [1, 2, 3, 4]},
                {"step": 200, "thread_id": 1, "address": 0x6000, "data": [5, 6, 7, 8]},
            ],
            "memory_reads": [
                {"step": 130, "thread_id": 2, "address": 0x5000, "size": 4},
                {"step": 230, "thread_id": 2, "address": 0x6000, "size": 4},
            ],
            "sync_events": [
                {"step": 110, "thread_id": 1, "sync_type": "MutexUnlock",
                 "sync_object_addr": PC_LOCK, "result": "Success", "wait_duration_ns": null},
                {"step": 120, "thread_id": 2, "sync_type": "MutexLock",
                 "sync_object_addr": PC_LOCK, "result": "Success", "wait_duration_ns": 1000},
                {"step": 210, "thread_id": 1, "sync_type": "MutexUnlock",
                 "sync_object_addr": PC_LOCK, "result": "Success", "wait_duration_ns": null},
                {"step": 220, "thread_id": 2, "sync_type": "MutexLock",
                 "sync_object_addr": PC_LOCK, "result": "Success", "wait_duration_ns": 1000},
            ],
        });
        let _ = dispatch_tool(&server, "import_trace", &args).await.unwrap();

        let result = dispatch_tool(&server, "detect_producer_consumer", &json!({"trace_id": 7})).await.unwrap();
        let patterns = result["producer_consumer_patterns"].as_array().unwrap();
        assert!(!patterns.is_empty(), "producer-consumer pattern must be detected");
        let pc = patterns.iter()
            .find(|p| p["producer_thread"] == 1 && p["consumer_thread"] == 2)
            .unwrap();
        assert_eq!(pc["sync_mechanism"]["addr"], PC_LOCK);
        assert_eq!(pc["sync_mechanism"]["kind"], "Mutex");
        // #116: shared_addresses entries are objects with address + sizes
        let slots = pc["shared_addresses"].as_array().unwrap();
        assert!(!slots.is_empty(), "shared_addresses must list the slots");
        let slot = slots.iter().find(|s| s["address"] == 0x5000).unwrap();
        assert_eq!(slot["access_size"], 4);
        assert_eq!(slot["overlap_size"], 4);
    }

    #[tokio::test]
    async fn test_analyze_scheduling() {
        let server = McpServer::new();
        import_test_data(&server).await;
        // import_test_data feeds a context switch, so scheduling is non-empty.
        let result = dispatch_tool(&server, "analyze_scheduling", &json!({"trace_id": 7})).await.unwrap();
        let sched = result["scheduling"].as_array().expect("scheduling array");
        assert!(!sched.is_empty(), "context switches should yield per-thread scheduling rows");
        assert!(sched.iter().all(|s| s["thread_id"].is_u64()));
        // #117: core_residency is an array of [core, steps] pairs per thread.
        assert!(sched.iter().all(|s| s["core_residency"].is_array()));
    }

    #[tokio::test]
    async fn test_analyze_thread_lifecycle() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "analyze_thread_lifecycle", &json!({"trace_id": 7})).await.unwrap();
        let life = result["lifecycle"].as_array().expect("lifecycle array");
        assert_eq!(life.len(), 2, "two registered threads yield two lifecycle rows");
        assert_eq!(result["thread_count"], 2);
        // Both test threads are roots (parent 0), still alive, at depth 0.
        for l in life {
            assert_eq!(l["parent_thread_id"], 0);
            assert_eq!(l["tree_depth"], 0);
            assert_eq!(l["is_alive"], true);
            assert!(l["lifespan"].is_null());
        }
    }

    #[tokio::test]
    async fn test_analyze_thread_states() {
        let server = McpServer::new();
        // A dedicated trace with an exiting thread and a state-change stream so
        // residency intervals are bounded and measurable.
        let args = json!({
            "trace_id": 11,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": 100, "name": "worker",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "state_changes": [
                {"step": 0, "thread_id": 1, "new_state": "Running", "prev_state": null, "prev_running_thread": null},
                {"step": 30, "thread_id": 1, "new_state": "WaitingForLock", "prev_state": "Running", "prev_running_thread": null},
                {"step": 50, "thread_id": 1, "new_state": "Running", "prev_state": "WaitingForLock", "prev_running_thread": null},
            ],
        });
        dispatch_tool(&server, "import_trace", &args).await.unwrap();

        let result = dispatch_tool(&server, "analyze_thread_states", &json!({"trace_id": 11})).await.unwrap();
        let stats = result["state_stats"].as_array().expect("state_stats array");
        assert_eq!(stats.len(), 1);
        assert_eq!(result["thread_count"], 1);
        let s = &stats[0];
        assert_eq!(s["thread_id"], 1);
        // Running 80 (0→30 + 50→100), WaitingForLock 20 (30→50).
        assert_eq!(s["running_steps"], 80);
        assert_eq!(s["waiting_steps"], 20);
        assert_eq!(s["total_measured_steps"], 100);
        assert_eq!(s["final_state"], "Running");
    }

    #[tokio::test]
    async fn test_analyze_critical_sections() {
        let server = McpServer::new();
        // A trace where thread 1 holds a mutex from step 10 to 40 (hold = 30).
        let args = json!({
            "trace_id": 12,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "worker",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "sync_events": [
                {"step": 10, "thread_id": 1, "sync_type": "MutexLock", "sync_object_addr": LOCK_ADDR, "result": "Success", "wait_duration_ns": null},
                {"step": 40, "thread_id": 1, "sync_type": "MutexUnlock", "sync_object_addr": LOCK_ADDR, "result": "Success", "wait_duration_ns": null},
            ],
        });
        dispatch_tool(&server, "import_trace", &args).await.unwrap();

        let result = dispatch_tool(&server, "analyze_critical_sections", &json!({"trace_id": 12})).await.unwrap();
        let cs = result["critical_sections"].as_array().expect("critical_sections array");
        assert_eq!(cs.len(), 1);
        assert_eq!(result["lock_count"], 1);
        let c = &cs[0];
        assert_eq!(c["lock_address"]["addr"], LOCK_ADDR);
        assert_eq!(c["lock_address"]["kind"], "Mutex");
        assert_eq!(c["hold_count"], 1);
        assert_eq!(c["total_hold_steps"], 30);
        assert_eq!(c["max_hold_steps"], 30);
        assert_eq!(c["longest_hold_thread"], 1);
    }

    #[tokio::test]
    async fn test_analyze_jni_boundary() {
        let server = McpServer::new();
        let args = json!({
            "trace_id": 13,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "jni-worker",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
            ],
            "jni_calls": [
                {"id": 1, "seq": 10, "thread_id": 1, "direction": "JavaToNative",
                 "java_class": "com.app.Foo", "java_method": "doWork", "java_signature": "()V",
                 "native_func_id": null, "native_address": 8192, "jni_env_address": null},
                {"id": 2, "seq": 20, "thread_id": 1, "direction": "NativeToJava",
                 "java_class": "com.app.Bar", "java_method": "callback", "java_signature": "()V",
                 "native_func_id": null, "native_address": 8192, "jni_env_address": null},
            ],
        });
        let imp = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(imp["imported"]["jni_calls"], 2);

        let result = dispatch_tool(&server, "analyze_jni_boundary", &json!({"trace_id": 13})).await.unwrap();
        let stats = result["jni_boundary"].as_array().expect("jni_boundary array");
        assert_eq!(stats.len(), 1);
        assert_eq!(result["thread_count"], 1);
        let s = &stats[0];
        assert_eq!(s["thread_id"], 1);
        assert_eq!(s["is_jni_attached"], true);
        assert_eq!(s["total_crossings"], 2);
        assert_eq!(s["java_to_native_count"], 1);
        assert_eq!(s["native_to_java_count"], 1);
        assert_eq!(s["native_addresses"], serde_json::json!([8192]));
        assert_eq!(s["java_methods"], serde_json::json!(["com.app.Bar.callback", "com.app.Foo.doWork"]));
        // #119: first/last crossing step locate the JNI activity window (seq 10..20).
        assert_eq!(s["first_crossing_step"], 10);
        assert_eq!(s["last_crossing_step"], 20);
    }

    // --- query tools (register / memory / call-stack) ---

    /// Helper: import a trace with register deltas, calls, and a memory write
    /// so the five query_* tools have real data to surface.
    async fn import_query_test_data(server: &McpServer) {
        // x0 (register_id 0) is set to 0xAA at step 5, then 0xBB at step 5
        // (same-seq second delta — last-writer-wins, exercising EventLog).
        // PC (register_id 32) is set at step 6.
        // A call into callee 0x8000 at step 3 (thread 1, depth 0), no return
        // before the query step → one frame on the stack.
        // A 4-byte memory write at 0x2000 step 2 (page 0x2000).
        let args = json!({
            "trace_id": 14,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "q-worker",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 2, "thread_id": 1, "address": 0x2000, "data": [0xde, 0xad, 0xbe, 0xef]},
            ],
            "register_deltas": [
                {"seq": 5, "change_mask": 1u64, "values": [0xAA]},
                {"seq": 5, "change_mask": 1u64, "values": [0xBB]},
                {"seq": 6, "change_mask": 1u64 << 32, "values": [0x40000C00]},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call",
                 "caller_address": 0x4000, "callee_address": 0x8000,
                 "callee_func_id": null, "seq": 3, "depth": 0, "return_seq": null},
            ],
        });
        let imp = dispatch_tool(server, "import_trace", &args).await.unwrap();
        assert_eq!(imp["status"], "ok");
        assert_eq!(imp["imported"]["register_deltas"], 3);
        assert_eq!(imp["imported"]["calls"], 1);
    }

    #[tokio::test]
    async fn test_query_register_returns_last_wins_value() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        // x0 at step 5 → two same-seq deltas, the second (0xBB) wins.
        let r = dispatch_tool(&server, "query_register",
            &json!({"trace_id": 14, "register_id": 0, "step": 5})).await.unwrap();
        assert_eq!(r["register_id"], 0);
        assert_eq!(r["step"], 5);
        assert_eq!(r["value"], 0xBB);
        assert_eq!(r["value_hex"], "0xbb");

        // Before step 5, x0 was never written → None.
        let r = dispatch_tool(&server, "query_register",
            &json!({"trace_id": 14, "register_id": 0, "step": 4})).await.unwrap();
        assert!(r["value"].is_null());

        // PC (register_id 32) set at step 6 is visible at step 6 but not step 5.
        let r = dispatch_tool(&server, "query_register",
            &json!({"trace_id": 14, "register_id": 32, "step": 6})).await.unwrap();
        assert_eq!(r["value"], 0x40000C00);
    }

    #[tokio::test]
    async fn test_query_register_missing_id_errors() {
        let server = McpServer::new();
        import_query_test_data(&server).await;
        let err = dispatch_tool(&server, "query_register",
            &json!({"trace_id": 14, "step": 5})).await.unwrap_err();
        assert!(err.message.contains("register_id"));
    }

    #[tokio::test]
    async fn test_query_register_state_snapshot() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        let r = dispatch_tool(&server, "query_register_state",
            &json!({"trace_id": 14, "step": 6})).await.unwrap();
        assert_eq!(r["trace_id"], 14);
        assert_eq!(r["step"], 6);
        // RegisterState is serialized directly — x0 and pc populated.
        assert_eq!(r["state"]["gp_regs"][0], 0xBB);
        assert_eq!(r["state"]["pc"], 0x40000C00);

        // No deltas at or before step 1 → state is null.
        let r = dispatch_tool(&server, "query_register_state",
            &json!({"trace_id": 14, "step": 1})).await.unwrap();
        assert!(r["state"].is_null());
    }

    #[tokio::test]
    async fn test_query_register_history_lists_change_steps() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        // x0 (register_id 0) was set at step 5 (two same-seq deltas collapse to
        // one index entry). PC (32) was set at step 6.
        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 0})).await.unwrap();
        assert_eq!(r["change_count"], 1);
        assert_eq!(r["steps"], serde_json::json!([5]));

        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 32})).await.unwrap();
        assert_eq!(r["steps"], serde_json::json!([6]));

        // x1 (register_id 1) never changed → empty.
        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 1})).await.unwrap();
        assert_eq!(r["change_count"], 0);

        // Range filter: x0 in [6, max] → empty (x0 only changed at 5).
        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 0, "start": 6})).await.unwrap();
        assert_eq!(r["change_count"], 0);

        // Out-of-range register_id → empty, not an error.
        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 999})).await.unwrap();
        assert_eq!(r["change_count"], 0);
    }

    #[tokio::test]
    async fn test_query_memory_value_and_page() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        // 4 bytes written at 0x2000 (step 2), readable at step 5.
        let r = dispatch_tool(&server, "query_memory_value",
            &json!({"trace_id": 14, "address": 0x2000, "step": 5, "size": 4})).await.unwrap();
        assert_eq!(r["address"], 0x2000);
        assert_eq!(r["size"], 4);
        assert!(r["result"].is_object());
        assert_eq!(r["value_hex"], "deadbeef");

        // Before the write, the value is absent.
        let r = dispatch_tool(&server, "query_memory_value",
            &json!({"trace_id": 14, "address": 0x2000, "step": 1, "size": 4})).await.unwrap();
        assert!(r["result"].is_null());
        assert!(r["value_hex"].is_null());

        // Page rebuild: page 0x2000 holds the 4 written bytes at step 5.
        let r = dispatch_tool(&server, "query_memory_page",
            &json!({"trace_id": 14, "page_address": 0x2000, "step": 5})).await.unwrap();
        assert_eq!(r["page_address"], 0x2000);
        assert!(r["length"].as_u64().unwrap() >= 4);
        let hex = r["bytes_hex"].as_str().unwrap();
        assert!(hex.starts_with("deadbeef"));
    }

    #[tokio::test]
    async fn test_query_memory_value_straddling_page_boundary() {
        // #80 end-to-end at the MCP tool layer: a single query_memory_value
        // spanning a 4KB page boundary must return the full stitched value,
        // not a silently truncated first-page tail.
        let server = McpServer::new();
        // PAGE_SIZE = 4096 = 0x1000. Write 6 bytes starting 3 bytes before the
        // 0x2000/0x3000 boundary: [0x2FFD, 0x3003) straddles both pages.
        let args = json!({
            "trace_id": 16,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "m",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 2, "thread_id": 1, "address": 0x2FFD, "data": [0x10, 0x20, 0x30, 0x40, 0x50, 0x60]},
            ],
        });
        dispatch_tool(&server, "import_trace", &args).await.unwrap();

        let r = dispatch_tool(&server, "query_memory_value",
            &json!({"trace_id": 16, "address": 0x2FFD, "step": 5, "size": 6})).await.unwrap();
        assert_eq!(r["size"], 6);
        assert!(r["result"].is_object(), "expected a result, got: {}", r);
        // Full 6 bytes stitched across the boundary (not truncated to 3).
        assert_eq!(r["value_hex"], "102030405060");
        assert_eq!(r["result"]["page_address"], 0x2000);
    }

    #[tokio::test]
    async fn test_query_call_stack_one_frame() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        // A Call at step 3 with no Return before step 10 → exactly one frame.
        let r = dispatch_tool(&server, "query_call_stack",
            &json!({"trace_id": 14, "thread_id": 1, "step": 10})).await.unwrap();
        assert_eq!(r["trace_id"], 14);
        assert_eq!(r["thread_id"], 1);
        assert_eq!(r["step"], 10);
        assert_eq!(r["frame_count"], 1);
        let frame = &r["frames"][0];
        assert_eq!(frame["entry_address"], 0x8000);
        assert_eq!(frame["call_site"], 0x4000);
        assert_eq!(frame["call_seq"], 3);

        // Before the call, the stack is empty.
        let r = dispatch_tool(&server, "query_call_stack",
            &json!({"trace_id": 14, "thread_id": 1, "step": 2})).await.unwrap();
        assert_eq!(r["frame_count"], 0);

        // Wrong thread → empty.
        let r = dispatch_tool(&server, "query_call_stack",
            &json!({"trace_id": 14, "thread_id": 2, "step": 10})).await.unwrap();
        assert_eq!(r["frame_count"], 0);
    }

    #[tokio::test]
    async fn test_query_jni_calls_filters_same_step_sibling() {
        let server = McpServer::new();
        // Two threads share seq 10 but call DIFFERENT native addresses; a
        // third call reaches 0x4000 again at seq 30.
        let args = json!({
            "trace_id": 15,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": null,
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": null,
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
            ],
            "jni_calls": [
                {"id": 1, "seq": 10, "thread_id": 1, "direction": "JavaToNative",
                 "java_class": "com.app.Foo", "java_method": "doWork", "java_signature": "()V",
                 "native_func_id": null, "native_address": 16384, "jni_env_address": null},
                {"id": 2, "seq": 10, "thread_id": 2, "direction": "JavaToNative",
                 "java_class": "com.app.Bar", "java_method": "other", "java_signature": "()V",
                 "native_func_id": null, "native_address": 24576, "jni_env_address": null},
                {"id": 3, "seq": 30, "thread_id": 1, "direction": "NativeToJava",
                 "java_class": "com.app.Bar", "java_method": "callback", "java_signature": "()V",
                 "native_func_id": null, "native_address": 16384, "jni_env_address": null},
            ],
        });
        let imp = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(imp["imported"]["jni_calls"], 3);

        // 0x4000 = 16384: two calls (seq 10 + 30); the 0x6000 sibling at seq 10
        // is excluded despite sharing the step.
        let r = dispatch_tool(&server, "query_jni_calls",
            &json!({"trace_id": 15, "address": 16384})).await.unwrap();
        assert_eq!(r["count"], 2);
        let calls = r["jni_calls"].as_array().unwrap();
        assert_eq!(calls[0]["seq"], 10);
        assert_eq!(calls[1]["seq"], 30);
        assert!(calls.iter().all(|c| c["native_address"] == 16384));

        // Range [0,20] keeps only the seq-10 call.
        let r = dispatch_tool(&server, "query_jni_calls",
            &json!({"trace_id": 15, "address": 16384, "start": 0, "end": 20})).await.unwrap();
        assert_eq!(r["count"], 1);
        assert_eq!(r["jni_calls"][0]["java_method"], "doWork");

        // The 0x6000 sibling is reachable via its own address.
        let r = dispatch_tool(&server, "query_jni_calls",
            &json!({"trace_id": 15, "address": 24576})).await.unwrap();
        assert_eq!(r["count"], 1);
        assert_eq!(r["jni_calls"][0]["thread_id"], 2);

        // Unknown address → empty, no error.
        let r = dispatch_tool(&server, "query_jni_calls",
            &json!({"trace_id": 15, "address": 99999})).await.unwrap();
        assert_eq!(r["count"], 0);
    }

    #[tokio::test]
    async fn test_query_threads_at_address_keeps_both_threads_at_shared_step() {
        let server = McpServer::new();
        let args = json!({
            "trace_id": 16,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": null,
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": null,
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "instructions": [
                {"seq": 7, "thread_id": 1, "address": 4096, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 7, "thread_id": 2, "address": 4096, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 9, "thread_id": 1, "address": 4096, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
            ],
        });
        dispatch_tool(&server, "import_trace", &args).await.unwrap();

        // 0x1000 = 4096: both threads at seq 7 + thread 1 at seq 9 → 3 accesses.
        // Each entry carries `step`, not a mislabeled `count`.
        let r = dispatch_tool(&server, "query_threads_at_address",
            &json!({"trace_id": 16, "address": 4096})).await.unwrap();
        assert_eq!(r["address"], 4096);
        let accesses = r["thread_accesses"].as_array().unwrap();
        assert_eq!(accesses.len(), 3);
        let mut pairs: Vec<(u64, u64)> = accesses.iter()
            .map(|a| (a["thread_id"].as_u64().unwrap(), a["step"].as_u64().unwrap()))
            .collect();
        pairs.sort();
        assert_eq!(pairs, vec![(1, 7), (1, 9), (2, 7)]);

        // Unknown address → empty.
        let r = dispatch_tool(&server, "query_threads_at_address",
            &json!({"trace_id": 16, "address": 99999})).await.unwrap();
        assert!(r["thread_accesses"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_missing_trace_id_returns_error() {
        let server = McpServer::new();
        let result = dispatch_tool(&server, "analyze_threads", &json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("trace_id"));
    }

    #[tokio::test]
    async fn test_empty_trace_analyze() {
        let server = McpServer::new();
        // Analyze a trace with no data — should return empty results, not error
        let result = dispatch_tool(&server, "analyze_threads", &json!({"trace_id": 999})).await.unwrap();
        assert_eq!(result["trace_id"], 999);
        assert!(result["analysis"]["race_conditions"].is_array());
    }

    // --- persistence tools ---

    #[tokio::test]
    async fn test_persistence_disabled_errors() {
        // No data dir → persistence tools must report a clear error.
        let server = McpServer::new();
        let err = dispatch_tool(&server, "save_trace", &json!({"trace_id": 7})).await.unwrap_err();
        assert!(err.message.contains("persistence is disabled"));
        let err = dispatch_tool(&server, "list_persisted_traces", &json!({})).await.unwrap_err();
        assert!(err.message.contains("persistence is disabled"));
    }

    #[tokio::test]
    async fn test_save_trace_without_import_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "save_trace", &json!({"trace_id": 7})).await.unwrap_err();
        // No in-memory trace 7 → error.
        assert!(err.message.contains("no in-memory trace"));
    }

    #[tokio::test]
    async fn test_save_load_list_delete_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        import_test_data(&server).await;

        // Save the in-memory trace 7.
        let saved = dispatch_tool(&server, "save_trace", &json!({"trace_id": 7})).await.unwrap();
        assert_eq!(saved["status"], "ok");
        let persisted_id = saved["persisted_id"].as_u64().unwrap();

        // It appears in the persisted listing.
        let listed = dispatch_tool(&server, "list_persisted_traces", &json!({})).await.unwrap();
        assert_eq!(listed["trace_count"], 1);
        assert_eq!(listed["traces"][0]["trace_id"], persisted_id);
        assert_eq!(listed["traces"][0]["source"], "mcp");

        // A fresh server (empty pool) loads it by id and can query its threads.
        let server2 = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let loaded = dispatch_tool(&server2, "load_trace", &json!({"persisted_id": persisted_id})).await.unwrap();
        assert_eq!(loaded["status"], "ok");
        assert_eq!(loaded["persisted_id"], persisted_id);
        // event_count matches what import_test_data fed (2 threads + 3 instrs + 1 write + 2 sync + 1 switch = 9).
        assert_eq!(loaded["event_count"], 9);

        // The replayed trace has the same threads as the original.
        let threads = dispatch_tool(&server2, "list_threads", &json!({"trace_id": persisted_id})).await.unwrap();
        assert_eq!(threads["thread_count"], 2);

        // Delete it.
        let deleted = dispatch_tool(&server2, "delete_persisted_trace", &json!({"trace_id": persisted_id})).await.unwrap();
        assert_eq!(deleted["status"], "deleted");
        // Listing now empty.
        let listed2 = dispatch_tool(&server2, "list_persisted_traces", &json!({})).await.unwrap();
        assert_eq!(listed2["trace_count"], 0);
        // Re-delete is not_found.
        let deleted2 = dispatch_tool(&server2, "delete_persisted_trace", &json!({"trace_id": persisted_id})).await.unwrap();
        assert_eq!(deleted2["status"], "not_found");
    }

    #[tokio::test]
    async fn test_load_trace_missing_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "load_trace", &json!({"persisted_id": 9999})).await.unwrap_err();
        assert!(err.message.contains("no persisted trace") || err.message.contains("9999"));
    }

    /// Build a ParsedSoFile with one "decrypt" function at 0x4000 (size 100),
    /// persist it, return the assigned so_file_id. Mirrors the persistence
    /// test helper and the HTTP test fixture.
    fn save_decrypt_so(data_dir: &std::path::Path) -> u64 {
        use sotrace_core::elf::ParsedSoFile;
        use sotrace_core::models::so_file::{Architecture, SOFile};
        use sotrace_core::models::so_function::SOFunction;
        use sotrace_core::models::so_segment::{SOSegment, SegmentType};
        use sotrace_core::models::so_symbol::{SOSymbol, SymbolType, SymbolBind};
        let parsed = ParsedSoFile {
            so_file: SOFile {
                id: 0, path: "/fake/libtest.so".into(), build_id: Some(vec![0xab; 20]),
                arch: Architecture::AArch64, file_size: 4096, md5: [1; 16], sha256: [2; 32],
                loaded_base_address: 0, created_at: 1_700_000_000,
            },
            segments: vec![SOSegment {
                id: 0, so_file_id: 0, name: ".text".into(),
                seg_type: SegmentType::Load, offset: 0, vaddr: 0, size: 100, flags: 0,
            }],
            symbols: vec![SOSymbol {
                id: 0, so_file_id: 0, name: "decrypt".into(), value: 0x4000, size: 100,
                sym_type: SymbolType::Func, bind: SymbolBind::Global,
                is_imported: false, is_exported: true,
            }],
            functions: vec![SOFunction {
                id: 0, so_file_id: 0, symbol_id: Some(0), name: "decrypt".into(),
                offset: 0x4000, size: 100, is_jni: false, is_imported: false,
                is_exported: true, is_thunk: false,
            }],
        };
        sotrace_engine::persistence::SoRepository::open(data_dir)
            .and_then(|repo| repo.save(&parsed).map(|o| o.id))
            .expect("save ParsedSoFile")
    }

    /// #106: MCP import_trace with so_file_id registers the SO function table,
    /// so analyze_function_assoc resolves a function-internal callee PC (0x4034,
    /// within [0x4000, 0x4064) — exercising #105's range query) to "decrypt".
    #[tokio::test]
    async fn test_import_with_so_file_id_resolves_function_name() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let so_id = save_decrypt_so(tmp.path());

        let args = json!({
            "trace_id": 700,
            "so_file_id": so_id,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");

        let result = dispatch_tool(&server, "analyze_function_assoc", &json!({"trace_id": 700})).await.unwrap();
        let assocs = result["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0]["function_address"], 0x4034);
        assert_eq!(assocs[0]["function_name"], "decrypt",
                   "function name must be backfilled from the registered SO; got {:?}", assocs[0]);
    }

    /// #106 boundary: MCP import without a data_dir but so_file_id == 0 must
    /// still succeed (no SO requested → no data_dir needed).
    #[tokio::test]
    async fn test_import_without_so_file_id_no_data_dir() {
        let server = McpServer::new(); // no data_dir
        let args = json!({
            "trace_id": 701,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");

        let result = dispatch_tool(&server, "analyze_function_assoc", &json!({"trace_id": 701})).await.unwrap();
        let assocs = result["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1);
        // No SO → function_name absent/null.
        assert!(assocs[0].get("function_name").is_none() || assocs[0]["function_name"].is_null(),
                "function_name must be absent without an SO; got {:?}", assocs[0]);
    }

    /// #106 boundary: MCP import with so_file_id > 0 but NO data_dir must
    /// return a ToolError (cannot load the SO without a repository), not
    /// silently degrade.
    #[tokio::test]
    async fn test_import_with_so_file_id_but_no_data_dir_errors() {
        let server = McpServer::new(); // no data_dir
        let args = json!({
            "trace_id": 702,
            "so_file_id": 5,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
        });
        let err = dispatch_tool(&server, "import_trace", &args).await.unwrap_err();
        assert!(err.message.contains("persistence is disabled"),
                "expected persistence-disabled error, got: {}", err.message);
    }

    /// #106: MCP load_trace re-registers the SO. import(so_file_id) → save →
    /// load into a fresh server; function name still resolves after load.
    #[tokio::test]
    async fn test_load_trace_re_registers_so_function_name() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let so_id = save_decrypt_so(&data_dir);

        let server = McpServer::new_with_data_dir(Some(data_dir.clone()));
        let args = json!({
            "trace_id": 702,
            "so_file_id": so_id,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");

        let save_args = json!({"trace_id": 702, "so_file_id": so_id, "source": "test"});
        let saved = dispatch_tool(&server, "save_trace", &save_args).await.unwrap();
        let persisted_id = saved["persisted_id"].as_u64().unwrap();

        // Fresh server + engine (no in-memory state shared) to force a replay.
        // load_trace keys the replayed engine under `persisted_id` (not the
        // original trace_id 702), so analyze must query persisted_id.
        let server2 = McpServer::new_with_data_dir(Some(data_dir));
        let result = dispatch_tool(&server2, "load_trace", &json!({"persisted_id": persisted_id})).await.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["so_file_id"], so_id);

        let result = dispatch_tool(&server2, "analyze_function_assoc", &json!({"trace_id": persisted_id})).await.unwrap();
        let assocs = result["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0]["function_name"], "decrypt",
                   "load_trace must re-register the SO; got {:?}", assocs[0]);
    }

    /// #106 boundary: MCP import with a non-existent so_file_id must still
    /// succeed (load failure is warned + swallowed, names stay None).
    #[tokio::test]
    async fn test_import_with_nonexistent_so_file_id_degrades() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let args = json!({
            "trace_id": 703,
            "so_file_id": 999987,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok",
                   "import must succeed despite a bad so_file_id (graceful degradation)");
    }

    // ======================================================================
    // #107: SO management tools (import_so / list_so_files / get_so_file /
    // delete_so) — mirror the HTTP /so-files endpoints so MCP is CRUD-symmetric
    // with CLI and HTTP.
    // ======================================================================

    /// Base64-encode a byte slice for the `bytes` arg of `import_so`.
    fn b64(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    /// Read the system libc.so.6 if present (x86_64 Linux only). Returns None
    /// on any other platform / missing file so callers can `return` to skip.
    fn read_libc_if_present() -> Option<Vec<u8>> {
        let path = std::path::Path::new("/lib/x86_64-linux-gnu/libc.so.6");
        if !path.exists() {
            return None;
        }
        std::fs::read(path).ok()
    }

    #[tokio::test]
    async fn test_import_so_missing_bytes_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "import_so", &json!({})).await.unwrap_err();
        assert!(err.message.contains("bytes"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_import_so_invalid_base64_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "import_so",
            &json!({"bytes": "!!!not-base64!!!"})).await.unwrap_err();
        assert!(err.message.contains("base64"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_import_so_empty_bytes_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        // b64("") == "".
        let err = dispatch_tool(&server, "import_so", &json!({"bytes": b64(b"")})).await.unwrap_err();
        assert!(err.message.contains("empty"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_import_so_invalid_elf_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "import_so",
            &json!({"bytes": b64(b"not an elf")})).await.unwrap_err();
        assert!(err.message.contains("ELF") || err.message.contains("parse"),
                "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_import_so_without_data_dir_errors() {
        // No data dir → persistence disabled.
        let server = McpServer::new();
        let err = dispatch_tool(&server, "import_so",
            &json!({"bytes": b64(b"not an elf")})).await.unwrap_err();
        assert!(err.message.contains("data directory") || err.message.contains("persistence"),
                "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_list_so_files_seeded() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        save_decrypt_so(tmp.path());

        let r = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(r["count"], 1);
        let so = &r["so_files"][0];
        assert_eq!(so["path"], "/fake/libtest.so");
        assert_eq!(so["function_count"], 1);
    }

    #[tokio::test]
    async fn test_list_so_files_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let r = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(r["count"], 0);
    }

    #[tokio::test]
    async fn test_get_so_file_seeded() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let so_id = save_decrypt_so(tmp.path());

        let r = dispatch_tool(&server, "get_so_file", &json!({"so_id": so_id})).await.unwrap();
        let so = &r["so_file"];
        assert_eq!(so["id"], so_id);
        assert_eq!(so["path"], "/fake/libtest.so");
        assert_eq!(so["function_count"], 1);
        assert!(so["build_id"].is_string(), "build_id present as hex string");
    }

    #[tokio::test]
    async fn test_get_so_file_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "get_so_file", &json!({"so_id": 9999})).await.unwrap_err();
        assert!(err.message.contains("not found") && err.message.contains("9999"),
                "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_get_so_file_missing_id_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "get_so_file", &json!({})).await.unwrap_err();
        assert!(err.message.contains("so_id"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_delete_so_seeded_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let so_id = save_decrypt_so(tmp.path());

        // Delete → deleted.
        let r = dispatch_tool(&server, "delete_so", &json!({"so_id": so_id})).await.unwrap();
        assert_eq!(r["status"], "deleted");
        assert_eq!(r["so_id"], so_id);

        // List now empty.
        let listed = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(listed["count"], 0);

        // Re-delete → not_found.
        let r2 = dispatch_tool(&server, "delete_so", &json!({"so_id": so_id})).await.unwrap();
        assert_eq!(r2["status"], "not_found");
    }

    #[tokio::test]
    async fn test_delete_so_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let r = dispatch_tool(&server, "delete_so", &json!({"so_id": 9999})).await.unwrap();
        assert_eq!(r["status"], "not_found");
    }

    /// import_so success path against a real ELF (libc). Skipped when the
    /// fixture is absent (non x86_64 Linux). Verifies so_id assignment,
    /// function-count population, build_id, list/get roundtrip, and that
    /// re-importing the same bytes deduplicates to the same so_id.
    #[tokio::test]
    async fn test_import_so_from_libc() {
        let bytes = match read_libc_if_present() {
            Some(b) => b,
            None => {
                eprintln!("skipping: /lib/x86_64-linux-gnu/libc.so.6 not present");
                return;
            }
        };
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));

        let args = json!({"bytes": b64(&bytes), "path": "/lib/x86_64-linux-gnu/libc.so.6"});
        let r = dispatch_tool(&server, "import_so", &args).await.unwrap();
        let so_id = r["so_id"].as_u64().unwrap();
        assert!(so_id >= 1, "so_id assigned: {:?}", r);
        // Fresh import — no prior entry with this sha256, so NOT deduped.
        assert_eq!(r["deduped"], false, "first import must not be deduped: {:?}", r);
        assert!(r["summary"]["function_count"].as_u64().unwrap() > 0,
                "parsed functions: {:?}", r["summary"]);
        assert!(r["summary"]["build_id"].is_string(),
                "libc has a GNU build-id: {:?}", r["summary"]);

        // list shows exactly this one.
        let listed = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(listed["count"], 1);

        // get roundtrip.
        let got = dispatch_tool(&server, "get_so_file", &json!({"so_id": so_id})).await.unwrap();
        assert_eq!(got["so_file"]["id"], so_id);
        assert_eq!(got["so_file"]["path"], "/lib/x86_64-linux-gnu/libc.so.6");

        // Re-import the same bytes → same id, no new row, and deduped is now
        // deterministically true: the flag comes straight from save's index
        // lookup (find_by_sha256 hit), not a second-grained created_at
        // heuristic, so same-second re-imports are flagged correctly.
        let r2 = dispatch_tool(&server, "import_so", &args).await.unwrap();
        assert_eq!(r2["so_id"], so_id, "dedup keeps the same id: {:?}", r2);
        assert_eq!(r2["deduped"], true, "re-import must be flagged deduped: {:?}", r2);
        let listed2 = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(listed2["count"], 1, "no duplicate row added");
    }
}
