
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
