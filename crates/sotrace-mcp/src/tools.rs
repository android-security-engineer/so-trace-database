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
include!("tools_in01.rs");
include!("tools_in02.rs");
include!("tools_in03.rs");
include!("tools_in04.rs");
#[cfg(test)]
mod tests {
include!("tools_in05.rs");
include!("tools_in06.rs");
include!("tools_in07.rs");
}
