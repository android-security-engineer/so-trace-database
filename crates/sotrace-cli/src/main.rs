//! SO Trace Database — CLI Tool
//!
//! Provides command-line access to trace import, thread analysis, and
//! querying. Since the persistence layer is not yet implemented, the CLI
//! operates in an in-memory "load-then-query/analyze" mode: a trace JSON file
//! is loaded into a TraceEngine, then either analyzed (`analyze`) or queried
//! (`query <subcommand>`), with results printed.
//!
//! # Commands
//!
//! - `analyze <trace>` — run race/deadlock/contention/safety analysis.
//! - `query <trace> <subcommand>` — inspect threads, instructions, memory,
//!   sync events, locks, context switches, or a thread's timeline.
//! - `import-so <path>` — parse an ELF/SO file and print its metadata.
//!
//! # Trace JSON format
//!
//! The input JSON mirrors the `import_trace` MCP tool / HTTP `/traces/import`:
//! ```json
//! {
//!   "trace_id": 1,
//!   "so_file_id": 0,
//!   "threads": [ { ...ThreadInfo } ],
//!   "instructions": [ { ...InstructionTrace } ],
//!   "memory_writes": [ { "step", "thread_id", "address", "data": [bytes] } ],
//!   "memory_reads": [ { "step", "thread_id", "address", "size" } ],
//!   "sync_events": [ { ...ThreadSyncEvent } ],
//!   "context_switches": [ { ...ContextSwitch } ],
//!   "state_changes": [ { ...ThreadStateChange } ]
//! }
//! ```
include!("main_in01.rs");
include!("main_in02.rs");
include!("main_in03.rs");
include!("main_in04.rs");
#[cfg(test)]
mod tests {
include!("main_in05.rs");
include!("main_in06.rs");
include!("main_in07.rs");
}
