
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::Value;
use sotrace_core::adapters::TraceEvent;
use sotrace_core::elf::ParsedSoFile;
use sotrace_core::models::call_trace::CallTrace;
use sotrace_core::models::instruction_trace::InstructionTrace;
use sotrace_core::models::jni_call::JNICall;
use sotrace_core::models::register_delta::RegisterDelta;
use sotrace_core::models::thread::{    ContextSwitch, ThreadInfo, ThreadStateChange, ThreadSyncEvent,
};
use sotrace_engine::trace_store::memory_store::MemoryWrite;
use sotrace_engine::TraceEngine;

#[derive(Parser)]
#[command(name = "sotrace")]
#[command(about = "SO Trace Database — Android SO execution trace storage and query")]
struct Cli {
    /// Data directory for persistent storage (SO metadata, etc.).
    /// Created if missing. Default: ./.sotrace
    #[arg(long, global = true, env = "SOTRACE_DATA_DIR", default_value = ".sotrace")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Import a trace JSON file and run thread analysis, printing a report.
    ///
    /// This is the primary workflow: load a captured trace, then inspect
    /// races / deadlocks / contentions / thread safety / thread-function
    /// associations / inter-thread data flows / producer-consumer patterns.
    Analyze {
        /// Path to the trace JSON file. Optional if --trace-id is given (replays
        /// a persisted trace instead of re-parsing the file).
        trace_file: Option<PathBuf>,

        /// Replay a persisted trace by ID (from `trace-save`) instead of parsing
        /// `trace_file`. Mutually exclusive with trace_file in practice.
        #[arg(long)]
        trace_id: Option<u64>,

        /// SO file ID to associate with the trace (default: 0)
        #[arg(long, default_value_t = 0)]
        so_id: u64,

        /// Trace format. `native` = internal envelope JSON; the frida-* options
        /// parse Frida tool output via the adapter layer.
        #[arg(long, value_enum, default_value_t = TraceFormat::Native)]
        format: TraceFormat,

        /// Runtime base address of the target SO (for frida formats, to convert
        /// absolute addresses to SO-relative offsets). Accepts decimal or 0x-hex.
        /// Default 0 = keep as-is.
        #[arg(long, default_value_t = 0, value_parser = parse_addr_arg)]
        base_addr: u64,

        /// Output only a specific analysis dimension. If omitted, runs all.
        #[arg(long, value_enum)]
        only: Option<AnalysisDim>,

        /// Path to the target SO file. When provided, the ELF is parsed and its
        /// function symbols are registered so analysis results show function
        /// names instead of bare offsets.
        #[arg(long)]
        so: Option<PathBuf>,

        /// Emit raw JSON instead of a human-readable report
        #[arg(long)]
        json: bool,
    },
    /// Query a loaded trace: inspect threads, instructions, memory, sync
    /// events, or the timeline. Like `analyze`, this loads a trace (from file
    /// or via --trace-id) into an in-memory engine and runs queries against it.
    Query {
        /// Path to the trace JSON file. Optional if --trace-id is given.
        trace_file: Option<PathBuf>,

        /// Replay a persisted trace by ID instead of parsing `trace_file`.
        #[arg(long)]
        trace_id: Option<u64>,

        /// SO file ID to associate with the trace (default: 0)
        #[arg(long, default_value_t = 0)]
        so_id: u64,

        /// Trace format. `native` = internal envelope JSON; the frida-* options
        /// parse Frida tool output via the adapter layer.
        #[arg(long, value_enum, default_value_t = TraceFormat::Native)]
        format: TraceFormat,

        /// Runtime base address of the target SO (for frida formats, to convert
        /// absolute addresses to SO-relative offsets). Accepts decimal or 0x-hex.
        /// Default 0 = keep as-is.
        #[arg(long, default_value_t = 0, value_parser = parse_addr_arg)]
        base_addr: u64,

        /// Path to the target SO file. When provided, the ELF is parsed and its
        /// function symbols are registered so query results show function names
        /// instead of bare offsets.
        #[arg(long)]
        so: Option<PathBuf>,

        /// Query to run (determines output shape).
        #[command(subcommand)]
        query: QueryCmd,
    },
    /// Parse an SO (ELF) file and print its metadata: architecture, segments,
    /// symbols, and functions. With --save, persist it to the data directory
    /// (deduplicated by SHA-256) and print the assigned SO ID.
    ImportSo {
        /// Path to the SO file
        path: PathBuf,

        /// Persist the parsed SO to <data_dir>/so/<id>.bincode. Re-importing the
        /// same file (by SHA-256) is a no-op and reuses the existing ID.
        #[arg(long)]
        save: bool,
    },
    /// List all SOs persisted in the data directory.
    SoList,
    /// Show details of a persisted SO by ID.
    SoShow {
        /// SO file ID
        so_id: u64,
    },
    /// Delete a persisted SO by ID.
    SoDelete {
        /// SO file ID
        so_id: u64,
    },
    /// Import a trace file, parse it into events, and persist the event stream
    /// to <data_dir>/trace/<id>.bincode. Prints the assigned trace ID. Later
    /// `analyze`/`query --trace-id <id>` replays it without re-parsing.
    TraceSave {
        /// Path to the trace file (native envelope or adapter format).
        trace_file: PathBuf,

        /// SO file ID to associate with the persisted trace (default: 0).
        #[arg(long, default_value_t = 0)]
        so_id: u64,

        /// Trace format. `native` = internal envelope JSON; frida-* / dynamorio-* / pin
        /// options parse tool output via the adapter layer.
        #[arg(long, value_enum, default_value_t = TraceFormat::Native)]
        format: TraceFormat,

        /// Runtime base address of the target SO (for adapter formats). Default 0.
        #[arg(long, default_value_t = 0, value_parser = parse_addr_arg)]
        base_addr: u64,

        /// Path to the target SO file. When provided, the SO is parsed and
        /// persisted (deduplicated by SHA-256) and its returned ID is associated
        /// with the trace, so later replays show function names.
        #[arg(long)]
        so: Option<PathBuf>,
    },
    /// List all traces persisted in the data directory.
    TraceList,
    /// Show details of a persisted trace by ID.
    TraceShow {
        /// Trace ID
        trace_id: u64,
    },
    /// Delete a persisted trace by ID.
    TraceDelete {
        /// Trace ID
        trace_id: u64,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum AnalysisDim {
    /// Race conditions only
    Races,
    /// Deadlock risks only
    Deadlocks,
    /// Lock contentions only
    Contentions,
    /// Function thread-safety classification only
    Safety,
    /// Thread-function associations only
    #[value(name = "function-assoc")]
    FunctionAssoc,
    /// Inter-thread data flows only
    #[value(name = "data-flows")]
    DataFlows,
    /// Producer-consumer patterns only
    #[value(name = "producer-consumer")]
    ProducerConsumer,
    /// Per-thread scheduling / context-switch stats only
    Scheduling,
    /// Per-thread lifecycle / spawn tree only
    Lifecycle,
    /// Per-thread state residency / transitions only
    #[value(name = "thread-states")]
    ThreadStates,
    /// Per-lock critical-section / hold-time stats only
    #[value(name = "critical-sections")]
    CriticalSections,
    /// Per-thread JNI boundary-crossing stats only
    #[value(name = "jni-boundary")]
    JniBoundary,
}

/// Sub-queries for the `query` command. Each maps to a TraceEngine query API
/// and emits a JSON object (or human-readable report).
#[derive(Debug, Subcommand)]
enum QueryCmd {
    /// List all threads and their stats.
    Threads,
    /// Show one thread's metadata + stats.
    Thread {
        /// Thread ID
        thread_id: u32,
    },
    /// Show a thread's timeline (state changes, sync events, context switches)
    /// over an optional step range.
    Timeline {
        /// Thread ID
        thread_id: u32,
        /// Start step (inclusive). Default 0.
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// End step (exclusive). Default u64::MAX = to the end.
        #[arg(long, default_value_t = u64::MAX)]
        end: u64,
    },
    /// Look up an instruction by step.
    Instruction {
        /// Step / sequence number
        step: u64,
    },
    /// List instructions in a step range.
    Instructions {
        /// Start step (inclusive)
        start: u64,
        /// End step (exclusive)
        end: u64,
    },
    /// List instructions executed at a given SO-relative address.
    Address {
        /// SO-relative address (decimal or 0x-hex)
        #[arg(value_parser = parse_addr_arg)]
        address: u64,
    },
    /// Reconstruct the memory value at an address/step.
    Memory {
        /// Address (decimal or 0x-hex)
        #[arg(value_parser = parse_addr_arg)]
        address: u64,
        /// Step to reconstruct at
        step: u64,
        /// Number of bytes to read
        #[arg(long, default_value_t = 16)]
        size: usize,
    },
    /// List sync events (lock/unlock/futex) for a thread in a step range.
    Sync {
        /// Thread ID
        thread_id: u32,
        /// Start step (inclusive). Default 0.
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// End step (exclusive). Default u64::MAX.
        #[arg(long, default_value_t = u64::MAX)]
        end: u64,
    },
    /// Show the contention history for a specific lock object.
    Lock {
        /// Lock object address (decimal or 0x-hex)
        #[arg(value_parser = parse_addr_arg)]
        address: u64,
        /// Start step (inclusive). Default 0.
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// End step (exclusive). Default u64::MAX.
        #[arg(long, default_value_t = u64::MAX)]
        end: u64,
    },
    /// List context switches in a step range.
    Switches {
        /// Start step (inclusive). Default 0.
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// End step (exclusive). Default u64::MAX.
        #[arg(long, default_value_t = u64::MAX)]
        end: u64,
    },
    /// Reconstruct a register's value at a given step.
    ///
    /// register_id follows the ARM64 layout: 0-30 = x0-x30, 31 = SP,
    /// 32 = PC, 33 = NZCV.
    Register {
        /// Register ID (0-30 = x0-x30, 31 = SP, 32 = PC, 33 = NZCV)
        register_id: usize,
        /// Step to reconstruct the value at
        step: u64,
    },
    /// Instruction, register file, and this step's memory writes.
    ///
    /// One step. Does not take a register id or a memory address.
    Snapshot {
        /// Instruction step
        step: u64,
    },
    /// Reconstruct the full ARM64 register file at a given step.
    ///
    /// Returns every register's value at `step` in one snapshot (x0-x30, SP,
    /// PC, NZCV). Slots never recorded read as 0.
    RegisterState {
        /// Step to reconstruct the register file at
        step: u64,
    },
    /// List the steps at which a register was modified.
    ///
    /// Answers "when did register X change?" — the list form of `register`.
    /// Uses the per-register index (O(log K + R)), not a full-log scan.
    RegisterHistory {
        /// Register ID (0-30 = x0-x30, 31 = SP, 32 = PC, 33 = NZCV)
        register_id: usize,
        /// Start step (inclusive). Default 0.
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// End step (inclusive). Default u64::MAX = to the end.
        #[arg(long, default_value_t = u64::MAX)]
        end: u64,
    },
    /// Reconstruct a thread's live call stack at a given step.
    ///
    /// Replays the thread's call/return events up to `step`, returning the
    /// active frames outermost-first (each with entry address, call site,
    /// call seq and depth).
    CallStack {
        /// Thread ID
        thread_id: u32,
        /// Step to reconstruct the call stack at
        step: u64,
    },
    /// List JNI boundary calls reaching a given native function address.
    ///
    /// Answers "which Java methods called into this native entry point, and
    /// when?" — the JNI analogue of `address`. Uses the AddressIndex maintained
    /// on every imported JNI call.
    JniCalls {
        /// Native function address (decimal or 0x-hex)
        #[arg(value_parser = parse_addr_arg)]
        address: u64,
        /// Start step (inclusive). Default 0.
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// End step (inclusive). Default u64::MAX = to the end.
        #[arg(long, default_value_t = u64::MAX)]
        end: u64,
    },
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq)]
enum TraceFormat {
    /// Internal envelope JSON (threads/instructions/... arrays)
    Native,
    /// Frida Stalker instruction trace (newline-delimited JSON)
    FridaStalker,
    /// Frida Interceptor function call trace
    FridaInterceptor,
    /// jnitrace JNI boundary trace
    Jnitrace,
    /// DynamoRIO drcachesim instruction trace (text)
    DrCachesim,
    /// DynamoRIO memtrace memory-access trace (text)
    DrMemtrace,
    /// Pin pinatrace memory-access trace (text)
    Pinatrace,
}

impl TraceFormat {
    /// Returns `(adapter_name, trace_type)` for adapter formats, or `None` for
    /// the native envelope format.
    fn adapter(&self) -> Option<(&'static str, &'static str)> {
        match self {
            TraceFormat::Native => None,
            TraceFormat::FridaStalker => Some(("frida", "stalker")),
            TraceFormat::FridaInterceptor => Some(("frida", "interceptor")),
            TraceFormat::Jnitrace => Some(("frida", "jnitrace")),
            TraceFormat::DrCachesim => Some(("dynamorio", "drcachesim")),
            TraceFormat::DrMemtrace => Some(("dynamorio", "memtrace")),
            TraceFormat::Pinatrace => Some(("pin", "pinatrace")),
        }
    }
}

/// The trace JSON envelope (mirrors import_trace MCP tool / HTTP import).
#[derive(Debug, Deserialize)]
struct TraceEnvelope {
    #[serde(default)]
    trace_id: Option<u64>,
    #[serde(default)]
    so_file_id: Option<u64>,
    #[serde(default)]
    threads: Vec<ThreadInfo>,
    #[serde(default)]
    instructions: Vec<InstructionTrace>,
    /// Register-change deltas (bitmask + values). Typed shape maps directly.
    #[serde(default)]
    register_deltas: Vec<RegisterDelta>,
    /// Function call/return events. Typed shape maps directly.
    #[serde(default)]
    calls: Vec<CallTrace>,
    /// Memory writes use a flat shape (step/thread_id/address/data) that
    /// doesn't directly map to MemoryWrite, so we parse them manually.
    #[serde(default)]
    memory_writes: Vec<Value>,
    /// Memory reads feed the analyzer's race detector (not stored).
    #[serde(default)]
    memory_reads: Vec<Value>,
    #[serde(default)]
    sync_events: Vec<ThreadSyncEvent>,
    #[serde(default)]
    context_switches: Vec<ContextSwitch>,
    #[serde(default)]
    state_changes: Vec<ThreadStateChange>,
    /// JNI boundary crossings (Java↔native). Typed shape maps directly.
    #[serde(default)]
    jni_calls: Vec<JNICall>,
}
