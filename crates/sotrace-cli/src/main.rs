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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone();
    // Take the import timestamp once per invocation; passed into trace-save so
    // tests can pin it via a fixed value through the same code path.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match cli.command {
        Commands::Analyze {
            trace_file,
            trace_id,
            so_id,
            format,
            base_addr,
            only,
            so,
            json,
        } => run_analyze(&data_dir, trace_file, trace_id, so_id, format, base_addr, only, so, json),
        Commands::Query {
            trace_file,
            trace_id,
            so_id,
            format,
            base_addr,
            so,
            query,
        } => run_query(&data_dir, trace_file, trace_id, so_id, format, base_addr, so, query),
        Commands::ImportSo { path, save } => run_import_so(&data_dir, path, save),
        Commands::SoList => run_so_list(&data_dir),
        Commands::SoShow { so_id } => run_so_show(&data_dir, so_id),
        Commands::SoDelete { so_id } => run_so_delete(&data_dir, so_id),
        Commands::TraceSave { trace_file, so_id, format, base_addr, so } => {
            run_trace_save(&data_dir, trace_file, so_id, format, base_addr, so, now)
        }
        Commands::TraceList => run_trace_list(&data_dir),
        Commands::TraceShow { trace_id } => run_trace_show(&data_dir, trace_id),
        Commands::TraceDelete { trace_id } => run_trace_delete(&data_dir, trace_id),
    }
}

/// Load a trace into a fresh in-memory TraceEngine.
///
/// Two load sources, mutually exclusive:
/// - `trace_id = Some(id)`: replay a persisted trace from `TraceRepository`.
///   The original trace file is not re-parsed; the saved event stream is fed
///   back through [`feed_events`], and the associated SO (by `so_file_id`) is
///   loaded from `SoRepository` for function-name backfill.
/// - `trace_id = None` + `trace_file = Some(path)`: parse the trace file
///   (native envelope or adapter format) into events, then feed them.
///
/// Returns the engine, import counts, and the event vector. The event vector
/// is returned even on file parse so callers (e.g. `trace-save`) can persist
/// it without re-parsing. Progress goes to stderr so stdout stays clean.
///
/// SO source priority:
/// 1. `--so <path>` — parse the ELF file directly (in-memory, not persisted).
/// 2. else if `so_file_id > 0` — load the persisted SO with that ID from
///    `data_dir`. On trace-id replay, `so_file_id` comes from the persisted
///    trace (authoritative); otherwise from `--so-id` / the envelope.
fn load_engine(
    data_dir: &Path,
    trace_file: Option<&PathBuf>,
    trace_id: Option<u64>,
    so_id: u64,
    format: TraceFormat,
    base_addr: u64,
    so: &Option<PathBuf>,
    quiet: bool,
) -> Result<(TraceEngine, ImportedCounts, Vec<TraceEvent>)> {
    // For trace-id replay, the persisted trace's so_file_id is authoritative
    // and overrides the caller's --so-id.
    let mut resolved_so_file_id = so_id;
    let events: Vec<TraceEvent>;
    let mut imported = ImportedCounts::default();

    if let Some(id) = trace_id {
        // Replay path: load persisted trace, replay its event stream.
        let trace_repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
            .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
        let persisted = trace_repo
            .load(id)
            .with_context(|| format!("no persisted trace with id {} in {}", id, data_dir.display()))?;
        resolved_so_file_id = persisted.so_file_id;
        events = persisted.events;
        if !quiet {
            eprintln!(
                "Replaying trace {} (so_file_id={}, source={:?}, base_addr=0x{:x}): {} events",
                id, resolved_so_file_id, persisted.source, persisted.base_addr, events.len()
            );
        }
    } else {
        let trace_file = trace_file
            .context("either --trace-id or a trace file path must be provided")?;
        let raw = std::fs::read_to_string(trace_file)
            .with_context(|| format!("failed to read trace file: {}", trace_file.display()))?;

        if let Some((adapter_name, trace_type)) = format.adapter() {
            // Adapter path: Frida / DynamoRIO / Pin
            use sotrace_core::adapters::TraceAdapter;
            let adapter: Box<dyn TraceAdapter> = match adapter_name {
                "frida" => Box::new(sotrace_core::adapters::frida::FridaAdapter::new()),
                "dynamorio" => Box::new(sotrace_core::adapters::dynamorio::DynamoRioAdapter::new()),
                "pin" => Box::new(sotrace_core::adapters::pin::PinAdapter::new()),
                other => anyhow::bail!("unknown adapter '{}'", other),
            };
            let (parsed_events, stats) = adapter
                .parse(trace_type, &raw, base_addr)
                .with_context(|| format!("failed to parse {} {} trace", adapter_name, trace_type))?;
            events = parsed_events;
            if !quiet {
                eprintln!(
                    "Loaded {} {} trace (so_file_id={}, base_addr=0x{:x}): {} events ({} skipped)",
                    adapter_name, trace_type, resolved_so_file_id, base_addr,
                    events.len(), stats.skipped
                );
            }
        } else {
            // Native envelope path
            let envelope: TraceEnvelope = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse trace JSON: {}", trace_file.display()))?;
            let trace_id = envelope.trace_id.unwrap_or(1);
            if let Some(env_so_id) = envelope.so_file_id {
                resolved_so_file_id = env_so_id;
            }
            events = envelope_to_events(&envelope)?;
            if !quiet {
                eprintln!(
                    "Loaded trace {} (so_file_id={}): {} events",
                    trace_id, resolved_so_file_id, events.len()
                );
            }
        }
    }

    let mut engine = TraceEngine::new(resolved_so_file_id, Default::default());

    // Resolve the SO source: explicit --so path takes priority; otherwise fall
    // back to loading a persisted SO by ID from the data directory.
    let so_source: Option<ParsedSoFile> = if let Some(so_path) = so {
        Some(
            sotrace_engine::elf::parse_elf(so_path)
                .with_context(|| format!("failed to parse SO file: {}", so_path.display()))?,
        )
    } else if resolved_so_file_id > 0 {
        let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
            .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
        repo.load(resolved_so_file_id).ok()
    } else {
        None
    };

    if let Some(parsed) = &so_source {
        engine.register_parsed_so(parsed);
        if !quiet {
            eprintln!(
                "Loaded SO {:?}, {} bytes, {} functions ({} JNI, {} exported)",
                parsed.so_file.arch,
                parsed.so_file.file_size,
                parsed.functions.len(),
                parsed.jni_function_count(),
                parsed.exported_function_count(),
            );
        }
    }

    feed_events(&mut engine, &events, &mut imported)?;

    Ok((engine, imported, events))
}

fn run_analyze(
    data_dir: &Path,
    trace_file: Option<PathBuf>,
    trace_id: Option<u64>,
    so_id: u64,
    format: TraceFormat,
    base_addr: u64,
    only: Option<AnalysisDim>,
    so: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let (mut engine, _imported, _events) = load_engine(
        data_dir, trace_file.as_ref(), trace_id, so_id, format, base_addr, &so, json,
    )?;

    // --- Run analysis ---
    if json {
        let out = build_json_output(&mut engine, only)?;
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    print_human_report(&mut engine, only)?;
    Ok(())
}

fn run_query(
    data_dir: &Path,
    trace_file: Option<PathBuf>,
    trace_id: Option<u64>,
    so_id: u64,
    format: TraceFormat,
    base_addr: u64,
    so: Option<PathBuf>,
    query: QueryCmd,
) -> Result<()> {
    // `query` always emits JSON to stdout; load progress goes to stderr.
    let (engine, _imported, _events) =
        load_engine(data_dir, trace_file.as_ref(), trace_id, so_id, format, base_addr, &so, true)?;
    // Borrow immutably for all read-only queries.
    let engine = engine;

    let out: Value = match &query {
        QueryCmd::Threads => {
            let ids = engine.all_thread_ids();
            let stats = engine.all_thread_stats();
            let mut entries = Vec::with_capacity(ids.len());
            for tid in ids {
                let info = engine.get_thread_info(tid).cloned();
                let st = stats.iter().find(|s| s.thread_id == tid).cloned();
                entries.push(serde_json::json!({
                    "thread_id": tid,
                    "info": info,
                    "stats": st,
                }));
            }
            serde_json::json!({ "threads": entries })
        }
        QueryCmd::Thread { thread_id } => {
            let info = engine.get_thread_info(*thread_id).cloned();
            let stats = engine.get_thread_stats(*thread_id);
            serde_json::json!({
                "thread_id": thread_id,
                "info": info,
                "stats": stats,
            })
        }
        QueryCmd::Timeline { thread_id, start, end } => {
            let tl = engine.query_thread_timeline(*thread_id, *start, *end);
            serde_json::json!({ "timeline": tl })
        }
        QueryCmd::Instruction { step } => {
            let inst = engine.query_instruction(*step).cloned();
            serde_json::json!({ "step": step, "instruction": inst })
        }
        QueryCmd::Instructions { start, end } => {
            let insts: Vec<_> = engine
                .query_instructions_range(*start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({ "start": start, "end": end, "count": insts.len(), "instructions": insts })
        }
        QueryCmd::Address { address } => {
            let steps: Vec<u64> = engine.query_instructions_by_address(*address).to_vec();
            let threads = engine.query_threads_at_address(*address);
            serde_json::json!({
                "address": address,
                "step_count": steps.len(),
                "steps": steps,
                // `query_threads_at_address` returns (thread_id, step) pairs —
                // each entry is "thread T executed this address at step S", not
                // a count. Emitting `step` (not a mislabeled `count`) keeps the
                // field name honest and lets callers see exactly when each
                // thread touched the address.
                "thread_accesses": threads.iter().map(|(t, s)| serde_json::json!({"thread_id": t, "step": s})).collect::<Vec<_>>(),
            })
        }
        QueryCmd::Memory { address, step, size } => {
            let res = engine.query_memory_value(*address, *size, *step);
            serde_json::json!({
                "address": address,
                "step": step,
                "size": size,
                "result": res,
            })
        }
        QueryCmd::Sync { thread_id, start, end } => {
            let events: Vec<_> = engine
                .query_thread_sync_events(*thread_id, *start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({
                "thread_id": thread_id,
                "start": start,
                "end": end,
                "count": events.len(),
                "sync_events": events,
            })
        }
        QueryCmd::Lock { address, start, end } => {
            let events: Vec<_> = engine
                .query_lock_contentions(*address, *start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({
                "lock_address": address,
                "start": start,
                "end": end,
                "count": events.len(),
                "contentions": events,
            })
        }
        QueryCmd::Switches { start, end } => {
            let switches: Vec<_> = engine
                .query_context_switches(*start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({
                "start": start,
                "end": end,
                "count": switches.len(),
                "context_switches": switches,
            })
        }
        QueryCmd::Register { register_id, step } => {
            let value = engine.query_register(*register_id, *step);
            serde_json::json!({
                "register_id": register_id,
                "step": step,
                "value": value,
                "value_hex": value.map(|v| format!("0x{v:x}")),
            })
        }
        QueryCmd::RegisterState { step } => {
            let state = engine.reconstruct_register_state(*step);
            serde_json::json!({
                "step": step,
                "state": state,
            })
        }
        QueryCmd::RegisterHistory { register_id, start, end } => {
            let steps = engine.query_register_history(*register_id, *start, *end);
            serde_json::json!({
                "register_id": register_id,
                "start": start,
                "end": end,
                "change_count": steps.len(),
                "steps": steps,
            })
        }
        QueryCmd::CallStack { thread_id, step } => {
            let frames = engine.rebuild_call_stack(*thread_id, *step);
            serde_json::json!({
                "thread_id": thread_id,
                "step": step,
                "depth": frames.len(),
                "frames": frames,
            })
        }
        QueryCmd::JniCalls { address, start, end } => {
            let calls: Vec<_> = engine
                .query_jni_calls_by_address(*address, *start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({
                "native_address": address,
                "start": start,
                "end": end,
                "count": calls.len(),
                "jni_calls": calls,
            })
        }
    };

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn run_import_so(data_dir: &Path, path: PathBuf, save: bool) -> Result<()> {
    let parsed = sotrace_engine::elf::parse_elf(&path)
        .with_context(|| format!("failed to parse SO file: {}", path.display()))?;
    let so = &parsed.so_file;

    // If --save, persist to the data dir (dedup by SHA-256) and print the ID.
    let assigned_id = if save {
        let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
            .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
        let outcome = repo.save(&parsed)?;
        // deduped is the authoritative signal from save's index lookup — no
        // second-grained created_at heuristic (which broke on same-second
        // re-imports).
        if outcome.deduped {
            eprintln!("SO already imported (dedup by sha256): reusing id={}", outcome.id);
        } else {
            eprintln!("Saved SO id={} to {}", outcome.id, data_dir.join("so").display());
        }
        Some(outcome.id)
    } else {
        None
    };

    println!("SO file: {}", so.path);
    if let Some(id) = assigned_id {
        println!("  so_id        : {}", id);
    }
    println!("  architecture : {:?}", so.arch);
    if let Some(bid) = &so.build_id {
        println!("  build_id     : {}", hex(bid));
    } else {
        println!("  build_id     : (none)");
    }
    println!("  file size    : {} bytes", so.file_size);
    println!("  sha256       : {}", hex(&so.sha256));
    println!("  segments     : {}", parsed.segments.len());
    println!("  symbols      : {}", parsed.symbols.len());
    println!("  functions    : {}", parsed.functions.len());
    println!("    JNI        : {}", parsed.jni_function_count());
    println!("    exported   : {}", parsed.exported_function_count());

    // List the first few function symbols (skip PLT/imported stubs).
    let named: Vec<_> = parsed.functions.iter()
        .filter(|f| !f.is_imported)
        .take(20)
        .collect();
    if !named.is_empty() {
        println!("\n  Sample functions (first {}):", named.len());
        for f in named {
            let tag = if f.is_jni { " [JNI]" } else { "" };
            println!("    0x{:08x}  {} ({} bytes){}", f.offset, f.name, f.size, tag);
        }
        let total = parsed.functions.len();
        if total > 20 {
            println!("    ... and {} more", total - 20);
        }
    }
    Ok(())
}

/// List all persisted SOs in the data directory.
fn run_so_list(data_dir: &Path) -> Result<()> {
    let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
        .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
    let list = repo.list()?;
    if list.is_empty() {
        println!("No SOs persisted in {}.", data_dir.join("so").display());
        return Ok(());
    }
    println!("{:<6} {:<10} {:<8} {:<10} {:<40} PATH", "ID", "ARCH", "FUNCS", "JNI", "SHA256(prefix)");
    for s in list {
        println!(
            "{:<6} {:<10} {:<8} {:<10} {:<40} {}",
            s.id, s.arch, s.function_count, s.jni_function_count,
            &s.sha256[..12.min(s.sha256.len())], s.path,
        );
    }
    Ok(())
}

/// Show details of a persisted SO by ID.
fn run_so_show(data_dir: &Path, so_id: u64) -> Result<()> {
    let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
        .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
    let parsed = repo.load(so_id)
        .with_context(|| format!("no persisted SO with id {} in {}", so_id, data_dir.display()))?;
    let so = &parsed.so_file;
    println!("SO id: {}", so_id);
    println!("  path         : {}", so.path);
    println!("  architecture : {:?}", so.arch);
    if let Some(bid) = &so.build_id {
        println!("  build_id     : {}", hex(bid));
    } else {
        println!("  build_id     : (none)");
    }
    println!("  file size    : {} bytes", so.file_size);
    println!("  sha256       : {}", hex(&so.sha256));
    println!("  segments     : {}", parsed.segments.len());
    println!("  symbols      : {}", parsed.symbols.len());
    println!("  functions    : {}", parsed.functions.len());
    println!("    JNI        : {}", parsed.jni_function_count());
    println!("    exported   : {}", parsed.exported_function_count());
    Ok(())
}

/// Delete a persisted SO by ID.
fn run_so_delete(data_dir: &Path, so_id: u64) -> Result<()> {
    let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
        .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
    if repo.delete(so_id)? {
        println!("Deleted SO id={}.", so_id);
    } else {
        println!("No SO with id={} found.", so_id);
    }
    Ok(())
}

/// Persist a trace's normalized event stream so it can be replayed later via
/// `analyze`/`query --trace-id` without re-parsing the source file.
fn run_trace_save(
    data_dir: &Path,
    trace_file: PathBuf,
    so_id: u64,
    format: TraceFormat,
    base_addr: u64,
    so: Option<PathBuf>,
    created_at: u64,
) -> Result<()> {
    // If --so is given, persist the SO first and use its (possibly deduped) ID
    // as the trace's so_file_id, so replays can backfill function names.
    let resolved_so_id = if let Some(so_path) = &so {
        let parsed = sotrace_engine::elf::parse_elf(so_path)
            .with_context(|| format!("failed to parse SO file: {}", so_path.display()))?;
        let so_repo = sotrace_engine::persistence::SoRepository::open(data_dir)
            .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
        so_repo.save(&parsed)?.id
    } else {
        so_id
    };

    // Compute the source label before `format` is moved into load_engine.
    let source = format
        .adapter()
        .map(|(a, t)| format!("{}:{}", a, t))
        .unwrap_or_else(|| "native".to_string());

    // Load (parse) the trace into events + an engine we discard. quiet=true so
    // stdout stays clean for the trace_id line.
    let (_engine, _imported, events) = load_engine(
        data_dir,
        Some(&trace_file),
        None,
        resolved_so_id,
        format,
        base_addr,
        &None, // SO already persisted above; load_engine will load it by id.
        true,
    )?;

    let trace = sotrace_engine::persistence::PersistedTrace {
        trace_id: 0, // auto-assigned by the repository
        so_file_id: resolved_so_id,
        source,
        base_addr,
        events,
        created_at,
    };

    let trace_repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
        .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
    let id = trace_repo.save(trace)?;

    println!("{}", id);
    Ok(())
}

/// List all persisted traces in the data directory.
fn run_trace_list(data_dir: &Path) -> Result<()> {
    let repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
        .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
    let list = repo.list()?;
    if list.is_empty() {
        println!("No traces persisted in {}.", data_dir.join("trace").display());
        return Ok(());
    }
    println!("{:<6} {:<8} {:<24} {:<12} {:<12} CREATED", "ID", "SO_ID", "SOURCE", "EVENTS", "BASE_ADDR");
    for s in list {
        println!(
            "{:<6} {:<8} {:<24} {:<12} 0x{:<10x} {}",
            s.trace_id, s.so_file_id, s.source, s.event_count, s.base_addr, s.created_at,
        );
    }
    Ok(())
}

/// Show details of a persisted trace by ID.
fn run_trace_show(data_dir: &Path, trace_id: u64) -> Result<()> {
    let repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
        .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
    let summary = repo.summary(trace_id)?
        .ok_or_else(|| anyhow::anyhow!("no persisted trace with id {} in {}", trace_id, data_dir.display()))?;
    println!("Trace id: {}", summary.trace_id);
    println!("  so_file_id   : {}", summary.so_file_id);
    println!("  source       : {}", summary.source);
    println!("  base_addr    : 0x{:x}", summary.base_addr);
    println!("  event_count  : {}", summary.event_count);
    println!("  created_at   : {}", summary.created_at);
    Ok(())
}

/// Delete a persisted trace by ID.
fn run_trace_delete(data_dir: &Path, trace_id: u64) -> Result<()> {
    let repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
        .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
    if repo.delete(trace_id)? {
        println!("Deleted trace id={}.", trace_id);
    } else {
        println!("No trace with id={} found.", trace_id);
    }
    Ok(())
}

/// Lowercase hex encoding of a byte slice (no 0x prefix).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Feed adapter-produced events into the engine in chronological order.
///
/// Takes a borrowed slice so the caller may keep the events (e.g. to persist
/// them via `TraceRepository`). A sorted owned copy is made internally.
fn feed_events(
    engine: &mut TraceEngine,
    events: &[TraceEvent],
    imported: &mut ImportedCounts,
) -> Result<()> {
    // Sort by step for timeline correctness; stable to preserve relative order.
    // The engine has `feed_events` that sorts+feeds by value, but we need the
    // borrowed slice + per-type counts, so we sort a clone and dispatch each
    // event through the engine's single `feed_event` table (no duplicated
    // match here — the engine owns the dispatch).
    let mut sorted: Vec<TraceEvent> = events.to_vec();
    sorted.sort_by_key(|e| e.step());
    for ev in sorted {
        engine.feed_event(ev.clone())?;
        match ev {
            TraceEvent::Thread(_) => imported.threads += 1,
            TraceEvent::Instruction(_) => imported.instructions += 1,
            TraceEvent::Register(_) => imported.register_deltas += 1,
            TraceEvent::Call(_) => imported.calls += 1,
            TraceEvent::JniCall(_) => imported.jni_calls += 1,
            TraceEvent::MemoryWrite { .. } => imported.memory_writes += 1,
            TraceEvent::MemoryRead { .. } => imported.memory_reads += 1,
            TraceEvent::Sync(_) => imported.sync_events += 1,
            TraceEvent::ContextSwitch(_) => imported.context_switches += 1,
            TraceEvent::StateChange(_) => imported.state_changes += 1,
        }
    }
    Ok(())
}

/// Convert a parsed native envelope into a uniform `TraceEvent` stream.
///
/// This is the persistence pivot: the same event vector is (a) fed to the
/// engine via [`feed_events`] for live analysis, and (b) serialized by
/// `TraceRepository` for later replay. Only envelope fields that exist are
/// converted (native envelopes carry no JNI events).
fn envelope_to_events(envelope: &TraceEnvelope) -> Result<Vec<TraceEvent>> {
    let mut events = Vec::new();
    for t in &envelope.threads {
        events.push(TraceEvent::Thread(t.clone()));
    }
    for i in &envelope.instructions {
        events.push(TraceEvent::Instruction(i.clone()));
    }
    for r in &envelope.register_deltas {
        events.push(TraceEvent::Register(r.clone()));
    }
    for c in &envelope.calls {
        events.push(TraceEvent::Call(c.clone()));
    }
    for w in &envelope.memory_writes {
        let mw = parse_memory_write(w)?;
        events.push(TraceEvent::MemoryWrite {
            step: mw.step,
            thread_id: mw.thread_id,
            address: mw.address,
            data: mw.data,
        });
    }
    for r in &envelope.memory_reads {
        let (step, thread_id, address, size) = parse_memory_read(r)?;
        events.push(TraceEvent::MemoryRead { step, thread_id, address, size });
    }
    for e in &envelope.sync_events {
        events.push(TraceEvent::Sync(e.clone()));
    }
    for s in &envelope.context_switches {
        events.push(TraceEvent::ContextSwitch(s.clone()));
    }
    for c in &envelope.state_changes {
        events.push(TraceEvent::StateChange(c.clone()));
    }
    for j in &envelope.jni_calls {
        events.push(TraceEvent::JniCall(j.clone()));
    }
    Ok(events)
}

#[derive(Default)]
struct ImportedCounts {
    threads: usize,
    instructions: usize,
    register_deltas: usize,
    calls: usize,
    jni_calls: usize,
    memory_writes: usize,
    memory_reads: usize,
    sync_events: usize,
    context_switches: usize,
    state_changes: usize,
}

fn parse_addr_arg(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn parse_memory_write(v: &Value) -> Result<MemoryWrite> {
    let step = v.get("step").and_then(|x| x.as_u64())
        .context("memory_write missing 'step'")?;
    let thread_id = v.get("thread_id").and_then(|x| x.as_u64())
        .context("memory_write missing 'thread_id'")? as u32;
    let address = v.get("address").and_then(|x| x.as_u64())
        .context("memory_write missing 'address'")?;
    let data: Vec<u8> = v.get("data")
        .and_then(|x| serde_json::from_value(x.clone()).ok())
        .unwrap_or_default();
    Ok(MemoryWrite { step, thread_id, address, data })
}

fn parse_memory_read(v: &Value) -> Result<(u64, u32, u64, usize)> {
    let step = v.get("step").and_then(|x| x.as_u64())
        .context("memory_read missing 'step'")?;
    let thread_id = v.get("thread_id").and_then(|x| x.as_u64())
        .context("memory_read missing 'thread_id'")? as u32;
    let address = v.get("address").and_then(|x| x.as_u64())
        .context("memory_read missing 'address'")?;
    let size = v.get("size").and_then(|x| x.as_u64()).unwrap_or(1) as usize;
    Ok((step, thread_id, address, size))
}

fn build_json_output(engine: &mut TraceEngine, only: Option<AnalysisDim>) -> Result<Value> {
    use serde_json::json;
    Ok(match only {
        None => serde_json::to_value(engine.analyze_threads())?,
        Some(AnalysisDim::Races) => json!({ "race_conditions": engine.detect_race_conditions() }),
        Some(AnalysisDim::Deadlocks) => json!({ "deadlock_risks": engine.detect_deadlocks() }),
        Some(AnalysisDim::Contentions) => json!({ "lock_contentions": engine.analyze_lock_contention() }),
        Some(AnalysisDim::Safety) => json!({ "function_safety": engine.classify_function_thread_safety() }),
        Some(AnalysisDim::FunctionAssoc) => json!({ "thread_function_assocs": engine.analyze_thread_function_assoc() }),
        Some(AnalysisDim::DataFlows) => json!({ "data_flows": engine.analyze_data_flows() }),
        Some(AnalysisDim::ProducerConsumer) => json!({ "producer_consumer_patterns": engine.detect_producer_consumer() }),
        Some(AnalysisDim::Scheduling) => json!({ "scheduling": engine.analyze_scheduling() }),
        Some(AnalysisDim::Lifecycle) => json!({ "lifecycle": engine.analyze_thread_lifecycle() }),
        Some(AnalysisDim::ThreadStates) => json!({ "state_stats": engine.analyze_thread_states() }),
        Some(AnalysisDim::CriticalSections) => json!({ "critical_sections": engine.analyze_critical_sections() }),
        Some(AnalysisDim::JniBoundary) => json!({ "jni_boundary": engine.analyze_jni_boundary() }),
    })
}

fn print_human_report(engine: &mut TraceEngine, only: Option<AnalysisDim>) -> Result<()> {
    match only {
        Some(AnalysisDim::Races) => print_races(&engine.detect_race_conditions()),
        Some(AnalysisDim::Deadlocks) => print_deadlocks(&engine.detect_deadlocks()),
        Some(AnalysisDim::Contentions) => print_contentions(&engine.analyze_lock_contention()),
        Some(AnalysisDim::Safety) => print_safety(&engine.classify_function_thread_safety()),
        Some(AnalysisDim::FunctionAssoc) => print_function_assoc(&engine.analyze_thread_function_assoc()),
        Some(AnalysisDim::DataFlows) => print_data_flows(&engine.analyze_data_flows()),
        Some(AnalysisDim::ProducerConsumer) => print_producer_consumer(&engine.detect_producer_consumer()),
        Some(AnalysisDim::Scheduling) => print_scheduling(&engine.analyze_scheduling()),
        Some(AnalysisDim::Lifecycle) => print_lifecycle(&engine.analyze_thread_lifecycle()),
        Some(AnalysisDim::ThreadStates) => print_thread_states(&engine.analyze_thread_states()),
        Some(AnalysisDim::CriticalSections) => print_critical_sections(&engine.analyze_critical_sections()),
        Some(AnalysisDim::JniBoundary) => print_jni_boundary(&engine.analyze_jni_boundary()),
        None => {
            let result = engine.analyze_threads();
            print_races(&result.race_conditions);
            print_deadlocks(&result.deadlock_risks);
            print_contentions(&result.lock_contentions);
            print_safety(&result.function_safety);
            print_function_assoc(&result.thread_function_assocs);
            print_data_flows(&result.data_flows);
            print_producer_consumer(&result.producer_consumer_patterns);
            print_scheduling(&result.scheduling);
            print_lifecycle(&result.lifecycle);
            print_thread_states(&result.state_stats);
            print_critical_sections(&result.critical_sections);
            print_jni_boundary(&result.jni_boundary);
            println!(
                "\nSummary: {} races, {} deadlocks, {} contended locks, {} functions classified, {} data flows, {} producer-consumer patterns, {} threads scheduled, {} threads tracked, {} threads state-profiled, {} locks hold-profiled, {} threads with JNI activity",
                result.race_conditions.len(),
                result.deadlock_risks.len(),
                result.lock_contentions.iter().filter(|c| c.contention_count > 0).count(),
                result.function_safety.len(),
                result.data_flows.len(),
                result.producer_consumer_patterns.len(),
                result.scheduling.len(),
                result.lifecycle.len(),
                result.state_stats.len(),
                result.critical_sections.len(),
                result.jni_boundary.iter().filter(|j| j.total_crossings > 0 || j.is_jni_attached).count()
            );
        }
    }
    Ok(())
}

fn print_races(races: &[sotrace_engine::analyzer::thread_analyzer::RaceCondition]) {
    println!("\n=== Race Conditions ({}) ===", races.len());
    for (i, r) in races.iter().enumerate() {
        let first = if r.first_is_write { "write" } else { "read" };
        let second = if r.second_is_write { "write" } else { "read" };
        println!(
            "  [{}] addr=0x{:x}  T{} {} ({}B) @ step {}  →  T{} {} ({}B) @ step {}  conflict=0x{:x}+{}B",
            i, r.address, r.first_thread, first, r.first_access_size, r.first_step,
            r.second_thread, second, r.second_access_size, r.second_step,
            r.overlap_address, r.overlap_size,
        );
    }
}

fn print_deadlocks(dl: &[sotrace_engine::analyzer::thread_analyzer::DeadlockRisk]) {
    println!("\n=== Deadlock Risks ({}) ===", dl.len());
    for (i, d) in dl.iter().enumerate() {
        let cycle: Vec<String> = d.lock_cycle.iter()
            .map(|m| format!("0x{:x} ({:?})", m.addr, m.kind)).collect();
        let threads: Vec<String> = d.threads.iter().map(|t| format!("T{}", t)).collect();
        println!("  [{}] locks=[{}] threads=[{}]", i, cycle.join(" → "), threads.join(", "));
        println!("       {}", d.description);
    }
}

fn print_contentions(cs: &[sotrace_engine::analyzer::thread_analyzer::LockContentionInfo]) {
    println!("\n=== Lock Contentions ({}) ===", cs.len());
    for (i, c) in cs.iter().enumerate() {
        println!(
            "  [{}] lock=0x{:x} ({:?})  acquires={} contended={} ({:.0}%) avg_wait={}ns",
            i, c.lock_address.addr, c.lock_address.kind, c.acquire_count, c.contention_count,
            c.contention_ratio * 100.0, c.avg_wait_ns
        );
    }
}

fn print_safety(fs: &[sotrace_engine::analyzer::thread_analyzer::FunctionThreadSafety]) {
    println!("\n=== Function Thread Safety ({}) ===", fs.len());
    for (i, f) in fs.iter().enumerate() {
        let threads: Vec<String> = f.calling_threads.iter().map(|t| format!("T{}", t)).collect();
        let name = f.function_name.as_deref().unwrap_or("");
        println!(
            "  [{}] 0x{:x} {} {:?}  callers=[{}] races={} sync={}",
            i, f.function_address, name, f.safety, threads.join(", "),
            f.race_count, f.sync_event_count
        );
    }
}

fn print_function_assoc(asocs: &[sotrace_engine::analyzer::thread_analyzer::ThreadFunctionAssoc]) {
    println!("\n=== Thread-Function Associations ({}) ===", asocs.len());
    for (i, a) in asocs.iter().enumerate() {
        let name = a.function_name.as_deref().unwrap_or("");
        println!(
            "  [{}] T{} 0x{:x} {}  calls={} first@{} last@{}",
            i, a.thread_id, a.function_address, name, a.call_count, a.first_call_step, a.last_call_step
        );
    }
}

fn print_data_flows(flows: &[sotrace_engine::analyzer::thread_analyzer::ThreadDataFlow]) {
    println!("\n=== Thread Data Flows ({}) ===", flows.len());
    for (i, f) in flows.iter().enumerate() {
        let sync = if f.is_synchronized { "sync" } else { "unsync" };
        println!(
            "  [{}] T{} write ({}B) @ step {}  →  T{} read ({}B) @ step {}  transfer=0x{:x}+{}B  [{}]",
            i, f.from_thread, f.write_size, f.write_step,
            f.to_thread, f.read_size, f.read_step,
            f.overlap_address, f.overlap_size, sync
        );
    }
}

fn print_producer_consumer(pcs: &[sotrace_engine::analyzer::thread_analyzer::ProducerConsumerPattern]) {
    println!("\n=== Producer-Consumer Patterns ({}) ===", pcs.len());
    for (i, p) in pcs.iter().enumerate() {
        let addrs: Vec<String> = p.shared_addresses.iter().map(|a| format!("0x{:x}", a)).collect();
        // sync_mechanism now carries the primitive kind alongside the address,
        // so the human-readable line reports "0x.. (mutex)" instead of a bare
        // address the reverse engineer would have to cross-reference manually.
        let sync = p
            .sync_mechanism
            .as_ref()
            .map(|m| format!("0x{:x} ({:?})", m.addr, m.kind))
            .unwrap_or_else(|| "none".into());
        println!(
            "  [{}] T{} → T{}  cycles={} avg_latency={}  addrs=[{}]  sync={}",
            i, p.producer_thread, p.consumer_thread, p.cycle_count, p.avg_latency_steps,
            addrs.join(", "), sync
        );
    }
}

fn print_scheduling(stats: &[sotrace_engine::analyzer::thread_analyzer::ThreadSchedulingStats]) {
    println!("\n=== Thread Scheduling ({}) ===", stats.len());
    for (i, s) in stats.iter().enumerate() {
        let cores: Vec<String> = s.cpu_cores.iter().map(|c| c.to_string()).collect();
        println!(
            "  [{}] T{}  in={} out={} (vol={} invol={}) migrations={}  cores=[{}]",
            i, s.thread_id, s.scheduled_in_count, s.scheduled_out_count,
            s.voluntary_switches, s.involuntary_switches, s.migration_count,
            cores.join(", ")
        );
    }
}

fn print_lifecycle(life: &[sotrace_engine::analyzer::thread_analyzer::ThreadLifecycleInfo]) {
    println!("\n=== Thread Lifecycle ({}) ===", life.len());
    for (i, l) in life.iter().enumerate() {
        let indent = "  ".repeat(l.tree_depth as usize);
        let parent = if l.parent_thread_id == 0 {
            "root".to_string()
        } else {
            format!("T{}", l.parent_thread_id)
        };
        let children: Vec<String> = l.child_thread_ids.iter().map(|c| format!("T{}", c)).collect();
        let lifespan = match l.lifespan {
            Some(span) => format!("{} steps", span),
            None if l.is_alive => "alive".to_string(),
            None => "unknown".to_string(),
        };
        println!(
            "  [{}] {}T{} \"{}\"  parent={} depth={} create@{} {} lifespan={}  children=[{}]",
            i, indent, l.thread_id, l.name, parent, l.tree_depth, l.create_step,
            l.exit_step.map(|e| format!("exit@{}", e)).unwrap_or_else(|| "running".to_string()),
            lifespan, children.join(", ")
        );
    }
}

fn print_thread_states(stats: &[sotrace_engine::analyzer::thread_analyzer::ThreadStateStats]) {
    println!("\n=== Thread States ({}) ===", stats.len());
    for (i, s) in stats.iter().enumerate() {
        let states: Vec<String> = s
            .time_in_state
            .iter()
            .map(|(name, steps)| format!("{}={}", name, steps))
            .collect();
        println!(
            "  [{}] T{}  transitions={} measured={} run={} wait={} blocked={:.0}% final={}  [{}]",
            i, s.thread_id, s.transition_count, s.total_measured_steps,
            s.running_steps, s.waiting_steps, s.blocked_ratio * 100.0,
            s.final_state, states.join(", ")
        );
    }
}

fn print_critical_sections(cs: &[sotrace_engine::analyzer::thread_analyzer::CriticalSectionStats]) {
    println!("\n=== Critical Sections ({}) ===", cs.len());
    for (i, c) in cs.iter().enumerate() {
        let holders: Vec<String> = c.holder_threads.iter().map(|t| format!("T{}", t)).collect();
        println!(
            "  [{}] lock=0x{:X} ({:?})  holds={} total={} avg={} max={} (T{} steps {}..{})  holders=[{}]",
            i, c.lock_address.addr, c.lock_address.kind, c.hold_count, c.total_hold_steps, c.avg_hold_steps,
            c.max_hold_steps, c.longest_hold_thread, c.longest_hold_start, c.longest_hold_end,
            holders.join(", ")
        );
    }
}

fn print_jni_boundary(stats: &[sotrace_engine::analyzer::thread_analyzer::JniBoundaryStats]) {
    println!("\n=== JNI Boundary ({}) ===", stats.len());
    for (i, s) in stats.iter().enumerate() {
        // Pair each native address with its resolved function name (if any).
        let addrs: Vec<String> = s.native_addresses.iter().zip(s.native_functions.iter())
            .map(|(a, n)| match n {
                Some(name) if !name.is_empty() => format!("0x{:X}={}", a, name),
                _ => format!("0x{:X}", a),
            })
            .collect();
        println!(
            "  [{}] T{} attached={} crossings={} (j2n={} n2j={})  native=[{}]  java={}",
            i, s.thread_id, s.is_jni_attached, s.total_crossings,
            s.java_to_native_count, s.native_to_java_count,
            addrs.join(", "),
            s.java_methods.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sotrace_core::adapters::TraceAdapter;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const LOCK_ADDR: u64 = 0xABCD_0000;

    /// A fresh empty data directory for tests that exercise the persistence
    /// layer (or just need a data_dir to pass to run_analyze/run_query).
    fn data_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A trace with two threads, a cross-thread memory race, and a contended lock.
    fn write_trace_json(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    const RACE_TRACE: &str = r#"{
        "trace_id": 1, "so_file_id": 0,
        "threads": [
            {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "writer", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "reader", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
        ],
        "instructions": [
            {"seq": 0, "thread_id": 1, "address": 4096, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
            {"seq": 2, "thread_id": 2, "address": 5120, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null}
        ],
        "memory_writes": [
            {"step": 5, "thread_id": 1, "address": 4096, "data": [255, 255, 255, 255]}
        ],
        "memory_reads": [
            {"step": 8, "thread_id": 2, "address": 4096, "size": 4}
        ],
        "sync_events": [
            {"step": 3, "thread_id": 1, "sync_type": "MutexLock", "sync_object_addr": 2882338816, "result": "Success", "wait_duration_ns": null},
            {"step": 6, "thread_id": 2, "sync_type": "MutexLock", "sync_object_addr": 2882338816, "result": "Success", "wait_duration_ns": 1500}
        ],
        "context_switches": [
            {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0}
        ]
    }"#;

    #[test]
    fn test_parse_memory_write() {
        let v: Value = serde_json::from_str(
            r#"{"step": 10, "thread_id": 3, "address": 4096, "data": [1, 2, 3]}"#
        ).unwrap();
        let mw = parse_memory_write(&v).unwrap();
        assert_eq!(mw.step, 10);
        assert_eq!(mw.thread_id, 3);
        assert_eq!(mw.address, 4096);
        assert_eq!(mw.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_parse_memory_write_missing_field() {
        let v: Value = serde_json::from_str(r#"{"step": 10, "thread_id": 3}"#).unwrap();
        assert!(parse_memory_write(&v).is_err());
    }

    #[test]
    fn test_parse_memory_read_defaults_size() {
        let v: Value = serde_json::from_str(
            r#"{"step": 1, "thread_id": 2, "address": 4096}"#
        ).unwrap();
        let (step, tid, addr, size) = parse_memory_read(&v).unwrap();
        assert_eq!((step, tid, addr, size), (1, 2, 4096, 1));
    }

    #[test]
    fn test_analyze_detects_race() {
        let f = write_trace_json(RACE_TRACE);
        // Capture stdout to verify the race appears
        // run_analyze prints to stdout; we just assert it succeeds and the
        // JSON path surfaces the race.
        run_analyze(data_dir().path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, Some(AnalysisDim::Races), None, true).unwrap();
        // Re-run capturing JSON via build_json_output path indirectly is hard;
        // instead verify via the JSON flag by capturing process output.
    }

    #[test]
    fn test_analyze_json_races_nonempty() {
        let f = write_trace_json(RACE_TRACE);
        // Build the engine inline to assert analysis content directly.
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }
        for i in &env.instructions {
            engine.import_instruction(i.clone()).unwrap();
        }
        for w in &env.memory_writes {
            engine.import_memory_write(parse_memory_write(w).unwrap()).unwrap();
        }
        for r in &env.memory_reads {
            let (s, t, a, sz) = parse_memory_read(r).unwrap();
            engine.feed_memory_read(s, t, a, sz);
        }
        for e in &env.sync_events {
            engine.record_sync_event(e.clone()).unwrap();
        }
        let races = engine.detect_race_conditions();
        assert!(!races.is_empty(), "should detect at least one race");
        assert!(races.iter().any(|r| r.address == 4096));
        // #112: sizes + conflict range present
        assert!(races.iter().any(|r| r.overlap_address == 4096 && r.overlap_size > 0));
    }

    #[test]
    fn test_analyze_json_contentions() {
        let f = write_trace_json(RACE_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        for e in &env.sync_events {
            engine.record_sync_event(e.clone()).unwrap();
        }
        let cs = engine.analyze_lock_contention();
        assert!(cs.iter().any(|c| c.lock_address.addr == LOCK_ADDR));
        let contended = cs.iter().find(|c| c.lock_address.addr == LOCK_ADDR).unwrap();
        assert_eq!(contended.acquire_count, 2);
        assert_eq!(contended.contention_count, 1);
    }

    /// A trace with a parent thread and two children; `--only lifecycle` must
    /// surface the spawn tree (children, depth) and liveness through the JSON path.
    #[test]
    fn test_analyze_json_lifecycle() {
        const TREE_TRACE: &str = r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "main", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 1, "create_step": 10, "exit_step": 50, "name": "worker-a", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 3, "pthread_id": null, "parent_thread_id": 1, "create_step": 20, "exit_step": null, "name": "worker-b", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [], "context_switches": []
        }"#;
        let f = write_trace_json(TREE_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }

        let out = build_json_output(&mut engine, Some(AnalysisDim::Lifecycle)).unwrap();
        let life = out.get("lifecycle").unwrap().as_array().unwrap();
        assert_eq!(life.len(), 3);

        // Root thread 1 has both children and depth 0.
        let root = life.iter().find(|l| l["thread_id"] == 1).unwrap();
        assert_eq!(root["parent_thread_id"], 0);
        assert_eq!(root["tree_depth"], 0);
        assert_eq!(root["child_thread_ids"], serde_json::json!([2, 3]));
        assert_eq!(root["is_alive"], true);

        // Worker-a exited: lifespan 40, not alive, depth 1.
        let a = life.iter().find(|l| l["thread_id"] == 2).unwrap();
        assert_eq!(a["lifespan"], 40);
        assert_eq!(a["is_alive"], false);
        assert_eq!(a["tree_depth"], 1);

        // Worker-b still alive: null lifespan.
        let b = life.iter().find(|l| l["thread_id"] == 3).unwrap();
        assert!(b["lifespan"].is_null());
        assert_eq!(b["is_alive"], true);
    }

    /// A trace with per-thread state changes; `--only thread-states` must surface
    /// state residency (running/waiting steps, blocked ratio) via the JSON path,
    /// exercising the full envelope → feed_events → record_thread_state_change →
    /// analyzer wiring that #65 activated.
    #[test]
    fn test_analyze_json_thread_states() {
        const STATE_TRACE: &str = r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": 100, "name": "worker", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [], "context_switches": [],
            "state_changes": [
                {"step": 0, "thread_id": 1, "new_state": "Running", "prev_state": null, "prev_running_thread": null},
                {"step": 30, "thread_id": 1, "new_state": "WaitingForLock", "prev_state": "Running", "prev_running_thread": null},
                {"step": 50, "thread_id": 1, "new_state": "Running", "prev_state": "WaitingForLock", "prev_running_thread": null}
            ]
        }"#;
        let f = write_trace_json(STATE_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let events = envelope_to_events(&env).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        // Register the thread first so the final interval can be bounded by exit.
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }
        feed_events(&mut engine, &events, &mut counts).unwrap();
        assert_eq!(counts.state_changes, 3);

        let out = build_json_output(&mut engine, Some(AnalysisDim::ThreadStates)).unwrap();
        let stats = out.get("state_stats").unwrap().as_array().unwrap();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert_eq!(s["thread_id"], 1);
        assert_eq!(s["transition_count"], 3);
        // Running: 0→30 (30) + 50→100 (50) = 80; WaitingForLock: 30→50 (20).
        assert_eq!(s["running_steps"], 80);
        assert_eq!(s["waiting_steps"], 20);
        assert_eq!(s["total_measured_steps"], 100);
        assert_eq!(s["final_state"], "Running");
        let ratio = s["blocked_ratio"].as_f64().unwrap();
        assert!((ratio - 0.2).abs() < 1e-9);
    }

    /// End-to-end wiring for the critical-section (hold-time) dimension: a lock
    /// acquired then released must surface one hold interval through the CLI JSON
    /// path (`--only critical-sections`).
    #[test]
    fn test_analyze_json_critical_sections() {
        const HOLD_TRACE: &str = r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "worker", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [
                {"step": 10, "thread_id": 1, "sync_type": "MutexLock", "sync_object_addr": 2882338816, "result": "Success", "wait_duration_ns": null},
                {"step": 40, "thread_id": 1, "sync_type": "MutexUnlock", "sync_object_addr": 2882338816, "result": "Success", "wait_duration_ns": null}
            ],
            "context_switches": [], "state_changes": []
        }"#;
        let f = write_trace_json(HOLD_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let events = envelope_to_events(&env).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }
        feed_events(&mut engine, &events, &mut counts).unwrap();

        let out = build_json_output(&mut engine, Some(AnalysisDim::CriticalSections)).unwrap();
        let cs = out.get("critical_sections").unwrap().as_array().unwrap();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c["lock_address"]["addr"], 2882338816u64);
        assert_eq!(c["lock_address"]["kind"], "Mutex");
        assert_eq!(c["hold_count"], 1);
        assert_eq!(c["total_hold_steps"], 30);
        assert_eq!(c["max_hold_steps"], 30);
        assert_eq!(c["longest_hold_thread"], 1);
        assert_eq!(c["longest_hold_start"], 10);
        assert_eq!(c["longest_hold_end"], 40);
    }

    #[test]
    fn test_analyze_json_jni_boundary() {
        const JNI_TRACE: &str = r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "jni-worker", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "native-only", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [], "context_switches": [], "state_changes": [],
            "jni_calls": [
                {"id": 1, "seq": 10, "thread_id": 1, "direction": "JavaToNative", "java_class": "com.app.Foo", "java_method": "doWork", "java_signature": "()V", "native_func_id": null, "native_address": 8192, "jni_env_address": null},
                {"id": 2, "seq": 20, "thread_id": 1, "direction": "NativeToJava", "java_class": "com.app.Bar", "java_method": "callback", "java_signature": "()V", "native_func_id": null, "native_address": 8192, "jni_env_address": null}
            ]
        }"#;
        let f = write_trace_json(JNI_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let events = envelope_to_events(&env).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }
        feed_events(&mut engine, &events, &mut counts).unwrap();
        assert_eq!(counts.jni_calls, 2);

        let out = build_json_output(&mut engine, Some(AnalysisDim::JniBoundary)).unwrap();
        let stats = out.get("jni_boundary").unwrap().as_array().unwrap();
        // Thread 1 has crossings; thread 2 is attached? No — only thread 1.
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert_eq!(s["thread_id"], 1);
        assert_eq!(s["is_jni_attached"], true);
        assert_eq!(s["total_crossings"], 2);
        assert_eq!(s["java_to_native_count"], 1);
        assert_eq!(s["native_to_java_count"], 1);
        assert_eq!(s["native_addresses"], serde_json::json!([8192]));
        assert_eq!(s["java_methods"], serde_json::json!(["com.app.Bar.callback", "com.app.Foo.doWork"]));
    }

    #[test]
    fn test_analyze_missing_file_errors() {
        let result = run_analyze(data_dir().path(), Some(PathBuf::from("/tmp/does_not_exist_xyz.json")), None, 0, TraceFormat::Native, 0, None, None, false);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("failed to read trace file"));
    }

    #[test]
    fn test_analyze_invalid_json_errors() {
        let f = write_trace_json(r#"{ this is not valid json"#);
        let result = run_analyze(data_dir().path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None, None, false);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("failed to parse trace JSON"));
    }

    #[test]
    fn test_envelope_default_fields() {
        // An envelope with only trace_id should parse (all event arrays default to empty).
        let f = write_trace_json(r#"{"trace_id": 7}"#);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        assert_eq!(env.trace_id, Some(7));
        assert!(env.threads.is_empty());
        assert!(env.instructions.is_empty());
        assert!(env.sync_events.is_empty());
    }

    #[test]
    fn test_instructions_sorted_by_seq() {
        // Instructions provided out of order should still import (sorted internally).
        let json = r#"{
            "trace_id": 1,
            "instructions": [
                {"seq": 5, "thread_id": 1, "address": 5000, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 1, "thread_id": 1, "address": 1000, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 3, "thread_id": 1, "address": 3000, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null}
            ]
        }"#;
        let f = write_trace_json(json);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        // run_analyze sorts before import; replicate that here.
        let mut instrs = env.instructions.clone();
        instrs.sort_by_key(|t| t.seq);
        for i in &instrs {
            engine.import_instruction(i.clone()).unwrap();
        }
        let range = engine.query_instructions_range(0, u64::MAX);
        let seqs: Vec<u64> = range.iter().map(|t| t.seq).collect();
        assert_eq!(seqs, vec![1, 3, 5]);
    }

    /// A Frida Stalker trace with an SO base address and a cross-thread race.
    const FRIDA_STALKER_TRACE: &str = r#"{"type":"inst","tid":100,"pc":"0x7fff1000"}
{"type":"inst","tid":100,"pc":"0x7fff1004","is_branch":true,"branch_taken":true}
{"type":"memwrite","tid":100,"address":"0x7fff1000","data":[255,255,255,255]}
{"type":"inst","tid":200,"pc":"0x7fff2000"}
{"type":"memread","tid":200,"address":"0x7fff1000","size":4}
{"type":"sync","tid":100,"sync_type":"MutexLock","sync_object_addr":"0xABCD0000","result":"Success"}
{"type":"sync","tid":200,"sync_type":"MutexLock","sync_object_addr":"0xABCD0000","result":"Success","wait_duration_ns":1500}"#;

    #[test]
    fn test_analyze_frida_stalker_format() {
        let dd = data_dir();
        let f = write_trace_json(FRIDA_STALKER_TRACE);
        // base_addr converts 0x7fff1000 → 0x1000
        let result = run_analyze(
            dd.path(),
            Some(f.path().to_path_buf()),
            None,
            0,
            TraceFormat::FridaStalker,
            0x7fff0000,
            Some(AnalysisDim::Races),
            None,
            true,
        );
        // Capture stdout to inspect the JSON race output.
        // run_analyze prints to stdout; we verify via direct engine feed instead.
        assert!(result.is_ok());

        // Direct verification: adapter + feed_events + detect_races
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let adapter = sotrace_core::adapters::frida::FridaAdapter::new();
        let (events, _) = adapter.parse("stalker", &raw, 0x7fff0000).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        feed_events(&mut engine, &events, &mut counts).unwrap();
        assert!(counts.instructions >= 3);
        assert!(counts.memory_writes >= 1);
        assert!(counts.memory_reads >= 1);
        assert!(counts.sync_events >= 2);
        let races = engine.detect_race_conditions();
        assert!(!races.is_empty(), "should detect the cross-thread race");
        // The race address should be the SO-relative offset 0x1000
        assert!(races.iter().any(|r| r.address == 0x1000));
        // #112: sizes + conflict range present
        assert!(races.iter().any(|r| r.overlap_address == 0x1000 && r.overlap_size > 0));
    }

    #[test]
    fn test_analyze_frida_stalker_contentions() {
        let f = write_trace_json(FRIDA_STALKER_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let adapter = sotrace_core::adapters::frida::FridaAdapter::new();
        let (events, _) = adapter.parse("stalker", &raw, 0x7fff0000).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        feed_events(&mut engine, &events, &mut counts).unwrap();
        let cs = engine.analyze_lock_contention();
        assert!(cs.iter().any(|c| c.lock_address.addr == 0xABCD_0000));
    }

    #[test]
    fn test_analyze_jnitrace_format() {
        let trace = r#"{"type":"async","payload":[{"tid":300,"type":"J2N","class":"com.example.Crypto","method":"decrypt","signature":"([B)[B","address":"0x4000","env":"0x7f00"}]}"#;
        let f = write_trace_json(trace);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let adapter = sotrace_core::adapters::frida::FridaAdapter::new();
        let (events, stats) = adapter.parse("jnitrace", &raw, 0).unwrap();
        assert_eq!(stats.jni_calls, 1);
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        feed_events(&mut engine, &events, &mut counts).unwrap();
        assert_eq!(counts.jni_calls, 1);
    }

    #[test]
    fn test_trace_format_adapter_mapping() {
        assert_eq!(TraceFormat::Native.adapter(), None);
        assert_eq!(TraceFormat::FridaStalker.adapter(), Some(("frida", "stalker")));
        assert_eq!(TraceFormat::FridaInterceptor.adapter(), Some(("frida", "interceptor")));
        assert_eq!(TraceFormat::Jnitrace.adapter(), Some(("frida", "jnitrace")));
        assert_eq!(TraceFormat::DrCachesim.adapter(), Some(("dynamorio", "drcachesim")));
        assert_eq!(TraceFormat::DrMemtrace.adapter(), Some(("dynamorio", "memtrace")));
        assert_eq!(TraceFormat::Pinatrace.adapter(), Some(("pin", "pinatrace")));
    }

    #[test]
    fn test_hex_encoding() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00]), "00");
        assert_eq!(hex(&[0xff, 0x10, 0xab]), "ff10ab");
    }

    #[test]
    fn test_parse_addr_arg_decimal() {
        assert_eq!(parse_addr_arg("4096").unwrap(), 4096);
    }

    #[test]
    fn test_parse_addr_arg_hex() {
        assert_eq!(parse_addr_arg("0x7fff0000").unwrap(), 0x7fff0000);
        assert_eq!(parse_addr_arg("0XABCD").unwrap(), 0xABCD);
    }

    #[test]
    fn test_parse_addr_arg_invalid() {
        assert!(parse_addr_arg("not a number").is_err());
    }

    // --- query command tests ---

    /// load_engine + the engine query APIs that `run_query` wraps should
    /// surface the race trace's threads, sync events, and reconstructed memory.
    #[test]
    fn test_query_threads_and_sync() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        // Two threads registered.
        let mut ids = engine.all_thread_ids();
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
        // Each has stats.
        assert_eq!(engine.all_thread_stats().len(), 2);
        // Thread 1's sync events include the MutexLock at step 3.
        let sync = engine.query_thread_sync_events(1, 0, u64::MAX);
        assert_eq!(sync.len(), 1);
        assert_eq!(sync[0].step, 3);
        assert!(matches!(
            sync[0].sync_type,
            sotrace_core::models::thread::SyncEventType::MutexLock
        ));
    }

    /// The `jni-calls` subcommand exposes the AddressIndex that import has been
    /// maintaining: look up JNI boundary calls by native function address, with
    /// an optional step range. Previously the index existed but no query path
    /// surfaced it (the #95 pattern, JNI-side).
    #[test]
    fn test_query_jni_calls_by_address_subcommand() {
        let dd = data_dir();
        // Two JNI calls reach native_address 0x2000 (seq 10 and 20); a third
        // reaches 0x3000 at the SAME seq 10 as the first — must not leak into
        // the 0x2000 query.
        let f = write_trace_json(r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": null, "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": null, "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [], "context_switches": [], "state_changes": [],
            "jni_calls": [
                {"id": 1, "seq": 10, "thread_id": 1, "direction": "JavaToNative", "java_class": "com.app.Foo", "java_method": "doWork", "java_signature": "()V", "native_func_id": null, "native_address": 8192, "jni_env_address": null},
                {"id": 2, "seq": 10, "thread_id": 2, "direction": "JavaToNative", "java_class": "com.app.Bar", "java_method": "other", "java_signature": "()V", "native_func_id": null, "native_address": 12288, "jni_env_address": null},
                {"id": 3, "seq": 20, "thread_id": 1, "direction": "NativeToJava", "java_class": "com.app.Bar", "java_method": "callback", "java_signature": "()V", "native_func_id": null, "native_address": 8192, "jni_env_address": null}
            ]
        }"#);
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();

        // 0x2000 = 8192: two calls (seq 10 + 20), the 0x3000 sibling at seq 10
        // is filtered out despite sharing the step.
        let calls = engine.query_jni_calls_by_address(8192, 0, u64::MAX);
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|c| c.native_address == 8192));
        assert_eq!(calls[0].seq, 10);
        assert_eq!(calls[1].seq, 20);

        // Range [0,15] keeps only the seq-10 call.
        let early = engine.query_jni_calls_by_address(8192, 0, 15);
        assert_eq!(early.len(), 1);
        assert_eq!(early[0].java_method, "doWork");

        // The 0x3000 sibling is reachable via its own address.
        let other = engine.query_jni_calls_by_address(12288, 0, u64::MAX);
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].thread_id, 2);

        // The subcommand path also succeeds end to end.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::JniCalls { address: 8192, start: 0, end: u64::MAX },
        ).unwrap();
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::JniCalls { address: 8192, start: 0, end: 15 },
        ).unwrap();
    }

    /// `query_threads_at_address` returns (thread_id, step) pairs — the step at
    /// which each thread executed the address, NOT an access count. The
    /// `Address` subcommand renders these pairs; this test pins the (thread,
    /// step) contract so the CLI field name (`step`) stays honest. Two threads
    /// sharing one `seq` at the same address must both survive (regression for
    /// the field-mislabel fix — previously the step was emitted as `count`).
    #[test]
    fn test_query_threads_at_address_returns_step_not_count() {
        let dd = data_dir();
        // Two threads both execute address 0x1000 at seq 7 (shared seq), plus
        // thread 1 hits it again at seq 9.
        let f = write_trace_json(
            r#"{
                "threads": [
                    {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": null, "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                    {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": null, "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
                ],
                "instructions": [
                    {"seq": 7, "thread_id": 1, "address": 4096, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
                    {"seq": 7, "thread_id": 2, "address": 4096, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
                    {"seq": 9, "thread_id": 1, "address": 4096, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null}
                ]
            }"#,
        );
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        let accesses = engine.query_threads_at_address(4096);
        // Both threads at the shared seq survive, plus thread 1's later hit.
        assert_eq!(accesses.len(), 3);
        // Each entry carries the real step, not a count. Sort to make the
        // assertion order-independent (EventLog preserves insertion order
        // within a step, but we don't want the test coupled to thread write
        // order).
        let mut sorted = accesses.clone();
        sorted.sort();
        // Two (thread, step) pairs at seq 7 — threads 1 and 2 — plus thread 1
        // at seq 9. Tuple sort is lexicographic so (1,7) < (1,9) < (2,7). If
        // `step` were a count, seq-7 entries would read 2 instead of 7.
        assert_eq!(sorted, vec![(1, 7), (1, 9), (2, 7)]);
        // The subcommand renders successfully and (via the contract above) now
        // emits `step` rather than the old mislabeled `count`.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::Address { address: 4096 },
        ).unwrap();
    }

    /// query_memory_value reconstructs the written bytes at the write step.
    #[test]
    fn test_query_memory_reconstruction() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        // step 5 wrote [255,255,255,255] at address 4096.
        let res = engine.query_memory_value(4096, 4, 5).expect("value reconstructed");
        assert_eq!(res.value, vec![255, 255, 255, 255]);
        assert!(res.deltas_applied >= 1);
    }

    /// query_lock_contentions returns both lock acquisitions for the shared lock.
    #[test]
    fn test_query_lock_contentions() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        let events = engine.query_lock_contentions(2882338816, 0, u64::MAX);
        assert_eq!(events.len(), 2);
        let mut steps: Vec<u64> = events.iter().map(|e| e.step).collect();
        steps.sort();
        assert_eq!(steps, vec![3, 6]);
    }

    /// A native trace envelope carrying `register_deltas` feeds through
    /// `envelope_to_events` -> `TraceEvent::Register` -> engine, and the
    /// reconstructed value is queryable per register / per step.
    #[test]
    fn test_query_register_from_native_envelope() {
        let dd = data_dir();
        // x0 = 0x1000 at seq 5; then x0 = 0x2000 and x2 = 0x12345678 at seq 10.
        let f = write_trace_json(
            r#"{
                "register_deltas": [
                    {"seq": 5, "change_mask": 1, "values": [4096]},
                    {"seq": 10, "change_mask": 5, "values": [8192, 305419896]}
                ]
            }"#,
        );
        let (engine, imported, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        assert_eq!(imported.register_deltas, 2);
        // Before any delta the register is unknown.
        assert_eq!(engine.query_register(0, 3), None);
        // The first value holds until the next delta.
        assert_eq!(engine.query_register(0, 7), Some(0x1000));
        // The second delta updates x0 and sets x2 (bit-order value extraction).
        assert_eq!(engine.query_register(0, 12), Some(0x2000));
        assert_eq!(engine.query_register(2, 12), Some(0x12345678));

        // The full register file reconstructs the same values in one snapshot.
        let state = engine.reconstruct_register_state(12).expect("state reconstructed");
        assert_eq!(state.gp_regs[0], 0x2000);
        assert_eq!(state.gp_regs[2], 0x12345678);
        assert_eq!(state.gp_regs[1], 0); // never written

        // Both subcommand paths also succeed end to end.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::Register { register_id: 0, step: 7 },
        ).unwrap();
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::RegisterState { step: 12 },
        ).unwrap();
    }

    /// Two register deltas sharing the same `seq` must both survive ingestion
    /// through the native envelope path (`envelope_to_events` ->
    /// `TraceEvent::Register` -> `feed_events` -> engine) and resolve with
    /// last-writer-wins semantics — the same contract verified at the store
    /// layer in `register_store::tests`. This guards the end-to-end CLI path
    /// against a regression that would silently drop same-step deltas.
    #[test]
    fn test_query_register_same_seq_last_wins_native() {
        let dd = data_dir();
        let f = write_trace_json(
            r#"{
                "register_deltas": [
                    {"seq": 5, "change_mask": 1, "values": [170]},
                    {"seq": 5, "change_mask": 1, "values": [187]}
                ]
            }"#,
        );
        let (engine, imported, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        assert_eq!(imported.register_deltas, 2);
        // Both deltas landed; the second (0xBB) wins over the first (0xAA).
        assert_eq!(engine.query_register(0, 5), Some(0xBB));
        assert_eq!(engine.query_register(0, 6), Some(0xBB));
        // Before step 5 the register is still unknown.
        assert_eq!(engine.query_register(0, 4), None);

        // The full register file agrees with the point query.
        let state = engine.reconstruct_register_state(5).expect("state reconstructed");
        assert_eq!(state.gp_regs[0], 0xBB);

        // The `register` subcommand surfaces the same last-wins value.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::Register { register_id: 0, step: 5 },
        ).unwrap();
    }

    /// The `register-history` subcommand lists the steps at which a register
    /// changed. Exposes the per-register index that `register` uses for its
    /// single-point lookup — the list query was previously unreachable.
    #[test]
    fn test_query_register_history_subcommand() {
        let dd = data_dir();
        // x0 changes at seq 5 and 10; x2 only at seq 10.
        let f = write_trace_json(
            r#"{
                "register_deltas": [
                    {"seq": 5, "change_mask": 1, "values": [4096]},
                    {"seq": 10, "change_mask": 5, "values": [8192, 305419896]}
                ]
            }"#,
        );
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        // x0 changed at 5 and 10.
        assert_eq!(engine.query_register_history(0, 0, u64::MAX), vec![5, 10]);
        // x2 changed only at 10.
        assert_eq!(engine.query_register_history(2, 0, u64::MAX), vec![10]);
        // x1 never.
        assert!(engine.query_register_history(1, 0, u64::MAX).is_empty());
        // Range filter.
        assert_eq!(engine.query_register_history(0, 6, u64::MAX), vec![10]);
        // Out-of-range register_id → empty.
        assert!(engine.query_register_history(999, 0, u64::MAX).is_empty());

        // The subcommand path also succeeds end to end.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::RegisterHistory { register_id: 0, start: 0, end: u64::MAX },
        ).unwrap();
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::RegisterHistory { register_id: 0, start: 6, end: u64::MAX },
        ).unwrap();
    }

    /// A native envelope carrying `calls` feeds through `envelope_to_events`
    /// -> `TraceEvent::Call` -> engine, and the live call stack is
    /// reconstructable per thread / per step.
    #[test]
    fn test_callstack_from_native_envelope() {
        let dd = data_dir();
        // f(0x1000) calls g(0x2000); g returns at seq 3.
        let f = write_trace_json(
            r#"{
                "calls": [
                    {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 4080, "callee_address": 4096, "callee_func_id": 100, "seq": 1, "depth": 0, "return_seq": null},
                    {"id": 2, "thread_id": 1, "event_type": "Call", "caller_address": 4112, "callee_address": 8192, "callee_func_id": 200, "seq": 2, "depth": 1, "return_seq": null},
                    {"id": 3, "thread_id": 1, "event_type": "Return", "caller_address": 0, "callee_address": 0, "callee_func_id": null, "seq": 3, "depth": 1, "return_seq": null}
                ]
            }"#,
        );
        let (engine, imported, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        assert_eq!(imported.calls, 3);

        // At step 2 both frames are live, outermost first.
        let at2 = engine.rebuild_call_stack(1, 2);
        assert_eq!(at2.len(), 2);
        assert_eq!(at2[0].entry_address, 4096);
        assert_eq!(at2[1].entry_address, 8192);

        // After g returns (step 3) only f remains.
        let at3 = engine.rebuild_call_stack(1, 3);
        assert_eq!(at3.len(), 1);
        assert_eq!(at3[0].entry_address, 4096);

        // The `call-stack` subcommand path also succeeds end to end.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::CallStack { thread_id: 1, step: 2 },
        ).unwrap();
    }

    /// run_query for each subcommand should succeed (Ok) on the race trace.
    #[test]
    fn test_run_query_all_subcommands_succeed() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        let path = f.path().to_path_buf();
        let d = dd.path();
        // Threads
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Threads).unwrap();
        // Thread { id }
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Thread { thread_id: 1 }).unwrap();
        // Timeline
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Timeline {
            thread_id: 1, start: 0, end: 100,
        }).unwrap();
        // Instruction
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Instruction { step: 0 }).unwrap();
        // Instructions range
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Instructions {
            start: 0, end: 10,
        }).unwrap();
        // Address
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Address { address: 4096 }).unwrap();
        // Memory
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Memory {
            address: 4096, step: 5, size: 4,
        }).unwrap();
        // Sync
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Sync {
            thread_id: 1, start: 0, end: u64::MAX,
        }).unwrap();
        // Lock
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Lock {
            address: 2882338816, start: 0, end: u64::MAX,
        }).unwrap();
        // Switches
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Switches {
            start: 0, end: u64::MAX,
        }).unwrap();
        // Register (no register deltas in this trace — should still succeed with null)
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Register {
            register_id: 0, step: 5,
        }).unwrap();
        // RegisterState (no register deltas — should still succeed with null state)
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::RegisterState {
            step: 5,
        }).unwrap();
        // RegisterHistory (no register deltas — should still succeed with empty)
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::RegisterHistory {
            register_id: 0, start: 0, end: u64::MAX,
        }).unwrap();
        // CallStack (no calls in this trace — should still succeed with empty stack)
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::CallStack {
            thread_id: 1, step: 5,
        }).unwrap();
        // JniCalls (no jni_calls in this trace — should still succeed with empty)
        run_query(d, Some(path), None, 0, TraceFormat::Native, 0, None, QueryCmd::JniCalls {
            address: 4096, start: 0, end: u64::MAX,
        }).unwrap();
    }

    /// run_query surfaces a read error for a missing file.
    #[test]
    fn test_run_query_missing_file_errors() {
        let result = run_query(
            data_dir().path(),
            Some(PathBuf::from("/tmp/does_not_exist_xyz_query.json")),
            None, 0, TraceFormat::Native, 0, None, QueryCmd::Threads,
        );
        assert!(result.is_err());
    }

    // --- trace persistence CLI ---

    use sotrace_engine::persistence::{PersistedTrace, TraceRepository};

    /// Build a minimal PersistedTrace from RACE_TRACE's threads so load_engine
    /// can replay it. Uses the same event shape `envelope_to_events` produces.
    fn save_race_trace(data_dir: &Path) -> u64 {
        let f = write_trace_json(RACE_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let envelope: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let events = envelope_to_events(&envelope).unwrap();
        let trace = PersistedTrace {
            trace_id: 0,
            so_file_id: 0,
            source: "native".into(),
            base_addr: 0,
            events,
            created_at: 1_700_000_000,
        };
        let repo = TraceRepository::open(data_dir).unwrap();
        repo.save(trace).unwrap()
    }

    /// trace-save (via run_trace_save) persists the trace to disk.
    #[test]
    fn test_run_trace_save_persists() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        // quiet load inside run_trace_save; prints trace_id to stdout.
        let result = run_trace_save(
            dd.path(), f.path().to_path_buf(), 0, TraceFormat::Native, 0, None, 1_700_000_000,
        );
        assert!(result.is_ok(), "trace-save failed: {:?}", result.err());
        // Exactly one trace should now be persisted.
        let repo = TraceRepository::open(dd.path()).unwrap();
        let list = repo.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].source, "native");
        assert!(list[0].event_count > 0);
    }

    /// trace-list / trace-show / trace-delete run without error.
    #[test]
    fn test_run_trace_list_show_delete() {
        let dd = data_dir();
        let id = save_race_trace(dd.path());
        assert!(run_trace_list(dd.path()).is_ok());
        assert!(run_trace_show(dd.path(), id).is_ok());
        assert!(run_trace_delete(dd.path(), id).is_ok());
        // After delete, list is empty.
        let repo = TraceRepository::open(dd.path()).unwrap();
        assert!(repo.list().unwrap().is_empty());
    }

    /// Replaying a persisted trace via --trace-id yields the same thread set
    /// as parsing the source file directly.
    #[test]
    fn test_trace_id_replay_matches_file_parse() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);

        // Direct file parse.
        let (engine_file, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0,
            TraceFormat::Native, 0, &None, true,
        ).unwrap();
        let mut from_file: Vec<u32> = engine_file.all_thread_ids();
        from_file.sort();

        // Persist then replay by id.
        let id = save_race_trace(dd.path());
        let (engine_replay, _, _) = load_engine(
            dd.path(), None, Some(id), 0,
            TraceFormat::Native, 0, &None, true,
        ).unwrap();
        let mut from_replay: Vec<u32> = engine_replay.all_thread_ids();
        from_replay.sort();

        assert_eq!(from_file, from_replay, "replayed trace must match file-parsed thread set");
        // Replay should also preserve sync events for the thread.
        assert!(engine_replay.query_thread_sync_events(from_replay[0], 0, u64::MAX).len()
            == engine_file.query_thread_sync_events(from_file[0], 0, u64::MAX).len());
    }

    /// trace_id pointing at a non-existent id errors.
    #[test]
    fn test_trace_id_missing_errors() {
        let dd = data_dir();
        let result = load_engine(
            dd.path(), None, Some(9999), 0,
            TraceFormat::Native, 0, &None, true,
        );
        assert!(result.is_err());
    }
}
