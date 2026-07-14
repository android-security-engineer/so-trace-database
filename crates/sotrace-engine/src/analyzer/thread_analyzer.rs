//! Thread analyzer — comprehensive thread analysis for Android SO reverse engineering
//!
//! This is the primary analysis module for SO security analysis. It combines
//! data from ThreadStore, MemoryStore, CallStore, and InstructionStore to
//! detect patterns critical for understanding multi-threaded SO behavior.
//!
//! # Key Analysis Capabilities
//!
//! ## 1. Race Condition Detection
//!
//! Detects when two threads access the same memory location without proper
//! synchronization. This is the #1 vulnerability pattern in Android SO:
//!
//! ```text
//! Thread A: write(addr=0x1000, step=100)  ─┐
//!                                            ├─ NO SYNC ─→ RACE CONDITION!
//! Thread B: read(addr=0x1000, step=150)   ─┘
//! ```
//!
//! Algorithm:
//! 1. For each memory write, record (address, step, thread_id)
//! 2. For each memory read, check if another thread wrote to the same
//!    page between the last sync event and this read
//! 3. If no sync event separates the write and read → potential race
//!
//! ## 2. Deadlock Detection
//!
//! Detects lock ordering violations that can lead to deadlocks:
//!
//! ```text
//! Thread A: lock(M1) → lock(M2)    (order: M1 → M2)
//! Thread B: lock(M2) → lock(M1)    (order: M2 → M1) ← VIOLATION!
//! ```
//!
//! Algorithm:
//! 1. Build a lock graph: for each thread, record lock acquisition order
//! 2. Check for cycles in the lock graph
//! 3. Any cycle = potential deadlock
//!
//! ## 3. Lock Contention Analysis
//!
//! Identifies hot locks and measures contention:
//! - Which locks have the most waiters?
//! - What's the average wait time per lock?
//! - Which threads contend most?
//!
//! ## 4. Thread-Function Association
//!
//! Maps which threads called which functions:
//! - Per-thread call frequency
//! - Thread safety classification (thread-safe vs thread-unsafe)
//! - JNI boundary mapping (which Java threads call which native functions)

use std::collections::{HashMap, HashSet, BTreeMap};
use serde::{Serialize, Deserialize};
use sotrace_core::models::thread::{
    ThreadInfo, ThreadSyncEvent, SyncEventType, SyncResult,
    ContextSwitch, SwitchReason, ThreadStateChange, ThreadState,
    SyncPrimitiveKind,
};
use sotrace_core::models::jni_call::{JNICall, JNICallDirection};

// ============================================================================
// Analysis result types
// ============================================================================

/// A detected race condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaceCondition {
    /// Memory address where the race occurred (page-aligned base of the first
    /// access). Kept for backwards compatibility; the *precise* conflict region
    /// is in `overlap_address`/`overlap_size`.
    pub address: u64,
    /// Step of the first access (write)
    pub first_step: u64,
    /// Thread that performed the first access
    pub first_thread: u32,
    /// Step of the second access (read or write)
    pub second_step: u64,
    /// Thread that performed the second access
    pub second_thread: u32,
    /// Whether the first access was a write
    pub first_is_write: bool,
    /// Whether the second access was a write
    pub second_is_write: bool,
    /// Byte size of the first access (1, 2, 4, 8, …). Lets the RE judge whether
    /// the conflict is a single field or an entire struct.
    pub first_access_size: u64,
    /// Byte size of the second access.
    pub second_access_size: u64,
    /// Start address of the *actual* overlapping byte range between the two
    /// accesses (the intersection of `[a, a+a_size)` and `[b, b+b_size)`). This
    /// is the precise set of contended bytes — not page-aligned, not an
    /// approximation. Saturating arithmetic keeps it safe near `u64::MAX`.
    pub overlap_address: u64,
    /// Length in bytes of the overlapping range (`overlap_size` bytes starting
    /// at `overlap_address`). Zero only if the two accesses are degenerate.
    pub overlap_size: u64,
    /// Confidence level (0.0-1.0)
    pub confidence: f64,
    /// Description of the race condition
    pub description: String,
}

/// A detected potential deadlock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlockRisk {
    /// Locks involved in the cycle (in order), each typed with its primitive kind
    pub lock_cycle: Vec<SyncMechanism>,
    /// Threads involved in the deadlock
    pub threads: Vec<u32>,
    /// Steps where the lock ordering violation occurred
    pub violation_steps: Vec<u64>,
    /// Description of the deadlock pattern
    pub description: String,
}

/// Lock contention analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockContentionInfo {
    /// Lock/mutex address, typed with its primitive kind
    pub lock_address: SyncMechanism,
    /// Total number of acquisitions
    pub acquire_count: u64,
    /// Number of contended acquisitions (had to wait)
    pub contention_count: u64,
    /// Contention ratio (0.0-1.0)
    pub contention_ratio: f64,
    /// Total wait time in nanoseconds
    pub total_wait_ns: u64,
    /// Average wait time in nanoseconds
    pub avg_wait_ns: u64,
    /// Maximum wait time in nanoseconds
    pub max_wait_ns: u64,
    /// Threads that contended on this lock
    pub contending_threads: Vec<u32>,
}

/// Thread-function association
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadFunctionAssoc {
    /// Thread ID
    pub thread_id: u32,
    /// Function address
    pub function_address: u64,
    /// Function name (filled by the engine from ELF symbols, if known)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub function_name: Option<String>,
    /// Number of times this thread called this function
    pub call_count: u64,
    /// First call step
    pub first_call_step: u64,
    /// Last call step
    pub last_call_step: u64,
}

/// Thread safety classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadSafety {
    /// Function is thread-safe (properly synchronized)
    ThreadSafe,
    /// Function may not be thread-safe (no synchronization observed)
    PotentiallyUnsafe,
    /// Function is definitely not thread-safe (race condition detected)
    Unsafe,
    /// Unknown (not enough data)
    Unknown,
}

/// Function thread safety info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionThreadSafety {
    /// Function address
    pub function_address: u64,
    /// Function name (filled by the engine from ELF symbols, if known)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub function_name: Option<String>,
    /// Number of threads that called this function
    pub calling_thread_count: u32,
    /// Thread IDs that called this function
    pub calling_threads: Vec<u32>,
    /// Safety classification
    pub safety: ThreadSafety,
    /// Number of detected race conditions involving this function
    pub race_count: u32,
    /// Number of sync events within this function
    pub sync_event_count: u64,
}

/// Data flow between threads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadDataFlow {
    /// Source thread (writer)
    pub from_thread: u32,
    /// Destination thread (reader)
    pub to_thread: u32,
    /// Memory address of the data transfer
    pub address: u64,
    /// Step when the write occurred
    pub write_step: u64,
    /// Step when the read occurred
    pub read_step: u64,
    /// Whether there was proper synchronization between write and read
    pub is_synchronized: bool,
}

/// A synchronization mechanism identified by both its address AND its
/// primitive kind. Richer than a bare `u64` address: when the analyzer reports
/// the mechanism coordinating a producer-consumer pair, it now says *what*
/// primitive lives at that address (mutex / rwlock / semaphore / futex /
/// condvar / barrier), derived from the `SyncEventType` of operations seen on
/// it during `build_indexes`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncMechanism {
    /// Address of the synchronization object (mutex, futex word, condvar, etc.)
    pub addr: u64,
    /// Primitive kind, derived from the SyncEventType observed on this address
    pub kind: SyncPrimitiveKind,
}

/// Producer-consumer pattern detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducerConsumerPattern {
    /// Producer thread
    pub producer_thread: u32,
    /// Consumer thread
    pub consumer_thread: u32,
    /// Shared memory addresses used for communication
    pub shared_addresses: Vec<u64>,
    /// Number of produce-consume cycles detected
    pub cycle_count: u64,
    /// Average time between produce and consume (in steps)
    pub avg_latency_steps: u64,
    /// Synchronization mechanism used (typed: address + primitive kind), or
    /// `None` if no sync object was shared between the two threads.
    pub sync_mechanism: Option<SyncMechanism>,
}

/// Per-thread scheduling / context-switch statistics.
///
/// Derived from the context-switch stream. A reverse engineer uses these to see
/// how a thread was scheduled: whether it mostly yielded/blocked (cooperative)
/// or was preempted (contended for CPU), and how many cores it bounced across.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSchedulingStats {
    /// Thread ID
    pub thread_id: u32,
    /// Times this thread was scheduled onto a CPU (`to_thread == tid`)
    pub scheduled_in_count: u64,
    /// Times this thread was scheduled off a CPU (`from_thread == tid`)
    pub scheduled_out_count: u64,
    /// Switch-outs where the thread gave up the CPU willingly (Yield / Blocking)
    pub voluntary_switches: u64,
    /// Switch-outs forced by the scheduler (Preemption / TimeSliceExpired / Interrupt)
    pub involuntary_switches: u64,
    /// Number of migration events that scheduled this thread onto a core
    pub migration_count: u64,
    /// Distinct CPU cores this thread ran on (sorted; empty if cores unknown)
    pub cpu_cores: Vec<u32>,
}

/// Per-thread lifecycle / spawn-tree information.
///
/// Derived purely from the `ThreadInfo` metadata (parent, create/exit steps),
/// which the engine captures but no analysis surfaced before. A reverse engineer
/// uses this to see the thread topology of an SO: which thread spawned which,
/// how long each lived, and which threads never exited (potential leaks or
/// long-running workers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadLifecycleInfo {
    /// Thread ID
    pub thread_id: u32,
    /// Parent thread ID (0 = no parent / root, by convention)
    pub parent_thread_id: u32,
    /// Threads directly spawned by this thread (sorted, ascending)
    pub child_thread_ids: Vec<u32>,
    /// Step at which the thread was created
    pub create_step: u64,
    /// Step at which the thread exited, or `None` if it never exited in the trace
    pub exit_step: Option<u64>,
    /// Lifespan in steps (`exit_step - create_step`), or `None` if still alive or
    /// if the trace is malformed (exit before create)
    pub lifespan: Option<u64>,
    /// Whether the thread was still alive at the end of the trace (no exit event)
    pub is_alive: bool,
    /// Depth in the spawn tree: 0 for roots, +1 per ancestor present in the trace
    pub tree_depth: u32,
    /// Human-readable thread name
    pub name: String,
}

/// Per-thread state residency / transition statistics.
///
/// Derived from the `ThreadStateChange` stream (Running / Runnable / Blocked /
/// WaitingForLock / … / Terminated) that the engine captures but no analysis
/// surfaced before. A reverse engineer uses this to see where a thread spends
/// its time: a thread stuck mostly in `WaitingForLock` points at contention, one
/// mostly `WaitingForIO` at an I/O bottleneck, one mostly `Running` at CPU work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadStateStats {
    /// Thread ID
    pub thread_id: u32,
    /// Number of state transitions recorded for this thread
    pub transition_count: u64,
    /// Accumulated steps spent in each state, `(state_name, steps)`, sorted by
    /// state name. Only intervals bounded by a following change (or the thread's
    /// exit) contribute; an unbounded trailing state contributes nothing.
    pub time_in_state: Vec<(String, u64)>,
    /// Steps spent Running
    pub running_steps: u64,
    /// Steps spent in any waiting/blocked state (see `ThreadState::is_waiting`)
    pub waiting_steps: u64,
    /// Total measured steps across all states (sum of `time_in_state` values)
    pub total_measured_steps: u64,
    /// Fraction of measured time spent waiting/blocked, in `[0.0, 1.0]`
    /// (0.0 when nothing was measured)
    pub blocked_ratio: f64,
    /// The thread's final recorded state (highest-step change), or empty if none
    pub final_state: String,
}

/// Per-lock critical-section / hold-time statistics.
///
/// Contention analysis ([`LockContentionInfo`]) answers "how long did threads
/// *wait* for this lock"; this answers the root cause — "how long did a thread
/// *hold* it once acquired". A hold interval spans a thread's outermost
/// successful acquire to its matching release (recursive re-acquires nest and do
/// not open a new interval, mirroring [`ThreadAnalyzer::is_lock_held_at`]). A
/// long critical section is what forces the waits contention measures; a reverse
/// engineer uses this to find the lock whose held region dominates and should be
/// shortened. An acquire never released within the trace is unbounded and
/// contributes nothing (same principle as trailing thread states in #65).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalSectionStats {
    /// Lock/mutex address, typed with its primitive kind
    pub lock_address: SyncMechanism,
    /// Number of completed hold intervals (acquire matched by a release)
    pub hold_count: u64,
    /// Total steps the lock was held, summed across all completed intervals
    pub total_hold_steps: u64,
    /// Average hold length in steps (`total_hold_steps / hold_count`, 0 if none)
    pub avg_hold_steps: u64,
    /// Longest single hold interval, in steps
    pub max_hold_steps: u64,
    /// Thread that held the lock for `max_hold_steps`
    pub longest_hold_thread: u32,
    /// Acquire step of the longest hold interval
    pub longest_hold_start: u64,
    /// Release step of the longest hold interval
    pub longest_hold_end: u64,
    /// Threads that completed at least one hold of this lock (sorted)
    pub holder_threads: Vec<u32>,
}

/// Per-thread JNI boundary-crossing statistics (#67).
///
/// Android SO reverse-engineering revolves around the Java/Native boundary:
/// which threads cross it, in which direction, and which native functions are
/// reached from Java. `JNICall` records are captured by the ingest chain and
/// written to the JNI store, but until #67 no analysis dimension read them —
/// the same dead-storage pattern as scheduling (#59) and state residency (#65).
/// This activates them into a per-thread crossing profile, correlated with the
/// `ThreadInfo.is_jni_attached` flag (a thread the runtime marked JNI-attached).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JniBoundaryStats {
    /// Thread ID
    pub thread_id: u32,
    /// Whether the thread was marked JNI-attached in its metadata. A thread can
    /// be attached yet have zero recorded crossings (attached-but-idle, or the
    /// crossings were not captured) — surfacing that anomaly is itself useful.
    pub is_jni_attached: bool,
    /// Total JNI boundary crossings recorded for this thread
    pub total_crossings: u64,
    /// Crossings where Java called into native code (`JavaToNative`)
    pub java_to_native_count: u64,
    /// Crossings where native code called back into Java (`NativeToJava`)
    pub native_to_java_count: u64,
    /// Distinct native function addresses reached across the boundary (sorted).
    /// For RE these are the concrete native entry points the thread exercises.
    /// These are SO-relative offsets (the adapter converts `address` via
    /// `to_so_offset`), so they can be resolved to function names via the
    /// engine's ELF function table.
    pub native_addresses: Vec<u64>,
    /// Function name for each entry in `native_addresses` (parallel Vec),
    /// resolved from the SO's symbol table by the engine wrapper. `None` when
    /// no function is registered at that offset (stripped SO / unknown addr).
    /// Populated by `TraceEngine::analyze_jni_boundary`, left `None` by the
    /// raw analyzer (which has no ELF context).
    pub native_functions: Vec<Option<String>>,
    /// Distinct Java methods involved, formatted `class.method` (sorted). These
    /// are the Java-side endpoints — call targets for J2N, callbacks for N2J.
    pub java_methods: Vec<String>,
}

/// Comprehensive thread analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadAnalysisResult {
    /// Detected race conditions
    pub race_conditions: Vec<RaceCondition>,
    /// Detected deadlock risks
    pub deadlock_risks: Vec<DeadlockRisk>,
    /// Lock contention analysis
    pub lock_contentions: Vec<LockContentionInfo>,
    /// Thread-function associations
    pub thread_function_assocs: Vec<ThreadFunctionAssoc>,
    /// Function thread safety classifications
    pub function_safety: Vec<FunctionThreadSafety>,
    /// Thread data flows
    pub data_flows: Vec<ThreadDataFlow>,
    /// Producer-consumer patterns
    pub producer_consumer_patterns: Vec<ProducerConsumerPattern>,
    /// Per-thread scheduling / context-switch statistics
    pub scheduling: Vec<ThreadSchedulingStats>,
    /// Per-thread lifecycle / spawn-tree information
    pub lifecycle: Vec<ThreadLifecycleInfo>,
    /// Per-thread state residency / transition statistics
    pub state_stats: Vec<ThreadStateStats>,
    /// Per-lock critical-section / hold-time statistics
    pub critical_sections: Vec<CriticalSectionStats>,
    /// Per-thread JNI boundary-crossing statistics
    pub jni_boundary: Vec<JniBoundaryStats>,
}

// ============================================================================
// Thread Analyzer
// ============================================================================

/// Thread analyzer — combines data from multiple stores for high-level analysis
///
/// The analyzer does NOT own the trace data. It takes references to the
/// collected data and performs analysis on demand. This keeps the analyzer
/// stateless and composable.
pub struct ThreadAnalyzer {
    // --- Collected data (populated by feed_* methods) ---
    /// Thread metadata
    thread_info: HashMap<u32, ThreadInfo>,
    /// Sync events indexed by step
    /// Sync events keyed by step. A step is NOT unique (it comes from the
    /// caller/adapter, not a monotonic engine counter), so multiple threads may
    /// emit events at the same step — hence a `Vec` per step, never a single
    /// value that would silently overwrite its predecessor.
    sync_events: BTreeMap<u64, Vec<ThreadSyncEvent>>,
    /// Context switches keyed by step. Like `sync_events`, a step is NOT unique
    /// (it comes from the caller/adapter, not a monotonic engine counter), so
    /// two cores can switch at the same step — hence a `Vec` per step, never a
    /// single value that would silently overwrite its predecessor.
    context_switches: BTreeMap<u64, Vec<ContextSwitch>>,
    /// Thread state changes keyed by step. Like `sync_events`/`context_switches`,
    /// a step is NOT unique, so two threads may change state at the same step —
    /// hence a `Vec` per step, never a single value that would overwrite.
    state_changes: BTreeMap<u64, Vec<ThreadStateChange>>,
    /// Memory writes: (step, thread_id, address, size)
    memory_writes: Vec<(u64, u32, u64, usize)>,
    /// Memory reads: (step, thread_id, address, size)
    memory_reads: Vec<(u64, u32, u64, usize)>,
    /// Call events: (step, thread_id, callee_address)
    call_events: Vec<(u64, u32, u64)>,
    /// JNI boundary crossings keyed by step (= `JNICall.seq`). Like the other
    /// event logs, a step is NOT unique (it comes from the adapter, not a
    /// monotonic engine counter), so multiple crossings can share a step —
    /// hence a `Vec` per step, never a single value that would overwrite.
    jni_calls: BTreeMap<u64, Vec<JNICall>>,

    // --- Derived indexes (built on demand) ---
    /// Lock acquisition order per thread: thread_id → Vec<(lock_addr, step)>
    lock_order: HashMap<u32, Vec<(u64, u64)>>,
    /// Per-lock sync events: lock_addr → Vec<(step, thread_id, event_type, result)>.
    /// The `result` is retained so held-state replay can ignore *failed* acquires
    /// (a trylock that `WouldBlock`, a timed lock that `Timeout`s) — those never
    /// took the lock and must not count as "held".
    lock_events: HashMap<u64, Vec<(u64, u32, SyncEventType, SyncResult)>>,
    /// Locks acquired at least once in an *exclusive* (non-shared) mode anywhere
    /// in the trace. A lock acquired only via `RwLockRead` is absent here: since
    /// readers never block readers and there is no writer, acquiring it never
    /// waits, so it cannot be the lock a thread is stuck on in a deadlock cycle.
    /// `detect_deadlocks` uses this to drop lock-graph edges whose waited-for
    /// lock is pure-shared, eliminating false read-read ordering deadlocks.
    exclusive_locks: HashSet<u64>,
    /// Per-thread function calls: thread_id → HashMap<func_addr, call_count>
    thread_functions: HashMap<u32, HashMap<u64, u64>>,
    /// Per-function thread callers: func_addr → HashSet<thread_id>
    function_threads: HashMap<u64, HashSet<u32>>,
    /// Per-function sync events: func_addr → sync_event_count
    function_sync_count: HashMap<u64, u64>,
    /// First/last call step per (thread_id, func_addr): (min_step, max_step).
    ///
    /// Built in one pass over `call_events` so thread-function association does
    /// not rescan all call events per (thread, function) pair (O(T·F·C) → O(C)).
    /// Uses min/max rather than first/last insertion, so it is correct even when
    /// call events are fed out of step order.
    call_step_range: HashMap<(u32, u64), (u64, u64)>,
    /// Per-thread call events sorted by step: thread_id → Vec<(step, func_addr)>.
    ///
    /// Lets `get_active_function` binary-search the last call at or before a step
    /// (O(log C)) instead of scanning all call events (O(C)), and makes the
    /// "active function at a sync event" pass in `build_indexes` O(S·log C)
    /// instead of O(S·C). Sorting also fixes correctness when calls are fed out
    /// of step order (raw insertion order no longer determines the active call).
    calls_by_thread: HashMap<u32, Vec<(u64, u64)>>,
    /// Per-thread lock acquire/release counts: thread_id → HashMap<lock_addr, count>.
    ///
    /// Built in one O(S) pass so `find_sync_mechanism` merges two threads' lock
    /// usage (O(locks)) instead of rescanning all sync events per thread pair
    /// (producer-consumer detection: O(P·S) → O(P·locks)).
    sync_locks_by_thread: HashMap<u32, HashMap<u64, u64>>,
    /// Address → primitive-kind mapping, built in the same pass as
    /// `sync_locks_by_thread`. Lets `find_sync_mechanism` annotate the chosen
    /// address with its primitive class without rescanning sync events. First
    /// kind seen for an address wins (in practice a single address is one
    /// primitive, so there is no real conflict).
    sync_types_by_addr: HashMap<u64, SyncPrimitiveKind>,
    /// Whether indexes have been built
    indexes_built: bool,

    // --- Derived indexes for memory-access analysis (built on demand) ---
    /// Memory writes sorted by step (cache to avoid re-sorting on every call).
    sorted_writes: Vec<(u64, u32, u64, usize)>,
    /// Memory reads sorted by step (cache to avoid re-sorting on every call).
    sorted_reads: Vec<(u64, u32, u64, usize)>,
    /// Page-granular index of reads: page_base → list of (step, thread_id, addr, size).
    ///
    /// Each read is registered under every 4 KiB page its byte range `[addr, addr+size)`
    /// touches, so a write overlapping any part of a read's range is found via the
    /// pages the write itself touches — no full scan needed. This drops race/data-flow
    /// detection from O(W·R) to roughly O(W·k) where k = reads sharing a page.
    reads_by_page: HashMap<u64, Vec<(u64, u32, u64, usize)>>,
    /// Page-granular index of writes, symmetric to [`reads_by_page`]. Used by the
    /// write-write race scan so each write only checks writes sharing its pages
    /// instead of all writes (O(W²) → O(W·k)).
    writes_by_page: HashMap<u64, Vec<(u64, u32, u64, usize)>>,
}

/// Page size (4 KiB) used for the memory-access read index.
const MEM_PAGE_SIZE: u64 = 4096;

/// Iterate the 4 KiB page bases covering `[addr, addr+size)` (size in bytes).
/// A zero-size access is treated as touching the single page containing `addr`.
/// Saturating arithmetic keeps this safe even for addresses near `u64::MAX`:
/// the range end clamps to `u64::MAX` instead of wrapping, so an oversized
/// access is treated as reaching the top of the address space (no underflow
/// when computing the page span, no missed overlaps in callers).
fn pages_covering(addr: u64, size: usize) -> impl Iterator<Item = u64> {
    let start = addr / MEM_PAGE_SIZE * MEM_PAGE_SIZE;
    let end_inclusive = if size == 0 {
        start
    } else {
        let last = addr.saturating_add((size as u64).saturating_sub(1));
        last / MEM_PAGE_SIZE * MEM_PAGE_SIZE
    };
    // `end_inclusive >= start` always holds: `last >= addr` (saturating_add),
    // and page-aligning both preserves that order. So the subtraction can't
    // underflow.
    (0..=(end_inclusive - start) / MEM_PAGE_SIZE)
        .map(move |i| start + i * MEM_PAGE_SIZE)
}

/// Rotate a directed cycle so it begins at its minimum lock address, yielding a
/// stable representative that is independent of which node the DFS entered from.
/// Rotating a cycle preserves its edge order, so `A→B→C→A` and `B→C→A→B` both
/// canonicalize to the same `[min, ...]` sequence and are recognized as one.
fn canonicalize_cycle(cycle: &[u64]) -> Vec<u64> {
    if cycle.is_empty() {
        return Vec::new();
    }
    let min_pos = cycle
        .iter()
        .enumerate()
        .min_by_key(|&(_, &v)| v)
        .map(|(i, _)| i)
        .unwrap();
    let mut out = Vec::with_capacity(cycle.len());
    out.extend_from_slice(&cycle[min_pos..]);
    out.extend_from_slice(&cycle[..min_pos]);
    out
}

impl ThreadAnalyzer {
    /// Create a new thread analyzer
    pub fn new() -> Self {
        Self {
            thread_info: HashMap::new(),
            sync_events: BTreeMap::new(),
            context_switches: BTreeMap::new(),
            state_changes: BTreeMap::new(),
            jni_calls: BTreeMap::new(),
            memory_writes: Vec::new(),
            memory_reads: Vec::new(),
            call_events: Vec::new(),
            lock_order: HashMap::new(),
            exclusive_locks: HashSet::new(),
            lock_events: HashMap::new(),
            thread_functions: HashMap::new(),
            function_threads: HashMap::new(),
            function_sync_count: HashMap::new(),
            call_step_range: HashMap::new(),
            calls_by_thread: HashMap::new(),
            sync_locks_by_thread: HashMap::new(),
            sync_types_by_addr: HashMap::new(),
            indexes_built: false,
            sorted_writes: Vec::new(),
            sorted_reads: Vec::new(),
            reads_by_page: HashMap::new(),
            writes_by_page: HashMap::new(),
        }
    }

    // ========================================================================
    // Data feeding — populate the analyzer with trace data
    // ========================================================================

    /// Feed thread metadata
    pub fn feed_thread_info(&mut self, info: ThreadInfo) {
        self.thread_info.insert(info.thread_id, info);
        self.indexes_built = false;
    }

    /// Feed a synchronization event
    pub fn feed_sync_event(&mut self, event: ThreadSyncEvent) {
        // Build lock-specific index
        self.lock_events
            .entry(event.sync_object_addr)
            .or_default()
            .push((event.step, event.thread_id, event.sync_type.clone(), event.result));

        // Track lock acquisition order per thread
        match &event.sync_type {
            // Holdable acquires only — a `Success` makes the thread hold the
            // lock, recorded in `lock_order` for `detect_deadlocks` and replayed
            // by `is_lock_held_at`. CondvarWait/BarrierWait are excluded (they
            // are sync signals, not holds — see `is_holdable_acquire`): a condvar
            // wait releases its mutex, a barrier has no per-thread hold, and
            // neither has a paired release, so counting them fabricated depth
            // that only ever increased, producing false deadlocks.
            ref t if t.is_holdable_acquire() => {
                if event.result == SyncResult::Success {
                    // Thread acquired this lock — record it in acquisition order.
                    // Held-state at any step is derived on demand by
                    // `is_lock_held_at`, which replays this thread's
                    // acquire/release events from `lock_order` and `lock_events`;
                    // there is deliberately no separate "currently held" set to
                    // keep in sync (a stale one caused recursive-lock bugs).
                    self.lock_order
                        .entry(event.thread_id)
                        .or_default()
                        .push((event.sync_object_addr, event.step));
                }
            }
            _ => {}
        }

        self.sync_events.entry(event.step).or_default().push(event);
        self.indexes_built = false;
    }

    /// Feed a context switch event
    pub fn feed_context_switch(&mut self, switch: ContextSwitch) {
        self.context_switches.entry(switch.step).or_default().push(switch);
        self.indexes_built = false;
    }

    /// Feed a thread state change event
    pub fn feed_state_change(&mut self, change: ThreadStateChange) {
        self.state_changes.entry(change.step).or_default().push(change);
        self.indexes_built = false;
    }

    /// Feed a JNI boundary-crossing event. Keyed by `seq` into a `Vec` per step
    /// so same-step crossings are never overwritten (step is not unique).
    pub fn feed_jni_call(&mut self, call: JNICall) {
        self.jni_calls.entry(call.seq).or_default().push(call);
        self.indexes_built = false;
    }

    /// Feed a memory write event
    pub fn feed_memory_write(&mut self, step: u64, thread_id: u32, address: u64, size: usize) {
        self.memory_writes.push((step, thread_id, address, size));
        self.indexes_built = false;
    }

    /// Feed a memory read event
    pub fn feed_memory_read(&mut self, step: u64, thread_id: u32, address: u64, size: usize) {
        self.memory_reads.push((step, thread_id, address, size));
        self.indexes_built = false;
    }

    /// Feed a function call event
    pub fn feed_call_event(&mut self, step: u64, thread_id: u32, callee_address: u64) {
        // Build thread-function association
        self.thread_functions
            .entry(thread_id)
            .or_default()
            .entry(callee_address)
            .and_modify(|count| *count += 1)
            .or_insert(1);

        // Build function-thread association
        self.function_threads
            .entry(callee_address)
            .or_default()
            .insert(thread_id);

        self.call_events.push((step, thread_id, callee_address));
        self.indexes_built = false;
    }

    // ========================================================================
    // Index building
    // ========================================================================

    /// Build derived indexes from the fed data
    fn build_indexes(&mut self) {
        if self.indexes_built {
            return;
        }

        // Build per-thread call lists sorted by step, plus the first/last
        // call-step range per (thread, function), in one pass over call_events.
        // Both replace repeated O(C) scans: the sorted lists back the binary
        // search in `get_active_function`, and the range map backs thread-function
        // association (O(T·F·C) → O(C)). Sorting also fixes ordering correctness
        // when calls are fed out of step order.
        self.calls_by_thread.clear();
        self.call_step_range.clear();
        for &(step, tid, func_addr) in &self.call_events {
            self.calls_by_thread
                .entry(tid)
                .or_default()
                .push((step, func_addr));
            self.call_step_range
                .entry((tid, func_addr))
                .and_modify(|(first, last)| {
                    *first = (*first).min(step);
                    *last = (*last).max(step);
                })
                .or_insert((step, step));
        }
        for calls in self.calls_by_thread.values_mut() {
            calls.sort_by_key(|&(step, _)| step);
        }

        // In one pass over sync events, (a) attribute each to the function active
        // on its thread at that step — binary search over the sorted per-thread
        // call list instead of scanning all call events (O(S·C) → O(S·log C)) —
        // and (b) tally per-thread lock acquire/release usage so
        // `find_sync_mechanism` need not rescan sync events per thread pair.
        self.sync_locks_by_thread.clear();
        self.sync_types_by_addr.clear();
        self.exclusive_locks.clear();
        for (_, events) in &self.sync_events {
            for event in events {
                if let Some(func_addr) = self.active_function_at(event.thread_id, event.step) {
                    *self.function_sync_count.entry(func_addr).or_insert(0) += 1;
                }
                if event.sync_type.is_acquire()
                    || event.sync_type.is_release()
                    || event.sync_type.is_sync_signal()
                {
                    *self
                        .sync_locks_by_thread
                        .entry(event.thread_id)
                        .or_default()
                        .entry(event.sync_object_addr)
                        .or_insert(0) += 1;
                    // Record the primitive kind for this address. First kind
                    // seen wins; in practice one address is one primitive so the
                    // variants that share an address (MutexLock + MutexUnlock)
                    // all map to the same kind and never conflict.
                    self.sync_types_by_addr
                        .entry(event.sync_object_addr)
                        .or_insert(event.sync_type.primitive_kind());
                }
                // A lock is exclusive-capable if it is ever acquired in a
                // non-shared mode (anything but a reader rwlock acquire). Only
                // such locks can block an acquirer and thus anchor a deadlock.
                // #109: use `is_holdable_acquire` (not the broad `is_acquire`)
                // so BarrierWait/CondvarWait — which are sync signals, not
                // holds — never enter `exclusive_locks`. They have no paired
                // release, so `is_lock_held_at` would always return false for
                // them, dropping every deadlock edge they anchored (the
                // `a_still_held` check below rejects edges where lock_a is not
                // held). Keeping them out avoids that self-contradiction.
                if event.sync_type.is_holdable_acquire() && !event.sync_type.is_shared_acquire() {
                    self.exclusive_locks.insert(event.sync_object_addr);
                }
            }
        }

        // Build the sorted memory-access caches and the page-granular read index
        // used by race / data-flow detection to avoid an O(W·R) full scan.
        self.sorted_writes = self.memory_writes.clone();
        self.sorted_writes.sort_by_key(|w| w.0);

        self.sorted_reads = self.memory_reads.clone();
        self.sorted_reads.sort_by_key(|r| r.0);

        self.reads_by_page.clear();
        for &read @ (r_step, r_tid, r_addr, r_size) in &self.sorted_reads {
            for page in pages_covering(r_addr, r_size) {
                self.reads_by_page
                    .entry(page)
                    .or_default()
                    .push((r_step, r_tid, r_addr, r_size));
            }
        }

        self.writes_by_page.clear();
        for &write @ (w_step, w_tid, w_addr, w_size) in &self.sorted_writes {
            for page in pages_covering(w_addr, w_size) {
                self.writes_by_page
                    .entry(page)
                    .or_default()
                    .push((w_step, w_tid, w_addr, w_size));
            }
        }

        // The lock vectors are pushed in feed order, but two deadlock-path
        // consumers fold them assuming step order: `is_lock_held_at` replays a
        // lock's acquire/release events into a held/not-held boolean, and
        // `detect_deadlocks` treats each thread's acquisition list as a temporal
        // sequence (order[i] acquired before order[j]). An out-of-order feed —
        // step/seq comes from the caller, not a monotonic engine counter — would
        // otherwise flip a held state or mis-orient a lock-graph edge. Sort by
        // step here; idempotent under the `indexes_built` guard.
        for events in self.lock_events.values_mut() {
            events.sort_by_key(|&(step, _, _, _)| step);
        }
        for order in self.lock_order.values_mut() {
            order.sort_by_key(|&(_, step)| step);
        }

        self.indexes_built = true;
    }

    /// Collect reads whose byte range overlaps `[w_addr, w_addr+w_size)`,
    /// using the page-granular index to avoid a full scan. Each read appears
    /// at most once even if it was registered under multiple pages. The
    /// returned slice is `sorted_reads`-ordered (by step).
    fn reads_overlapping(&self, w_addr: u64, w_size: usize) -> Vec<(u64, u32, u64, usize)> {
        let w_end = w_addr.saturating_add(w_size as u64);
        let mut seen_steps: HashSet<(u64, u32, u64)> = HashSet::new();
        let mut candidates: Vec<(u64, u32, u64, usize)> = Vec::new();
        for page in pages_covering(w_addr, w_size) {
            if let Some(reads) = self.reads_by_page.get(&page) {
                for &(r_step, r_tid, r_addr, r_size) in reads {
                    let r_end = r_addr.saturating_add(r_size as u64);
                    // Precise overlap check (page bucketing only narrows candidates).
                    if r_addr >= w_end || w_addr >= r_end {
                        continue;
                    }
                    let key = (r_step, r_tid, r_addr);
                    if seen_steps.insert(key) {
                        candidates.push((r_step, r_tid, r_addr, r_size));
                    }
                }
            }
        }
        // Already step-ordered because reads_by_page was filled from sorted_reads,
        // but pages are visited out of order — re-sort to keep a stable contract.
        candidates.sort_by_key(|r| r.0);
        candidates
    }

    /// Collect writes whose byte range overlaps `[addr, addr+size)`, using the
    /// page-granular write index. Symmetric to [`reads_overlapping`]; each write
    /// appears at most once. Sorted by step.
    fn writes_overlapping(&self, addr: u64, size: usize) -> Vec<(u64, u32, u64, usize)> {
        let end = addr.saturating_add(size as u64);
        let mut seen_steps: HashSet<(u64, u32, u64)> = HashSet::new();
        let mut candidates: Vec<(u64, u32, u64, usize)> = Vec::new();
        for page in pages_covering(addr, size) {
            if let Some(writes) = self.writes_by_page.get(&page) {
                for &(w_step, w_tid, w_addr, w_size) in writes {
                    let w_end = w_addr.saturating_add(w_size as u64);
                    if w_addr >= end || addr >= w_end {
                        continue;
                    }
                    let key = (w_step, w_tid, w_addr);
                    if seen_steps.insert(key) {
                        candidates.push((w_step, w_tid, w_addr, w_size));
                    }
                }
            }
        }
        candidates.sort_by_key(|w| w.0);
        candidates
    }

    // ========================================================================
    // Race condition detection
    // ========================================================================

    /// Detect race conditions
    ///
    /// A race condition occurs when two threads access the same address with
    /// at least one write, and no synchronization event separates them:
    /// 1. **write→read**: A writes X at S1, B reads X at S2 (S2 > S1)
    /// 2. **write→write**: A writes X at S1, B writes X at S2 (S2 > S1)
    /// 3. **read→write**: A reads X at S1, B writes X at S2 (S2 > S1)
    ///
    /// The outer loop anchors on every write and scans both directions in time,
    /// so a read that precedes a conflicting write on another thread — an
    /// equally real data race — is caught as well, not just accesses that
    /// follow the write.
    ///
    /// Returns detected race conditions sorted by confidence (highest first).
    pub fn detect_race_conditions(&mut self) -> Vec<RaceCondition> {
        self.build_indexes();

        let mut races = Vec::new();

        // Use the cached, step-sorted writes (built in build_indexes) instead of
        // cloning+sorting on every call.
        let writes: Vec<(u64, u32, u64, usize)> = self.sorted_writes.clone();

        // For each write, check if another thread reads/writes the same
        // address range without intervening synchronization
        for (w_step, w_tid, w_addr, w_size) in &writes {
            let w_end = w_addr.saturating_add(*w_size as u64);

            // Check against reads by other threads — use the page index so we
            // only scan reads that actually share a page with this write.
            for (r_step, r_tid, r_addr, r_size) in self.reads_overlapping(*w_addr, *w_size) {
                if r_tid == *w_tid { continue; } // Same thread, not a race
                // `<`, not `<=`: a read at the *same* step as the write is not
                // "before" it — steps come from the caller's `trace.seq` and are
                // not unique, so a same-step read+write on two threads is fully
                // concurrent, the strongest possible race. Keep it here (labelled
                // write-first) and let the read→write loop below skip `==` so the
                // pair is reported exactly once.
                if r_step < *w_step { continue; }

                let r_end = r_addr.saturating_add(r_size as u64);
                // Redundant with reads_overlapping's check, but cheap and keeps
                // the invariant explicit at the call site.
                if r_addr >= w_end || *w_addr >= r_end { continue; }

                // Check for synchronization between write and read
                let has_sync = self.has_sync_between(*w_tid, r_tid, *w_step, r_step);

                if !has_sync {
                    let confidence = self.compute_race_confidence(
                        *w_tid, r_tid, *w_step, r_step,
                    );

                    // first=write [w_addr, w_end), second=read [r_addr, r_end)
                    let overlap_address = (*w_addr).max(r_addr);
                    let overlap_end = w_end.min(r_end);
                    let overlap_size = overlap_end.saturating_sub(overlap_address);
                    races.push(RaceCondition {
                        address: *w_addr,
                        first_step: *w_step,
                        first_thread: *w_tid,
                        second_step: r_step,
                        second_thread: r_tid,
                        first_is_write: true,
                        second_is_write: false,
                        first_access_size: *w_size as u64,
                        second_access_size: r_size as u64,
                        overlap_address,
                        overlap_size,
                        confidence,
                        description: format!(
                            "Thread {} wrote {} bytes at 0x{:X} (step {}), then thread {} read {} bytes at 0x{:X} (step {}) without synchronization; conflict range 0x{:X}-0x{:X} ({} bytes)",
                            w_tid, w_size, w_addr, w_step, r_tid, r_size, r_addr, r_step,
                            overlap_address, overlap_end, overlap_size,
                        ),
                    });
                }
            }

            // Check against writes by other threads (write-write race) — use the
            // page index so we only scan writes that actually share a page.
            for (w2_step, w2_tid, w2_addr, w2_size) in self.writes_overlapping(*w_addr, *w_size) {
                if w2_tid == *w_tid { continue; }
                // Same rationale as the write→read loop: a same-step write on
                // another thread is a concurrent write-write race, not ordered
                // "after". But both writes come from one collection, so a naive
                // `==` would report the pair twice (once from each side) and could
                // self-pair. Report each same-step cross-thread write pair once by
                // taking only the lower-tid-first orientation.
                if w2_step < *w_step { continue; }
                if w2_step == *w_step && w2_tid < *w_tid { continue; }

                let w2_end = w2_addr.saturating_add(w2_size as u64);
                if w2_addr >= w_end || *w_addr >= w2_end { continue; }

                let has_sync = self.has_sync_between(*w_tid, w2_tid, *w_step, w2_step);

                if !has_sync {
                    let confidence = self.compute_race_confidence(
                        *w_tid, w2_tid, *w_step, w2_step,
                    );

                    // first=write1 [w_addr, w_end), second=write2 [w2_addr, w2_end)
                    let overlap_address = (*w_addr).max(w2_addr);
                    let overlap_end = w_end.min(w2_end);
                    let overlap_size = overlap_end.saturating_sub(overlap_address);
                    races.push(RaceCondition {
                        address: *w_addr,
                        first_step: *w_step,
                        first_thread: *w_tid,
                        second_step: w2_step,
                        second_thread: w2_tid,
                        first_is_write: true,
                        second_is_write: true,
                        first_access_size: *w_size as u64,
                        second_access_size: w2_size as u64,
                        overlap_address,
                        overlap_size,
                        confidence: confidence * 0.8, // Write-write slightly less severe
                        description: format!(
                            "Thread {} wrote {} bytes at 0x{:X} (step {}), then thread {} wrote {} bytes at 0x{:X} (step {}) without synchronization; conflict range 0x{:X}-0x{:X} ({} bytes)",
                            w_tid, w_size, w_addr, w_step, w2_tid, w2_size, w2_addr, w2_step,
                            overlap_address, overlap_end, overlap_size,
                        ),
                    });
                }
            }

            // Check against reads by other threads that happened BEFORE this
            // write (read-then-write race). The two forward-looking loops above
            // only pair accesses that come AFTER the write, so a read on another
            // thread that precedes the write — an equally real data race, the
            // reader may act on a value the writer is about to change — would
            // otherwise be silently missed.
            for (r_step, r_tid, r_addr, r_size) in self.reads_overlapping(*w_addr, *w_size) {
                if r_tid == *w_tid { continue; } // Same thread, not a race
                // Strictly before: a read at the *same* step as the write is the
                // concurrent case already reported (write-first) by the write→read
                // loop above — skipping `==` here keeps it from being double-counted.
                if r_step >= *w_step { continue; } // Only reads strictly before the write

                let r_end = r_addr.saturating_add(r_size as u64);
                if r_addr >= w_end || *w_addr >= r_end { continue; }

                // Range is [read, write] since the read is the earlier event.
                let has_sync = self.has_sync_between(r_tid, *w_tid, r_step, *w_step);

                if !has_sync {
                    let confidence = self.compute_race_confidence(
                        r_tid, *w_tid, r_step, *w_step,
                    );

                    // first=read [r_addr, r_end), second=write [w_addr, w_end)
                    let overlap_address = r_addr.max(*w_addr);
                    let overlap_end = r_end.min(w_end);
                    let overlap_size = overlap_end.saturating_sub(overlap_address);
                    races.push(RaceCondition {
                        address: *w_addr,
                        first_step: r_step,
                        first_thread: r_tid,
                        second_step: *w_step,
                        second_thread: *w_tid,
                        first_is_write: false,
                        second_is_write: true,
                        first_access_size: r_size as u64,
                        second_access_size: *w_size as u64,
                        overlap_address,
                        overlap_size,
                        confidence,
                        description: format!(
                            "Thread {} read {} bytes at 0x{:X} (step {}), then thread {} wrote {} bytes at 0x{:X} (step {}) without synchronization; conflict range 0x{:X}-0x{:X} ({} bytes)",
                            r_tid, r_size, r_addr, r_step, w_tid, w_size, w_addr, w_step,
                            overlap_address, overlap_end, overlap_size,
                        ),
                    });
                }
            }
        }

        // Sort by confidence (highest first)
        races.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        // Deduplicate the EXACT same race pair. The key must include both
        // steps: the same pair of threads can race repeatedly on one address
        // (e.g. a racy loop), and each occurrence is a distinct event the
        // reverse engineer wants to see — collapsing them onto the address+thread
        // pair would silently drop the repetition. The three detection loops
        // above can also surface the same concrete pair from more than one
        // direction (notably a same-step cross-thread pair), so exact-pair
        // dedup is still needed.
        let mut seen = HashSet::new();
        races.retain(|race| {
            let key = (
                race.address,
                race.first_step,
                race.first_thread,
                race.second_step,
                race.second_thread,
            );
            seen.insert(key)
        });

        races
    }

    /// Check if there is a synchronization event between two threads
    /// in the step range [from_step, to_step]
    fn has_sync_between(&self, thread_a: u32, thread_b: u32, from_step: u64, to_step: u64) -> bool {
        // Check sync events in the range
        for (_, events_at_step) in self.sync_events.range(from_step..=to_step) {
            for event in events_at_step {
                // A sync event by either thread that involves a lock
                // counts as synchronization if the other thread also
                // interacted with the same lock
                if event.thread_id == thread_a || event.thread_id == thread_b {
                    // #109: a sync event counts as synchronization if it is a
                    // holdable acquire/release OR a non-holdable sync signal
                    // (condvar wait/signal, barrier, futex-wake-count). The
                    // latter establish happens-before edges that suppress races
                    // but must NOT build hold state — `is_holdable_acquire`/
                    // `is_holdable_release` gate the depth counters separately.
                    if event.sync_type.is_acquire()
                        || event.sync_type.is_release()
                        || event.sync_type.is_sync_signal()
                    {
                        // Check if the other thread also touched this lock
                        let other_tid = if event.thread_id == thread_a { thread_b } else { thread_a };
                        if let Some(lock_evs) = self.lock_events.get(&event.sync_object_addr) {
                            let other_touched = lock_evs.iter().any(|&(s, tid, _, _)| {
                                tid == other_tid && s >= from_step && s <= to_step
                            });
                            if other_touched {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Compute confidence score for a race condition
    ///
    /// Higher confidence when:
    /// - Steps are close together (more likely to actually race)
    /// - Both threads are in the same function (more likely to be a bug)
    /// - The address is on the heap (more likely to be shared data)
    fn compute_race_confidence(&self, thread_a: u32, thread_b: u32, step_a: u64, step_b: u64) -> f64 {
        let mut confidence: f64 = 0.5;

        // Closer steps = higher confidence
        let step_distance = step_b.saturating_sub(step_a);
        if step_distance < 100 {
            confidence += 0.3;
        } else if step_distance < 1000 {
            confidence += 0.15;
        }

        // Both threads in same function = higher confidence
        let func_a = self.get_active_function(thread_a, step_a);
        let func_b = self.get_active_function(thread_b, step_b);
        if let (Some(fa), Some(fb)) = (func_a, func_b) {
            if fa == fb {
                confidence += 0.2;
            }
        }

        confidence.min(1.0_f64)
    }

    /// Get the function active on a thread at a given step.
    ///
    /// Requires indexes to be built (`calls_by_thread` populated); all callers
    /// run inside analysis methods that call `build_indexes` first.
    fn get_active_function(&self, thread_id: u32, step: u64) -> Option<u64> {
        self.active_function_at(thread_id, step)
    }

    /// Binary-search the last call on `thread_id` at or before `step`, returning
    /// its callee address. Relies on `calls_by_thread` being sorted by step.
    fn active_function_at(&self, thread_id: u32, step: u64) -> Option<u64> {
        let calls = self.calls_by_thread.get(&thread_id)?;
        // Index of the first call with step > `step`; the one before it (if any)
        // is the last call at or before `step`.
        let idx = calls.partition_point(|&(s, _)| s <= step);
        if idx == 0 {
            None
        } else {
            Some(calls[idx - 1].1)
        }
    }

    // ========================================================================
    // Deadlock detection
    // ========================================================================

    /// Detect potential deadlocks via lock ordering analysis
    ///
    /// Builds a lock graph and checks for cycles. A cycle in the lock
    /// graph means there exists a sequence of lock acquisitions that
    /// can deadlock.
    ///
    /// Algorithm:
    /// 1. For each thread, extract the lock acquisition order
    /// 2. Build a directed graph: lock A → lock B means "some thread
    ///    acquired A while holding B" (i.e., A was held when B was acquired)
    /// 3. Find cycles in this graph using DFS
    pub fn detect_deadlocks(&mut self) -> Vec<DeadlockRisk> {
        self.build_indexes();

        let mut lock_graph: HashMap<u64, HashSet<u64>> = HashMap::new();
        let mut lock_thread_map: HashMap<(u64, u64), Vec<u32>> = HashMap::new(); // (from_lock, to_lock) → threads

        // Build lock graph from lock acquisition order
        for (&thread_id, order) in &self.lock_order {
            // For each pair of locks acquired by this thread,
            // if lock B was acquired while lock A was held,
            // add edge A → B
            for i in 0..order.len() {
                for j in (i + 1)..order.len() {
                    let (lock_a, _step_a) = order[i];
                    let (lock_b, step_b) = order[j];

                    // A lock-ordering deadlock is a cycle between *distinct*
                    // locks. A self-pair (lock_a == lock_b) arises when a thread
                    // re-acquires the same lock (e.g. lock B, unlock B, lock B
                    // again): `is_lock_held_at` would report B "held" at the
                    // re-acquire's own step (the replay includes that very
                    // acquire), fabricating a B→B self-edge that DFS then reports
                    // as a one-lock "cycle". Sequential re-locking is not an
                    // ordering deadlock, so drop these pairs. (True same-lock
                    // self-deadlock — double-lock without release on a
                    // non-recursive mutex — is a separate concern, not modeled by
                    // the ordering graph, and unknowable without mutex kind.)
                    if lock_a == lock_b {
                        continue;
                    }

                    // Skip edges whose waited-for lock (B) is pure-shared: a
                    // read-only rwlock never blocks an acquirer, so holding A
                    // while read-acquiring B cannot stall the thread and cannot
                    // close a deadlock cycle. This drops false read-read ordering
                    // deadlocks (two threads read-locking A,B in opposite order)
                    // while preserving every case where B can actually block.
                    if !self.exclusive_locks.contains(&lock_b) {
                        continue;
                    }

                    // Only if lock A was still held when lock B was acquired
                    // (check by looking at unlock events between step_a and step_b)
                    let a_still_held = self.is_lock_held_at(thread_id, lock_a, step_b);

                    if a_still_held {
                        lock_graph.entry(lock_a).or_default().insert(lock_b);
                        lock_thread_map
                            .entry((lock_a, lock_b))
                            .or_default()
                            .push(thread_id);
                    }
                }
            }
        }

        // Find cycles using DFS. Iterate roots in address order (not HashMap
        // order) so the set of cycles discovered is deterministic; `seen` holds
        // canonical (min-rotated) cycles so the same cycle is never reported
        // twice under different entry rotations.
        let mut deadlocks = Vec::new();
        let mut path = Vec::new();
        let mut path_set = HashSet::new();
        let mut seen: HashSet<Vec<u64>> = HashSet::new();
        // Defensive bound on DFS node-visits. Enumerating all simple cycles is
        // worst-case exponential; real lock graphs are tiny, but a pathological
        // or adversarial trace must not hang the database. If exhausted we stop
        // with whatever was found so far — still sound, every reported cycle is
        // real; only completeness (not correctness) degrades past the bound.
        let mut budget: u64 = 5_000_000;

        let mut roots: Vec<u64> = lock_graph.keys().copied().collect();
        roots.sort_unstable();
        for start_lock in roots {
            // Start DFS from every node (address-sorted). There is deliberately
            // NO cross-root `visited` black-set: a permanent visited mark prunes
            // cycles that merely share a node with an already-explored path,
            // silently dropping real deadlocks (false negatives). `path_set`
            // keeps every explored path simple (guaranteeing termination) and
            // `seen` dedups cycles found from different entry points.
            self.dfs_find_cycles(
                start_lock,
                &lock_graph,
                &mut path,
                &mut path_set,
                &lock_thread_map,
                &mut seen,
                &mut deadlocks,
                &mut budget,
            );
        }

        // Stable output order: sort the reported cycles by their canonical form.
        // Compare by the address sequence (kind is derived, not a sort key).
        deadlocks.sort_by(|a, b| {
            a.lock_cycle
                .iter()
                .map(|m| m.addr)
                .collect::<Vec<_>>()
                .cmp(&b.lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>())
        });
        deadlocks
    }

    /// Check if a lock was held by a thread at a given step
    fn is_lock_held_at(&self, thread_id: u32, lock_addr: u64, step: u64) -> bool {
        // Check lock events for this lock and thread
        if let Some(events) = self.lock_events.get(&lock_addr) {
            // Track *hold depth*, not a bool. A recursive mutex (or a nested
            // rwlock read) can be acquired multiple times by the same thread and
            // is only released once the matching number of unlocks arrive. A bool
            // would clear on the FIRST unlock and report the lock free while it is
            // still held one level deep — a false negative that drops a genuine
            // deadlock edge. A saturating counter tracks nesting correctly and is
            // identical to the bool for non-recursive locks (a well-formed trace
            // keeps their depth in {0, 1}). No mutex-kind info is required.
            let mut depth: u32 = 0;
            // `events` is step-sorted in `build_indexes`, so replaying in vector
            // order is replaying in step order; stop once past the query step.
            for &(s, tid, ref event_type, result) in events {
                if s > step { break; }
                if tid != thread_id { continue; }
                match event_type {
                    ref t if t.is_holdable_acquire() => {
                        // Only a *successful* acquire takes the lock. A trylock
                        // that returned WouldBlock, a timed lock that Timed
                        // out / was interrupted, or a spurious/EAGAIN futex wait
                        // (returns non-Success) never held it — treating those
                        // as "held" invents a lock that is not actually held and
                        // can fabricate a deadlock edge. #109: this now covers
                        // SemWait/FutexWait too (previously omitted, so
                        // semaphore/futex-backed mutex deadlocks were missed).
                        if result == SyncResult::Success {
                            depth += 1;
                        }
                    }
                    ref t if t.is_holdable_release() => {
                        // Saturating: a stray unlock without a matching acquire
                        // (truncated trace, lost prefix) must not underflow and
                        // wrap to a huge depth that reports the lock permanently
                        // held. #109: this now covers SemPost/FutexWake too
                        // (previously omitted, so a semaphore acquire was counted
                        // but its release never decremented depth → permanent
                        // hold → false deadlocks).
                        depth = depth.saturating_sub(1);
                    }
                    _ => {}
                }
            }
            depth > 0
        } else {
            false
        }
    }

    /// DFS to find cycles in the lock graph
    fn dfs_find_cycles(
        &self,
        current: u64,
        graph: &HashMap<u64, HashSet<u64>>,
        path: &mut Vec<u64>,
        path_set: &mut HashSet<u64>,
        lock_thread_map: &HashMap<(u64, u64), Vec<u32>>,
        seen: &mut HashSet<Vec<u64>>,
        results: &mut Vec<DeadlockRisk>,
        budget: &mut u64,
    ) {
        if path_set.contains(&current) {
            // Found a cycle! Canonicalize to a min-address rotation so the same
            // cycle entered from a different node is recognized as a duplicate.
            let cycle_start = path.iter().position(|&l| l == current).unwrap();
            let cycle = canonicalize_cycle(&path[cycle_start..]);
            if !seen.insert(cycle.clone()) {
                return; // already reported (a rotation of this cycle)
            }

            // Collect threads involved (sorted for deterministic output).
            let mut thread_set = HashSet::new();
            for i in 0..cycle.len() {
                let from = cycle[i];
                let to = cycle[(i + 1) % cycle.len()];
                if let Some(tids) = lock_thread_map.get(&(from, to)) {
                    for &tid in tids {
                        thread_set.insert(tid);
                    }
                }
            }
            let mut threads: Vec<u32> = thread_set.into_iter().collect();
            threads.sort_unstable();

            // Collect the steps that actually participate in this cycle: an
            // involved thread's acquisitions of the locks *in the cycle*. Dumping
            // every acquisition a thread ever made (including locks unrelated to
            // this deadlock) bloats the report and misattributes noise to the
            // cycle — a trace DB should point at the precise offending events.
            let cycle_locks: HashSet<u64> = cycle.iter().copied().collect();
            let mut violation_steps = Vec::new();
            for &tid in &threads {
                if let Some(order) = self.lock_order.get(&tid) {
                    for &(lock, step) in order {
                        if cycle_locks.contains(&lock) {
                            violation_steps.push(step);
                        }
                    }
                }
            }
            violation_steps.sort_unstable();
            violation_steps.dedup();

            let description = format!(
                "Lock ordering cycle detected: {} (involving threads: {})",
                cycle.iter()
                    .map(|&l| {
                        let m = self.sync_mechanism_for(l);
                        format!("0x{:X} ({:?})", m.addr, m.kind)
                    })
                    .collect::<Vec<_>>()
                    .join(" → "),
                threads.iter()
                    .map(|t| format!("{}", t))
                    .collect::<Vec<_>>()
                    .join(", "),
            );

            results.push(DeadlockRisk {
                lock_cycle: cycle.iter().map(|&a| self.sync_mechanism_for(a)).collect(),
                threads,
                violation_steps,
                description,
            });
            return;
        }

        // Bound total work (see `budget` note in `detect_deadlocks`). Checked
        // after the cycle branch so an in-progress cycle is always recorded.
        if *budget == 0 {
            return;
        }
        *budget -= 1;

        path.push(current);
        path_set.insert(current);

        // Visit neighbors in address order so cycle discovery is deterministic.
        if let Some(neighbors) = graph.get(&current) {
            let mut next_locks: Vec<u64> = neighbors.iter().copied().collect();
            next_locks.sort_unstable();
            for next in next_locks {
                self.dfs_find_cycles(next, graph, path, path_set, lock_thread_map, seen, results, budget);
            }
        }

        path.pop();
        path_set.remove(&current);
    }

    // ========================================================================
    // Lock contention analysis
    // ============================================================================

    /// Analyze lock contention across all locks
    ///
    /// Returns contention info for each lock, sorted by contention ratio
    /// (highest contention first).
    pub fn analyze_lock_contention(&mut self) -> Vec<LockContentionInfo> {
        self.build_indexes();

        let mut results = Vec::new();

        for (&lock_addr, events) in &self.lock_events {
            let mut acquire_count: u64 = 0;
            let mut contention_count: u64 = 0;
            let mut total_wait_ns: u64 = 0;
            let mut max_wait_ns: u64 = 0;
            let mut contending_threads = HashSet::new();

            for &(step, thread_id, ref event_type, _) in events {
                match event_type {
                    // #109: holdable acquires only. Adds FutexWait (previously
                    // omitted, so futex-backed lock contention was missed) and
                    // keeps SemWait. Excludes BarrierWait (not a lock) and
                    // CondvarWait (releases its mutex, not an acquire).
                    ref t if t.is_holdable_acquire() => {
                        acquire_count += 1;

                        // Recover this acquisition's wait/result from the sync
                        // event matching (step, thread, lock, type). Multiple
                        // events can share a step, so match on all four fields
                        // rather than blindly taking the first event at `step`.
                        let sync_event = self.sync_events.get(&step).and_then(|evs| {
                            evs.iter().find(|e| {
                                e.thread_id == thread_id
                                    && e.sync_object_addr == lock_addr
                                    && e.sync_type == *event_type
                            })
                        });
                        if let Some(sync_event) = sync_event {
                            // An attempt is contended if it waited OR failed to
                            // take the lock immediately (trylock WouldBlock /
                            // timed lock Timeout). Count it at most ONCE: a timed
                            // lock that waits then times out satisfies both
                            // conditions, and double-counting would push
                            // `contention_count` past `acquire_count` and the
                            // ratio above 1.0.
                            let wait = sync_event.wait_duration_ns.unwrap_or(0);
                            let waited = wait > 0;
                            let blocked = sync_event.result == SyncResult::WouldBlock
                                || sync_event.result == SyncResult::Timeout;
                            if waited {
                                total_wait_ns += wait;
                                max_wait_ns = max_wait_ns.max(wait);
                            }
                            if waited || blocked {
                                contention_count += 1;
                                contending_threads.insert(thread_id);
                            }
                        }
                    }
                    _ => {}
                }
            }

            let contention_ratio = if acquire_count > 0 {
                contention_count as f64 / acquire_count as f64
            } else {
                0.0
            };

            let avg_wait_ns = if contention_count > 0 {
                total_wait_ns / contention_count
            } else {
                0
            };

            let mut contending_threads: Vec<u32> = contending_threads.into_iter().collect();
            contending_threads.sort_unstable();

            results.push(LockContentionInfo {
                lock_address: self.sync_mechanism_for(lock_addr),
                acquire_count,
                contention_count,
                contention_ratio,
                total_wait_ns,
                avg_wait_ns,
                max_wait_ns,
                contending_threads,
            });
        }

        // Sort by contention ratio (highest first), tie-breaking on lock address
        // so equal-ratio locks come out in a deterministic order rather than
        // `lock_events` HashMap iteration order.
        results.sort_by(|a, b| {
            b.contention_ratio
                .partial_cmp(&a.contention_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.lock_address.addr.cmp(&b.lock_address.addr))
        });

        results
    }

    /// Analyze per-lock critical-section hold time.
    ///
    /// Where [`Self::analyze_lock_contention`] measures how long threads *waited*
    /// for each lock, this measures how long each lock was *held* — the root
    /// cause of those waits. For every lock it replays the step-sorted
    /// `lock_events` per thread, pairing each thread's outermost successful
    /// acquire with its matching release and recording the `[acquire, release]`
    /// step span. Recursive re-acquires nest (a depth counter) and do not open a
    /// second interval, mirroring [`Self::is_lock_held_at`]; only a successful
    /// acquire takes the lock (a `WouldBlock` trylock / `Timeout` never held it).
    /// An acquire with no matching release before the trace ends is unbounded and
    /// contributes nothing — the same "never invent duration" rule used for
    /// trailing thread states.
    pub fn analyze_critical_sections(&mut self) -> Vec<CriticalSectionStats> {
        self.build_indexes();

        let mut results = Vec::new();

        for (&lock_addr, events) in &self.lock_events {
            // Per-thread hold state: (nesting depth, step of the outermost
            // acquire that opened the current interval). Keyed by thread because
            // a lock can be held by different threads at different times, and an
            // rwlock read can be held by several threads at once — each thread's
            // acquire/release pairs are independent.
            let mut open: HashMap<u32, (u32, u64)> = HashMap::new();

            let mut hold_count: u64 = 0;
            let mut total_hold_steps: u64 = 0;
            let mut max_hold_steps: u64 = 0;
            let mut longest_hold_thread: u32 = 0;
            let mut longest_hold_start: u64 = 0;
            let mut longest_hold_end: u64 = 0;
            let mut holder_threads: HashSet<u32> = HashSet::new();

            // `events` is step-sorted in `build_indexes`, so vector order is step
            // order; replay it to fold acquire/release into hold intervals.
            for &(step, thread_id, ref event_type, result) in events {
                match event_type {
                    // #109: holdable acquires only — adds SemWait/FutexWait
                    // (previously omitted, so semaphore/futex critical sections
                    // were never reported). Excludes CondvarWait/BarrierWait.
                    ref t if t.is_holdable_acquire() => {
                        // Only a successful acquire takes the lock.
                        if result != SyncResult::Success {
                            continue;
                        }
                        let entry = open.entry(thread_id).or_insert((0, step));
                        // The outermost acquire (depth 0 → 1) opens the interval
                        // and stamps its start; nested re-acquires only deepen it.
                        if entry.0 == 0 {
                            entry.1 = step;
                        }
                        entry.0 += 1;
                    }
                    // #109: holdable releases only — adds SemPost/FutexWake
                    // (previously omitted, so a semaphore hold never closed →
                    // no critical-section interval recorded).
                    ref t if t.is_holdable_release() => {
                        if let Some(entry) = open.get_mut(&thread_id) {
                            if entry.0 > 0 {
                                entry.0 -= 1;
                                // Outermost release (depth 1 → 0) closes the
                                // interval held since `entry.1`.
                                if entry.0 == 0 {
                                    let start = entry.1;
                                    // `step >= start` because events are
                                    // step-sorted; saturating guards a malformed
                                    // (out-of-order) trace against underflow.
                                    let dur = step.saturating_sub(start);
                                    hold_count += 1;
                                    total_hold_steps += dur;
                                    holder_threads.insert(thread_id);
                                    // Strict `>` keeps the earliest-starting hold
                                    // on ties, for deterministic output.
                                    if dur > max_hold_steps {
                                        max_hold_steps = dur;
                                        longest_hold_thread = thread_id;
                                        longest_hold_start = start;
                                        longest_hold_end = step;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // A lock that only ever appeared as failed acquires / unmatched
            // events has no completed hold interval — skip it rather than emit a
            // zero-hold row that would clutter the report.
            if hold_count == 0 {
                continue;
            }

            let avg_hold_steps = total_hold_steps / hold_count;
            let mut holder_threads: Vec<u32> = holder_threads.into_iter().collect();
            holder_threads.sort_unstable();

            results.push(CriticalSectionStats {
                lock_address: self.sync_mechanism_for(lock_addr),
                hold_count,
                total_hold_steps,
                avg_hold_steps,
                max_hold_steps,
                longest_hold_thread,
                longest_hold_start,
                longest_hold_end,
                holder_threads,
            });
        }

        // Sort by aggregate held time (the lock whose critical sections dominate
        // first), tie-breaking on lock address so equal-hold locks come out in a
        // deterministic order rather than `lock_events` HashMap iteration order.
        results.sort_by(|a, b| {
            b.total_hold_steps
                .cmp(&a.total_hold_steps)
                .then(a.lock_address.addr.cmp(&b.lock_address.addr))
        });

        results
    }

    // ========================================================================
    // JNI boundary analysis
    // ============================================================================

    /// Summarize per-thread JNI boundary-crossing behavior (#67).
    ///
    /// Groups every recorded `JNICall` by thread and reports, for each, the total
    /// crossings, the Java→Native / Native→Java split, the distinct native
    /// functions reached, and the distinct Java methods involved — the core
    /// signals for Android SO reverse-engineering. A thread marked
    /// `is_jni_attached` in its metadata is included even with zero recorded
    /// crossings (an attached-but-idle thread is itself worth surfacing).
    /// Read-only over the fed `jni_calls`; no derived index needed. Output is
    /// sorted by thread id and every distinct set is sorted, so results are
    /// deterministic regardless of feed / HashMap iteration order (#46–#48).
    pub fn analyze_jni_boundary(&self) -> Vec<JniBoundaryStats> {
        // Per-thread accumulator.
        struct Acc {
            total: u64,
            j2n: u64,
            n2j: u64,
            native_addrs: HashSet<u64>,
            java_methods: HashSet<String>,
        }
        impl Acc {
            fn new() -> Self {
                Acc { total: 0, j2n: 0, n2j: 0, native_addrs: HashSet::new(), java_methods: HashSet::new() }
            }
        }

        let mut per_thread: HashMap<u32, Acc> = HashMap::new();

        // Seed threads the runtime marked JNI-attached so they appear even with
        // no captured crossings (surfacing the attached-but-idle anomaly).
        for (&tid, info) in &self.thread_info {
            if info.is_jni_attached {
                per_thread.entry(tid).or_insert_with(Acc::new);
            }
        }

        for calls in self.jni_calls.values() {
            for call in calls {
                let acc = per_thread.entry(call.thread_id).or_insert_with(Acc::new);
                acc.total += 1;
                match call.direction {
                    JNICallDirection::JavaToNative => acc.j2n += 1,
                    JNICallDirection::NativeToJava => acc.n2j += 1,
                }
                acc.native_addrs.insert(call.native_address);
                acc.java_methods.insert(format!("{}.{}", call.java_class, call.java_method));
            }
        }

        let mut results: Vec<JniBoundaryStats> = per_thread
            .into_iter()
            .map(|(thread_id, acc)| {
                let is_jni_attached = self
                    .thread_info
                    .get(&thread_id)
                    .map(|i| i.is_jni_attached)
                    .unwrap_or(false);
                let mut native_addresses: Vec<u64> = acc.native_addrs.into_iter().collect();
                native_addresses.sort_unstable();
                let native_functions: Vec<Option<String>> = native_addresses.iter().map(|_| None).collect();
                let mut java_methods: Vec<String> = acc.java_methods.into_iter().collect();
                java_methods.sort_unstable();
                JniBoundaryStats {
                    thread_id,
                    is_jni_attached,
                    total_crossings: acc.total,
                    java_to_native_count: acc.j2n,
                    native_to_java_count: acc.n2j,
                    native_addresses,
                    native_functions,
                    java_methods,
                }
            })
            .collect();

        results.sort_unstable_by_key(|s| s.thread_id);
        results
    }

    // ========================================================================
    // Thread-function association
    // ========================================================================

    /// Analyze thread-function associations
    ///
    /// Returns which threads called which functions and how many times.
    pub fn analyze_thread_function_assoc(&mut self) -> Vec<ThreadFunctionAssoc> {
        self.build_indexes();

        let mut results = Vec::new();

        for (&thread_id, functions) in &self.thread_functions {
            for (&func_addr, &call_count) in functions {
                // First/last call steps come from the precomputed range index
                // (min/max over all matching call events), not a per-pair rescan.
                let (first_call_step, last_call_step) = self
                    .call_step_range
                    .get(&(thread_id, func_addr))
                    .copied()
                    .unwrap_or((0, 0));

                results.push(ThreadFunctionAssoc {
                    thread_id,
                    function_address: func_addr,
                    function_name: None,
                    call_count,
                    first_call_step,
                    last_call_step,
                });
            }
        }

        // Sort by call count (highest first), tie-breaking on (thread, function)
        // so equal-count rows are ordered deterministically rather than by
        // `thread_functions` HashMap iteration order.
        results.sort_by(|a, b| {
            b.call_count
                .cmp(&a.call_count)
                .then((a.thread_id, a.function_address).cmp(&(b.thread_id, b.function_address)))
        });

        results
    }

    /// Classify function thread safety
    ///
    /// A function is:
    /// - **ThreadSafe**: called by multiple threads with proper synchronization
    /// - **PotentiallyUnsafe**: called by multiple threads, no sync observed
    /// - **Unsafe**: called by multiple threads AND race condition detected
    /// - **Unknown**: called by only one thread (can't determine)
    pub fn classify_function_thread_safety(&mut self) -> Vec<FunctionThreadSafety> {
        self.build_indexes();

        let races = self.detect_race_conditions();
        let mut race_functions: HashMap<u64, u32> = HashMap::new();

        // Map race conditions to functions
        for race in &races {
            if let Some(func) = self.get_active_function(race.first_thread, race.first_step) {
                *race_functions.entry(func).or_insert(0) += 1;
            }
            if let Some(func) = self.get_active_function(race.second_thread, race.second_step) {
                *race_functions.entry(func).or_insert(0) += 1;
            }
        }

        let mut results = Vec::new();

        for (&func_addr, threads) in &self.function_threads {
            let calling_thread_count = threads.len() as u32;
            let mut calling_threads: Vec<u32> = threads.iter().copied().collect();
            calling_threads.sort_unstable();
            let sync_count = self.function_sync_count.get(&func_addr).copied().unwrap_or(0);
            let race_count = race_functions.get(&func_addr).copied().unwrap_or(0);

            let safety = if calling_thread_count <= 1 {
                ThreadSafety::Unknown
            } else if race_count > 0 {
                ThreadSafety::Unsafe
            } else if sync_count > 0 {
                ThreadSafety::ThreadSafe
            } else {
                ThreadSafety::PotentiallyUnsafe
            };

            results.push(FunctionThreadSafety {
                function_address: func_addr,
                function_name: None,
                calling_thread_count,
                calling_threads,
                safety,
                race_count,
                sync_event_count: sync_count,
            });
        }

        // Sort: Unsafe first, then PotentiallyUnsafe, then Unknown, then
        // ThreadSafe; tie-break on function address so same-class rows are
        // deterministic rather than in `function_threads` HashMap order.
        results.sort_by(|a, b| {
            let order = |s: ThreadSafety| match s {
                ThreadSafety::Unsafe => 0,
                ThreadSafety::PotentiallyUnsafe => 1,
                ThreadSafety::Unknown => 2,
                ThreadSafety::ThreadSafe => 3,
            };
            order(a.safety)
                .cmp(&order(b.safety))
                .then(a.function_address.cmp(&b.function_address))
        });

        results
    }

    // ========================================================================
    // Thread data flow analysis
    // ========================================================================

    /// Analyze data flow between threads via shared memory
    ///
    /// Detects when one thread writes to memory and another thread
    /// reads from the same location, indicating inter-thread data flow.
    pub fn analyze_data_flows(&mut self) -> Vec<ThreadDataFlow> {
        self.build_indexes();

        let mut flows = Vec::new();

        // Use the cached, step-sorted writes (built in build_indexes).
        let writes: Vec<(u64, u32, u64, usize)> = self.sorted_writes.clone();

        for (w_step, w_tid, w_addr, w_size) in &writes {
            // Use the page index to scan only reads sharing a page with this write.
            for (r_step, r_tid, _r_addr, _r_size) in self.reads_overlapping(*w_addr, *w_size) {
                if r_tid == *w_tid { continue; } // Same thread
                if r_step <= *w_step { continue; } // Read before write

                let is_sync = self.has_sync_between(*w_tid, r_tid, *w_step, r_step);

                flows.push(ThreadDataFlow {
                    from_thread: *w_tid,
                    to_thread: r_tid,
                    address: *w_addr,
                    write_step: *w_step,
                    read_step: r_step,
                    is_synchronized: is_sync,
                });
            }
        }

        // Deduplicate: keep only one flow per (from_thread, to_thread, address, write_step) pair
        // This allows multiple cycles on the same address while removing exact duplicates
        let mut seen = HashSet::new();
        flows.retain(|flow| {
            let key = (flow.from_thread, flow.to_thread, flow.address, flow.write_step);
            seen.insert(key)
        });

        flows
    }

    /// Detect producer-consumer patterns
    ///
    /// A producer-consumer pattern is detected when:
    /// 1. Thread A repeatedly writes to a set of addresses
    /// 2. Thread B repeatedly reads from the same addresses
    /// 3. There is synchronization between produce and consume
    pub fn detect_producer_consumer(&mut self) -> Vec<ProducerConsumerPattern> {
        self.build_indexes();

        let flows = self.analyze_data_flows();

        // Group flows by (from_thread, to_thread)
        let mut flow_groups: HashMap<(u32, u32), Vec<&ThreadDataFlow>> = HashMap::new();
        for flow in &flows {
            flow_groups
                .entry((flow.from_thread, flow.to_thread))
                .or_default()
                .push(flow);
        }

        let mut patterns = Vec::new();

        for ((producer, consumer), group_flows) in &flow_groups {
            // Need at least 2 cycles to confirm a pattern
            if group_flows.len() < 2 {
                continue;
            }

            // Note: has_sync indicates whether synchronization exists between
            // producer and consumer — we report patterns regardless
            let _has_sync = group_flows.iter().any(|f| f.is_synchronized);

            // Collect the distinct shared addresses. A producer typically writes
            // the same slot every cycle, so the raw per-flow list repeats the
            // address once per cycle; report each address once, sorted for
            // deterministic output. `cycle_count` (below) still reflects the
            // number of produce-consume cycles, not the address count.
            let mut shared_addresses: Vec<u64> = group_flows.iter()
                .map(|f| f.address)
                .collect();
            shared_addresses.sort_unstable();
            shared_addresses.dedup();

            // Compute average latency
            let total_latency: u64 = group_flows.iter()
                .map(|f| f.read_step.saturating_sub(f.write_step))
                .sum();
            let avg_latency = total_latency / group_flows.len() as u64;

            // Find the sync mechanism (most common lock used between these threads)
            let sync_mechanism = self.find_sync_mechanism(*producer, *consumer);

            patterns.push(ProducerConsumerPattern {
                producer_thread: *producer,
                consumer_thread: *consumer,
                shared_addresses,
                cycle_count: group_flows.len() as u64,
                avg_latency_steps: avg_latency,
                sync_mechanism,
            });
        }

        // Sort by cycle count (most active patterns first), tie-breaking on the
        // (producer, consumer) pair so equal-count patterns are ordered
        // deterministically rather than by `flow_groups` HashMap iteration order.
        patterns.sort_by(|a, b| {
            b.cycle_count.cmp(&a.cycle_count).then(
                (a.producer_thread, a.consumer_thread)
                    .cmp(&(b.producer_thread, b.consumer_thread)),
            )
        });

        patterns
    }

    /// Find the primary synchronization mechanism between two threads.
    ///
    /// Returns the lock most used across these two threads, annotated with its
    /// primitive kind (looked up in `sync_types_by_addr`, built during
    /// `build_indexes`). Merges their precomputed per-thread lock-usage tallies
    /// instead of rescanning all sync events. Ties broken by lowest address for
    /// deterministic output. If the chosen address has no recorded kind (e.g.
    /// `build_indexes` not yet run), falls back to `Mutex` — the most common
    /// primitive — so the result is never a bare address.
    fn find_sync_mechanism(&self, thread_a: u32, thread_b: u32) -> Option<SyncMechanism> {
        // Find the lock most used across these two threads, merging their
        // precomputed per-thread lock-usage tallies instead of rescanning all
        // sync events. Ties broken by lowest address for deterministic output.
        let mut lock_usage: HashMap<u64, u64> = HashMap::new();
        for tid in [thread_a, thread_b] {
            if let Some(usage) = self.sync_locks_by_thread.get(&tid) {
                for (&addr, &count) in usage {
                    *lock_usage.entry(addr).or_insert(0) += count;
                }
            }
        }

        // Pick the most-used lock; on ties pick the LOWEST address so the
        // choice is deterministic and stable. `(count, Reverse(addr))` ordered
        // ascending-by-max_by means: highest count wins, and among equal counts
        // the smallest address wins (Reverse flips the addr ordering).
        lock_usage
            .into_iter()
            .max_by_key(|&(addr, count)| (count, std::cmp::Reverse(addr)))
            .map(|(addr, _)| self.sync_mechanism_for(addr))
    }

    /// Wrap a sync object address into a typed [`SyncMechanism`], looking up its
    /// primitive kind in `sync_types_by_addr` (built during `build_indexes`).
    /// If the address was never recorded (e.g. indexes not yet built, or an
    /// address that only ever appeared as a non-tallied event), falls back to
    /// `Mutex` — the most common primitive — so reports are never bare addresses.
    fn sync_mechanism_for(&self, addr: u64) -> SyncMechanism {
        SyncMechanism {
            addr,
            kind: self
                .sync_types_by_addr
                .get(&addr)
                .copied()
                .unwrap_or(SyncPrimitiveKind::Mutex),
        }
    }

    /// Summarize per-thread scheduling behavior from the context-switch stream.
    ///
    /// Turns the raw switch events into one row per thread: how often it was
    /// scheduled on/off, whether it left the CPU willingly (Yield / Blocking) or
    /// was forced off (Preemption / TimeSliceExpired / Interrupt), how many
    /// migrations landed it on a core, and which cores it ran on. This is the
    /// consumer for `context_switches`, which was otherwise collected but never
    /// analyzed.
    pub fn analyze_scheduling(&mut self) -> Vec<ThreadSchedulingStats> {
        // Per-thread accumulator. `cpu_cores` is a set so repeated runs on the
        // same core collapse to one entry.
        #[derive(Default)]
        struct Acc {
            scheduled_in: u64,
            scheduled_out: u64,
            voluntary: u64,
            involuntary: u64,
            migrations: u64,
            cores: HashSet<u32>,
        }
        let mut per_thread: HashMap<u32, Acc> = HashMap::new();

        // Iterate in (step, insertion) order — a BTreeMap<step, Vec<_>>. Order
        // does not affect the counts, but keeps traversal deterministic.
        for switches in self.context_switches.values() {
            for sw in switches {
                // The thread being scheduled OFF: classify why it left.
                let out = per_thread.entry(sw.from_thread).or_default();
                out.scheduled_out += 1;
                match sw.switch_reason {
                    SwitchReason::Yield | SwitchReason::Blocking => out.voluntary += 1,
                    SwitchReason::Preemption
                    | SwitchReason::TimeSliceExpired
                    | SwitchReason::Interrupt => out.involuntary += 1,
                    // Migration / Other are neither cleanly voluntary nor forced;
                    // they still count toward scheduled_out above.
                    _ => {}
                }

                // The thread being scheduled ON: it now runs on `cpu_core`.
                let in_acc = per_thread.entry(sw.to_thread).or_default();
                in_acc.scheduled_in += 1;
                if sw.switch_reason == SwitchReason::Migration {
                    in_acc.migrations += 1;
                }
                if let Some(core) = sw.cpu_core {
                    in_acc.cores.insert(core);
                }
            }
        }

        let mut results: Vec<ThreadSchedulingStats> = per_thread
            .into_iter()
            .map(|(thread_id, acc)| {
                let mut cpu_cores: Vec<u32> = acc.cores.into_iter().collect();
                cpu_cores.sort_unstable();
                ThreadSchedulingStats {
                    thread_id,
                    scheduled_in_count: acc.scheduled_in,
                    scheduled_out_count: acc.scheduled_out,
                    voluntary_switches: acc.voluntary,
                    involuntary_switches: acc.involuntary,
                    migration_count: acc.migrations,
                    cpu_cores,
                }
            })
            .collect();
        // Deterministic output regardless of HashMap iteration order.
        results.sort_unstable_by_key(|s| s.thread_id);
        results
    }

    /// Analyze thread lifecycle and reconstruct the spawn tree.
    ///
    /// Turns the per-thread `ThreadInfo` metadata into one row per thread: its
    /// parent, the children it spawned, its lifespan (create → exit), whether it
    /// is still alive, and its depth in the spawn tree. This consumes only
    /// `thread_info`, so — unlike most dimensions — it needs no index build.
    pub fn analyze_thread_lifecycle(&self) -> Vec<ThreadLifecycleInfo> {
        // Build the parent → children map in one pass. A thread is a child of
        // `p` when its `parent_thread_id == p`; parent 0 (the "no parent"
        // convention) and self-parenting (malformed) are not real edges.
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (&tid, info) in &self.thread_info {
            let parent = info.parent_thread_id;
            if parent != 0 && parent != tid {
                children.entry(parent).or_default().push(tid);
            }
        }

        let mut results: Vec<ThreadLifecycleInfo> = self
            .thread_info
            .iter()
            .map(|(&tid, info)| {
                let mut child_thread_ids = children.remove(&tid).unwrap_or_default();
                child_thread_ids.sort_unstable();

                // Lifespan is defined only when the thread exited AND the exit
                // step is not before creation (a malformed trace yields None
                // rather than an underflowed span).
                let lifespan = info
                    .exit_step
                    .and_then(|exit| exit.checked_sub(info.create_step));

                ThreadLifecycleInfo {
                    thread_id: tid,
                    parent_thread_id: info.parent_thread_id,
                    child_thread_ids,
                    create_step: info.create_step,
                    exit_step: info.exit_step,
                    lifespan,
                    is_alive: info.exit_step.is_none(),
                    tree_depth: self.spawn_tree_depth(tid),
                    name: info.name.clone().unwrap_or_default(),
                }
            })
            .collect();
        // Deterministic output regardless of HashMap iteration order.
        results.sort_unstable_by_key(|l| l.thread_id);
        results
    }

    /// Depth of `thread_id` in the spawn tree: 0 for a root, +1 per ancestor
    /// that is present in the trace.
    ///
    /// Walks the parent chain upward. A thread is a root when its parent is 0
    /// (the "no parent" convention), points at itself, or is absent from the
    /// trace (the parent was never recorded). A `seen` set guards against a
    /// malformed parent cycle so the walk always terminates.
    fn spawn_tree_depth(&self, thread_id: u32) -> u32 {
        let mut depth = 0u32;
        let mut cur = thread_id;
        let mut seen: HashSet<u32> = HashSet::new();
        while let Some(info) = self.thread_info.get(&cur) {
            let parent = info.parent_thread_id;
            // Root conditions: explicit no-parent, self-loop, or unknown parent.
            if parent == 0 || parent == cur || !self.thread_info.contains_key(&parent) {
                break;
            }
            // Cycle guard: if we have already visited `cur`, stop.
            if !seen.insert(cur) {
                break;
            }
            cur = parent;
            depth += 1;
        }
        depth
    }

    /// Analyze per-thread state residency and transitions.
    ///
    /// Consumes the `ThreadStateChange` stream (which the engine captures but no
    /// dimension surfaced before) to answer "where does each thread spend its
    /// time?". Each change marks the *start* of a state at its step; the interval
    /// runs until the thread's next change, or — for the last change — until the
    /// thread's recorded exit step. An unbounded trailing state (no next change,
    /// unknown exit) contributes nothing, so we never invent a duration.
    ///
    /// A thread mostly in `WaitingForLock` signals contention, mostly in
    /// `WaitingForIO` an I/O bottleneck, mostly `Running` CPU work — the
    /// `blocked_ratio` collapses this into one comparable number.
    pub fn analyze_thread_states(&self) -> Vec<ThreadStateStats> {
        // Group changes by thread, preserving step order. `state_changes` is a
        // BTreeMap keyed by step, so iterating its values yields ascending steps
        // and each per-thread list comes out already sorted.
        let mut per_thread: HashMap<u32, Vec<&ThreadStateChange>> = HashMap::new();
        for changes in self.state_changes.values() {
            for c in changes {
                per_thread.entry(c.thread_id).or_default().push(c);
            }
        }

        let mut results: Vec<ThreadStateStats> = per_thread
            .into_iter()
            .map(|(tid, changes)| {
                let transition_count = changes.len() as u64;
                let mut time: HashMap<&'static str, u64> = HashMap::new();
                let mut running_steps = 0u64;
                let mut waiting_steps = 0u64;

                for (i, c) in changes.iter().enumerate() {
                    // The interval that STARTS at this change is bounded by the
                    // next change, or (for the last one) by the thread's exit.
                    let end = if i + 1 < changes.len() {
                        Some(changes[i + 1].step)
                    } else {
                        self.thread_info.get(&tid).and_then(|info| info.exit_step)
                    };
                    // A missing or backwards bound yields 0 — never invent time.
                    let dur = end.map_or(0, |e| e.checked_sub(c.step).unwrap_or(0));
                    if dur == 0 {
                        continue;
                    }
                    *time.entry(c.new_state.name()).or_default() += dur;
                    if c.new_state == ThreadState::Running {
                        running_steps += dur;
                    }
                    if c.new_state.is_waiting() {
                        waiting_steps += dur;
                    }
                }

                let total_measured_steps: u64 = time.values().sum();
                let blocked_ratio = if total_measured_steps > 0 {
                    waiting_steps as f64 / total_measured_steps as f64
                } else {
                    0.0
                };
                let final_state = changes
                    .last()
                    .map(|c| c.new_state.name().to_string())
                    .unwrap_or_default();

                // Deterministic table ordering (per-state), independent of the
                // HashMap iteration order.
                let mut time_in_state: Vec<(String, u64)> =
                    time.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
                time_in_state.sort_by(|a, b| a.0.cmp(&b.0));

                ThreadStateStats {
                    thread_id: tid,
                    transition_count,
                    time_in_state,
                    running_steps,
                    waiting_steps,
                    total_measured_steps,
                    blocked_ratio,
                    final_state,
                }
            })
            .collect();

        // Deterministic output regardless of HashMap iteration order.
        results.sort_unstable_by_key(|s| s.thread_id);
        results
    }

    // ========================================================================
    // Full analysis
    // ========================================================================

    /// Run all analyses and return a comprehensive result
    pub fn analyze_all(&mut self) -> ThreadAnalysisResult {
        ThreadAnalysisResult {
            race_conditions: self.detect_race_conditions(),
            deadlock_risks: self.detect_deadlocks(),
            lock_contentions: self.analyze_lock_contention(),
            thread_function_assocs: self.analyze_thread_function_assoc(),
            function_safety: self.classify_function_thread_safety(),
            data_flows: self.analyze_data_flows(),
            producer_consumer_patterns: self.detect_producer_consumer(),
            scheduling: self.analyze_scheduling(),
            lifecycle: self.analyze_thread_lifecycle(),
            state_stats: self.analyze_thread_states(),
            critical_sections: self.analyze_critical_sections(),
            jni_boundary: self.analyze_jni_boundary(),
        }
    }

    /// Get thread info
    pub fn get_thread_info(&self, thread_id: u32) -> Option<&ThreadInfo> {
        self.thread_info.get(&thread_id)
    }

    /// Get all thread IDs
    pub fn all_thread_ids(&self) -> Vec<u32> {
        self.thread_info.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sotrace_core::models::thread::{ThreadInfo, SyncResult};

    fn make_thread_info(thread_id: u32, name: &str) -> ThreadInfo {
        ThreadInfo {
            thread_id,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: Some(name.to_string()),
            stack_base: 0x7F000000,
            stack_size: 8 * 1024 * 1024,
            tls_addr: 0,
            is_jni_attached: false,
        }
    }

    #[test]
    fn test_race_condition_detection() {
        let mut analyzer = ThreadAnalyzer::new();

        // Register threads
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes to address 0x1000 at step 100
        analyzer.feed_memory_write(100, 1, 0x1000, 4);

        // Thread 2 reads from address 0x1000 at step 200 (NO sync!)
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        assert_eq!(races[0].first_thread, 1);
        assert_eq!(races[0].second_thread, 2);
        assert_eq!(races[0].address, 0x1000);
        assert!(races[0].first_is_write);
        assert!(!races[0].second_is_write);
        // #112: access sizes and precise conflict range are now reported
        assert_eq!(races[0].first_access_size, 4);
        assert_eq!(races[0].second_access_size, 4);
        assert_eq!(races[0].overlap_address, 0x1000);
        assert_eq!(races[0].overlap_size, 4);
    }

    /// #112: when two accesses only partially overlap, the conflict range must
    /// be the *intersection*, not either access's full span. Thread 1 writes 8
    /// bytes at 0x5000 (0x5000-0x5007), thread 2 reads 8 bytes at 0x5004
    /// (0x5004-0x500B) — the real conflict is 0x5004-0x5007 (4 bytes).
    #[test]
    fn test_race_partial_overlap_conflict_range() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, 0x5000, 8);
        analyzer.feed_memory_read(200, 2, 0x5004, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert_eq!(r.first_access_size, 8);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x5004);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: write-write race also reports per-access sizes and the overlap.
    #[test]
    fn test_write_write_race_reports_access_sizes() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, 0x6000, 4);
        analyzer.feed_memory_write(200, 2, 0x6000, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert!(r.first_is_write && r.second_is_write);
        assert_eq!(r.first_access_size, 4);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x6000);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: read-then-write race reports the read's real address as first
    /// access size source, not the write's page-aligned address.
    #[test]
    fn test_read_then_write_race_reports_access_sizes() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_read(100, 1, 0x7004, 8);
        analyzer.feed_memory_write(200, 2, 0x7000, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert!(!r.first_is_write && r.second_is_write);
        assert_eq!(r.first_access_size, 8);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x7004);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: accesses near `u64::MAX` must not overflow when computing the
    /// overlap range (saturating arithmetic, mirroring `reads_overlapping`).
    /// With saturating end-points, an 8-byte write at `MAX-7` and an 8-byte
    /// read at `MAX-3` both have their end clamped to `MAX`, so the contended
    /// region is `[MAX-3, MAX)` = 3 bytes. The point of this test is that the
    /// computation does not panic/overflow, not the exact count.
    #[test]
    fn test_race_overlap_no_overflow_near_u64_max() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, u64::MAX - 7, 8);
        analyzer.feed_memory_read(200, 2, u64::MAX - 3, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert_eq!(r.overlap_address, u64::MAX - 3);
        // Saturating end clamps both ranges to MAX, so overlap is 3 bytes.
        assert_eq!(r.overlap_size, 3);
    }

    #[test]
    fn test_no_race_with_sync() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes to address 0x2000 at step 100
        analyzer.feed_memory_write(100, 1, 0x2000, 4);

        // Thread 1 releases mutex at step 150
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Thread 2 acquires same mutex at step 160
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 160, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });

        // Thread 2 reads from address 0x2000 at step 200
        analyzer.feed_memory_read(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        // Should detect no race because there is synchronization
        // (both threads touched the same mutex between write and read)
        assert!(races.is_empty() || races.iter().all(|r| r.address != 0x2000));
    }

    /// A `MutexLocked` event (frida emits it for a *successful* acquire, as
    /// opposed to `MutexLock` which is the attempt) is just as strong a sync
    /// signal as `MutexLock` — it proves the thread holds the lock. `has_sync_between`
    /// only recognizes a sync pair when at least one side is `is_acquire() ||
    /// is_release()`; `MutexLocked` is neither, so two threads that BOTH record
    /// only `MutexLocked` (no unlock, no attempt) on the same lock are treated as
    /// unsynchronized — a false race. This covers the frida path that stamps
    /// successful acquires as `MutexLocked` and nothing else.
    #[test]
    fn test_no_race_when_both_threads_only_emit_mutex_locked() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes to address 0x2000 at step 100.
        analyzer.feed_memory_write(100, 1, 0x2000, 4);

        // Thread 1 holds the mutex (MutexLocked) at step 150.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexLocked,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Thread 2 also acquires the SAME mutex (MutexLocked) at 160 — serialized.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 160, thread_id: 2,
            sync_type: SyncEventType::MutexLocked,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });

        // Thread 2 reads from address 0x2000 at step 200.
        analyzer.feed_memory_read(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(
            races.iter().all(|r| r.address != 0x2000),
            "MutexLocked is a real acquire — the write/read pair is serialized; got race: {races:?}"
        );
    }

    /// Two INDEPENDENT races between the same pair of threads on the same
    /// address — at different steps — must both be reported. The dedup key
    /// used to be `(address, first_thread, second_thread)`, which collapsed the
    /// second race onto the first and silently dropped it. For reverse
    /// engineering, repeated races on one address (e.g. a racy loop) are a
    /// strong signal, so losing the repetition loses real information.
    #[test]
    fn test_repeated_race_same_threads_address_not_deduped() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // First race: T1 writes 0x1000 @ step 100, T2 reads @ step 200.
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        // Second independent race, much later, same address + thread pair,
        // no synchronization in between.
        analyzer.feed_memory_write(500, 1, 0x1000, 4);
        analyzer.feed_memory_read(530, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        // Both (first_step, second_step) pairs must survive dedup.
        let pairs: Vec<(u64, u64)> = races
            .iter()
            .map(|r| (r.first_step, r.second_step))
            .collect();
        assert!(
            pairs.contains(&(100, 200)),
            "first race (100, 200) must be reported, got {pairs:?}"
        );
        assert!(
            pairs.contains(&(500, 530)),
            "second race (500, 530) must be reported, got {pairs:?}"
        );
    }

    #[test]
    fn test_deadlock_detection() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let lock_m1 = 0xABCD0000;
        let lock_m2 = 0xEF010000;

        // Thread 1: lock(M1) → lock(M2) (order: M1 → M2)
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_m1,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 200, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_m2,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Thread 2: lock(M2) → lock(M1) (order: M2 → M1) — VIOLATION!
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_m2,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 250, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_m1,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        let deadlocks = analyzer.detect_deadlocks();
        // Should detect a cycle in the lock graph
        assert!(!deadlocks.is_empty());
    }

    /// Deadlock detection must be invariant to the order sync events are fed.
    /// `lock_order` (per-thread acquisition sequence) and `lock_events` (folded
    /// by `is_lock_held_at`) are step-sorted in `build_indexes`, so a scrambled
    /// feed of the same A→B / B→A deadlock is still detected.
    #[test]
    fn test_deadlock_detection_out_of_order_feed() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // Intended step order: T1 A@10 then B@20; T2 B@15 then A@25 (A→B / B→A
        // cycle). Feed them badly scrambled — later steps first, threads mixed.
        analyzer.feed_sync_event(lock(25, 2, a));
        analyzer.feed_sync_event(lock(20, 1, b));
        analyzer.feed_sync_event(lock(15, 2, b));
        analyzer.feed_sync_event(lock(10, 1, a));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(!deadlocks.is_empty(), "scrambled feed of a real deadlock must still be detected");
    }

    /// A `MutexLocked` event (frida's "successful acquire") must count as holding
    /// the lock just like `MutexLock`. The acquire match in `lock_order`,
    /// `is_lock_held_at`, and `analyze_critical_sections` used to list only
    /// `MutexLock | MutexTryLock | RwLockRead | RwLockWrite`, so a trace that
    /// stamps successful acquires as `MutexLocked` (and nothing else) built no
    /// lock-hold state — the ABBA cycle below was MISSED. This mirrors the frida
    /// adapter path that maps `"mutexlocked"` to `SyncEventType::MutexLocked`.
    #[test]
    fn test_deadlock_detected_with_mutex_locked_acquires() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLocked,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // T1: hold A@10, then acquire B@20 while still holding A → A→B edge.
        analyzer.feed_sync_event(lock(10, 1, a));
        analyzer.feed_sync_event(lock(20, 1, b));
        // T2: hold B@15, then acquire A@25 while still holding B → B→A edge.
        analyzer.feed_sync_event(lock(15, 2, b));
        analyzer.feed_sync_event(lock(25, 2, a));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            !deadlocks.is_empty(),
            "MutexLocked acquires form a real ABBA cycle; got deadlocks: {deadlocks:?}"
        );
    }

    /// A thread that releases a lock before taking the next one has no nested
    /// hold, so no deadlock edge — even when the release is fed BEFORE the
    /// acquire it follows in step time. Guards against `is_lock_held_at` folding
    /// events in feed order (which would report the lock still held).
    #[test]
    fn test_no_false_deadlock_when_lock_released_out_of_order() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: lock A@10, UNLOCK A@15, lock B@20  → A not held when B taken.
        // T2: lock B@12, UNLOCK B@18, lock A@25  → B not held when A taken.
        // No nested holds → no cycle. Feed each thread's unlock BEFORE its lock.
        analyzer.feed_sync_event(ev(15, 1, a, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(18, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(12, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(25, 2, a, SyncEventType::MutexLock));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(deadlocks.is_empty(), "released locks must not fabricate a deadlock: {:?}", deadlocks);
    }

    /// A *failed* re-acquire must not count as holding the lock. T2 releases B,
    /// then a later trylock-B returns WouldBlock (it did NOT take B) before it
    /// acquires A. If `is_lock_held_at` treated that failed trylock as "held",
    /// it would fabricate a B→A edge and, with T1's A→B, a phantom ABBA cycle.
    #[test]
    fn test_no_false_deadlock_from_failed_reacquire() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType, res: SyncResult| {
            ThreadSyncEvent {
                step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
                result: res, wait_duration_ns: None,
            }
        };
        // T1: lock A@10, lock B@20 (holds both → real A→B edge).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock, SyncResult::Success));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock, SyncResult::Success));
        // T2: lock B@30 (success), UNLOCK B@35, trylock B@40 WouldBlock (FAILED —
        // does not hold B), then lock A@50. B is not held when A is taken, so
        // there must be NO B→A edge and NO cycle.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock, SyncResult::Success));
        analyzer.feed_sync_event(ev(35, 2, b, SyncEventType::MutexUnlock, SyncResult::Success));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexTryLock, SyncResult::WouldBlock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock, SyncResult::Success));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(deadlocks.is_empty(), "a failed trylock must not be treated as held: {:?}", deadlocks);
    }

    /// Control for the test above: with the SAME failed-trylock noise present,
    /// if T2 additionally holds B (successfully) while taking A, the B→A edge is
    /// real and the ABBA cycle must still be reported — the `result` guard must
    /// suppress only the failed acquire, not the genuine hold beside it.
    #[test]
    fn test_deadlock_detected_despite_failed_reacquire_noise() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType, res: SyncResult| {
            ThreadSyncEvent {
                step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
                result: res, wait_duration_ns: None,
            }
        };
        // T1: lock A@10, lock B@20 (real A→B).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock, SyncResult::Success));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock, SyncResult::Success));
        // T2: lock B@30 (success, and NEVER released), a failed trylock-B@40
        // WouldBlock (noise — already holds B), then lock A@50. B is genuinely
        // held across A's acquire → real B→A edge → cycle. The failed trylock
        // neither adds nor removes the hold.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock, SyncResult::Success));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexTryLock, SyncResult::WouldBlock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock, SyncResult::Success));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "a genuine hold beside failed-trylock noise keeps the deadlock real: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
    }

    /// A thread that sequentially re-acquires the SAME lock (lock B, unlock B,
    /// lock B again) must NOT produce a single-lock self-loop "cycle". Lock
    /// ordering is only meaningful between distinct locks; the re-acquire's own
    /// event would otherwise make `is_lock_held_at` report B held at its own
    /// step, fabricating a B→B edge. Here T1 forms a real A→B edge and T2
    /// re-locks B around it — only the genuine [a, b] cycle may be reported, and
    /// no bogus [b] self-cycle alongside it.
    #[test]
    fn test_no_self_loop_cycle_from_lock_reacquire() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: lock A@10, lock B@20 (real A→B edge).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock));
        // T2: lock B@30, unlock B@35, lock B@40 (sequential re-acquire — a (B,B)
        // pair that must be dropped), then lock A@50 while holding B → real B→A.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(35, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock));

        let deadlocks = analyzer.detect_deadlocks();
        // Exactly the genuine two-lock cycle, no single-lock self-loop.
        assert_eq!(deadlocks.len(), 1, "self-loop must not be reported alongside the real cycle: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
        assert!(
            deadlocks.iter().all(|d| d.lock_cycle.len() >= 2),
            "no single-lock self-cycle may appear: {:?}",
            deadlocks
        );
    }

    /// A recursively-held lock is still held after a SINGLE unlock. T2 locks B
    /// twice (recursive nesting, depth 2), unlocks B ONCE (back to depth 1 —
    /// still held), then acquires A while T1 holds the A→B order. B is genuinely
    /// held across A's acquire → real B→A edge → ABBA cycle. A bool-based
    /// `is_lock_held_at` would clear on the first unlock and MISS this deadlock
    /// (false negative); the depth counter tracks the nesting and reports it.
    #[test]
    fn test_deadlock_detected_with_recursive_lock_partial_unlock() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: lock A@10, lock B@20 (real A→B edge).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock));
        // T2: lock B@30, lock B@40 (recursive → depth 2), UNLOCK B@45 (depth 1,
        // STILL held), then lock A@50 while B is still held → real B→A edge.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(45, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "recursive lock still held after one unlock must keep the deadlock: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
    }

    /// Control for the recursive case: once BOTH nesting levels are released, the
    /// lock is free. T2 locks B twice (depth 2), unlocks B TWICE (depth 0 — no
    /// longer held), then acquires A. B is NOT held when A is taken → no B→A edge
    /// → no cycle. Guards the saturating counter against reporting a phantom
    /// hold when the unlocks fully balance the acquires.
    #[test]
    fn test_no_deadlock_when_recursive_lock_fully_unlocked() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: lock A@10, lock B@20 (real A→B edge).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock));
        // T2: lock B@30, lock B@40 (depth 2), UNLOCK B@45, UNLOCK B@48 (depth 0 —
        // fully released), then lock A@50. B not held when A taken → no cycle.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(45, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(48, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(deadlocks.is_empty(), "fully-released recursive lock must not fabricate a deadlock: {:?}", deadlocks);
    }

    /// Two threads read-locking the same pair of rwlocks in opposite order is
    /// NOT a deadlock: readers are mutually compatible, so neither acquire ever
    /// blocks. The analyzer must not fabricate a read-read ordering deadlock.
    #[test]
    fn test_no_false_deadlock_for_read_read_rwlock() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let rd = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::RwLockRead,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // T1: read-A@10, read-B@20 (A→B). T2: read-B@15, read-A@25 (B→A).
        // Shaped exactly like the mutex ABBA deadlock, but all read locks.
        analyzer.feed_sync_event(rd(10, 1, a));
        analyzer.feed_sync_event(rd(20, 1, b));
        analyzer.feed_sync_event(rd(15, 2, b));
        analyzer.feed_sync_event(rd(25, 2, a));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(deadlocks.is_empty(), "read-read opposite ordering is not a deadlock: {:?}", deadlocks);
    }

    /// When one of the two locks in an ABBA ordering is genuinely written
    /// (exclusive) by a thread, the acquire can block, so the deadlock is real
    /// and must still be reported — the read-lock exemption must not swallow it.
    #[test]
    fn test_deadlock_still_detected_when_one_lock_is_written() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0x1000u64;
        let b = 0x2000u64;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: write-A@10, write-B@20 (A→B, both exclusive).
        // T2: read-B@15, write-A@25 (B→A). B is written by T1, so B is
        // exclusive-capable: T2's read-B can block behind T1's write. Cycle real.
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::RwLockWrite));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::RwLockWrite));
        analyzer.feed_sync_event(ev(15, 2, b, SyncEventType::RwLockRead));
        analyzer.feed_sync_event(ev(25, 2, a, SyncEventType::RwLockWrite));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "an exclusive-capable lock in the cycle keeps the deadlock real: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
    }

    /// A single A↔B lock-order cycle must be reported exactly once, with a
    /// canonical (min-address-first) `lock_cycle` and sorted `threads` —
    /// regardless of HashMap/HashSet iteration order. Before the canonical
    /// dedup the same cycle surfaced as either `[a, b]` or `[b, a]` depending
    /// on which lock the DFS happened to root at.
    #[test]
    fn test_deadlock_cycle_is_canonical_and_unique() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0x1000u64; // smaller address → canonical cycle starts here
        let b = 0x2000u64;
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // T1: A then B (edge A→B). T2: B then A (edge B→A). Cycle A↔B.
        analyzer.feed_sync_event(lock(10, 1, a));
        analyzer.feed_sync_event(lock(20, 1, b));
        analyzer.feed_sync_event(lock(15, 2, b));
        analyzer.feed_sync_event(lock(25, 2, a));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "one cycle must be reported once, got {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b],
            "cycle must be min-address-first"
        );
        assert_eq!(deadlocks[0].threads, vec![1, 2], "threads must be sorted and deduped");

        // Deterministic: re-running yields byte-identical output.
        let again = analyzer.detect_deadlocks();
        assert_eq!(deadlocks[0].lock_cycle, again[0].lock_cycle);
        assert_eq!(deadlocks[0].threads, again[0].threads);
    }

    /// Two DISTINCT lock-order cycles that share a node must BOTH be reported.
    /// Graph: A→B, A→C, B→D, C→D, D→A → cycles A→B→D→A and A→C→D→A share
    /// node D and edge D→A. A DFS with a permanent `visited` black-set marks D
    /// visited on the B-branch, then returns early when the C-branch reaches D,
    /// silently dropping the second deadlock. For a deadlock *detector*, a missed
    /// cycle is a false negative — the costly kind. Both must surface.
    #[test]
    fn test_two_cycles_sharing_a_node_both_reported() {
        let mut analyzer = ThreadAnalyzer::new();
        for tid in 1..=5 {
            analyzer.feed_thread_info(make_thread_info(tid, "t"));
        }
        let (a, b, c, d) = (0x1000u64, 0x2000u64, 0x3000u64, 0x4000u64);
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // Each thread acquires exactly two locks in order → exactly one edge,
        // so the graph is precisely {A→B, A→C, B→D, C→D, D→A} and nothing else.
        analyzer.feed_sync_event(lock(10, 1, a)); // T1: A→B
        analyzer.feed_sync_event(lock(11, 1, b));
        analyzer.feed_sync_event(lock(20, 2, a)); // T2: A→C
        analyzer.feed_sync_event(lock(21, 2, c));
        analyzer.feed_sync_event(lock(30, 3, b)); // T3: B→D
        analyzer.feed_sync_event(lock(31, 3, d));
        analyzer.feed_sync_event(lock(40, 4, c)); // T4: C→D
        analyzer.feed_sync_event(lock(41, 4, d));
        analyzer.feed_sync_event(lock(50, 5, d)); // T5: D→A
        analyzer.feed_sync_event(lock(51, 5, a));

        let mut cycles: Vec<Vec<u64>> =
            analyzer.detect_deadlocks().into_iter()
                .map(|d| d.lock_cycle.into_iter().map(|m| m.addr).collect())
                .collect();
        cycles.sort();
        assert_eq!(
            cycles,
            vec![vec![a, b, d], vec![a, c, d]],
            "both node-sharing cycles must be reported, got {:?}",
            cycles
        );
    }

    /// `violation_steps` must point at the precise events that form the cycle —
    /// the involved threads' acquisitions of the *cycle's* locks — not every
    /// lock a thread ever touched. A cycle thread that also grabs an unrelated
    /// lock must not have that unrelated acquisition leak into the report.
    #[test]
    fn test_violation_steps_are_scoped_to_cycle_locks() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0x1000u64;
        let b = 0x2000u64;
        let unrelated = 0x9000u64; // not part of the A↔B cycle
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // T1: A@10, B@20 (A→B). T2: B@30, A@40 (B→A). Cycle A↔B, steps 10/20/30/40.
        analyzer.feed_sync_event(lock(10, 1, a));
        analyzer.feed_sync_event(lock(20, 1, b));
        analyzer.feed_sync_event(lock(30, 2, b));
        analyzer.feed_sync_event(lock(40, 2, a));
        // T1 also grabs an unrelated lock at step 99 — must NOT appear in the report.
        analyzer.feed_sync_event(lock(99, 1, unrelated));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "one A↔B cycle expected: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].violation_steps,
            vec![10, 20, 30, 40],
            "only cycle-lock acquisitions belong in violation_steps (step 99 is unrelated)"
        );
    }

    fn make_switch(
        step: u64,
        from: u32,
        to: u32,
        reason: SwitchReason,
        core: Option<u32>,
    ) -> ContextSwitch {
        ContextSwitch { step, from_thread: from, to_thread: to, switch_reason: reason, cpu_core: core }
    }

    /// `analyze_scheduling` must classify each switch-out as voluntary
    /// (Yield/Blocking) or involuntary (Preemption/TimeSliceExpired/Interrupt),
    /// count migrations onto a core, and collect the distinct cores a thread ran
    /// on — all deterministically ordered by thread id.
    #[test]
    fn test_scheduling_classifies_switch_reasons() {
        let mut analyzer = ThreadAnalyzer::new();
        for tid in 1..=3 {
            analyzer.feed_thread_info(make_thread_info(tid, "t"));
        }
        // T1 preempted off → T2 on core 0
        analyzer.feed_context_switch(make_switch(10, 1, 2, SwitchReason::Preemption, Some(0)));
        // T2 yields off → T1 on core 0
        analyzer.feed_context_switch(make_switch(20, 2, 1, SwitchReason::Yield, Some(0)));
        // T1 blocks off → T3 on core 1
        analyzer.feed_context_switch(make_switch(30, 1, 3, SwitchReason::Blocking, Some(1)));
        // T3 off → T1 migrated onto core 2
        analyzer.feed_context_switch(make_switch(40, 3, 1, SwitchReason::Migration, Some(2)));

        let stats = analyzer.analyze_scheduling();
        // Sorted by thread_id: T1, T2, T3.
        let ids: Vec<u32> = stats.iter().map(|s| s.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3], "output must be ordered by thread id");

        let t1 = &stats[0];
        assert_eq!(t1.scheduled_in_count, 2); // steps 20, 40
        assert_eq!(t1.scheduled_out_count, 2); // steps 10, 30
        assert_eq!(t1.voluntary_switches, 1); // Blocking@30
        assert_eq!(t1.involuntary_switches, 1); // Preemption@10
        assert_eq!(t1.migration_count, 1); // Migration@40 landed on T1
        assert_eq!(t1.cpu_cores, vec![0, 2]); // ran on core 0 (@20) and 2 (@40)

        let t2 = &stats[1];
        assert_eq!(t2.scheduled_in_count, 1);
        assert_eq!(t2.scheduled_out_count, 1);
        assert_eq!(t2.voluntary_switches, 1); // Yield@20
        assert_eq!(t2.involuntary_switches, 0);
        assert_eq!(t2.migration_count, 0);
        assert_eq!(t2.cpu_cores, vec![0]);

        let t3 = &stats[2];
        assert_eq!(t3.scheduled_in_count, 1);
        assert_eq!(t3.scheduled_out_count, 1);
        // Migration as a switch-*out* reason is neither voluntary nor forced.
        assert_eq!(t3.voluntary_switches, 0);
        assert_eq!(t3.involuntary_switches, 0);
        assert_eq!(t3.migration_count, 0); // it was migrated *off*, not onto a core
        assert_eq!(t3.cpu_cores, vec![1]);
    }

    /// Two context switches at the SAME step (two cores switching at once) must
    /// both be counted. A step is not unique, so a keyed insert would drop one —
    /// this pins the `Vec`-per-step retention (same bug class as #49/#52).
    #[test]
    fn test_scheduling_same_step_switches_both_counted() {
        let mut analyzer = ThreadAnalyzer::new();
        for tid in 1..=4 {
            analyzer.feed_thread_info(make_thread_info(tid, "t"));
        }
        // Both at step 100 — an old BTreeMap<step, ContextSwitch> would keep only
        // the second, losing T1/T2 entirely.
        analyzer.feed_context_switch(make_switch(100, 1, 2, SwitchReason::Preemption, Some(0)));
        analyzer.feed_context_switch(make_switch(100, 3, 4, SwitchReason::Preemption, Some(1)));

        let stats = analyzer.analyze_scheduling();
        let ids: Vec<u32> = stats.iter().map(|s| s.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4], "all four threads from both same-step switches survive");
        assert_eq!(stats[0].scheduled_out_count, 1); // T1 switched out
        assert_eq!(stats[1].scheduled_in_count, 1); // T2 switched in
        assert_eq!(stats[2].scheduled_out_count, 1); // T3 switched out
        assert_eq!(stats[3].scheduled_in_count, 1); // T4 switched in
    }

    /// Build a thread info with an explicit parent and lifespan for lifecycle tests.
    fn make_lifecycle_info(
        thread_id: u32,
        parent: u32,
        create_step: u64,
        exit_step: Option<u64>,
    ) -> ThreadInfo {
        ThreadInfo {
            thread_id,
            pthread_id: None,
            parent_thread_id: parent,
            create_step,
            exit_step,
            name: Some(format!("t{thread_id}")),
            stack_base: 0x7F000000,
            stack_size: 8 * 1024 * 1024,
            tls_addr: 0,
            is_jni_attached: false,
        }
    }

    /// The spawn tree is reconstructed from `parent_thread_id`: each parent lists
    /// its children (sorted), and a child records its parent.
    #[test]
    fn test_lifecycle_spawn_tree_children() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, None)); // root
        analyzer.feed_thread_info(make_lifecycle_info(3, 1, 10, None)); // child of 1
        analyzer.feed_thread_info(make_lifecycle_info(2, 1, 5, None)); // child of 1

        let life = analyzer.analyze_thread_lifecycle();
        // Sorted by thread_id regardless of feed order.
        let ids: Vec<u32> = life.iter().map(|l| l.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);

        let root = &life[0];
        assert_eq!(root.thread_id, 1);
        assert_eq!(root.parent_thread_id, 0);
        // Children are sorted ascending.
        assert_eq!(root.child_thread_ids, vec![2, 3]);
        assert_eq!(root.tree_depth, 0);

        // Each child points back at parent 1 and has no children of its own.
        assert_eq!(life[1].parent_thread_id, 1);
        assert!(life[1].child_thread_ids.is_empty());
        assert_eq!(life[1].tree_depth, 1);
        assert_eq!(life[2].parent_thread_id, 1);
    }

    /// Lifespan and liveness derive from create/exit steps: an exited thread has
    /// `Some(exit - create)` and is not alive; a running thread has `None` and is
    /// alive.
    #[test]
    fn test_lifecycle_lifespan_and_liveness() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 100, Some(400))); // exited
        analyzer.feed_thread_info(make_lifecycle_info(2, 0, 50, None)); // still alive

        let life = analyzer.analyze_thread_lifecycle();
        let exited = life.iter().find(|l| l.thread_id == 1).unwrap();
        assert_eq!(exited.lifespan, Some(300));
        assert!(!exited.is_alive);
        assert_eq!(exited.exit_step, Some(400));

        let alive = life.iter().find(|l| l.thread_id == 2).unwrap();
        assert_eq!(alive.lifespan, None);
        assert!(alive.is_alive);
        assert_eq!(alive.exit_step, None);
    }

    /// Tree depth counts present ancestors: a three-level chain 1 → 2 → 3 yields
    /// depths 0, 1, 2.
    #[test]
    fn test_lifecycle_tree_depth_multilevel() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, None));
        analyzer.feed_thread_info(make_lifecycle_info(2, 1, 1, None));
        analyzer.feed_thread_info(make_lifecycle_info(3, 2, 2, None));

        let life = analyzer.analyze_thread_lifecycle();
        assert_eq!(life[0].tree_depth, 0); // thread 1, root
        assert_eq!(life[1].tree_depth, 1); // thread 2
        assert_eq!(life[2].tree_depth, 2); // thread 3
    }

    /// An orphan whose parent was never recorded is treated as a root (depth 0),
    /// and it is not attributed as anyone's child.
    #[test]
    fn test_lifecycle_unknown_parent_is_root() {
        let mut analyzer = ThreadAnalyzer::new();
        // Parent 99 is never fed.
        analyzer.feed_thread_info(make_lifecycle_info(5, 99, 0, None));

        let life = analyzer.analyze_thread_lifecycle();
        assert_eq!(life.len(), 1);
        assert_eq!(life[0].thread_id, 5);
        assert_eq!(life[0].parent_thread_id, 99); // recorded as-is
        assert_eq!(life[0].tree_depth, 0); // but treated as a root
        assert!(life[0].child_thread_ids.is_empty());
    }

    /// A malformed exit step before creation yields `None` lifespan (no underflow)
    /// rather than a wrapped huge span.
    #[test]
    fn test_lifecycle_malformed_exit_before_create() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 500, Some(200))); // exit < create

        let life = analyzer.analyze_thread_lifecycle();
        assert_eq!(life[0].lifespan, None);
        // Still marked not-alive because an exit step is present.
        assert!(!life[0].is_alive);
    }

    /// A parent cycle (1 → 2 → 1) does not hang: the `seen` guard terminates the
    /// depth walk.
    #[test]
    fn test_lifecycle_parent_cycle_guard() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 2, 0, None));
        analyzer.feed_thread_info(make_lifecycle_info(2, 1, 0, None));

        // Must terminate; depth is bounded by the number of threads.
        let life = analyzer.analyze_thread_lifecycle();
        assert_eq!(life.len(), 2);
        for l in &life {
            assert!(l.tree_depth <= 2);
        }
    }

    fn make_state_change(step: u64, thread_id: u32, new_state: ThreadState) -> ThreadStateChange {
        ThreadStateChange {
            step,
            thread_id,
            new_state,
            prev_state: None,
            prev_running_thread: None,
        }
    }

    /// State residency accumulates the interval between consecutive changes,
    /// attributing it to the earlier state; the final open interval is bounded by
    /// the thread's exit step.
    #[test]
    fn test_state_residency_across_transitions() {
        let mut analyzer = ThreadAnalyzer::new();
        // Thread 1 exits at step 100 so the final Running interval is bounded.
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, Some(100)));
        analyzer.feed_state_change(make_state_change(0, 1, ThreadState::Running));
        analyzer.feed_state_change(make_state_change(30, 1, ThreadState::WaitingForLock));
        analyzer.feed_state_change(make_state_change(50, 1, ThreadState::Running));

        let stats = analyzer.analyze_thread_states();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert_eq!(s.thread_id, 1);
        assert_eq!(s.transition_count, 3);
        // Running: 0→30 (30) + 50→100 (50) = 80; WaitingForLock: 30→50 (20).
        assert_eq!(s.running_steps, 80);
        assert_eq!(s.waiting_steps, 20);
        assert_eq!(s.total_measured_steps, 100);
        assert!((s.blocked_ratio - 0.2).abs() < 1e-9);
        assert_eq!(s.final_state, "Running");
        // time_in_state is sorted by state name.
        assert_eq!(
            s.time_in_state,
            vec![
                ("Running".to_string(), 80),
                ("WaitingForLock".to_string(), 20),
            ]
        );
    }

    /// Two threads changing state at the same step are both tracked (step is not
    /// unique — the per-step `Vec` must not overwrite).
    #[test]
    fn test_state_same_step_multi_thread() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, Some(20)));
        analyzer.feed_thread_info(make_lifecycle_info(2, 0, 0, Some(20)));
        // Both threads change at step 0 and again at step 10.
        analyzer.feed_state_change(make_state_change(0, 1, ThreadState::Running));
        analyzer.feed_state_change(make_state_change(0, 2, ThreadState::WaitingForIO));
        analyzer.feed_state_change(make_state_change(10, 1, ThreadState::Sleeping));
        analyzer.feed_state_change(make_state_change(10, 2, ThreadState::Running));

        let stats = analyzer.analyze_thread_states();
        assert_eq!(stats.len(), 2);
        // Thread 1: Running 0→10 (10), Sleeping 10→20 (10).
        let t1 = stats.iter().find(|s| s.thread_id == 1).unwrap();
        assert_eq!(t1.running_steps, 10);
        assert_eq!(t1.waiting_steps, 0);
        assert_eq!(t1.total_measured_steps, 20);
        // Thread 2: WaitingForIO 0→10 (10, waiting), Running 10→20 (10).
        let t2 = stats.iter().find(|s| s.thread_id == 2).unwrap();
        assert_eq!(t2.running_steps, 10);
        assert_eq!(t2.waiting_steps, 10);
        assert!((t2.blocked_ratio - 0.5).abs() < 1e-9);
    }

    /// A trailing state with no following change and no known exit step is
    /// unbounded, so it contributes zero measured time (we never invent duration).
    #[test]
    fn test_state_unbounded_trailing_contributes_nothing() {
        let mut analyzer = ThreadAnalyzer::new();
        // No exit step → the final interval is unbounded.
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, None));
        analyzer.feed_state_change(make_state_change(0, 1, ThreadState::Running));
        analyzer.feed_state_change(make_state_change(40, 1, ThreadState::WaitingForFutex));

        let stats = analyzer.analyze_thread_states();
        let s = &stats[0];
        // Only the bounded first interval (0→40) counts; the trailing wait is open.
        assert_eq!(s.running_steps, 40);
        assert_eq!(s.waiting_steps, 0);
        assert_eq!(s.total_measured_steps, 40);
        assert_eq!(s.transition_count, 2);
        assert_eq!(s.final_state, "WaitingForFutex");
    }

    /// A single state change yields zero measured steps (no interval to bound
    /// against) but still records the transition and final state.
    #[test]
    fn test_state_single_change_yields_zero_measured() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, None));
        analyzer.feed_state_change(make_state_change(5, 1, ThreadState::Blocked));

        let stats = analyzer.analyze_thread_states();
        let s = &stats[0];
        assert_eq!(s.transition_count, 1);
        assert_eq!(s.total_measured_steps, 0);
        assert_eq!(s.blocked_ratio, 0.0);
        assert!(s.time_in_state.is_empty());
        assert_eq!(s.final_state, "Blocked");
    }

    /// Output is sorted by thread_id regardless of feed order (determinism).
    #[test]
    fn test_state_stats_sorted_by_thread_id() {
        let mut analyzer = ThreadAnalyzer::new();
        for tid in [3u32, 1, 2] {
            analyzer.feed_thread_info(make_lifecycle_info(tid, 0, 0, Some(10)));
            analyzer.feed_state_change(make_state_change(0, tid, ThreadState::Running));
            analyzer.feed_state_change(make_state_change(10, tid, ThreadState::Terminated));
        }
        let stats = analyzer.analyze_thread_states();
        let ids: Vec<u32> = stats.iter().map(|s| s.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    /// `canonicalize_cycle` rotates any entry rotation of a directed cycle to
    /// start at its minimum element while preserving edge order.
    #[test]
    fn test_canonicalize_cycle_rotation() {
        assert_eq!(canonicalize_cycle(&[3, 1, 2]), vec![1, 2, 3]);
        assert_eq!(canonicalize_cycle(&[2, 3, 1]), vec![1, 2, 3]);
        assert_eq!(canonicalize_cycle(&[1, 2, 3]), vec![1, 2, 3]);
        // Edge order is preserved, not sorted: 1→3→2→1 stays 1,3,2.
        assert_eq!(canonicalize_cycle(&[3, 2, 1]), vec![1, 3, 2]);
        assert_eq!(canonicalize_cycle(&[5]), vec![5]);
        assert_eq!(canonicalize_cycle(&[]), Vec::<u64>::new());
    }

    #[test]
    fn test_lock_contention_analysis() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let mutex_addr = 0xABCD0000;

        // Thread 1 acquires mutex (no contention)
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Thread 2 acquires same mutex (contended, 5ms wait)
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 200, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(5_000_000), // 5ms
        });

        let contentions = analyzer.analyze_lock_contention();
        assert!(!contentions.is_empty());

        let mutex_contention = contentions.iter()
            .find(|c| c.lock_address.addr == mutex_addr)
            .unwrap();
        assert_eq!(mutex_contention.acquire_count, 2);
        assert!(mutex_contention.contention_count >= 1);
    }

    /// `analyze_critical_sections` and `analyze_lock_contention` must count a
    /// `MutexLocked` (frida's successful acquire) the same as a `MutexLock`:
    /// the acquire match used to list only `MutexLock | MutexTryLock |
    /// RwLockRead | RwLockWrite`, so a `MutexLocked`+`MutexUnlock` pair opened
    /// no hold interval (critical-section stats missed it) and was not tallied
    /// as an acquisition (contention stats missed it).
    #[test]
    fn test_critical_section_and_contention_count_mutex_locked() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));

        let lock_addr = 0xDEAD0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1 acquires (MutexLocked) @10, releases @20 — a 10-step hold.
        analyzer.feed_sync_event(ev(10, 1, lock_addr, SyncEventType::MutexLocked));
        analyzer.feed_sync_event(ev(20, 1, lock_addr, SyncEventType::MutexUnlock));

        let cs = analyzer.analyze_critical_sections();
        let cs_lock = cs.iter().find(|c| c.lock_address.addr == lock_addr).unwrap();
        assert_eq!(cs_lock.hold_count, 1, "MutexLocked+Unlock is one hold interval");
        assert_eq!(cs_lock.max_hold_steps, 10);
        assert_eq!(cs_lock.holder_threads, vec![1]);

        let ct = analyzer.analyze_lock_contention();
        let ct_lock = ct.iter().find(|c| c.lock_address.addr == lock_addr).unwrap();
        assert_eq!(ct_lock.acquire_count, 1, "MutexLocked counts as an acquisition");
    }

    /// Locks with equal contention ratio must be ordered deterministically by
    /// address (not `lock_events` HashMap order), and each lock's
    /// `contending_threads` must be sorted regardless of the feed order.
    #[test]
    fn test_lock_contention_is_deterministic() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let lock_hi = 0xBBBB_0000u64;
        let lock_lo = 0x1111_0000u64;
        let contended = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(1_000_000), // non-zero wait → contended
        };
        // Feed the high-address lock first so HashMap order would tend to place
        // it first; both locks end at contention_ratio == 1.0 (every acquire
        // contended). lock_lo is contended by thread 2 then thread 1.
        analyzer.feed_sync_event(contended(10, 1, lock_hi));
        analyzer.feed_sync_event(contended(20, 2, lock_lo));
        analyzer.feed_sync_event(contended(30, 1, lock_lo));

        let contentions = analyzer.analyze_lock_contention();
        assert_eq!(contentions.len(), 2);
        // Equal ratio (1.0 each) → ascending address order: lock_lo before lock_hi.
        assert_eq!(contentions[0].lock_address.addr, lock_lo);
        assert_eq!(contentions[1].lock_address.addr, lock_hi);
        // Threads that contended on lock_lo are sorted despite reverse feed.
        assert_eq!(contentions[0].contending_threads, vec![1, 2]);
    }

    // ------------------------------------------------------------------------
    // Critical-section / lock hold-time analysis (#66)
    // ------------------------------------------------------------------------

    /// Build a sync event for the hold-time tests. Successful by default; the
    /// hold-time analyzer only cares about type/step/thread/result.
    fn hold_ev(step: u64, tid: u32, addr: u64, ty: SyncEventType) -> ThreadSyncEvent {
        ThreadSyncEvent {
            step,
            thread_id: tid,
            sync_type: ty,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }
    }

    /// #111: contention and critical-section reports must type the lock with its
    /// primitive kind, not a bare address. A futex-backed lock yields kind: Futex
    /// in both `LockContentionInfo.lock_address` and `CriticalSectionStats.lock_address`.
    #[test]
    fn test_contention_and_critical_section_kind_is_futex() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        let futex_word = 0xF071_0000u64;
        // Acquire then release a futex word once → one hold interval + one acquire.
        analyzer.feed_sync_event(hold_ev(10, 1, futex_word, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(50, 1, futex_word, SyncEventType::FutexWake));

        let contentions = analyzer.analyze_lock_contention();
        let ct = contentions.iter().find(|c| c.lock_address.addr == futex_word).unwrap();
        assert_eq!(ct.lock_address.kind, SyncPrimitiveKind::Futex);

        let cs = analyzer.analyze_critical_sections();
        let cs_lock = cs.iter().find(|c| c.lock_address.addr == futex_word).unwrap();
        assert_eq!(cs_lock.lock_address.kind, SyncPrimitiveKind::Futex);
    }

    /// A single acquire→release pair yields one hold interval spanning the two
    /// steps, with the span attributed to the holding thread.
    #[test]
    fn test_critical_section_basic_hold() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xABCD_0000u64;

        analyzer.feed_sync_event(hold_ev(100, 1, lock, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(130, 1, lock, SyncEventType::MutexUnlock));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c.lock_address.addr, lock);
        assert_eq!(c.hold_count, 1);
        assert_eq!(c.total_hold_steps, 30);
        assert_eq!(c.avg_hold_steps, 30);
        assert_eq!(c.max_hold_steps, 30);
        assert_eq!(c.longest_hold_thread, 1);
        assert_eq!(c.longest_hold_start, 100);
        assert_eq!(c.longest_hold_end, 130);
        assert_eq!(c.holder_threads, vec![1]);
    }

    /// A recursively-acquired lock (nested acquire before the matching unlocks)
    /// is ONE hold interval spanning the outermost acquire to the outermost
    /// release — not two. A bool-based "held" flag would close the interval on
    /// the first unlock and under-report the true critical-section length.
    #[test]
    fn test_critical_section_recursive_is_single_interval() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x1111_0000u64;

        analyzer.feed_sync_event(hold_ev(100, 1, lock, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(110, 1, lock, SyncEventType::MutexLock)); // nested
        analyzer.feed_sync_event(hold_ev(120, 1, lock, SyncEventType::MutexUnlock)); // inner
        analyzer.feed_sync_event(hold_ev(140, 1, lock, SyncEventType::MutexUnlock)); // outer

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c.hold_count, 1, "nested re-acquire must not open a second interval");
        assert_eq!(c.total_hold_steps, 40, "held from outermost acquire (100) to outermost release (140)");
        assert_eq!(c.max_hold_steps, 40);
        assert_eq!(c.longest_hold_start, 100);
        assert_eq!(c.longest_hold_end, 140);
    }

    /// An acquire never matched by a release is an unbounded hold — it invents no
    /// duration and produces no row (mirrors trailing-state handling in #65).
    #[test]
    fn test_critical_section_unreleased_contributes_nothing() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x2222_0000u64;

        analyzer.feed_sync_event(hold_ev(100, 1, lock, SyncEventType::MutexLock));
        // no unlock

        let cs = analyzer.analyze_critical_sections();
        assert!(cs.is_empty(), "an unreleased lock has no completed hold: {:?}", cs);
    }

    /// A failed acquire (trylock WouldBlock) never held the lock, so a following
    /// stray unlock must not fabricate a hold interval or underflow the depth.
    #[test]
    fn test_critical_section_failed_acquire_not_held() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x3333_0000u64;

        let mut fail = hold_ev(100, 1, lock, SyncEventType::MutexTryLock);
        fail.result = SyncResult::WouldBlock;
        analyzer.feed_sync_event(fail);
        analyzer.feed_sync_event(hold_ev(110, 1, lock, SyncEventType::MutexUnlock)); // stray

        let cs = analyzer.analyze_critical_sections();
        assert!(cs.is_empty(), "a WouldBlock acquire never held the lock: {:?}", cs);
    }

    /// Two locks, each held once, must sort by aggregate hold time (longest-held
    /// first), tie-broken by address; a lock held by several threads lists them
    /// sorted regardless of feed order.
    #[test]
    fn test_critical_section_sort_and_multi_thread() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        let lock_short = 0x1000_0000u64; // low address, short hold
        let lock_long = 0x9000_0000u64;  // high address, long hold

        // lock_short: thread 2 holds 10 steps, then thread 1 holds 10 steps.
        analyzer.feed_sync_event(hold_ev(10, 2, lock_short, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(20, 2, lock_short, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(hold_ev(30, 1, lock_short, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(40, 1, lock_short, SyncEventType::MutexUnlock));
        // lock_long: thread 1 holds 100 steps.
        analyzer.feed_sync_event(hold_ev(0, 1, lock_long, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(100, 1, lock_long, SyncEventType::MutexUnlock));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 2);
        // Longest aggregate hold first: lock_long (100) before lock_short (20).
        assert_eq!(cs[0].lock_address.addr, lock_long);
        assert_eq!(cs[0].total_hold_steps, 100);
        assert_eq!(cs[1].lock_address.addr, lock_short);
        assert_eq!(cs[1].hold_count, 2);
        assert_eq!(cs[1].total_hold_steps, 20);
        assert_eq!(cs[1].avg_hold_steps, 10);
        // Both threads completed a hold; listed sorted despite thread 2 first.
        assert_eq!(cs[1].holder_threads, vec![1, 2]);
    }

    /// Acquire and release at the SAME step (steps come from `trace.seq` and are
    /// not unique) is still a completed hold — counted with a zero-step span,
    /// not dropped.
    #[test]
    fn test_critical_section_same_step_hold_counts() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x4444_0000u64;

        analyzer.feed_sync_event(hold_ev(50, 1, lock, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(50, 1, lock, SyncEventType::MutexUnlock));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].hold_count, 1, "same-step acquire/release is a real completed hold");
        assert_eq!(cs[0].total_hold_steps, 0);
    }

    /// A single acquisition that both waited AND timed out is one contended
    /// attempt, not two. It must count once so `contention_count` never exceeds
    /// `acquire_count` and the ratio stays within [0, 1].
    #[test]
    fn test_contention_waited_and_timeout_counts_once() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));

        let lock = 0xCAFE_0000u64;
        // One timed lock: it waited 3ms then timed out (both contention signals).
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock,
            result: SyncResult::Timeout,
            wait_duration_ns: Some(3_000_000),
        });

        let contentions = analyzer.analyze_lock_contention();
        let info = contentions.iter().find(|c| c.lock_address.addr == lock).unwrap();
        assert_eq!(info.acquire_count, 1);
        assert_eq!(info.contention_count, 1, "waited+timeout must count once, not twice");
        assert!(info.contention_ratio <= 1.0, "ratio must stay within [0,1]: {}", info.contention_ratio);
        assert_eq!(info.max_wait_ns, 3_000_000);
        assert_eq!(info.avg_wait_ns, 3_000_000);
    }

    /// Two sync events at the SAME step (different threads/locks) must both be
    /// retained. The old `BTreeMap<step, event>` silently overwrote one, so the
    /// lock whose event was dropped got another lock's wait/result attributed
    /// to it. With the multimap each acquisition matches its own event.
    #[test]
    fn test_sync_events_same_step_not_overwritten() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let lock_a = 0xAAAA_0000u64;
        let lock_b = 0xBBBB_0000u64;
        // Both acquisitions happen at step 100. Thread 1 waited on lock_a
        // (contended); thread 2 took lock_b with no wait (uncontended). Feed the
        // uncontended one LAST so the old map would have kept it and dropped the
        // contended one — mis-reporting lock_a as uncontended.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_a,
            result: SyncResult::Success,
            wait_duration_ns: Some(5_000_000),
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_b,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        let contentions = analyzer.analyze_lock_contention();
        let a = contentions.iter().find(|c| c.lock_address.addr == lock_a).unwrap();
        let b = contentions.iter().find(|c| c.lock_address.addr == lock_b).unwrap();
        // lock_a keeps its own 5ms wait → contended; lock_b stays uncontended.
        assert_eq!(a.acquire_count, 1);
        assert_eq!(a.contention_count, 1, "lock_a's own wait must not be lost to a same-step event");
        assert_eq!(a.max_wait_ns, 5_000_000);
        assert_eq!(b.acquire_count, 1);
        assert_eq!(b.contention_count, 0, "lock_b was never contended");
    }

    #[test]
    fn test_thread_function_association() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 calls function at 0x4000 three times
        analyzer.feed_call_event(100, 1, 0x4000);
        analyzer.feed_call_event(200, 1, 0x4000);
        analyzer.feed_call_event(300, 1, 0x4000);

        // Thread 2 calls function at 0x4000 once
        analyzer.feed_call_event(150, 2, 0x4000);

        // Thread 2 calls function at 0x5000 twice
        analyzer.feed_call_event(250, 2, 0x5000);
        analyzer.feed_call_event(350, 2, 0x5000);

        let assocs = analyzer.analyze_thread_function_assoc();

        // Thread 1 → 0x4000: 3 calls
        let assoc_1_4000 = assocs.iter()
            .find(|a| a.thread_id == 1 && a.function_address == 0x4000)
            .unwrap();
        assert_eq!(assoc_1_4000.call_count, 3);

        // Thread 2 → 0x4000: 1 call
        let assoc_2_4000 = assocs.iter()
            .find(|a| a.thread_id == 2 && a.function_address == 0x4000)
            .unwrap();
        assert_eq!(assoc_2_4000.call_count, 1);

        // Thread 2 → 0x5000: 2 calls
        let assoc_2_5000 = assocs.iter()
            .find(|a| a.thread_id == 2 && a.function_address == 0x5000)
            .unwrap();
        assert_eq!(assoc_2_5000.call_count, 2);

        // First/last call steps come from the range index
        assert_eq!(assoc_1_4000.first_call_step, 100);
        assert_eq!(assoc_1_4000.last_call_step, 300);
        assert_eq!(assoc_2_5000.first_call_step, 250);
        assert_eq!(assoc_2_5000.last_call_step, 350);
    }

    /// Thread-function rows with equal call counts must be ordered
    /// deterministically by (thread_id, function_address), not by
    /// `thread_functions` HashMap iteration order.
    #[test]
    fn test_thread_function_assoc_deterministic_order() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));

        // Two functions, each called exactly twice by thread 1 (equal counts).
        analyzer.feed_call_event(100, 1, 0x5000);
        analyzer.feed_call_event(200, 1, 0x5000);
        analyzer.feed_call_event(300, 1, 0x4000);
        analyzer.feed_call_event(400, 1, 0x4000);

        let assocs = analyzer.analyze_thread_function_assoc();
        // Both have call_count 2 → ascending (thread, address): 0x4000 then 0x5000.
        let addrs: Vec<u64> = assocs.iter().map(|a| a.function_address).collect();
        assert_eq!(addrs, vec![0x4000, 0x5000]);
    }

    /// `calling_threads` on a thread-safety row must be sorted regardless of the
    /// order the calls were fed.
    #[test]
    fn test_function_safety_calling_threads_sorted() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_thread_info(make_thread_info(3, "thread-3"));

        // Function 0x4000 called by threads 3, 1, 2 in that (unsorted) feed order.
        analyzer.feed_call_event(100, 3, 0x4000);
        analyzer.feed_call_event(200, 1, 0x4000);
        analyzer.feed_call_event(300, 2, 0x4000);

        let safety = analyzer.classify_function_thread_safety();
        let func = safety.iter().find(|f| f.function_address == 0x4000).unwrap();
        assert_eq!(func.calling_threads, vec![1, 2, 3], "calling threads must be sorted");
    }

    #[test]
    fn test_function_assoc_first_last_step_out_of_order() {
        // Call events fed out of step order: the range index must report the
        // true min/max step, not the first/last insertion order.
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));

        analyzer.feed_call_event(300, 1, 0x4000);
        analyzer.feed_call_event(100, 1, 0x4000);
        analyzer.feed_call_event(500, 1, 0x4000);
        analyzer.feed_call_event(200, 1, 0x4000);

        let assocs = analyzer.analyze_thread_function_assoc();
        let a = assocs.iter()
            .find(|a| a.thread_id == 1 && a.function_address == 0x4000)
            .unwrap();
        assert_eq!(a.call_count, 4);
        assert_eq!(a.first_call_step, 100, "first must be min step, not first fed");
        assert_eq!(a.last_call_step, 500, "last must be max step, not last fed");
    }

    #[test]
    fn test_function_assoc_stable_across_repeated_calls() {
        // Repeated analysis must be idempotent (index guarded by indexes_built).
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(7, "worker"));
        analyzer.feed_call_event(10, 7, 0xA000);
        analyzer.feed_call_event(40, 7, 0xA000);

        let first = analyzer.analyze_thread_function_assoc();
        let second = analyzer.analyze_thread_function_assoc();
        assert_eq!(first.len(), second.len());
        let f = first.iter().find(|a| a.function_address == 0xA000).unwrap();
        let s = second.iter().find(|a| a.function_address == 0xA000).unwrap();
        assert_eq!(f.call_count, s.call_count);
        assert_eq!((f.first_call_step, f.last_call_step), (s.first_call_step, s.last_call_step));
        assert_eq!((f.first_call_step, f.last_call_step), (10, 40));
    }

    #[test]
    fn test_active_function_attribution_out_of_order() {
        // A sync event must be attributed to the function active at its step,
        // determined by the highest call step <= the sync step — NOT by call
        // insertion order. Both funcs are called at steps below the sync step,
        // so binary search (not `.last()` on insertion order) is required.
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1: 0x2000 @ 80 is the active one at step 100, but it is fed
        // BEFORE 0x1000 @ 50 so insertion order would mis-pick 0x1000.
        analyzer.feed_call_event(80, 1, 0x2000);
        analyzer.feed_call_event(50, 1, 0x1000);
        // Thread 2: same two functions so both are called by 2 threads.
        analyzer.feed_call_event(80, 2, 0x2000);
        analyzer.feed_call_event(50, 2, 0x1000);

        // Sync events at step 100 on each thread → active function is 0x2000.
        for tid in [1u32, 2u32] {
            analyzer.feed_sync_event(ThreadSyncEvent {
                step: 100, thread_id: tid,
                sync_type: SyncEventType::MutexLock,
                sync_object_addr: 0xCAFE0000,
                result: SyncResult::Success,
                wait_duration_ns: None,
            });
        }

        let safety = analyzer.classify_function_thread_safety();
        let s2000 = safety.iter().find(|s| s.function_address == 0x2000).unwrap();
        let s1000 = safety.iter().find(|s| s.function_address == 0x1000).unwrap();
        // Sync attributed to 0x2000 → thread-safe; 0x1000 saw no sync.
        assert_eq!(s2000.safety, ThreadSafety::ThreadSafe,
            "sync must attribute to 0x2000 (active at step 100)");
        assert_eq!(s1000.safety, ThreadSafety::PotentiallyUnsafe,
            "0x1000 was not active at the sync step");
    }

    #[test]
    fn test_function_thread_safety_classification() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Function 0x4000 called by both threads (potentially unsafe)
        analyzer.feed_call_event(100, 1, 0x4000);
        analyzer.feed_call_event(200, 2, 0x4000);

        // Function 0x5000 called by both threads WITH sync (thread-safe)
        analyzer.feed_call_event(100, 1, 0x5000);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 110, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_call_event(200, 2, 0x5000);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 210, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Function 0x6000 called by only thread 1 (unknown)
        analyzer.feed_call_event(100, 1, 0x6000);

        let safety = analyzer.classify_function_thread_safety();

        let func_4000 = safety.iter().find(|f| f.function_address == 0x4000).unwrap();
        assert_eq!(func_4000.safety, ThreadSafety::PotentiallyUnsafe);

        let func_5000 = safety.iter().find(|f| f.function_address == 0x5000).unwrap();
        assert_eq!(func_5000.safety, ThreadSafety::ThreadSafe);

        let func_6000 = safety.iter().find(|f| f.function_address == 0x6000).unwrap();
        assert_eq!(func_6000.safety, ThreadSafety::Unknown);
    }

    #[test]
    fn test_data_flow_analysis() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes to 0x3000
        analyzer.feed_memory_write(100, 1, 0x3000, 4);

        // Thread 2 reads from 0x3000
        analyzer.feed_memory_read(200, 2, 0x3000, 4);

        let flows = analyzer.analyze_data_flows();
        assert!(!flows.is_empty());

        let flow = flows.iter()
            .find(|f| f.from_thread == 1 && f.to_thread == 2 && f.address == 0x3000)
            .unwrap();
        assert!(!flow.is_synchronized);
    }

    #[test]
    fn test_producer_consumer_detection() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));

        let mutex_addr = 0xABCD0000;

        // Produce-consume cycle 1
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 110, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 120, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_read(130, 2, 0x5000, 4);

        // Produce-consume cycle 2
        analyzer.feed_memory_write(200, 1, 0x5000, 4);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 210, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 220, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_read(230, 2, 0x5000, 4);

        let patterns = analyzer.detect_producer_consumer();
        assert!(!patterns.is_empty());

        let pc = patterns.iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert!(pc.cycle_count >= 2);
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: mutex_addr,
                kind: SyncPrimitiveKind::Mutex,
            })
        );
        // Both cycles reuse slot 0x5000, so the distinct shared-address set is a
        // single entry even though cycle_count is 2.
        assert_eq!(pc.shared_addresses, vec![0x5000]);
    }

    /// When two locks are used the same number of times by the thread pair,
    /// `find_sync_mechanism` must pick the LOWEST address — both for
    /// deterministic output and to match its doc comment. A prior version used
    /// `b.0.cmp(&a.0)` under `max_by`, which silently selected the HIGHEST
    /// address, contradicting the comment.
    #[test]
    fn test_find_sync_mechanism_tie_breaks_lowest_address() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));

        let low = 0x1000_0000u64;
        let high = 0x2000_0000u64;

        // Both threads touch BOTH locks the same number of times (2 each),
        // so the tie-break decides which address is reported.
        for &addr in &[low, high] {
            for &tid in &[1u32, 2u32] {
                analyzer.feed_sync_event(ThreadSyncEvent {
                    step: 10, thread_id: tid,
                    sync_type: SyncEventType::MutexLock,
                    sync_object_addr: addr,
                    result: SyncResult::Success,
                    wait_duration_ns: None,
                });
                analyzer.feed_sync_event(ThreadSyncEvent {
                    step: 20, thread_id: tid,
                    sync_type: SyncEventType::MutexUnlock,
                    sync_object_addr: addr,
                    result: SyncResult::Success,
                    wait_duration_ns: None,
                });
            }
        }

        analyzer.build_indexes();
        assert_eq!(
            analyzer.find_sync_mechanism(1, 2),
            Some(SyncMechanism {
                addr: low,
                kind: SyncPrimitiveKind::Mutex,
            })
        );
    }

    /// `find_sync_mechanism` reports the sync object two threads rendezvous on.
    /// #109 shrank `is_acquire()` to holdable-only (dropping CondvarWait/
    /// BarrierWait). `CondvarWait` is in neither `is_acquire()` nor
    /// `is_release()` after the shrink — only `is_sync_signal()` covers it — so
    /// `sync_locks_by_thread` (which `find_sync_mechanism` reads) must tally it
    /// via `is_sync_signal()`; otherwise two threads that BOTH only wait on a
    /// condvar (the pure-sync-signal case, no signal/broadcast to ride through
    /// `is_release()`) would lose their sync mechanism and report `None`.
    #[test]
    fn test_find_sync_mechanism_recognizes_condvar_signal_wait() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));

        let cv = 0xCD00_0000u64;
        // Both threads ONLY CondvarWait on the same condvar — neither emits a
        // signal/broadcast, so neither event is an `is_release()`; only
        // `is_sync_signal()` can carry them into `sync_locks_by_thread`.
        analyzer.feed_sync_event(hold_ev(10, 1, cv, SyncEventType::CondvarWait));
        analyzer.feed_sync_event(hold_ev(20, 2, cv, SyncEventType::CondvarWait));

        analyzer.build_indexes();
        assert_eq!(
            analyzer.find_sync_mechanism(1, 2),
            Some(SyncMechanism {
                addr: cv,
                kind: SyncPrimitiveKind::Condvar,
            }),
            "condvar wait-only rendezvous must be recognized as a condvar sync mechanism"
        );
    }

    /// `sync_mechanism` must report the *primitive kind*, not just the address.
    /// A futex-only producer-consumer rendezvous must yield `kind: Futex`,
    /// proving the address→kind annotation flows through `find_sync_mechanism`.
    #[test]
    fn test_producer_consumer_sync_mechanism_kind_is_futex() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));

        let futex_word = 0xF071_0000u64;
        // Producer wakes (FutexWake), consumer waits (FutexWait) on the same word.
        analyzer.feed_sync_event(hold_ev(110, 1, futex_word, SyncEventType::FutexWake));
        analyzer.feed_sync_event(hold_ev(120, 2, futex_word, SyncEventType::FutexWait));
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_memory_read(130, 2, 0x5000, 4);
        // Second cycle so detect_producer_consumer (needs >=2 cycles) reports it.
        analyzer.feed_sync_event(hold_ev(210, 1, futex_word, SyncEventType::FutexWake));
        analyzer.feed_sync_event(hold_ev(220, 2, futex_word, SyncEventType::FutexWait));
        analyzer.feed_memory_write(200, 1, 0x6000, 4);
        analyzer.feed_memory_read(230, 2, 0x6000, 4);

        let patterns = analyzer.detect_producer_consumer();
        let pc = patterns
            .iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: futex_word,
                kind: SyncPrimitiveKind::Futex,
            })
        );
    }

    /// A semaphore rendezvous must yield `kind: Semaphore`, covering the #109
    /// holdable-acquire family that was previously mis-tallied.
    #[test]
    fn test_producer_consumer_sync_mechanism_kind_is_semaphore() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));

        let sem = 0x5E80_0000u64;
        analyzer.feed_sync_event(hold_ev(110, 1, sem, SyncEventType::SemPost));
        analyzer.feed_sync_event(hold_ev(120, 2, sem, SyncEventType::SemWait));
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_memory_read(130, 2, 0x5000, 4);
        // Second cycle.
        analyzer.feed_sync_event(hold_ev(210, 1, sem, SyncEventType::SemPost));
        analyzer.feed_sync_event(hold_ev(220, 2, sem, SyncEventType::SemWait));
        analyzer.feed_memory_write(200, 1, 0x6000, 4);
        analyzer.feed_memory_read(230, 2, 0x6000, 4);

        let patterns = analyzer.detect_producer_consumer();
        let pc = patterns
            .iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: sem,
                kind: SyncPrimitiveKind::Semaphore,
            })
        );
    }

    #[test]
    fn test_full_analysis() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Add some data
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);
        analyzer.feed_call_event(50, 1, 0x4000);
        analyzer.feed_call_event(150, 2, 0x4000);

        let result = analyzer.analyze_all();

        // Should have results in all categories
        assert!(!result.race_conditions.is_empty());
        assert!(!result.thread_function_assocs.is_empty());
        assert!(!result.function_safety.is_empty());
        assert!(!result.data_flows.is_empty());
    }

    /// A read whose start address lives in a different 4 KiB page than the
    /// write, but whose byte range overlaps the write, must still be detected.
    /// This is the page-index's trickiest case — a naive per-page exact match
    /// would miss it; the page-covering expansion is what catches it.
    #[test]
    fn test_race_cross_page_overlap() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Write spans the page boundary at 0x2000: [0x1FFE, 0x2022)
        analyzer.feed_memory_write(100, 1, 0x1FFE, 0x24);
        // Read starts in the *next* page (0x2010) but overlaps the write range.
        analyzer.feed_memory_read(200, 2, 0x2010, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.iter().any(|r| r.address == 0x1FFE && r.first_thread == 1 && r.second_thread == 2),
            "cross-page overlapping read must be detected as a race: {:?}", races);

        let flows = analyzer.analyze_data_flows();
        assert!(flows.iter().any(|f| f.from_thread == 1 && f.to_thread == 2),
            "cross-page overlapping read must be detected as a data flow: {:?}", flows);
    }

    /// A large read spanning multiple pages must be found by a write touching
    /// any one of those pages (here the write sits in the middle page).
    #[test]
    fn test_race_multi_page_read() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Read spans three 4 KiB pages: [0x0FFC, 0x3004)
        analyzer.feed_memory_read(200, 2, 0x0FFC, 0x2008);
        // Write lands in the middle page at 0x2000.
        analyzer.feed_memory_write(100, 1, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.iter().any(|r| r.address == 0x2000),
            "write in a middle page of a multi-page read must be detected: {:?}", races);
    }

    /// Repeated analysis calls must not duplicate or drop results — the cached
    /// sorted/indexed structures are stable across calls.
    #[test]
    fn test_repeated_analysis_is_stable() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        let first_races = analyzer.detect_race_conditions();
        let first_flows = analyzer.analyze_data_flows();
        let second_races = analyzer.detect_race_conditions();
        let second_flows = analyzer.analyze_data_flows();

        assert_eq!(first_races.len(), second_races.len());
        assert_eq!(first_flows.len(), second_flows.len());
    }

    /// The page-granular read index must keep race detection fast even when
    /// many unrelated reads exist on different pages. With the index, the N
    /// unrelated reads are never scanned for the one write at 0x1000; a full
    /// O(W·R) scan would visit all of them. We assert the write at 0x1000 is
    /// still found (correctness) and the call returns promptly (the build runs
    /// in debug here; the point is it terminates without scanning everything).
    #[test]
    fn test_race_detection_ignores_unrelated_reads() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // One contended write + read on page 0x1000.
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        // Many unrelated reads scattered across other pages — these must NOT
        // produce false races (different addresses) nor slow down detection.
        for i in 0..2000u64 {
            let addr = 0x1_0000 + i * 0x100; // each on its own page region
            analyzer.feed_memory_read(150 + i, 2, addr, 4);
        }

        let races = analyzer.detect_race_conditions();
        // Exactly one race: the 0x1000 pair. Unrelated reads share no page with
        // the 0x1000 write, so the index prunes them before the overlap check.
        let races_on_1000 = races.iter().filter(|r| r.address == 0x1000).count();
        assert_eq!(races_on_1000, 1);
        // No race reported at any unrelated address.
        assert!(races.iter().all(|r| r.address == 0x1000),
            "unrelated reads on other pages must not surface as races: {:?}", races);
    }

    /// Write-write races (two threads writing the same address without sync)
    /// must be detected and flagged `second_is_write: true`. This covers the
    /// writes_by_page index path symmetric to the read path.
    #[test]
    fn test_write_write_race_detection() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes 0x1000 at step 100; thread 2 writes 0x1000 at step 200.
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_write(200, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        let ww = races.iter().find(|r| r.address == 0x1000 && r.first_thread == 1 && r.second_thread == 2);
        assert!(ww.is_some(), "write-write race should be detected: {:?}", races);
        let ww = ww.unwrap();
        assert!(ww.first_is_write && ww.second_is_write, "both sides should be writes");
    }

    /// Write-write race must NOT be reported when the two writes are
    /// synchronized via a shared mutex — mirrors the read-path sync test.
    #[test]
    fn test_no_write_write_race_with_sync() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        analyzer.feed_memory_write(100, 1, 0x2000, 4);
        // Both threads touch the same mutex between the writes.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success, wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 160, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success, wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_write(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.is_empty() || races.iter().all(|r| r.address != 0x2000),
            "synchronized write-write should not be a race: {:?}", races);
    }

    /// Read-then-write race: thread A reads an address, then thread B writes it
    /// without synchronization. The reader may act on a value the writer is
    /// about to change. The old detector only looked forward from a write and
    /// missed this ordering entirely; it must now be flagged with the read as
    /// the first (non-write) event and the write as the second.
    #[test]
    fn test_read_then_write_race_detection() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "reader"));
        analyzer.feed_thread_info(make_thread_info(2, "writer"));

        // Thread 1 reads 0x1000 at step 100; thread 2 writes 0x1000 at step 200.
        analyzer.feed_memory_read(100, 1, 0x1000, 4);
        analyzer.feed_memory_write(200, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        let rw = races
            .iter()
            .find(|r| r.address == 0x1000 && r.first_thread == 1 && r.second_thread == 2)
            .expect(&format!("read-then-write race should be detected: {:?}", races));
        assert!(!rw.first_is_write, "the earlier read must be the first, non-write event");
        assert!(rw.second_is_write, "the later write must be the second event");
        assert_eq!(rw.first_step, 100);
        assert_eq!(rw.second_step, 200);
    }

    /// A read-then-write pair separated by a shared mutex is NOT a race —
    /// mirrors the write-path sync tests for the new read-first ordering.
    #[test]
    fn test_no_read_then_write_race_with_sync() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "reader"));
        analyzer.feed_thread_info(make_thread_info(2, "writer"));

        analyzer.feed_memory_read(100, 1, 0x2000, 4);
        // Both threads touch the same mutex between the read and the write.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success, wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 160, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success, wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_write(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.is_empty() || races.iter().all(|r| r.address != 0x2000),
            "synchronized read-then-write should not be a race: {:?}", races);
    }

    /// Two reads by different threads are never a race (no write involved),
    /// even though the read-first loop now scans reads around every write.
    #[test]
    fn test_read_read_is_not_a_race() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "reader-a"));
        analyzer.feed_thread_info(make_thread_info(2, "reader-b"));

        analyzer.feed_memory_read(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.is_empty(), "read-read must not be flagged: {:?}", races);
    }

    /// An access whose `addr + size` would overflow `u64` must not panic or
    /// wrap to a tiny `end` (which would mis-classify overlaps). Saturating
    /// arithmetic clamps the range end to `u64::MAX`, so a write near the top
    /// of the address space still correctly races with a same-address read on
    /// another thread. Regression guard for #83.
    #[test]
    fn test_race_detection_near_u64_max_no_overflow() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "w"));
        analyzer.feed_thread_info(make_thread_info(2, "r"));

        // addr = u64::MAX - 7, size = 16 → addr+size overflows u64.
        let addr = u64::MAX - 7;
        analyzer.feed_memory_write(100, 1, addr, 16);
        analyzer.feed_memory_read(200, 2, addr, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.iter().any(|r| r.address == addr),
            "expected a race at {addr:#x}: {:?}", races);
    }

    /// A write and a read to the same address at the SAME step, on two threads,
    /// is the strongest possible race — fully concurrent, no ordering at all.
    /// Steps come from `trace.seq` and are not unique, so this must be reported
    /// (labelled write-first), not silently dropped by a `<=`/`>=` guard.
    #[test]
    fn test_same_step_write_read_is_a_race() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "writer"));
        analyzer.feed_thread_info(make_thread_info(2, "reader"));

        analyzer.feed_memory_write(100, 1, 0x3000, 4);
        analyzer.feed_memory_read(100, 2, 0x3000, 4);

        let races = analyzer.detect_race_conditions();
        let r = races
            .iter()
            .find(|r| r.address == 0x3000)
            .unwrap_or_else(|| panic!("same-step write/read must be a race: {:?}", races));
        assert_eq!(r.first_step, 100);
        assert_eq!(r.second_step, 100);
        assert!(r.first_is_write, "write is labelled first: {:?}", r);
        assert!(!r.second_is_write, "read is labelled second: {:?}", r);
        assert_eq!(r.first_thread, 1);
        assert_eq!(r.second_thread, 2);
        // Concurrent (zero step distance) → top confidence bucket.
        assert!(r.confidence >= 0.8, "same-step race should be high confidence: {:?}", r);
    }

    /// Two writes to the same address at the SAME step on two threads is a
    /// concurrent write-write race. It must be reported EXACTLY once (not twice
    /// from each side), with the lower-tid thread canonically first.
    #[test]
    fn test_same_step_write_write_reported_once() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "writer-a"));
        analyzer.feed_thread_info(make_thread_info(2, "writer-b"));

        // Feed higher tid first to prove ordering is by tid, not feed order.
        analyzer.feed_memory_write(100, 2, 0x4000, 4);
        analyzer.feed_memory_write(100, 1, 0x4000, 4);

        let races: Vec<_> = analyzer
            .detect_race_conditions()
            .into_iter()
            .filter(|r| r.address == 0x4000)
            .collect();
        assert_eq!(races.len(), 1, "same-step write-write must be reported once: {:?}", races);
        assert!(races[0].first_is_write && races[0].second_is_write);
        assert_eq!(races[0].first_thread, 1, "lower tid is canonically first");
        assert_eq!(races[0].second_thread, 2);
    }

    /// Same-step access on the SAME thread is not a race (a thread cannot race
    /// with itself), and must not be fabricated by the relaxed guards.
    #[test]
    fn test_same_step_same_thread_is_not_a_race() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "solo"));

        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_memory_read(100, 1, 0x5000, 4);
        analyzer.feed_memory_write(100, 1, 0x5000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.is_empty(), "one thread cannot race with itself: {:?}", races);
    }

    // ========================================================================
    // JNI boundary analysis (#67)
    // ========================================================================

    /// Build a `JNICall` fixture. `seq` is the trace step (may collide across
    /// calls — the store keeps a Vec per step).
    fn make_jni_call(
        seq: u64,
        thread_id: u32,
        direction: JNICallDirection,
        java_class: &str,
        java_method: &str,
        native_address: u64,
    ) -> JNICall {
        JNICall {
            id: seq,
            seq,
            thread_id,
            direction,
            java_class: java_class.to_string(),
            java_method: java_method.to_string(),
            java_signature: "()V".to_string(),
            native_func_id: None,
            native_address,
            jni_env_address: None,
        }
    }

    /// Basic split: crossings on one thread are counted and bucketed by
    /// direction, and distinct native addresses / java methods are collected.
    #[test]
    fn test_jni_boundary_basic_split() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "worker"));

        analyzer.feed_jni_call(make_jni_call(10, 1, JNICallDirection::JavaToNative, "com.app.Foo", "doWork", 0x2000));
        analyzer.feed_jni_call(make_jni_call(20, 1, JNICallDirection::JavaToNative, "com.app.Foo", "init", 0x3000));
        analyzer.feed_jni_call(make_jni_call(30, 1, JNICallDirection::NativeToJava, "com.app.Bar", "callback", 0x2000));

        let stats = analyzer.analyze_jni_boundary();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert_eq!(s.thread_id, 1);
        assert_eq!(s.total_crossings, 3);
        assert_eq!(s.java_to_native_count, 2);
        assert_eq!(s.native_to_java_count, 1);
        // 0x2000 appears twice → distinct set keeps it once.
        assert_eq!(s.native_addresses, vec![0x2000, 0x3000]);
        assert_eq!(s.java_methods, vec!["com.app.Bar.callback", "com.app.Foo.doWork", "com.app.Foo.init"]);
    }

    /// A thread the runtime marked JNI-attached but with no captured crossings
    /// must still appear (attached-but-idle surfacing), with zero counts.
    #[test]
    fn test_jni_boundary_attached_but_idle_appears() {
        let mut analyzer = ThreadAnalyzer::new();
        let mut idle = make_thread_info(7, "attached-idle");
        idle.is_jni_attached = true;
        analyzer.feed_thread_info(idle);

        let stats = analyzer.analyze_jni_boundary();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].thread_id, 7);
        assert!(stats[0].is_jni_attached);
        assert_eq!(stats[0].total_crossings, 0);
        assert!(stats[0].native_addresses.is_empty());
        assert!(stats[0].java_methods.is_empty());
    }

    /// Two JNI calls at the SAME seq on different threads must both be retained
    /// (Vec-per-step), not overwritten.
    #[test]
    fn test_jni_boundary_same_step_multi_thread() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));

        analyzer.feed_jni_call(make_jni_call(100, 1, JNICallDirection::JavaToNative, "A", "m", 0x1000));
        analyzer.feed_jni_call(make_jni_call(100, 2, JNICallDirection::JavaToNative, "B", "m", 0x1000));

        let stats = analyzer.analyze_jni_boundary();
        assert_eq!(stats.len(), 2, "same-seq calls on two threads must both count");
        assert_eq!(stats[0].total_crossings, 1);
        assert_eq!(stats[1].total_crossings, 1);
    }

    /// Output is deterministic: sorted by thread_id regardless of feed order.
    #[test]
    fn test_jni_boundary_sorted_by_thread_id() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(3, "t3"));
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));

        // Feed out of order.
        analyzer.feed_jni_call(make_jni_call(1, 3, JNICallDirection::JavaToNative, "C", "m", 0x30));
        analyzer.feed_jni_call(make_jni_call(2, 1, JNICallDirection::JavaToNative, "A", "m", 0x10));
        analyzer.feed_jni_call(make_jni_call(3, 2, JNICallDirection::NativeToJava, "B", "m", 0x20));

        let ids: Vec<u32> = analyzer.analyze_jni_boundary().iter().map(|s| s.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    /// A thread with crossings but no registered `ThreadInfo` still appears
    /// (default `is_jni_attached = false`), so JNI activity is never dropped
    /// just because thread metadata was missing.
    #[test]
    fn test_jni_boundary_unknown_thread_defaults_unattached() {
        let mut analyzer = ThreadAnalyzer::new();
        // No feed_thread_info for thread 9.
        analyzer.feed_jni_call(make_jni_call(5, 9, JNICallDirection::JavaToNative, "X", "y", 0x99));

        let stats = analyzer.analyze_jni_boundary();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].thread_id, 9);
        assert!(!stats[0].is_jni_attached);
        assert_eq!(stats[0].total_crossings, 1);
    }

    // ------------------------------------------------------------------------
    // #109: SyncEventType three-way classification — semaphore / futex /
    // condvar / barrier coverage. Before #109 the four inline match arms
    // (lock_order, is_lock_held_at, analyze_lock_contention,
    // analyze_critical_sections) only listed Mutex*/RwLock* (and BarrierWait
    // erroneously in lock_order). Semaphore acquire was counted without a
    // paired release, futex-backed locks were entirely missed, and BarrierWait
    // leaked into exclusive_locks while is_lock_held_at never recognized it —
    // a self-contradiction. These tests pin the corrected behavior and guard
    // against the direction-A regression (treating BarrierWait/CondvarWait as
    // holdable acquires, which fabricates ever-increasing depth → false
    // deadlocks).
    // ------------------------------------------------------------------------

    /// Helper mirroring `hold_ev` but allowing a non-Success result and a wait
    /// duration, needed for the futex-timeout and contention tests below.
    fn sync_ev(
        step: u64,
        tid: u32,
        addr: u64,
        ty: SyncEventType,
        res: SyncResult,
        wait_ns: Option<u64>,
    ) -> ThreadSyncEvent {
        ThreadSyncEvent {
            step,
            thread_id: tid,
            sync_type: ty,
            sync_object_addr: addr,
            result: res,
            wait_duration_ns: wait_ns,
        }
    }

    /// ABBA with SemWait acquires: T1 holds A then takes B, T2 holds B then
    /// takes A. Before #109 `is_lock_held_at` did not recognize SemWait, so
    /// `a_still_held` was false and the deadlock edge was dropped (missed
    /// deadlock). Now it must be reported.
    #[test]
    fn test_deadlock_detected_with_sem_wait_acquires() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        // T1: SemWait A@10, SemWait B@20 (real A→B).
        analyzer.feed_sync_event(hold_ev(10, 1, a, SyncEventType::SemWait));
        analyzer.feed_sync_event(hold_ev(20, 1, b, SyncEventType::SemWait));
        // T2: SemWait B@15, SemWait A@25 (real B→A).
        analyzer.feed_sync_event(hold_ev(15, 2, b, SyncEventType::SemWait));
        analyzer.feed_sync_event(hold_ev(25, 2, a, SyncEventType::SemWait));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            deadlocks.iter().any(|d| d.lock_cycle.iter().any(|m| m.addr == a) && d.lock_cycle.iter().any(|m| m.addr == b)),
            "semaphore-backed ABBA must be detected: {:?}",
            deadlocks
        );
        // #111: the cycle's locks are typed — a semaphore-backed deadlock must
        // report kind: Semaphore on every cycle entry, not bare addresses.
        let sem_cycle = deadlocks.iter()
            .find(|d| d.lock_cycle.iter().any(|m| m.addr == a) && d.lock_cycle.iter().any(|m| m.addr == b))
            .unwrap();
        assert!(sem_cycle.lock_cycle.iter().all(|m| m.kind == SyncPrimitiveKind::Semaphore));
    }

    /// Same ABBA as above but using FutexWait — bionic pthread_mutex/condvar
    /// and Java monitors are futex-backed, so this is the common path. Before
    /// #109 the deadlock was missed (FutexWait not in the acquire arm).
    #[test]
    fn test_deadlock_detected_with_futex_wait_acquires() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        analyzer.feed_sync_event(hold_ev(10, 1, a, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(20, 1, b, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(15, 2, b, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(25, 2, a, SyncEventType::FutexWait));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            deadlocks.iter().any(|d| d.lock_cycle.iter().any(|m| m.addr == a) && d.lock_cycle.iter().any(|m| m.addr == b)),
            "futex-backed ABBA must be detected: {:?}",
            deadlocks
        );
        // #111: the cycle's locks are typed — a futex-backed deadlock must
        // report kind: Futex on every cycle entry.
        let futex_cycle = deadlocks.iter()
            .find(|d| d.lock_cycle.iter().any(|m| m.addr == a) && d.lock_cycle.iter().any(|m| m.addr == b))
            .unwrap();
        assert!(futex_cycle.lock_cycle.iter().all(|m| m.kind == SyncPrimitiveKind::Futex));
    }

    /// A semaphore acquire followed by its post must drop the hold depth back
    /// to zero. Before #109 SemPost was not in the release arm, so depth only
    /// ever increased (permanent hold → false deadlocks downstream).
    #[test]
    fn test_semaphore_held_depth_decrements_on_sem_post() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x5E80_0000u64;

        analyzer.feed_sync_event(hold_ev(10, 1, lock, SyncEventType::SemWait));
        analyzer.feed_sync_event(hold_ev(20, 1, lock, SyncEventType::SemPost));

        analyzer.build_indexes();
        assert!(
            !analyzer.is_lock_held_at(1, lock, 20),
            "SemPost must release the hold acquired by SemWait"
        );
    }

    /// Same depth-decrement contract for futex: FutexWake (single-waiter wake)
    /// must drop the depth taken by FutexWait.
    #[test]
    fn test_futex_held_depth_decrements_on_futex_wake() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xF071_0000u64;

        analyzer.feed_sync_event(hold_ev(10, 1, lock, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(20, 1, lock, SyncEventType::FutexWake));

        analyzer.build_indexes();
        assert!(
            !analyzer.is_lock_held_at(1, lock, 20),
            "FutexWake must release the hold acquired by FutexWait"
        );
    }

    /// Critical-section stats must reflect a semaphore hold: one interval from
    /// SemWait to SemPost, span = 40 steps. Before #109 SemWait/SemPost were
    /// absent from both arms → no interval recorded.
    #[test]
    fn test_critical_sections_counts_semaphore_hold() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x5E80_0000u64;

        analyzer.feed_sync_event(hold_ev(10, 1, lock, SyncEventType::SemWait));
        analyzer.feed_sync_event(hold_ev(50, 1, lock, SyncEventType::SemPost));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c.lock_address.addr, lock);
        assert_eq!(c.hold_count, 1);
        assert_eq!(c.max_hold_steps, 40);
        assert_eq!(c.longest_hold_start, 10);
        assert_eq!(c.longest_hold_end, 50);
        assert_eq!(c.holder_threads, vec![1]);
    }

    /// Same critical-section contract for a futex-backed hold.
    #[test]
    fn test_critical_sections_counts_futex_hold() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xF071_0000u64;

        analyzer.feed_sync_event(hold_ev(10, 1, lock, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(50, 1, lock, SyncEventType::FutexWake));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c.lock_address.addr, lock);
        assert_eq!(c.hold_count, 1);
        assert_eq!(c.max_hold_steps, 40);
        assert_eq!(c.holder_threads, vec![1]);
    }

    /// A contended futex acquire (Success with a non-zero wait) must be counted
    /// as both an acquire and a contention. Before #109 FutexWait was not in
    /// the contention acquire arm → acquire_count == 0 (missed contention).
    #[test]
    fn test_contention_counts_futex_wait() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xF071_0000u64;

        // FutexWait that succeeded after waiting 5µs.
        analyzer.feed_sync_event(sync_ev(
            10, 1, lock, SyncEventType::FutexWait, SyncResult::Success, Some(5_000),
        ));

        let contention = analyzer.analyze_lock_contention();
        assert_eq!(contention.len(), 1);
        let ci = &contention[0];
        assert_eq!(ci.lock_address.addr, lock);
        assert_eq!(ci.acquire_count, 1);
        assert_eq!(ci.contention_count, 1);
    }

    /// Two threads meeting at a barrier in opposite order must NOT be reported
    /// as a lock-ordering deadlock. A barrier is a rendezvous, not a held lock:
    /// there is no per-thread hold and no paired release. Direction A (treat
    /// BarrierWait as a holdable acquire) would fabricate ever-increasing depth
    /// and report a false ABBA cycle here — this test guards against that
    /// regression.
    #[test]
    fn test_no_false_deadlock_from_barrier_wait() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let b1 = 0xBA11_0000u64;
        let b2 = 0xBA22_0000u64;
        // T1 "acquires" b1 then b2 (both BarrierWait).
        analyzer.feed_sync_event(hold_ev(10, 1, b1, SyncEventType::BarrierWait));
        analyzer.feed_sync_event(hold_ev(20, 1, b2, SyncEventType::BarrierWait));
        // T2 "acquires" b2 then b1 — opposite order.
        analyzer.feed_sync_event(hold_ev(15, 2, b2, SyncEventType::BarrierWait));
        analyzer.feed_sync_event(hold_ev(25, 2, b1, SyncEventType::BarrierWait));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            deadlocks.is_empty(),
            "barrier rendezvous must not fabricate a deadlock: {:?}",
            deadlocks
        );
    }

    /// Two threads crossing on a condvar must NOT be reported as a deadlock.
    /// CondvarWait releases its associated mutex before waiting — it is a sync
    /// signal, not a holdable acquire.
    #[test]
    fn test_no_false_deadlock_from_condvar_wait() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let c1 = 0xCD11_0000u64;
        let c2 = 0xCD22_0000u64;
        analyzer.feed_sync_event(hold_ev(10, 1, c1, SyncEventType::CondvarWait));
        analyzer.feed_sync_event(hold_ev(20, 1, c2, SyncEventType::CondvarWait));
        analyzer.feed_sync_event(hold_ev(15, 2, c2, SyncEventType::CondvarWait));
        analyzer.feed_sync_event(hold_ev(25, 2, c1, SyncEventType::CondvarWait));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            deadlocks.is_empty(),
            "condvar wait must not fabricate a deadlock: {:?}",
            deadlocks
        );
    }

    /// CondvarSignal on the writing thread plus CondvarWait on the reading
    /// thread establishes a happens-before edge: the read after the wait must
    /// NOT race with the write before the signal. `has_sync_between` recognizes
    /// the pair via `is_sync_signal()` (CondvarSignal/CondvarWait) — this is
    /// the race-suppression side of the three-way split.
    #[test]
    fn test_condvar_signal_suppresses_race() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let cv = 0xCD00_0000u64;
        // T1 writes, then signals the condvar.
        analyzer.feed_memory_write(100, 1, 0x2000, 4);
        analyzer.feed_sync_event(hold_ev(150, 1, cv, SyncEventType::CondvarSignal));
        // T2 waits on the condvar (released by the signal), then reads.
        analyzer.feed_sync_event(hold_ev(160, 2, cv, SyncEventType::CondvarWait));
        analyzer.feed_memory_read(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(
            races.is_empty() || races.iter().all(|r| r.address != 0x2000),
            "condvar signal→wait must suppress the write/read race: {:?}",
            races
        );
    }

    /// A futex wait that timed out never held the lock — the `result` guard in
    /// `is_lock_held_at` must keep depth at zero for a Timeout result.
    #[test]
    fn test_futex_wait_timeout_not_held() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xF071_0000u64;

        analyzer.feed_sync_event(sync_ev(
            10, 1, lock, SyncEventType::FutexWait, SyncResult::Timeout, Some(1_000_000),
        ));

        analyzer.build_indexes();
        assert!(
            !analyzer.is_lock_held_at(1, lock, 10),
            "a timed-out FutexWait must not be treated as a held lock"
        );
    }
}
