
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
    /// Memory address of the data transfer (page-aligned base of the write).
    /// Kept for backwards compatibility and the dedup key; the *precise*
    /// transferred region is in `overlap_address`/`overlap_size`.
    pub address: u64,
    /// Step when the write occurred
    pub write_step: u64,
    /// Step when the read occurred
    pub read_step: u64,
    /// Whether there was proper synchronization between write and read
    pub is_synchronized: bool,
    /// Byte size of the writer's access (1, 2, 4, 8, …). Lets the RE judge
    /// whether the transfer is a single field or an entire struct.
    pub write_size: u64,
    /// Byte size of the reader's access.
    pub read_size: u64,
    /// Start address of the *actual* overlapping byte range between the write
    /// and the read — the precise set of bytes the reader could have observed
    /// from the writer (the intersection of `[w, w+w_size)` and `[r, r+r_size)`).
    /// Saturating arithmetic keeps it safe near `u64::MAX`.
    pub overlap_address: u64,
    /// Length in bytes of the overlapping range. Zero only for degenerate
    /// boundary-touching accesses.
    pub overlap_size: u64,
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

/// A shared-memory slot used by a producer-consumer pair. Richer than a bare
/// `u64` address: it also reports the access size (how many bytes the producer
/// writes per cycle) and the precise transferred range, so an RE can tell
/// whether the slot carries a single field or an entire struct. Derived from
/// the underlying `ThreadDataFlow`s; when the same slot is used across multiple
/// cycles with differing sizes, the first cycle's values are kept (consistent
/// with the address-level deduplication of `shared_addresses`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedAddress {
    /// Write base address of the slot (page-aligned). The dedup key for
    /// `shared_addresses`: each distinct slot appears once.
    pub address: u64,
    /// Byte size of the producer's write to this slot (1, 2, 4, 8, …).
    pub access_size: u64,
    /// Length in bytes of the precise transferred range (the write/read
    /// overlap) for this slot. From the first cycle's flow.
    pub overlap_size: u64,
}

/// Producer-consumer pattern detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducerConsumerPattern {
    /// Producer thread
    pub producer_thread: u32,
    /// Consumer thread
    pub consumer_thread: u32,
    /// Shared memory slots used for communication, each typed with its
    /// address, access size, and transferred range. Sorted by address for
    /// deterministic output; each distinct slot appears once.
    pub shared_addresses: Vec<SharedAddress>,
    /// Number of produce-consume cycles detected
    pub cycle_count: u64,
    /// Average time between produce and consume (in steps)
    pub avg_latency_steps: u64,
    /// Longest single produce→consume latency in steps across all detected
    /// cycles (`max(read_step - write_step)`). Surfaces the tail that
    /// `avg_latency_steps` hides — the one pathological stall among many fast
    /// cycles is the real bottleneck for an RE (GC pause, contention spike,
    /// scheduling jitter). Mirrors `ThreadStats::max_lock_wait_ns` (#118) and
    /// `LockContentionInfo::max_wait_ns`.
    pub max_latency_steps: u64,
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
    /// Per-core residency in steps: how long (in steps) this thread ran on
    /// each CPU core, accumulated across all scheduling intervals. Sorted by
    /// core id for deterministic output. A residency interval's length is the
    /// step gap to the next switch that ended the interval; a final unbounded
    /// run-in (no following switch) contributes 0, never a fabricated span.
    /// Empty if no switch carried a `cpu_core` (cores unknown).
    pub core_residency: Vec<(u32, u64)>,
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
    /// Step (seq) of the thread's first JNI boundary crossing. `None` when the
    /// thread has no recorded crossings (attached-but-idle, or no crossings
    /// captured). Locates the initialization phase for an RE.
    pub first_crossing_step: Option<u64>,
    /// Step (seq) of the thread's last JNI boundary crossing. `None` when the
    /// thread has no recorded crossings. Locates the teardown / final callback.
    pub last_crossing_step: Option<u64>,
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
