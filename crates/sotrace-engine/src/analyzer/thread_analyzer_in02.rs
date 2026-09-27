
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

