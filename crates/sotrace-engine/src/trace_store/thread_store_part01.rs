// Thread store — comprehensive thread tracking for Android SO analysis
//
// Thread tracking in Android SO reverse engineering is crucial because:
// - Multiple Java threads may call JNI functions in the same SO
// - SO internal pthread_create creates worker threads
// - Mutex/futex/condvar synchronization is key for race condition analysis
// - Context switches determine execution order — directly affects data flow
//
// # Delta Encoding Strategy
//
// Thread data is highly repetitive:
// - **Thread ID**: DictionaryRef (few unique threads, ~1-10 for typical SO traces)
// - **Thread state**: DictionaryRef (9 unique states, highly repetitive cycles)
// - **Sync event type**: DictionaryRef (17 unique types)
// - **Sync object address**: AddressIndex + NumericDelta (same mutex used repeatedly)
// - **Context switch**: ByteLevel (from_thread → to_thread, both are dictionary refs)
//
// # Query Acceleration
//
// Three indexes enable fast queries:
// 1. **ThreadIndex** — thread_id → [steps where active]: "what did thread T do?"
// 2. **SyncObjectIndex** — lock_addr → [sync event steps]: "who contended on this lock?"
// 3. **ThreadSyncIndex** — thread_id → [sync event steps]: "what locks did thread T touch?"
//
// Without indexes: scan ALL events → O(total_events)
// With indexes: O(log K) where K = events for specific thread/lock

use anyhow::Result;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

use sotrace_core::models::thread::{
    ThreadInfo, ThreadState, ThreadStateChange, ThreadSyncEvent,
    SyncEventType, SyncResult, ContextSwitch, SwitchReason, ThreadStats,
};

use crate::delta_store::delta_log::EventLog;
use crate::delta_store::delta_index::{ThreadIndex, AddressIndex, insert_step_sorted};
use crate::delta_store::types::*;

/// Return the sub-slice of a sorted `steps` list that falls within the inclusive
/// range `[start, end]`, via two binary searches. O(log K + R) instead of an
/// O(K) linear filter over the whole list.
fn sorted_step_range(steps: &[u64], start: u64, end: u64) -> &[u64] {
    let lo = steps.partition_point(|&s| s < start);
    let hi = steps.partition_point(|&s| s <= end);
    &steps[lo..hi]
}

/// Iterate the distinct values of a sorted slice, skipping consecutive
/// duplicates. Step indexes are not deduplicated on insert (`insert_step_sorted`
/// keeps every registration), so a step touched by two events of the same key
/// appears twice. Since `EventLog::get_all(step)` already returns *every* record
/// at that step, we must visit each step only once to avoid multiplying results.
fn dedup_sorted_steps(steps: &[u64]) -> impl Iterator<Item = u64> + '_ {
    steps
        .iter()
        .enumerate()
        .filter_map(|(i, &s)| (i == 0 || steps[i - 1] != s).then_some(s))
}

/// Thread store — comprehensive thread tracking with metadata, state, sync, and context switches
pub struct ThreadStore {
    // --- Thread metadata ---
    /// Thread info: thread_id → ThreadInfo (recorded once per thread)
    thread_info: HashMap<u32, ThreadInfo>,
    /// Next available thread ID for auto-assignment
    next_thread_id: u32,

    // --- Thread state changes ---
    /// Event log for thread state change events. `EventLog` (not `DeltaLog`)
    /// because two threads can change state at the same step and both must be
    /// retained rather than the later clobbering the earlier.
    state_log: EventLog<ThreadStateChange>,
    /// Thread index: thread_id → steps where this thread was active
    thread_index: ThreadIndex,
    /// Current state of each thread
    thread_states: HashMap<u32, ThreadState>,
    /// Currently running thread
    current_thread: Option<u32>,

    // --- Synchronization events ---
    /// Event log for thread sync events (mutex/futex/condvar operations). Same
    /// step can hold several events (different threads, or a lock+unlock at one
    /// seq), so all must survive — see `EventLog`.
    sync_log: EventLog<ThreadSyncEvent>,
    /// Sync object index: lock_addr → steps where this lock was accessed
    sync_object_index: AddressIndex,
    /// Thread sync index: thread_id → steps where this thread did sync operations
    thread_sync_index: HashMap<u32, Vec<u64>>,

    // --- Context switches ---
    /// Event log for context switch records. Two switches can share a step, so
    /// all must survive — see `EventLog`.
    switch_log: EventLog<ContextSwitch>,
    /// Total number of context switches
    total_switches: u64,

    // --- Statistics tracking ---
    /// Per-thread statistics (updated on each event)
    thread_stats: HashMap<u32, ThreadStatsBuilder>,
}

/// Builder for ThreadStats — incrementally updated as events arrive
#[derive(Debug, Clone)]
struct ThreadStatsBuilder {
    steps_executed: u64,
    context_switch_count: u64,
    sync_event_count: u64,
    lock_acquire_count: u64,
    lock_release_count: u64,
    lock_contention_count: u64,
    lock_wait_total_ns: u64,
    /// Max single wait, tracked alongside the running total.
    max_lock_wait_ns: u64,
    function_call_count: u64,
}

impl ThreadStatsBuilder {
    fn new() -> Self {
        Self {
            steps_executed: 0,
            context_switch_count: 0,
            sync_event_count: 0,
            lock_acquire_count: 0,
            lock_release_count: 0,
            lock_contention_count: 0,
            lock_wait_total_ns: 0,
            max_lock_wait_ns: 0,
            function_call_count: 0,
        }
    }

    fn build(&self, thread_id: u32) -> ThreadStats {
        let avg_lock_wait_ns = if self.lock_contention_count > 0 {
            Some(self.lock_wait_total_ns / self.lock_contention_count)
        } else {
            None
        };
        // max is only meaningful when the thread actually waited at least once;
        // mirror avg's None-when-no-contention semantics.
        let max_lock_wait_ns = if self.max_lock_wait_ns > 0 {
            Some(self.max_lock_wait_ns)
        } else {
            None
        };

        ThreadStats {
            thread_id,
            steps_executed: self.steps_executed,
            running_time_ns: None, // Requires timestamp support
            context_switch_count: self.context_switch_count,
            sync_event_count: self.sync_event_count,
            lock_acquire_count: self.lock_acquire_count,
            lock_release_count: self.lock_release_count,
            lock_contention_count: self.lock_contention_count,
            avg_lock_wait_ns,
            max_lock_wait_ns,
            function_call_count: self.function_call_count,
        }
    }
}
