//! Thread store — comprehensive thread tracking for Android SO analysis
//!
//! Thread tracking in Android SO reverse engineering is crucial because:
//! - Multiple Java threads may call JNI functions in the same SO
//! - SO internal pthread_create creates worker threads
//! - Mutex/futex/condvar synchronization is key for race condition analysis
//! - Context switches determine execution order — directly affects data flow
//!
//! # Delta Encoding Strategy
//!
//! Thread data is highly repetitive:
//! - **Thread ID**: DictionaryRef (few unique threads, ~1-10 for typical SO traces)
//! - **Thread state**: DictionaryRef (9 unique states, highly repetitive cycles)
//! - **Sync event type**: DictionaryRef (17 unique types)
//! - **Sync object address**: AddressIndex + NumericDelta (same mutex used repeatedly)
//! - **Context switch**: ByteLevel (from_thread → to_thread, both are dictionary refs)
//!
//! # Query Acceleration
//!
//! Three indexes enable fast queries:
//! 1. **ThreadIndex** — thread_id → [steps where active]: "what did thread T do?"
//! 2. **SyncObjectIndex** — lock_addr → [sync event steps]: "who contended on this lock?"
//! 3. **ThreadSyncIndex** — thread_id → [sync event steps]: "what locks did thread T touch?"
//!
//! Without indexes: scan ALL events → O(total_events)
//! With indexes: O(log K) where K = events for specific thread/lock

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

impl ThreadStore {
    /// Create a new thread store
    pub fn new(config: DeltaStoreConfig) -> Self {
        // `config.compression` configures the three EventLogs; the rest is not
        // retained (no query path reads it back).
        Self {
            thread_info: HashMap::new(),
            next_thread_id: 1,
            state_log: EventLog::new(config.compression),
            thread_index: ThreadIndex::new(),
            thread_states: HashMap::new(),
            current_thread: None,
            sync_log: EventLog::new(config.compression),
            sync_object_index: AddressIndex::new(),
            thread_sync_index: HashMap::new(),
            switch_log: EventLog::new(config.compression),
            total_switches: 0,
            thread_stats: HashMap::new(),
        }
    }

    // ========================================================================
    // Thread metadata operations
    // ========================================================================

    /// Register a new thread (called when thread is created or first seen)
    pub fn register_thread(&mut self, info: ThreadInfo) -> Result<()> {
        let thread_id = info.thread_id;
        let is_new = !self.thread_info.contains_key(&thread_id);
        // Always (re)write the metadata — an adapter may re-report a thread
        // with refreshed info (e.g. name resolved later). But state and stats
        // are only initialized for a genuinely new thread: re-registering an
        // existing one must NOT reset `thread_states` to Runnable (it could be
        // Terminated, or mid-Running) nor wipe `thread_stats` (it has already
        // accumulated steps/sync/lock counts). Both were unconditional `insert`
        // before, silently losing state and statistics on re-registration.
        self.thread_info.insert(thread_id, info);
        if is_new {
            // Initialize state as Runnable (ready to run but not yet scheduled)
            self.thread_states.insert(thread_id, ThreadState::Runnable);
            // Initialize stats builder
            self.thread_stats.insert(thread_id, ThreadStatsBuilder::new());
        }
        // Auto-increment next available ID
        if thread_id >= self.next_thread_id {
            self.next_thread_id = thread_id + 1;
        }
        Ok(())
    }

    /// Record that a thread has exited
    pub fn record_thread_exit(&mut self, thread_id: u32, exit_step: u64) -> Result<()> {
        if let Some(info) = self.thread_info.get_mut(&thread_id) {
            info.exit_step = Some(exit_step);
        }
        // The thread's actual prior state — NOT a hardcoded Running. A thread
        // can exit from Blocked/Waiting/Sleeping (e.g. a pthread_cancel during
        // a wait), and stamping Running would mis-record the transition for any
        // future consumer of `ThreadStateChange.prev_state`. Fall back to
        // Runnable only when the thread was never observed (no state recorded).
        let prev_state = self
            .thread_states
            .get(&thread_id)
            .copied()
            .unwrap_or(ThreadState::Runnable);
        self.thread_states.insert(thread_id, ThreadState::Terminated);

        // Record the state change
        let change = ThreadStateChange {
            step: exit_step,
            thread_id,
            new_state: ThreadState::Terminated,
            prev_state: Some(prev_state),
            prev_running_thread: self.current_thread,
        };
        self.write_state_change(change)?;
        Ok(())
    }

    /// Get thread info by thread ID
    pub fn get_thread_info(&self, thread_id: u32) -> Option<&ThreadInfo> {
        self.thread_info.get(&thread_id)
    }

    /// Get all registered thread IDs
    pub fn all_thread_ids(&self) -> Vec<u32> {
        self.thread_info.keys().copied().collect()
    }

    /// All registered thread infos (clone), for snapshot/persistence.
    pub fn all_thread_infos(&self) -> Vec<ThreadInfo> {
        self.thread_info.values().cloned().collect()
    }

    /// All sync events (sorted by step), for snapshot/persistence.
    pub fn all_sync_events(&self) -> Vec<ThreadSyncEvent> {
        self.sync_log
            .all_records_sorted()
            .into_iter()
            .filter_map(|r| match r.payload {
                crate::delta_store::types::DeltaPayload::FullValue(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    /// All context switches (sorted by step), for snapshot/persistence.
    pub fn all_context_switches(&self) -> Vec<ContextSwitch> {
        self.switch_log
            .all_records_sorted()
            .into_iter()
            .filter_map(|r| match r.payload {
                crate::delta_store::types::DeltaPayload::FullValue(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    /// All thread state changes (sorted by step), for snapshot/persistence.
    pub fn all_state_changes(&self) -> Vec<ThreadStateChange> {
        self.state_log
            .all_records_sorted()
            .into_iter()
            .filter_map(|r| match r.payload {
                crate::delta_store::types::DeltaPayload::FullValue(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    /// Get the number of registered threads
    pub fn thread_count(&self) -> u32 {
        self.thread_info.len() as u32
    }

    // ========================================================================
    // Thread state operations
    // ========================================================================

    /// Write a thread state change event
    fn write_state_change(&mut self, change: ThreadStateChange) -> Result<()> {
        // Update thread index
        self.thread_index.register(change.thread_id, change.step);

        // Update current state
        self.thread_states.insert(change.thread_id, change.new_state);

        // Track currently running thread. Entering Running makes this thread
        // the running one. Leaving Running (to Blocked/Waiting/Terminated/…)
        // must clear it — otherwise `current_thread()` would keep reporting a
        // thread that is no longer executing, and later `prev_running_thread`
        // values (e.g. in `record_thread_exit`) would be recorded wrong. The
        // next Running transition or context switch re-establishes a runner.
        if change.new_state == ThreadState::Running {
            self.current_thread = Some(change.thread_id);
        } else if self.current_thread == Some(change.thread_id) {
            self.current_thread = None;
        }

        // Update stats
        if let Some(stats) = self.thread_stats.get_mut(&change.thread_id) {
            if change.new_state == ThreadState::Running {
                stats.steps_executed += 1;
            }
        }

        // Create delta record
        let record = DeltaRecord {
            step: change.step,
            encoding: DeltaEncoding::FullValue, // MVP: full value
            payload: DeltaPayload::FullValue(change),
            prev_hash: None,
        };

        self.state_log.append(record)?;
        Ok(())
    }

    /// Record a thread state change (public API)
    pub fn write(&mut self, change: ThreadStateChange) -> Result<()> {
        self.write_state_change(change)
    }

    /// Query thread state at a specific step
    ///
    /// Uses ThreadIndex to find the last state change before target_step.
    /// O(log K) where K = state changes for this thread.
    pub fn query_thread_state(&self, thread_id: u32, target_step: u64) -> Option<&ThreadStateChange> {
        let steps = self.thread_index.find_steps_for_thread(thread_id);
        // `steps` is sorted; binary-search for the last state change <= target_step.
        let idx = steps.partition_point(|&s| s <= target_step);
        let last_step = steps.get(idx.checked_sub(1)?)?;

        // Several threads may have a state change at `last_step`; pick this
        // thread's, taking the last-inserted if it somehow has more than one.
        self.state_log
            .get_all(*last_step)
            .iter()
            .rev()
            .find_map(|record| match &record.payload {
                DeltaPayload::FullValue(change) if change.thread_id == thread_id => Some(change),
                _ => None,
            })
    }

    /// Get all steps where a thread was active
    pub fn find_steps_for_thread(&self, thread_id: u32) -> &[u64] {
        self.thread_index.find_steps_for_thread(thread_id)
    }

    /// Get the currently running thread
    pub fn current_thread(&self) -> Option<u32> {
        self.current_thread
    }

    /// Get the state of all threads
    pub fn all_thread_states(&self) -> &HashMap<u32, ThreadState> {
        &self.thread_states
    }

    // ========================================================================
    // Synchronization event operations
    // ========================================================================

    /// Record a thread synchronization event (mutex/futex/condvar operation)
    pub fn write_sync_event(&mut self, event: ThreadSyncEvent) -> Result<()> {
        // Update sync object index: lock_addr → step
        self.sync_object_index.register(event.sync_object_addr, event.step);

        // Update thread sync index: thread_id → step (kept sorted so
        // query_sync_events can binary-search its range).
        insert_step_sorted(
            self.thread_sync_index.entry(event.thread_id).or_default(),
            event.step,
        );

        // Update statistics. Contention is "the acquire had to wait or was told
        // it would block", counted at most once per acquire — mirrors the
        // analyzer's `analyze_lock_contention` (#51). Crucially, wait time is
        // accumulated whenever the thread actually waited (`wait > 0`),
        // regardless of the final result: a lock that waited 3ms and then timed
        // out, or was interrupted, still consumed that wait time. The old code
        // only added wait time on `Success`, so `avg_lock_wait_ns` silently
        // dropped the wait of every timed-out / interrupted acquire, and missed
        // an interrupted-with-wait acquire as a contention entirely.
        if let Some(stats) = self.thread_stats.get_mut(&event.thread_id) {
            stats.sync_event_count += 1;
            if event.sync_type.is_acquire() {
                stats.lock_acquire_count += 1;
                let wait = event.wait_duration_ns.unwrap_or(0);
                let waited = wait > 0;
                let blocked = event.result == SyncResult::WouldBlock
                    || event.result == SyncResult::Timeout;
                if waited {
                    stats.lock_wait_total_ns += wait;
                    if wait > stats.max_lock_wait_ns {
                        stats.max_lock_wait_ns = wait;
                    }
                }
                if waited || blocked {
                    stats.lock_contention_count += 1;
                }
            } else if event.sync_type.is_release() {
                // #114: symmetric to acquire counting — release/wake ops
                // (MutexUnlock, RwLockUnlock, SemPost, FutexWake, and the
                // wider CondvarSignal/Broadcast/FutexWakeCount per #109's
                // is_release superset). acquire ≫ release flags a lock leak.
                stats.lock_release_count += 1;
            }
        }

        // Create delta record
        let record = DeltaRecord {
            step: event.step,
            encoding: DeltaEncoding::FullValue,
            payload: DeltaPayload::FullValue(event),
            prev_hash: None,
        };

        self.sync_log.append(record)?;
        Ok(())
    }

    /// Query synchronization events for a specific lock/mutex address
    ///
    /// Uses SyncObjectIndex for O(log K) lookup.
    /// Returns all sync events that touched this address.
    pub fn query_lock_contentions(&self, sync_object_addr: u64, start_step: u64, end_step: u64) -> Vec<&ThreadSyncEvent> {
        let steps = self.sync_object_index.find_steps_for_address(sync_object_addr);
        let in_range = sorted_step_range(steps, start_step, end_step);
        // A step may hold several sync events (other locks/threads, or a
        // lock+unlock at one seq); keep only those on this sync object. Visit
        // each step once — `get_all` already returns every record there.
        dedup_sorted_steps(in_range)
            .flat_map(|step| {
                self.sync_log.get_all(step).iter().filter_map(move |record| {
                    match &record.payload {
                        DeltaPayload::FullValue(event)
                            if event.sync_object_addr == sync_object_addr =>
                        {
                            Some(event)
                        }
                        _ => None,
                    }
                })
            })
            .collect()
    }

    /// Query synchronization events for a specific thread
    pub fn query_sync_events(&self, thread_id: u32, start_step: u64, end_step: u64) -> Vec<&ThreadSyncEvent> {
        let steps = self.thread_sync_index.get(&thread_id)
            .map(|s| s.as_slice())
            .unwrap_or(&[]);
        let in_range = sorted_step_range(steps, start_step, end_step);
        // Keep only this thread's events at each step (a step can carry several
        // threads' events); visit each step once.
        dedup_sorted_steps(in_range)
            .flat_map(|step| {
                self.sync_log.get_all(step).iter().filter_map(move |record| {
                    match &record.payload {
                        DeltaPayload::FullValue(event) if event.thread_id == thread_id => {
                            Some(event)
                        }
                        _ => None,
                    }
                })
            })
            .collect()
    }

    /// Find the last step where a specific sync object was accessed before target_step
    /// O(log K) where K = sync events for this object
    pub fn find_last_sync_access(&self, sync_object_addr: u64, target_step: u64) -> Option<u64> {
        self.sync_object_index.find_last_modification(sync_object_addr, target_step)
    }

    // ========================================================================
    // Context switch operations
    // ========================================================================

    /// Record a context switch event
    pub fn write_context_switch(&mut self, switch: ContextSwitch) -> Result<()> {
        // Update statistics for both threads
        if let Some(stats) = self.thread_stats.get_mut(&switch.from_thread) {
            stats.context_switch_count += 1;
        }
        if let Some(stats) = self.thread_stats.get_mut(&switch.to_thread) {
            stats.context_switch_count += 1;
        }

        // Update current thread tracking
        self.current_thread = Some(switch.to_thread);
        self.total_switches += 1;

        // Create delta record
        let record = DeltaRecord {
            step: switch.step,
            encoding: DeltaEncoding::FullValue,
            payload: DeltaPayload::FullValue(switch),
            prev_hash: None,
        };

        self.switch_log.append(record)?;
        Ok(())
    }

    /// Query context switches in a step range
    pub fn query_context_switches(&self, start_step: u64, end_step: u64) -> Vec<&ContextSwitch> {
        self.switch_log.get_range(start_step, end_step)
            .into_iter()
            .filter_map(|record| {
                match &record.payload {
                    DeltaPayload::FullValue(switch) => Some(switch),
                    _ => None,
                }
            })
            .collect()
    }

    /// Get the total number of context switches
    pub fn total_switches(&self) -> u64 {
        self.total_switches
    }

    // ========================================================================
    // Thread timeline query
    // ========================================================================

    /// Query the complete thread timeline for a specific thread
    ///
    /// Returns all events (state changes + sync events + context switches)
    /// for this thread in the given step range, sorted by step number.
    pub fn query_thread_timeline(&self, thread_id: u32, start_step: u64, end_step: u64) -> ThreadTimeline {
        // State changes. `state_log` is an `EventLog`, so a step can hold several
        // state changes (different threads switching at the same `trace.seq`).
        // `find_steps_for_thread` may list a step more than once, so dedup before
        // fanning out via `get_all`, then keep only this thread's changes.
        let thread_steps = self.find_steps_for_thread(thread_id);
        let in_range = sorted_step_range(thread_steps, start_step, end_step);
        let state_changes = dedup_sorted_steps(in_range)
            .flat_map(|step| {
                self.state_log.get_all(step).iter().filter_map(move |record| {
                    match &record.payload {
                        DeltaPayload::FullValue(change) if change.thread_id == thread_id => {
                            Some(change.clone())
                        }
                        _ => None,
                    }
                })
            })
            .collect();

        // Sync events
        let sync_events = self.query_sync_events(thread_id, start_step, end_step)
            .into_iter()
            .cloned()
            .collect();

        // Context switches involving this thread
        let context_switches = self.query_context_switches(start_step, end_step)
            .into_iter()
            .filter(|sw| sw.from_thread == thread_id || sw.to_thread == thread_id)
            .cloned()
            .collect();

        ThreadTimeline {
            thread_id,
            state_changes,
            sync_events,
            context_switches,
        }
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /// Get statistics for a specific thread
    pub fn get_thread_stats(&self, thread_id: u32) -> Option<ThreadStats> {
        self.thread_stats.get(&thread_id)
            .map(|builder| builder.build(thread_id))
    }

    /// Get statistics for all threads
    pub fn all_thread_stats(&self) -> Vec<ThreadStats> {
        self.thread_stats.keys()
            .filter_map(|&tid| self.get_thread_stats(tid))
            .collect()
    }
}

/// Thread timeline result — all events for a specific thread in a step range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadTimeline {
    /// Thread ID
    pub thread_id: u32,
    /// State changes in this range
    pub state_changes: Vec<ThreadStateChange>,
    /// Synchronization events in this range
    pub sync_events: Vec<ThreadSyncEvent>,
    /// Context switches involving this thread in this range
    pub context_switches: Vec<ContextSwitch>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> DeltaStoreConfig {
        DeltaStoreConfig::default()
    }

    #[test]
    fn test_thread_registration_and_info() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register main thread (thread_id=1, no parent)
        let main_info = ThreadInfo {
            thread_id: 1,
            pthread_id: Some(100),
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: Some("main".to_string()),
            stack_base: 0x7F000000,
            stack_size: 8 * 1024 * 1024, // 8MB
            tls_addr: 0x7F008000,
            is_jni_attached: false,
        };
        store.register_thread(main_info).unwrap();

        // Register worker thread created by main
        let worker_info = ThreadInfo {
            thread_id: 2,
            pthread_id: Some(101),
            parent_thread_id: 1, // Created by main thread
            create_step: 100,
            exit_step: None,
            name: Some("worker-1".to_string()),
            stack_base: 0x7E000000,
            stack_size: 4 * 1024 * 1024, // 4MB
            tls_addr: 0x7E040000,
            is_jni_attached: false,
        };
        store.register_thread(worker_info).unwrap();

        // Query thread info
        let main = store.get_thread_info(1).unwrap();
        assert_eq!(main.name, Some("main".to_string()));
        assert_eq!(main.parent_thread_id, 0);
        assert_eq!(main.stack_size, 8 * 1024 * 1024);

        let worker = store.get_thread_info(2).unwrap();
        assert_eq!(worker.parent_thread_id, 1);
        assert_eq!(worker.name, Some("worker-1".to_string()));

        // Check thread count
        assert_eq!(store.thread_count(), 2);
        let mut tids = store.all_thread_ids();
        tids.sort();
        assert_eq!(tids, vec![1, 2]);
    }

    #[test]
    fn test_thread_state_changes() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register thread
        let info = ThreadInfo {
            thread_id: 1,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: None,
            stack_base: 0,
            stack_size: 0,
            tls_addr: 0,
            is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // State changes: Runnable → Running → WaitingForLock → Running
        store.write(ThreadStateChange {
            step: 10, thread_id: 1,
            new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable),
            prev_running_thread: None,
        }).unwrap();

        store.write(ThreadStateChange {
            step: 500, thread_id: 1,
            new_state: ThreadState::WaitingForLock,
            prev_state: Some(ThreadState::Running),
            prev_running_thread: Some(1),
        }).unwrap();

        store.write(ThreadStateChange {
            step: 600, thread_id: 1,
            new_state: ThreadState::Running,
            prev_state: Some(ThreadState::WaitingForLock),
            prev_running_thread: Some(2),
        }).unwrap();

        // Query state at different steps
        let state_at_100 = store.query_thread_state(1, 100).unwrap();
        assert_eq!(state_at_100.new_state, ThreadState::Running);

        let state_at_550 = store.query_thread_state(1, 550).unwrap();
        assert_eq!(state_at_550.new_state, ThreadState::WaitingForLock);

        let state_at_700 = store.query_thread_state(1, 700).unwrap();
        assert_eq!(state_at_700.new_state, ThreadState::Running);

        // Check current running thread
        assert_eq!(store.current_thread(), Some(1));
    }

    #[test]
    fn test_sync_events_and_lock_contentions() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register two threads
        for tid in [1, 2] {
            let info = ThreadInfo {
                thread_id: tid,
                pthread_id: None,
                parent_thread_id: 0,
                create_step: 0,
                exit_step: None,
                name: None,
                stack_base: 0,
                stack_size: 0,
                tls_addr: 0,
                is_jni_attached: false,
            };
            store.register_thread(info).unwrap();
        }

        let mutex_addr = 0xABCD0000;

        // Thread 1 acquires mutex
        store.write_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // Thread 2 tries to acquire same mutex — contends
        store.write_sync_event(ThreadSyncEvent {
            step: 200, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success, // Eventually acquired
            wait_duration_ns: Some(5000000), // 5ms wait
        }).unwrap();

        // Thread 1 releases mutex
        store.write_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // Query: all events for this mutex
        let mutex_events = store.query_lock_contentions(mutex_addr, 0, 300);
        assert_eq!(mutex_events.len(), 3);

        // Query: all sync events for thread 1
        let thread1_events = store.query_sync_events(1, 0, 300);
        assert_eq!(thread1_events.len(), 2); // Lock + Unlock

        // Sub-range query must binary-search the (out-of-order-fed) sorted
        // index and return only events inside [120, 180] — i.e. the step-150
        // unlock, not the step-100 or step-200 locks.
        let mid = store.query_lock_contentions(mutex_addr, 120, 180);
        assert_eq!(mid.len(), 1);
        assert_eq!(mid[0].step, 150);
        // Per-thread sub-range: thread 1 only has the unlock at 150 in [120, 300].
        let t1_mid = store.query_sync_events(1, 120, 300);
        assert_eq!(t1_mid.len(), 1);
        assert_eq!(t1_mid[0].step, 150);

        // Query: last sync access before step 180
        let last = store.find_last_sync_access(mutex_addr, 180);
        assert_eq!(last, Some(150)); // Thread 1's unlock at step 150

        // Check stats
        let stats1 = store.get_thread_stats(1).unwrap();
        assert_eq!(stats1.lock_acquire_count, 1);
        assert_eq!(stats1.lock_release_count, 1); // thread 1 unlocked at step 150
        let stats2 = store.get_thread_stats(2).unwrap();
        assert_eq!(stats2.lock_acquire_count, 1);
        assert_eq!(stats2.lock_contention_count, 1);
    }

    /// #114: a MutexUnlock increments lock_release_count symmetric to acquire.
    #[test]
    fn test_lock_release_count_tracks_unlocks() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 1);
        assert_eq!(stats.lock_release_count, 1);
    }

    /// #114: CondvarSignal counts as a release (wake-the-waiter semantics,
    /// per #109's is_release superset).
    #[test]
    fn test_lock_release_count_includes_condvar_signal() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::CondvarSignal,
            sync_object_addr: 0xB000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 0);
        assert_eq!(stats.lock_release_count, 1);
    }

    /// #114: acquire without release is detectable (acquire > release → leak).
    #[test]
    fn test_lock_release_count_detects_leak() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        // Two acquires, one release → leak (acquire=2, release=1)
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA001, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 30, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 2);
        assert_eq!(stats.lock_release_count, 1);
        assert!(stats.lock_acquire_count > stats.lock_release_count);
    }

    #[test]
    fn test_context_switches() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register two threads
        for tid in [1, 2] {
            let info = ThreadInfo {
                thread_id: tid,
                pthread_id: None,
                parent_thread_id: 0,
                create_step: 0,
                exit_step: None,
                name: None,
                stack_base: 0,
                stack_size: 0,
                tls_addr: 0,
                is_jni_attached: false,
            };
            store.register_thread(info).unwrap();
        }

        // Context switch: thread 1 → thread 2
        store.write_context_switch(ContextSwitch {
            step: 1000,
            from_thread: 1,
            to_thread: 2,
            switch_reason: SwitchReason::Preemption,
            cpu_core: Some(0),
        }).unwrap();

        // Context switch: thread 2 → thread 1
        store.write_context_switch(ContextSwitch {
            step: 2000,
            from_thread: 2,
            to_thread: 1,
            switch_reason: SwitchReason::Blocking,
            cpu_core: Some(0),
        }).unwrap();

        // Query context switches in range
        let switches = store.query_context_switches(0, 3000);
        assert_eq!(switches.len(), 2);
        assert_eq!(switches[0].from_thread, 1);
        assert_eq!(switches[0].to_thread, 2);
        assert_eq!(switches[0].switch_reason, SwitchReason::Preemption);

        // Check total switches
        assert_eq!(store.total_switches(), 2);

        // Check stats
        let stats1 = store.get_thread_stats(1).unwrap();
        assert_eq!(stats1.context_switch_count, 2); // Involved in both switches
    }

    #[test]
    fn test_thread_timeline_query() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register thread
        let info = ThreadInfo {
            thread_id: 1,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: Some("main".to_string()),
            stack_base: 0x7F000000,
            stack_size: 8 * 1024 * 1024,
            tls_addr: 0,
            is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // State change
        store.write(ThreadStateChange {
            step: 10, thread_id: 1,
            new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable),
            prev_running_thread: None,
        }).unwrap();

        // Sync event
        store.write_sync_event(ThreadSyncEvent {
            step: 50, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // Context switch
        store.write_context_switch(ContextSwitch {
            step: 100, from_thread: 1, to_thread: 2,
            switch_reason: SwitchReason::Blocking,
            cpu_core: None,
        }).unwrap();

        // Query timeline
        let timeline = store.query_thread_timeline(1, 0, 200);
        assert_eq!(timeline.thread_id, 1);
        assert_eq!(timeline.state_changes.len(), 1);
        assert_eq!(timeline.sync_events.len(), 1);
        assert_eq!(timeline.context_switches.len(), 1);
    }

    #[test]
    fn test_thread_exit() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        let info = ThreadInfo {
            thread_id: 1,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: None,
            stack_base: 0,
            stack_size: 0,
            tls_addr: 0,
            is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // Record exit
        store.record_thread_exit(1, 10000).unwrap();

        // Check exit_step
        let info = store.get_thread_info(1).unwrap();
        assert_eq!(info.exit_step, Some(10000));

        // Check state
        let state = store.all_thread_states().get(&1).unwrap();
        assert_eq!(*state, ThreadState::Terminated);
    }

    /// `record_thread_exit` must stamp the thread's ACTUAL prior state in the
    /// generated `ThreadStateChange.prev_state`, not a hardcoded Running. A
    /// thread can exit from Blocked/Waiting (e.g. cancelled mid-wait); the
    /// transition record should reflect that. Before the fix `prev_state` was
    /// always `Some(Running)` regardless of the real state.
    #[test]
    fn test_thread_exit_records_actual_prev_state() {
        let mut store = ThreadStore::new(make_config());

        let info = ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // Move the thread into Blocked (not Running) before it exits.
        store.write(ThreadStateChange {
            step: 50, thread_id: 1, new_state: ThreadState::Blocked,
            prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
        }).unwrap();
        assert_eq!(*store.all_thread_states().get(&1).unwrap(), ThreadState::Blocked);

        // Now exit. The recorded transition must be Blocked → Terminated.
        store.record_thread_exit(1, 10000).unwrap();

        let change = store.query_thread_state(1, 10000).unwrap();
        assert_eq!(change.new_state, ThreadState::Terminated);
        assert_eq!(change.prev_state, Some(ThreadState::Blocked),
            "prev_state must be the real prior state (Blocked), not hardcoded Running");
    }

    /// A thread leaving Running must clear `current_thread` — otherwise the
    /// store keeps reporting a runner that is no longer executing, and any
    /// later `prev_running_thread` (e.g. in `record_thread_exit`) is recorded
    /// wrong. Before the fix, only the *entering* branch updated
    /// `current_thread`; the *leaving* branch was missing.
    #[test]
    fn test_leaving_running_clears_current_thread() {
        let mut store = ThreadStore::new(make_config());

        let info = ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // Runnable → Running: now thread 1 is the runner.
        store.write(ThreadStateChange {
            step: 10, thread_id: 1, new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
        }).unwrap();
        assert_eq!(store.current_thread(), Some(1));

        // Running → Blocked: thread 1 is no longer executing.
        store.write(ThreadStateChange {
            step: 20, thread_id: 1, new_state: ThreadState::Blocked,
            prev_state: Some(ThreadState::Running), prev_running_thread: Some(1),
        }).unwrap();
        assert_eq!(store.current_thread(), None,
            "leaving Running must clear current_thread — the thread is not running");

        // A different thread entering Running must still register as the runner.
        store.write(ThreadStateChange {
            step: 30, thread_id: 2, new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
        }).unwrap();
        assert_eq!(store.current_thread(), Some(2));
    }

    #[test]
    fn test_jni_attached_thread() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Java thread attaching to JNI
        let jni_info = ThreadInfo {
            thread_id: 100,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 500,
            exit_step: None,
            name: Some("Java-AsyncTask-1".to_string()),
            stack_base: 0,
            stack_size: 0,
            tls_addr: 0,
            is_jni_attached: true, // JNI attached!
        };
        store.register_thread(jni_info).unwrap();

        let info = store.get_thread_info(100).unwrap();
        assert_eq!(info.is_jni_attached, true);
        assert_eq!(info.name, Some("Java-AsyncTask-1".to_string()));
    }

    #[test]
    fn test_thread_state_helpers() {
        assert!(ThreadState::WaitingForLock.is_waiting());
        assert!(ThreadState::WaitingForFutex.is_waiting());
        assert!(ThreadState::WaitingForCondvar.is_waiting());
        assert!(!ThreadState::Running.is_waiting());
        assert!(!ThreadState::Runnable.is_waiting());

        assert!(ThreadState::Running.is_alive());
        assert!(ThreadState::WaitingForLock.is_alive());
        assert!(!ThreadState::Terminated.is_alive());

        assert!(SyncEventType::MutexLock.is_acquire());
        assert!(!SyncEventType::MutexLock.is_release());
        assert!(SyncEventType::MutexUnlock.is_release());
        assert!(!SyncEventType::MutexUnlock.is_acquire());
        // `MutexLocked` (frida's successful acquire) is an acquire, not a release.
        // Omitting it from `is_acquire` made `has_sync_between` miss synchronization
        // and `exclusive_locks` drop deadlock edges on MutexLocked-only traces.
        assert!(SyncEventType::MutexLocked.is_acquire());
        assert!(!SyncEventType::MutexLocked.is_release());

        // #109: three-way classification. CondvarWait/BarrierWait are NOT
        // holdable acquires (condvar wait releases its mutex; a barrier is a
        // rendezvous) — counting them as acquires fabricated monotonically-
        // increasing depth with no paired release, producing false deadlocks.
        // They remain synchronization signals for race suppression.
        assert!(SyncEventType::CondvarWait.is_sync_signal());
        assert!(!SyncEventType::CondvarWait.is_acquire());
        assert!(SyncEventType::BarrierWait.is_sync_signal());
        assert!(!SyncEventType::BarrierWait.is_acquire());
        // SemWait/FutexWait ARE holdable acquires (paired with SemPost/FutexWake).
        assert!(SyncEventType::SemWait.is_holdable_acquire());
        assert!(SyncEventType::SemPost.is_holdable_release());
        assert!(SyncEventType::FutexWait.is_holdable_acquire());
        assert!(SyncEventType::FutexWake.is_holdable_release());
        // FutexWakeCount is a sync signal, NOT a holdable release (waker-emitted,
        // no per-waiter identity → cannot account per-thread depth).
        assert!(SyncEventType::FutexWakeCount.is_sync_signal());
        assert!(!SyncEventType::FutexWakeCount.is_holdable_release());
        // CondvarSignal/Broadcast are sync signals; they stay in is_release() as
        // a broad superset for has_sync_between, but are not holdable releases.
        assert!(SyncEventType::CondvarSignal.is_sync_signal());
        assert!(!SyncEventType::CondvarSignal.is_holdable_release());
    }

    /// `primitive_kind()` classifies each of the 16 `SyncEventType` variants into
    /// its primitive class — all variants operating on the same primitive
    /// collapse together (every mutex op → `Mutex`, every condvar op →
    /// `Condvar`, etc.). Used to type the producer-consumer `sync_mechanism`
    /// field so the reported mechanism is a typed primitive, not a bare addr.
    #[test]
    fn test_primitive_kind_classifies_all_variants() {
        use sotrace_core::models::thread::SyncPrimitiveKind as K;
        use sotrace_core::models::thread::SyncEventType as T;

        // Mutex family — all four operations collapse to Mutex.
        assert_eq!(T::MutexLock.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexLocked.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexTryLock.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexUnlock.primitive_kind(), K::Mutex);

        // RwLock family.
        assert_eq!(T::RwLockRead.primitive_kind(), K::RwLock);
        assert_eq!(T::RwLockWrite.primitive_kind(), K::RwLock);
        assert_eq!(T::RwLockUnlock.primitive_kind(), K::RwLock);

        // Semaphore family.
        assert_eq!(T::SemWait.primitive_kind(), K::Semaphore);
        assert_eq!(T::SemPost.primitive_kind(), K::Semaphore);

        // Futex family — including the #109 sync-signal FutexWakeCount.
        assert_eq!(T::FutexWait.primitive_kind(), K::Futex);
        assert_eq!(T::FutexWake.primitive_kind(), K::Futex);
        assert_eq!(T::FutexWakeCount.primitive_kind(), K::Futex);

        // Condvar family.
        assert_eq!(T::CondvarWait.primitive_kind(), K::Condvar);
        assert_eq!(T::CondvarSignal.primitive_kind(), K::Condvar);
        assert_eq!(T::CondvarBroadcast.primitive_kind(), K::Condvar);

        // Barrier.
        assert_eq!(T::BarrierWait.primitive_kind(), K::Barrier);
    }

    // ------------------------------------------------------------------------
    // #52: EventLog same-step retention. `step`/`seq` comes from the adapter
    // (`trace.seq`) and is NOT unique, so two threads can emit an event at the
    // same step. The old `DeltaLog` keyed insert clobbered all but the last;
    // `EventLog` keeps every same-step record. These tests drive each of the
    // three event logs (sync / state / switch) with a colliding step and assert
    // both records survive on every read path (indexed query + `all_*`).
    // ------------------------------------------------------------------------

    /// Two sync events on different locks/threads at the SAME step both survive,
    /// and each read path attributes them to the right lock/thread.
    #[test]
    fn test_sync_events_same_step_both_retained() {
        let mut store = ThreadStore::new(make_config());

        // thread 1 waits on lock 0xA at step 100; thread 2 acquires lock 0xB at
        // the same step 100. A keyed-insert log would keep only the second.
        store.write_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000,
            result: SyncResult::Success,
            wait_duration_ns: Some(5_000_000),
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xB000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // all_sync_events keeps both.
        assert_eq!(store.all_sync_events().len(), 2);

        // Per-thread query returns exactly that thread's event.
        let t1 = store.query_sync_events(1, 0, u64::MAX);
        assert_eq!(t1.len(), 1);
        assert_eq!(t1[0].sync_object_addr, 0xA000);
        assert_eq!(t1[0].wait_duration_ns, Some(5_000_000));

        let t2 = store.query_sync_events(2, 0, u64::MAX);
        assert_eq!(t2.len(), 1);
        assert_eq!(t2[0].sync_object_addr, 0xB000);

        // Per-lock query returns exactly that lock's event.
        let lock_a = store.query_lock_contentions(0xA000, 0, u64::MAX);
        assert_eq!(lock_a.len(), 1);
        assert_eq!(lock_a[0].thread_id, 1);
        let lock_b = store.query_lock_contentions(0xB000, 0, u64::MAX);
        assert_eq!(lock_b.len(), 1);
        assert_eq!(lock_b[0].thread_id, 2);
    }

    /// Two state changes for different threads at the SAME step both survive;
    /// `query_thread_state` and `query_thread_timeline` each pick the right one.
    #[test]
    fn test_state_changes_same_step_both_retained() {
        let mut store = ThreadStore::new(make_config());
        for tid in [1u32, 2] {
            store.register_thread(ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: None,
                stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
            }).unwrap();
        }

        // A context switch: thread 1 blocks and thread 2 runs, both stamped at
        // step 200 (one seq, two state deltas).
        store.write(ThreadStateChange {
            step: 200, thread_id: 1,
            new_state: ThreadState::WaitingForLock,
            prev_state: Some(ThreadState::Running),
            prev_running_thread: Some(1),
        }).unwrap();
        store.write(ThreadStateChange {
            step: 200, thread_id: 2,
            new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable),
            prev_running_thread: Some(1),
        }).unwrap();

        // Both retained in the raw dump.
        assert_eq!(store.all_state_changes().len(), 2);

        // query_thread_state resolves per thread at that step.
        assert_eq!(
            store.query_thread_state(1, 200).unwrap().new_state,
            ThreadState::WaitingForLock
        );
        assert_eq!(
            store.query_thread_state(2, 200).unwrap().new_state,
            ThreadState::Running
        );

        // The timeline for each thread contains only its own change.
        let tl1 = store.query_thread_timeline(1, 0, u64::MAX);
        assert_eq!(tl1.state_changes.len(), 1);
        assert_eq!(tl1.state_changes[0].new_state, ThreadState::WaitingForLock);
        let tl2 = store.query_thread_timeline(2, 0, u64::MAX);
        assert_eq!(tl2.state_changes.len(), 1);
        assert_eq!(tl2.state_changes[0].new_state, ThreadState::Running);
    }

    /// A lock that waits then times out (or is interrupted) must still count its
    /// wait time toward the thread's `avg_lock_wait_ns`, and an interrupted wait
    /// must count as a contention. #53: the old stats only accumulated wait on
    /// `Success`, dropping the wait of every non-Success acquire.
    #[test]
    fn test_stats_wait_time_counted_for_nonsuccess_results() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();

        // Acquire A: waited 3ms then TIMED OUT. Old code: contention counted but
        // wait dropped → avg would be 0. New: wait accounted.
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0x1000,
            result: SyncResult::Timeout,
            wait_duration_ns: Some(3_000_000),
        }).unwrap();

        // Acquire B: waited 5ms then INTERRUPTED. Old code: neither branch fired
        // → not even counted as a contention, wait dropped entirely.
        store.write_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1,
            sync_type: SyncEventType::FutexWait,
            sync_object_addr: 0x2000,
            result: SyncResult::Interrupted,
            wait_duration_ns: Some(5_000_000),
        }).unwrap();

        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 2);
        // Both waited → both are contentions (each counted once).
        assert_eq!(stats.lock_contention_count, 2);
        // avg = (3ms + 5ms) / 2 contentions = 4ms. Old code would report 0.
        assert_eq!(stats.avg_lock_wait_ns, Some(4_000_000));
        // #118: the longest single wait (5ms Interrupted) is the long tail.
        assert_eq!(stats.max_lock_wait_ns, Some(5_000_000));
    }

    /// A trylock that WouldBlock with zero wait is a contention but contributes
    /// no wait time — so it must not deflate a real average via a phantom sample.
    #[test]
    fn test_stats_wouldblock_zero_wait_is_contention_without_wait() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();

        // A real wait of 6ms (succeeded).
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0x1000,
            result: SyncResult::Success,
            wait_duration_ns: Some(6_000_000),
        }).unwrap();
        // A trylock that would block, no measurable wait.
        store.write_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1,
            sync_type: SyncEventType::MutexTryLock,
            sync_object_addr: 0x2000,
            result: SyncResult::WouldBlock,
            wait_duration_ns: None,
        }).unwrap();

        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 2);
        assert_eq!(stats.lock_contention_count, 2);
        // total wait 6ms over 2 contentions = 3ms average.
        assert_eq!(stats.avg_lock_wait_ns, Some(3_000_000));
        // #118: only the 6ms acquire actually waited; WouldBlock trylock has
        // no wait, so max is the single real wait, not deflated by zero.
        assert_eq!(stats.max_lock_wait_ns, Some(6_000_000));
    }

    /// #118: max_lock_wait_ns tracks the longest single wait, not just the
    /// running average. A thread that waits 3ms then 5ms then 1ms must report
    /// max=5ms even though avg=3ms — the long tail avg hides.
    #[test]
    fn test_stats_max_lock_wait_tracks_longest() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        let mk = |step, wait_ns| ThreadSyncEvent {
            step, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000,
            result: SyncResult::Success,
            wait_duration_ns: Some(wait_ns),
        };
        store.write_sync_event(mk(10, 3_000_000)).unwrap();
        store.write_sync_event(mk(20, 5_000_000)).unwrap();
        store.write_sync_event(mk(30, 1_000_000)).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_contention_count, 3);
        assert_eq!(stats.avg_lock_wait_ns, Some(3_000_000)); // (3+5+1)/3 = 3ms
        assert_eq!(stats.max_lock_wait_ns, Some(5_000_000)); // long tail
    }

    /// #118: max_lock_wait_ns is None when the thread never waited (no
    /// contention with a real wait), mirroring avg_lock_wait_ns.
    #[test]
    fn test_stats_max_lock_wait_none_when_no_wait() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        // A successful acquire with zero wait is not a contention.
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_contention_count, 0);
        assert_eq!(stats.avg_lock_wait_ns, None);
        assert_eq!(stats.max_lock_wait_ns, None);
    }

    /// Two context switches at the SAME step both survive on every read path.
    #[test]
    fn test_context_switches_same_step_both_retained() {
        let mut store = ThreadStore::new(make_config());

        store.write_context_switch(ContextSwitch {
            step: 300, from_thread: 1, to_thread: 2,
            switch_reason: SwitchReason::Blocking, cpu_core: Some(0),
        }).unwrap();
        store.write_context_switch(ContextSwitch {
            step: 300, from_thread: 3, to_thread: 4,
            switch_reason: SwitchReason::Preemption, cpu_core: Some(1),
        }).unwrap();

        assert_eq!(store.all_context_switches().len(), 2);
        assert_eq!(store.total_switches(), 2);

        // Range query flattens both same-step switches.
        let switches = store.query_context_switches(0, u64::MAX);
        assert_eq!(switches.len(), 2);

        // The per-thread timeline filter still isolates the switch involving it.
        let mut cores: Vec<u32> = switches.iter().filter_map(|s| s.cpu_core).collect();
        cores.sort_unstable();
        assert_eq!(cores, vec![0, 1]);
    }

    /// Re-registering an existing thread must NOT reset its accumulated state
    /// or statistics. An adapter can re-report a thread (e.g. its name resolved
    /// later, or a duplicate event) — the metadata should refresh, but the
    /// thread's `thread_states` (could be Running/Terminated) and `thread_stats`
    /// (steps/sync/lock counts already accrued) must survive. Before the fix
    /// both were unconditional `insert`, silently zeroing stats and flipping a
    /// Terminated thread back to Runnable.
    #[test]
    fn test_reregister_thread_preserves_stats_and_state() {
        let mut store = ThreadStore::new(make_config());

        let info = |tid: u32, name: &str| ThreadInfo {
            thread_id: tid, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some(name.to_string()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };

        // Register thread 1, accrue a sync event + a state-change step.
        store.register_thread(info(1, "initial")).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();
        // A state change records a step executed and moves the thread to Running.
        store.write(ThreadStateChange {
            step: 110, thread_id: 1, new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
        }).unwrap();

        let before = store.get_thread_stats(1).unwrap();
        assert_eq!(before.sync_event_count, 1, "setup: one sync event counted");
        assert_eq!(before.steps_executed, 1, "setup: one state-change step counted");

        // Re-register thread 1 with refreshed metadata (name change).
        store.register_thread(info(1, "refreshed")).unwrap();

        // Metadata refreshed...
        assert_eq!(store.get_thread_info(1).unwrap().name.as_deref(), Some("refreshed"));

        // ...but stats preserved, NOT reset to zero.
        let after = store.get_thread_stats(1).unwrap();
        assert_eq!(after.sync_event_count, 1, "sync_event_count must survive re-register");
        assert_eq!(after.steps_executed, 1, "steps_executed must survive re-register");

        // And state not flipped back to Runnable — it was Running (and stays so).
        assert_eq!(*store.all_thread_states().get(&1).unwrap(), ThreadState::Running,
            "thread_states must not reset to Runnable on re-register");
    }
}
