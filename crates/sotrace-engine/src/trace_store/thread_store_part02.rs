
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
