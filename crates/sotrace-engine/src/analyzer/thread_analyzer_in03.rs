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
}
