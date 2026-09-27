impl ThreadAnalyzer {

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
}
