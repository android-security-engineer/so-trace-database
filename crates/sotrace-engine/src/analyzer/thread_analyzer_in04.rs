impl ThreadAnalyzer {

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
}
