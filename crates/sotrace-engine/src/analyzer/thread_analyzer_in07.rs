impl ThreadAnalyzer {

    /// Summarize per-thread scheduling behavior from the context-switch stream.
    ///
    /// Turns the raw switch events into one row per thread: how often it was
    /// scheduled on/off, whether it left the CPU willingly (Yield / Blocking) or
    /// was forced off (Preemption / TimeSliceExpired / Interrupt), how many
    /// migrations landed it on a core, and which cores it ran on. This is the
    /// consumer for `context_switches`, which was otherwise collected but never
    /// analyzed.
    pub fn analyze_scheduling(&mut self) -> Vec<ThreadSchedulingStats> {
        // Per-thread accumulator. Counts (in/out/vol/invol/migration) are
        // order-independent; `cores` is a set so repeated runs on the same
        // core collapse. `core_residency` is accumulated via a global
        // step-ordered pass below, because a residency interval's length is
        // the step gap to the next switch that ended it — a global (cross-
        // thread) temporal notion the per-thread counts cannot recover.
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
        // thread -> core -> accumulated residency steps.
        let mut residency: HashMap<u32, HashMap<u32, u64>> = HashMap::new();
        // Last "run-in" of each thread: (step, core) where it was scheduled
        // on, awaiting a closing switch to measure the span. None means no
        // tracked interval (never scheduled on a known core, or just closed).
        let mut last_in: HashMap<u32, (u64, u32)> = HashMap::new();

        // Flatten the BTreeMap<step, Vec<ContextSwitch>> into a global,
        // step-ordered sequence. BTreeMap iterates steps ascending; the Vec
        // per step preserves insertion order (same-step switches, see #59).
        let mut global: Vec<&ContextSwitch> = Vec::new();
        for switches in self.context_switches.values() {
            global.extend(switches.iter());
        }

        for sw in global {
            // Close the running interval of `from_thread`: it ran on its
            // last-in core from `last_in_step` until `sw.step`.
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
            if let Some((start, core)) = last_in.remove(&sw.from_thread) {
                let span = sw.step.saturating_sub(start);
                *residency
                    .entry(sw.from_thread)
                    .or_default()
                    .entry(core)
                    .or_insert(0) += span;
            }

            // The thread being scheduled ON: it now runs on `cpu_core`.
            let in_acc = per_thread.entry(sw.to_thread).or_default();
            in_acc.scheduled_in += 1;
            if sw.switch_reason == SwitchReason::Migration {
                in_acc.migrations += 1;
            }
            if let Some(core) = sw.cpu_core {
                in_acc.cores.insert(core);
                // Track the new run-in interval only if we know the core; a
                // None core leaves last_in unset so no residency is fabricated
                // when it later closes.
                last_in.insert(sw.to_thread, (sw.step, core));
            } else {
                // Unknown core: drop any prior interval so a later close
                // doesn't attribute span to a stale core.
                last_in.remove(&sw.to_thread);
            }
        }

        // Final unbounded run-ins contribute 0 (no following switch closes
        // them); we deliberately drop them rather than fabricate a span to
        // trace-end. This mirrors #65's tail-state handling.

        let mut results: Vec<ThreadSchedulingStats> = per_thread
            .into_iter()
            .map(|(thread_id, acc)| {
                let mut cpu_cores: Vec<u32> = acc.cores.into_iter().collect();
                cpu_cores.sort_unstable();
                // Collect this thread's residency, sorted by core id.
                let mut core_residency: Vec<(u32, u64)> = residency
                    .remove(&thread_id)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                core_residency.sort_unstable_by_key(|(core, _)| *core);
                ThreadSchedulingStats {
                    thread_id,
                    scheduled_in_count: acc.scheduled_in,
                    scheduled_out_count: acc.scheduled_out,
                    voluntary_switches: acc.voluntary,
                    involuntary_switches: acc.involuntary,
                    migration_count: acc.migrations,
                    cpu_cores,
                    core_residency,
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
