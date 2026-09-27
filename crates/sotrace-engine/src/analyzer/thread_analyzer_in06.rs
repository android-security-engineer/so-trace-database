impl ThreadAnalyzer {

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
            first_step: Option<u64>,
            last_step: Option<u64>,
        }
        impl Acc {
            fn new() -> Self {
                Acc {
                    total: 0, j2n: 0, n2j: 0,
                    native_addrs: HashSet::new(),
                    java_methods: HashSet::new(),
                    first_step: None,
                    last_step: None,
                }
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
                // Record first/last crossing step. jni_calls is a BTreeMap<seq,
                // Vec> iterated in ascending seq order, so the first call we
                // see for a thread is its globally-earliest crossing.
                if acc.first_step.is_none() {
                    acc.first_step = Some(call.seq);
                }
                acc.last_step = Some(call.seq);
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
                    first_crossing_step: acc.first_step,
                    last_crossing_step: acc.last_step,
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
            for (r_step, r_tid, r_addr, r_size) in self.reads_overlapping(*w_addr, *w_size) {
                if r_tid == *w_tid { continue; } // Same thread
                if r_step <= *w_step { continue; } // Read before write

                let is_sync = self.has_sync_between(*w_tid, r_tid, *w_step, r_step);

                // Precise transferred byte range: intersection of the write
                // `[w_addr, w_end)` and the read `[r_addr, r_end)`.
                let w_end = (*w_addr).saturating_add(*w_size as u64);
                let r_end = r_addr.saturating_add(r_size as u64);
                let overlap_address = (*w_addr).max(r_addr);
                let overlap_end = w_end.min(r_end);
                let overlap_size = overlap_end.saturating_sub(overlap_address);

                flows.push(ThreadDataFlow {
                    from_thread: *w_tid,
                    to_thread: r_tid,
                    address: *w_addr,
                    write_step: *w_step,
                    read_step: r_step,
                    is_synchronized: is_sync,
                    write_size: *w_size as u64,
                    read_size: r_size as u64,
                    overlap_address,
                    overlap_size,
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
            // number of produce-consume cycles, not the address count. Each
            // slot also carries the access size and transferred range from the
            // first cycle's flow (#116 — same slot keeps one size in practice).
            let mut shared_addresses: Vec<SharedAddress> = group_flows.iter()
                .map(|f| SharedAddress {
                    address: f.address,
                    access_size: f.write_size,
                    overlap_size: f.overlap_size,
                })
                .collect();
            // Dedup by address: keep the first occurrence per slot. A stable
            // sort by address groups duplicates, then dedup_by on address.
            shared_addresses.sort_by_key(|s| s.address);
            shared_addresses.dedup_by(|a, b| a.address == b.address);

            // Compute average and max latency. Both derive from the same
            // produce→consume step gap (read_step - write_step, saturating),
            // so a single collected pass gives both. max surfaces the tail that
            // avg hides (#120, mirroring #118's max_lock_wait_ns).
            let latencies: Vec<u64> = group_flows.iter()
                .map(|f| f.read_step.saturating_sub(f.write_step))
                .collect();
            let total_latency: u64 = latencies.iter().sum();
            let avg_latency = total_latency / group_flows.len() as u64;
            let max_latency = latencies.iter().copied().max().unwrap_or(0);

            // Find the sync mechanism (most common lock used between these threads)
            let sync_mechanism = self.find_sync_mechanism(*producer, *consumer);

            patterns.push(ProducerConsumerPattern {
                producer_thread: *producer,
                consumer_thread: *consumer,
                shared_addresses,
                cycle_count: group_flows.len() as u64,
                avg_latency_steps: avg_latency,
                max_latency_steps: max_latency,
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
}
