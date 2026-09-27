
impl QueryEngine {
    /// Execute an instruction query
    ///
    /// Uses address_index and thread_index to skip irrelevant steps:
    /// - If address_range specified: only steps in that range
    /// - If thread_id specified: only steps on that thread
    /// - Otherwise: sequential scan with skip-list optimization
    pub fn query_instructions(engine: &TraceEngine, query: InstructionQuery) -> Result<Vec<InstructionTrace>> {
        let start = query.start_step.unwrap_or(0);
        let end = query.end_step.unwrap_or(u64::MAX);

        let mut results: Vec<InstructionTrace> = engine.query_instructions_range(start, end)
            .into_iter()
            .filter(|t| {
                // Apply address range filter
                if let Some((lo, hi)) = query.address_range {
                    if t.address < lo || t.address > hi {
                        return false;
                    }
                }
                // Apply thread filter
                if let Some(tid) = query.thread_id {
                    if t.thread_id != tid {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Apply limit
        if let Some(limit) = query.limit {
            results.truncate(limit as usize);
        }

        Ok(results)
    }

    /// Execute a memory value query
    ///
    /// Fast path: find the last delta for the target page before
    /// the target step, then apply only that delta.
    /// O(log unique_pages + K) where K = deltas for that page
    pub fn query_memory(engine: &TraceEngine, query: MemoryQuery) -> Result<Option<MemoryValueResult>> {
        Ok(engine.query_memory_value(query.address, query.size, query.step))
    }

    /// Execute a call chain query (rebuild call stack)
    ///
    /// Replays the thread's call/return events up to `target_step` (push on
    /// Call, pop on Return, replace on TailCall), backed by the event log's
    /// range iterator — O(log N + K) where K is the number of the thread's
    /// call records in `[0, step]`.
    pub fn query_call_chain(engine: &TraceEngine, query: CallChainQuery) -> Result<Vec<StackFrame>> {
        Ok(engine.rebuild_call_stack(query.thread_id, query.step))
    }

    /// Execute a register query
    ///
    /// Uses the register index to find the last delta that touched the
    /// target register before the target step. O(log K) where
    /// K = changes to that specific register. Returns `None` when no delta
    /// touched the register at or before `step`, or when `register_id` is
    /// `None` (a full-state query belongs to `reconstruct_register_state`,
    /// exposed on the engine directly).
    pub fn query_register(engine: &TraceEngine, query: RegisterQuery) -> Result<Option<u64>> {
        let Some(register_id) = query.register_id else {
            return Ok(None);
        };
        Ok(engine.query_register(register_id, query.step))
    }

    /// Execute a thread query
    ///
    /// Returns thread info, state, and/or statistics.
    /// Uses ThreadIndex for O(log K) lookup.
    pub fn query_thread(engine: &TraceEngine, query: ThreadQuery) -> Result<Vec<ThreadQueryResult>> {
        let thread_ids: Vec<u32> = if let Some(tid) = query.thread_id {
            vec![tid]
        } else {
            engine.all_thread_ids()
        };

        let mut results = Vec::new();
        for tid in thread_ids {
            let info = if query.include_info {
                engine.get_thread_info(tid).cloned()
            } else {
                None
            };

            let state = if let Some(step) = query.step {
                engine.query_thread_state(tid, step).map(|c| c.new_state.clone())
            } else {
                None
            };

            let stats = if query.include_stats {
                engine.get_thread_stats(tid)
            } else {
                None
            };

            results.push(ThreadQueryResult { info, state, stats });
        }

        Ok(results)
    }

    /// Execute a thread synchronization query
    ///
    /// Uses SyncObjectIndex for lock-contention queries:
    /// "who contended on mutex at address X?"
    /// Uses ThreadSyncIndex for thread-scoped queries:
    /// "what locks did thread T touch?"
    pub fn query_thread_sync(engine: &TraceEngine, query: ThreadSyncQuery) -> Result<ThreadSyncQueryResult> {
        let events: Vec<ThreadSyncEvent> = if let Some(lock_addr) = query.sync_object_addr {
            // Query by lock address
            engine.query_lock_contentions(lock_addr, query.start_step, query.end_step)
                .into_iter()
                .filter(|e| {
                    // Optional thread filter
                    if let Some(tid) = query.thread_id {
                        e.thread_id == tid
                    } else {
                        true
                    }
                })
                .cloned()
                .collect()
        } else if let Some(tid) = query.thread_id {
            // Query by thread ID
            engine.query_thread_sync_events(tid, query.start_step, query.end_step)
                .into_iter()
                .cloned()
                .collect()
        } else {
            // No filter: get all sync events for all threads in range
            let all_tids = engine.all_thread_ids();
            let mut events = Vec::new();
            for tid in all_tids {
                let thread_events = engine.query_thread_sync_events(tid, query.start_step, query.end_step);
                events.extend(thread_events.into_iter().cloned());
            }
            events.sort_by_key(|e| e.step);
            events
        };

        let total_count = events.len() as u64;
        Ok(ThreadSyncQueryResult { events, total_count })
    }

    /// Execute a context switch query
    ///
    /// Returns context switches in the given step range,
    /// optionally filtered by thread involvement.
    pub fn query_context_switches(engine: &TraceEngine, query: ContextSwitchQuery) -> Result<ContextSwitchQueryResult> {
        let mut switches: Vec<ContextSwitch> = engine.query_context_switches(query.start_step, query.end_step)
            .into_iter()
            .filter(|s| {
                if let Some(tid) = query.thread_id {
                    s.from_thread == tid || s.to_thread == tid
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        let total_count = switches.len() as u64;
        Ok(ContextSwitchQueryResult { switches, total_count })
    }

    /// Execute a thread timeline query
    ///
    /// Returns all events (state changes + sync + context switches)
    /// for a specific thread in a step range.
    pub fn query_thread_timeline(engine: &TraceEngine, thread_id: u32, start_step: u64, end_step: u64) -> Result<ThreadTimeline> {
        Ok(engine.query_thread_timeline(thread_id, start_step, end_step))
    }

    /// Execute a timeline query
    ///
    /// The timeline is the unified index across all stores.
    /// It tells us which stores have data at each step.
    pub fn query_timeline(engine: &TraceEngine, query: TimelineQuery) -> Result<TimelineResult> {
        Ok(engine.query_timeline(query))
    }

    /// Query instructions for a specific thread
    ///
    /// Uses ThreadIndex for O(log K) lookup where K = steps on this thread.
    /// Supports address range filtering and result limiting.
    pub fn query_thread_instructions(engine: &TraceEngine, query: ThreadInstructionQuery) -> Result<Vec<InstructionTrace>> {
        let start = query.start_step.unwrap_or(0);
        let end = query.end_step.unwrap_or(u64::MAX);

        let mut results: Vec<InstructionTrace> = engine.query_instructions_by_thread_range(
            query.thread_id, start, end,
        )
        .into_iter()
        .filter(|t| {
            if let Some((lo, hi)) = query.address_range {
                t.address >= lo && t.address <= hi
            } else {
                true
            }
        })
        .cloned()
        .collect();

        if let Some(limit) = query.limit {
            results.truncate(limit as usize);
        }

        Ok(results)
    }

    /// Query which threads accessed a specific address
    ///
    /// Returns (thread_id, step) pairs for all instructions at the given address.
    pub fn query_threads_at_address(engine: &TraceEngine, address: u64) -> Result<ThreadAddressResult> {
        let accesses = engine.query_threads_at_address(address);
        Ok(ThreadAddressResult { address, accesses })
    }
}
