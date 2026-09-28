use serde::Serialize;

/// One memory write recorded at a single instruction step.
#[derive(Debug, Clone, Serialize)]
pub struct StepMemoryWrite {
    pub address: u64,
    pub data: Vec<u8>,
}

/// Instruction, register file, and this step's memory writes.
///
/// Reconstructed from the shared step timeline. Not a stored machine image.
/// `registers` is absent when no register delta exists at or before `step`.
/// `memory_writes` lists only writes whose step equals `step`.
#[derive(Debug, Clone, Serialize)]
pub struct StepSnapshot {
    pub step: u64,
    pub instruction: Option<InstructionTrace>,
    pub registers: Option<sotrace_core::models::register_delta::RegisterState>,
    pub memory_writes: Vec<StepMemoryWrite>,
}

impl TraceEngine {

    /// Query instruction at a specific step.
    ///
    /// Returns the last instruction recorded at `step` (matching the
    /// pre-EventLog DeltaLog overwrite behavior, so the public API stays
    /// backward-compatible). A step normally holds exactly one instruction;
    /// when an adapter assigns the same `seq` to several instructions, use
    /// [`Self::query_instructions_range`] or the store's `get_at_step` to see
    /// all of them.
    /// Instruction, register file, and memory writes at one step.
    ///
    /// The caller passes only the step. The register file is the replay as of
    /// that step, including earlier deltas. Memory writes are only those
    /// recorded at this step, not earlier bytes still visible to
    /// [`Self::query_memory_value`].
    pub fn query_step_snapshot(&self, step: u64) -> StepSnapshot {
        let memory_writes = self
            .memory
            .writes_at_step(step)
            .into_iter()
            .map(|(address, data)| StepMemoryWrite { address, data })
            .collect();
        StepSnapshot {
            step,
            instruction: self.query_instruction(step).cloned(),
            registers: self.reconstruct_register_state(step),
            memory_writes,
        }
    }

    pub fn query_instruction(&self, step: u64) -> Option<&InstructionTrace> {
        self.instructions.get_at_step(step).into_iter().next_back()
    }

    /// Query instructions in a step range

    /// Query instructions in a step range
    pub fn query_instructions_range(&self, start: u64, end: u64) -> Vec<&InstructionTrace> {
        self.instructions.query_range(start, end)
    }

    /// Query instructions by address (using AddressIndex)

    /// Query instructions by address (using AddressIndex)
    pub fn query_instructions_by_address(&self, address: u64) -> &[u64] {
        self.instructions.find_by_address(address)
    }

    /// Query instructions by thread ID
    ///
    /// Returns all steps where this thread executed instructions.
    /// Uses ThreadIndex for O(log K) lookup.

    /// Query instructions by thread ID
    ///
    /// Returns all steps where this thread executed instructions.
    /// Uses ThreadIndex for O(log K) lookup.
    pub fn query_instructions_by_thread(&self, thread_id: u32) -> &[u64] {
        self.instructions.find_by_thread(thread_id)
    }

    /// Query instructions by thread ID in a step range
    ///
    /// Returns instruction traces where the given thread was active,
    /// within the specified step range [start, end].

    /// Query instructions by thread ID in a step range
    ///
    /// Returns instruction traces where the given thread was active,
    /// within the specified step range [start, end].
    pub fn query_instructions_by_thread_range(&self, thread_id: u32, start: u64, end: u64) -> Vec<&InstructionTrace> {
        self.instructions.query_by_thread_range(thread_id, start, end)
    }

    /// Cross-reference: find which threads executed at a specific address
    ///
    /// Returns (thread_id, step) pairs for all instructions at the given address.
    /// Useful for identifying which threads touch a particular code location.

    /// Cross-reference: find which threads executed at a specific address
    ///
    /// Returns (thread_id, step) pairs for all instructions at the given address.
    /// Useful for identifying which threads touch a particular code location.
    pub fn query_threads_at_address(&self, address: u64) -> Vec<(u32, u64)> {
        let steps = self.instructions.find_by_address(address);
        steps.iter()
            .flat_map(|&step| {
                self.instructions.get_at_step(step)
                    .into_iter()
                    // The address index identifies matching *steps*, but an
                    // EventLog step can contain records for other addresses.
                    .filter(move |t| t.address == address)
                    .map(move |t| (t.thread_id, step))
            })
            .collect()
    }

    /// Query JNI calls by native function address.
    ///
    /// Returns every JNI boundary call whose `native_address` matches, in
    /// ascending step order. Uses `AddressIndex` for O(log K) lookup instead of
    /// scanning the whole JNI log; same-step calls (multiple threads sharing a
    /// `seq`) all survive via `get_at_step`. Optionally restrict to
    /// `[start, end]`.
    ///
    /// This is the JNI analogue of [`query_instructions_by_address`]: the
    /// `address_index` was already maintained on every `import_jni_call`, but
    /// until now no query path exposed it — callers could import and count JNI
    /// calls but not look them up by the native entry point they care about.

    /// Query JNI calls by native function address.
    ///
    /// Returns every JNI boundary call whose `native_address` matches, in
    /// ascending step order. Uses `AddressIndex` for O(log K) lookup instead of
    /// scanning the whole JNI log; same-step calls (multiple threads sharing a
    /// `seq`) all survive via `get_at_step`. Optionally restrict to
    /// `[start, end]`.
    ///
    /// This is the JNI analogue of [`query_instructions_by_address`]: the
    /// `address_index` was already maintained on every `import_jni_call`, but
    /// until now no query path exposed it — callers could import and count JNI
    /// calls but not look them up by the native entry point they care about.
    pub fn query_jni_calls_by_address(&self, address: u64, start: u64, end: u64) -> Vec<&JNICall> {
        let steps = self.jni.find_by_address(address);
        steps.iter()
            .filter(|&&step| step >= start && step <= end)
            .flat_map(|&step| self.jni.get_at_step(step))
            .filter(|c| c.native_address == address)
            .collect()
    }

    /// Query instructions by address range for a specific thread
    ///
    /// Returns instructions where the given thread executed within the
    /// specified address range [addr_lo, addr_hi], in the step range [start, end].

    /// Query instructions by address range for a specific thread
    ///
    /// Returns instructions where the given thread executed within the
    /// specified address range [addr_lo, addr_hi], in the step range [start, end].
    pub fn query_thread_instructions_by_address(
        &self, thread_id: u32, addr_lo: u64, addr_hi: u64, start: u64, end: u64,
    ) -> Vec<&InstructionTrace> {
        self.instructions.query_by_thread_range(thread_id, start, end)
            .into_iter()
            .filter(|t| t.address >= addr_lo && t.address <= addr_hi)
            .collect()
    }

    /// Query memory value at a specific address and step

    /// Query memory value at a specific address and step
    pub fn query_memory_value(&self, address: u64, size: usize, step: u64) -> Option<MemoryValueResult> {
        self.memory.query_value(address, size, step)
    }

    /// Rebuild a full memory page at a specific step

    /// Rebuild a full memory page at a specific step
    pub fn rebuild_memory_page(&self, page_addr: u64, step: u64) -> Option<Vec<u8>> {
        self.memory.reconstruct_page(page_addr, step)
    }

    /// Query a register's value at a specific step.
    ///
    /// Returns the value the register held as of the last register delta that
    /// touched it at or before `step`, or `None` if it was never recorded.
    /// `register_id` follows the ARM64 layout: 0-30 = x0-x30, 31 = SP,
    /// 32 = PC, 33 = NZCV.

    /// Query a register's value at a specific step.
    ///
    /// Returns the value the register held as of the last register delta that
    /// touched it at or before `step`, or `None` if it was never recorded.
    /// `register_id` follows the ARM64 layout: 0-30 = x0-x30, 31 = SP,
    /// 32 = PC, 33 = NZCV.
    pub fn query_register(&self, register_id: usize, step: u64) -> Option<u64> {
        self.registers.query_register(register_id, step)
    }

    /// List the steps at which a register was modified, in `[start, end]`.
    ///
    /// Exposes the per-register index that `query_register` uses internally —
    /// answers "when did register X change?" without scanning the whole delta
    /// log. `register_id` follows the ARM64 layout (0-30 = x0-x30, 31 = SP,
    /// 32 = PC, 33 = NZCV).

    /// List the steps at which a register was modified, in `[start, end]`.
    ///
    /// Exposes the per-register index that `query_register` uses internally —
    /// answers "when did register X change?" without scanning the whole delta
    /// log. `register_id` follows the ARM64 layout (0-30 = x0-x30, 31 = SP,
    /// 32 = PC, 33 = NZCV).
    pub fn query_register_history(&self, register_id: usize, start: u64, end: u64) -> Vec<u64> {
        self.registers.query_register_history(register_id, start, end)
    }

    /// Reconstruct the full ARM64 register file as of a given step.
    ///
    /// Returns every register's value at `step` in one coherent
    /// [`RegisterState`](sotrace_core::models::register_delta::RegisterState) —
    /// the multi-register form of [`Self::query_register`]. Slots never written
    /// read as 0; returns `None` when no register delta exists at or before
    /// `step`.

    /// Reconstruct the full ARM64 register file as of a given step.
    ///
    /// Returns every register's value at `step` in one coherent
    /// [`RegisterState`](sotrace_core::models::register_delta::RegisterState) —
    /// the multi-register form of [`Self::query_register`]. Slots never written
    /// read as 0; returns `None` when no register delta exists at or before
    /// `step`.
    pub fn reconstruct_register_state(
        &self,
        step: u64,
    ) -> Option<sotrace_core::models::register_delta::RegisterState> {
        self.registers.reconstruct_state(step)
    }

    /// Rebuild call stack at a specific step for a thread

    /// Rebuild call stack at a specific step for a thread
    pub fn rebuild_call_stack(&self, thread_id: u32, step: u64) -> Vec<sotrace_core::models::call_trace::StackFrame> {
        self.calls.rebuild_call_stack(thread_id, step)
    }

    // ========================================================================
    // Thread-specific query operations
    // ========================================================================

    /// Get thread info by thread ID

    /// Get thread info by thread ID
    pub fn get_thread_info(&self, thread_id: u32) -> Option<&ThreadInfo> {
        self.threads.get_thread_info(thread_id)
    }

    /// Get all thread IDs

    /// Get all thread IDs
    pub fn all_thread_ids(&self) -> Vec<u32> {
        self.threads.all_thread_ids()
    }

    /// Get thread count

    /// Get thread count
    pub fn thread_count(&self) -> u32 {
        self.threads.thread_count()
    }

    /// Query thread state at a specific step

    /// Query thread state at a specific step
    pub fn query_thread_state(&self, thread_id: u32, step: u64) -> Option<&ThreadStateChange> {
        self.threads.query_thread_state(thread_id, step)
    }

    /// Query synchronization events for a lock address

    /// Query synchronization events for a lock address
    pub fn query_lock_contentions(&self, lock_addr: u64, start: u64, end: u64) -> Vec<&ThreadSyncEvent> {
        self.threads.query_lock_contentions(lock_addr, start, end)
    }

    /// Query sync events for a specific thread

    /// Query sync events for a specific thread
    pub fn query_thread_sync_events(&self, thread_id: u32, start: u64, end: u64) -> Vec<&ThreadSyncEvent> {
        self.threads.query_sync_events(thread_id, start, end)
    }

    /// Query context switches in a step range

    /// Query context switches in a step range
    pub fn query_context_switches(&self, start: u64, end: u64) -> Vec<&ContextSwitch> {
        self.threads.query_context_switches(start, end)
    }

    /// Query thread timeline (all events for a thread)

    /// Query thread timeline (all events for a thread)
    pub fn query_thread_timeline(&self, thread_id: u32, start: u64, end: u64) -> ThreadTimeline {
        self.threads.query_thread_timeline(thread_id, start, end)
    }

    /// Get thread statistics

    /// Get thread statistics
    pub fn get_thread_stats(&self, thread_id: u32) -> Option<ThreadStats> {
        self.threads.get_thread_stats(thread_id)
    }

    /// Get all thread statistics

    /// Get all thread statistics
    pub fn all_thread_stats(&self) -> Vec<ThreadStats> {
        self.threads.all_thread_stats()
    }

    // ========================================================================
    // Thread analysis — high-level analysis operations
    // ========================================================================

    /// Feed a memory read event to the analyzer for race detection
    ///
    /// Memory reads are not stored (only writes affect memory state), but
    /// they are tracked by the analyzer to detect races (write-read conflicts
    /// across threads without synchronization).

    /// Feed a memory read event to the analyzer for race detection
    ///
    /// Memory reads are not stored (only writes affect memory state), but
    /// they are tracked by the analyzer to detect races (write-read conflicts
    /// across threads without synchronization).
    pub fn feed_memory_read(&mut self, step: u64, thread_id: u32, address: u64, size: usize) {
        self.analyzer.feed_memory_read(step, thread_id, address, size);
    }

    /// Run comprehensive thread analysis
    ///
    /// This executes all analysis passes:
    /// 1. Race condition detection
    /// 2. Deadlock detection
    /// 3. Lock contention analysis
    /// 4. Thread-function association
    /// 5. Function thread safety classification
    /// 6. Thread data flow analysis
    /// 7. Producer-consumer pattern detection
    ///
    /// The analyzer is incrementally fed data as events are imported,
    /// so this just triggers the analysis computations.

    /// Run comprehensive thread analysis
    ///
    /// This executes all analysis passes:
    /// 1. Race condition detection
    /// 2. Deadlock detection
    /// 3. Lock contention analysis
    /// 4. Thread-function association
    /// 5. Function thread safety classification
    /// 6. Thread data flow analysis
    /// 7. Producer-consumer pattern detection
    ///
    /// The analyzer is incrementally fed data as events are imported,
    /// so this just triggers the analysis computations.
    pub fn analyze_threads(&mut self) -> ThreadAnalysisResult {
        let mut result = self.analyzer.analyze_all();
        // Back-fill function names from the ELF symbol table.
        for a in &mut result.thread_function_assocs {
            if a.function_name.is_none() {
                a.function_name = self.function_name(a.function_address).map(|s| s.to_string());
            }
        }
        for f in &mut result.function_safety {
            if f.function_name.is_none() {
                f.function_name = self.function_name(f.function_address).map(|s| s.to_string());
            }
        }
        // Back-fill JNI boundary native function names (parity with the
        // single-dimension analyze_jni_boundary wrapper — without this the
        // full analyze_threads path leaves native_functions all None).
        for s in &mut result.jni_boundary {
            for (addr, name) in s.native_addresses.iter().zip(s.native_functions.iter_mut()) {
                if name.is_none() {
                    *name = self.function_name(*addr).map(|n| n.to_string());
                }
            }
        }
        result
    }

    /// Detect race conditions only

    /// Detect race conditions only
    pub fn detect_race_conditions(&mut self) -> Vec<crate::analyzer::thread_analyzer::RaceCondition> {
        self.analyzer.detect_race_conditions()
    }

    /// Detect deadlock risks only

    /// Detect deadlock risks only
    pub fn detect_deadlocks(&mut self) -> Vec<crate::analyzer::thread_analyzer::DeadlockRisk> {
        self.analyzer.detect_deadlocks()
    }

    /// Analyze lock contention only

    /// Analyze lock contention only
    pub fn analyze_lock_contention(&mut self) -> Vec<crate::analyzer::thread_analyzer::LockContentionInfo> {
        self.analyzer.analyze_lock_contention()
    }

    /// Classify function thread safety only

    /// Classify function thread safety only
    pub fn classify_function_thread_safety(&mut self) -> Vec<crate::analyzer::thread_analyzer::FunctionThreadSafety> {
        let mut results = self.analyzer.classify_function_thread_safety();
        for f in &mut results {
            if f.function_name.is_none() {
                f.function_name = self.function_name(f.function_address).map(|s| s.to_string());
            }
        }
        results
    }

    /// Analyze thread-function associations only.
    ///
    /// Like the full [`analyze_threads`], function names are back-filled from
    /// the registered ELF symbol table where available.

    /// Analyze thread-function associations only.
    ///
    /// Like the full [`analyze_threads`], function names are back-filled from
    /// the registered ELF symbol table where available.
    pub fn analyze_thread_function_assoc(&mut self) -> Vec<crate::analyzer::thread_analyzer::ThreadFunctionAssoc> {
        let mut results = self.analyzer.analyze_thread_function_assoc();
        for a in &mut results {
            if a.function_name.is_none() {
                a.function_name = self.function_name(a.function_address).map(|s| s.to_string());
            }
        }
        results
    }

    /// Analyze inter-thread data flows only (write→read transfers across threads)

    /// Analyze inter-thread data flows only (write→read transfers across threads)
    pub fn analyze_data_flows(&mut self) -> Vec<crate::analyzer::thread_analyzer::ThreadDataFlow> {
        self.analyzer.analyze_data_flows()
    }

    /// Detect producer-consumer patterns only

    /// Detect producer-consumer patterns only
    pub fn detect_producer_consumer(&mut self) -> Vec<crate::analyzer::thread_analyzer::ProducerConsumerPattern> {
        self.analyzer.detect_producer_consumer()
    }

    /// Summarize per-thread scheduling / context-switch behavior only

    /// Summarize per-thread scheduling / context-switch behavior only
    pub fn analyze_scheduling(&mut self) -> Vec<crate::analyzer::thread_analyzer::ThreadSchedulingStats> {
        self.analyzer.analyze_scheduling()
    }

    /// Reconstruct per-thread lifecycle / spawn tree only

    /// Reconstruct per-thread lifecycle / spawn tree only
    pub fn analyze_thread_lifecycle(&mut self) -> Vec<crate::analyzer::thread_analyzer::ThreadLifecycleInfo> {
        self.analyzer.analyze_thread_lifecycle()
    }

    /// Summarize per-thread state residency / transitions only

    /// Summarize per-thread state residency / transitions only
    pub fn analyze_thread_states(&mut self) -> Vec<crate::analyzer::thread_analyzer::ThreadStateStats> {
        self.analyzer.analyze_thread_states()
    }

    /// Summarize per-lock critical-section / hold-time behavior only

    /// Summarize per-lock critical-section / hold-time behavior only
    pub fn analyze_critical_sections(&mut self) -> Vec<crate::analyzer::thread_analyzer::CriticalSectionStats> {
        self.analyzer.analyze_critical_sections()
    }
}
