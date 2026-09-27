impl TraceEngine {

    /// Summarize per-thread JNI boundary-crossing behavior only
    pub fn analyze_jni_boundary(&mut self) -> Vec<crate::analyzer::thread_analyzer::JniBoundaryStats> {
        let mut stats = self.analyzer.analyze_jni_boundary();
        // Backfill ELF function names for each native address (mirrors
        // analyze_thread_function_assoc / classify_function_thread_safety).
        // native_addresses are SO-relative offsets; function_name range-resolves
        // each one against the function_names table populated by
        // register_so_functions, so a JNI call landing mid-function (not just
        // at the entry) still resolves to the containing function's name.
        for s in &mut stats {
            for (addr, name) in s.native_addresses.iter().zip(s.native_functions.iter_mut()) {
                if name.is_none() {
                    *name = self.function_name(*addr).map(|n| n.to_string());
                }
            }
        }
        stats
    }

    // ========================================================================
    // Timeline operations
    // ========================================================================

    /// Get the current step number

    /// Get the current step number
    pub fn current_step(&self) -> u64 {
        self.timeline.current_step()
    }

    /// Get the total number of steps

    /// Get the total number of steps
    pub fn total_steps(&self) -> u64 {
        self.timeline.total_steps()
    }

    /// Find the nearest snapshot before a target step

    /// Find the nearest snapshot before a target step
    pub fn find_snapshot_before(&self, target_step: u64) -> Option<(u64, u64)> {
        self.timeline.find_snapshot_before(target_step)
    }

    /// Find all steps for a specific thread (via timeline index)

    /// Find all steps for a specific thread (via timeline index)
    pub fn find_steps_for_thread(&self, thread_id: u32) -> &[u64] {
        self.timeline.find_steps_for_thread(thread_id)
    }

    /// Find all steps for a specific address (via timeline index)

    /// Find all steps for a specific address (via timeline index)
    pub fn find_steps_for_address(&self, address: u64) -> &[u64] {
        self.timeline.find_steps_for_address(address)
    }

    /// Find all steps for a specific function (via timeline index)

    /// Find all steps for a specific function (via timeline index)
    pub fn find_steps_for_function(&self, func_id: u64) -> &[u64] {
        self.timeline.find_steps_for_function(func_id)
    }

    /// Get the SO file ID this engine is tracking

    /// Get the SO file ID this engine is tracking
    pub fn so_file_id(&self) -> u64 {
        self.so_file_id
    }

    /// Register function metadata parsed from an ELF/SO file.
    ///
    /// Populates an offset→(size, name) table so that analysis results (race
    /// locations, thread-function associations, safety classifications, JNI
    /// boundary native addresses) can report function names instead of bare
    /// offsets. Storing `size` alongside the name lets [`Self::function_name`]
    /// resolve any PC inside a function body, not just the entry.

    /// Register function metadata parsed from an ELF/SO file.
    ///
    /// Populates an offset→(size, name) table so that analysis results (race
    /// locations, thread-function associations, safety classifications, JNI
    /// boundary native addresses) can report function names instead of bare
    /// offsets. Storing `size` alongside the name lets [`Self::function_name`]
    /// resolve any PC inside a function body, not just the entry.
    pub fn register_so_functions(&mut self, functions: &[sotrace_core::models::so_function::SOFunction]) {
        for f in functions {
            if !f.name.is_empty() {
                self.function_names.insert(f.offset, (f.size, f.name.clone()));
            }
        }
    }

    /// Register function metadata from a parsed SO file (convenience wrapper).

    /// Register function metadata from a parsed SO file (convenience wrapper).
    pub fn register_parsed_so(&mut self, parsed: &sotrace_core::elf::ParsedSoFile) {
        self.register_so_functions(&parsed.functions);
    }

    /// Look up the function name covering the given SO-relative offset, if known.
    ///
    /// Resolves a function for any PC inside the function body, not just the
    /// entry: finds the function with the greatest `offset <= addr` (standard
    /// symbol-resolution semantics, matching `addr2line`).
    /// - If that function has `size > 0`, the PC must fall in
    ///   `[offset, offset + size)` (half-open) to match.
    /// - If `size == 0` (stripped/dynsym-recovered function with no size), fall
    ///   back to exact-entry match (`addr == offset`), preserving prior
    ///   behavior so stripped SOs are not left unnamed.
    /// - Overlapping intervals resolve to the greatest-`offset <= addr`
    ///   function (innermost/most-specific), consistent with addr2line.

    /// Look up the function name covering the given SO-relative offset, if known.
    ///
    /// Resolves a function for any PC inside the function body, not just the
    /// entry: finds the function with the greatest `offset <= addr` (standard
    /// symbol-resolution semantics, matching `addr2line`).
    /// - If that function has `size > 0`, the PC must fall in
    ///   `[offset, offset + size)` (half-open) to match.
    /// - If `size == 0` (stripped/dynsym-recovered function with no size), fall
    ///   back to exact-entry match (`addr == offset`), preserving prior
    ///   behavior so stripped SOs are not left unnamed.
    /// - Overlapping intervals resolve to the greatest-`offset <= addr`
    ///   function (innermost/most-specific), consistent with addr2line.
    pub fn function_name(&self, offset: u64) -> Option<&str> {
        use std::ops::Bound;
        // Candidates with offset <= addr, greatest first.
        let (&func_offset, (size, name)) = self
            .function_names
            .range((Bound::Unbounded, Bound::Included(offset)))
            .next_back()?;
        if *size > 0 {
            // Interval match: addr in [func_offset, func_offset + size).
            (offset < func_offset + *size as u64).then_some(name.as_str())
        } else {
            // Stripped (size unknown): exact-match fallback.
            (offset == func_offset).then_some(name.as_str())
        }
    }

    /// Number of registered functions.

    /// Number of registered functions.
    pub fn registered_function_count(&self) -> usize {
        self.function_names.len()
    }

    /// Get a reference to the thread store

    /// Get a reference to the thread store
    pub fn thread_store(&self) -> &ThreadStore {
        &self.threads
    }

    /// Get a reference to the instruction store

    /// Get a reference to the instruction store
    pub fn instruction_store(&self) -> &InstructionStore {
        &self.instructions
    }

    /// Get a reference to the call store

    /// Get a reference to the call store
    pub fn call_store(&self) -> &CallStore {
        &self.calls
    }

    /// Get a reference to the memory store

    /// Get a reference to the memory store
    pub fn memory_store(&self) -> &MemoryStore {
        &self.memory
    }

    /// Get a reference to the JNI store

    /// Get a reference to the JNI store
    pub fn jni_store(&self) -> &JNIStore {
        &self.jni
    }

    /// Get a reference to the register store

    /// Get a reference to the register store
    pub fn register_store(&self) -> &RegisterStore {
        &self.registers
    }

    /// Get step metadata from the timeline

    /// Get step metadata from the timeline
    pub fn get_step_metadata(&self, step: u64) -> Option<&StepMetadata> {
        self.timeline.get_step(step)
    }

    /// Query the timeline with filters

    /// Query the timeline with filters
    pub fn query_timeline(&self, query: TimelineQuery) -> TimelineResult {
        self.timeline.query(query)
    }

    // ========================================================================
    // Performance & coverage analysis
    // ========================================================================

    /// Return the top-N most-executed instruction addresses in this trace.
    ///
    /// Useful for quickly locating hot loops, encryption kernels, or any
    /// frequently-executed code paths without manually inspecting raw logs.

    /// Return the top-N most-executed instruction addresses in this trace.
    ///
    /// Useful for quickly locating hot loops, encryption kernels, or any
    /// frequently-executed code paths without manually inspecting raw logs.
    pub fn analyze_hot_paths(
        &self,
        top_n: usize,
    ) -> crate::analyzer::HotPathsResult {
        let instructions = self.instructions.all_instructions();
        crate::analyzer::analyze_hot_paths(&instructions, top_n)
    }

    /// Compute taken/not-taken statistics for every branch instruction.
    ///
    /// `always_not_taken` branches are especially valuable: they indicate
    /// code paths that were never exercised — common in anti-debug checks
    /// (`if ptrace() != -1`) whose branch body never fires.

    /// Compute taken/not-taken statistics for every branch instruction.
    ///
    /// `always_not_taken` branches are especially valuable: they indicate
    /// code paths that were never exercised — common in anti-debug checks
    /// (`if ptrace() != -1`) whose branch body never fires.
    pub fn analyze_branch_stats(&self) -> crate::analyzer::BranchStatsResult {
        let instructions = self.instructions.all_instructions();
        crate::analyzer::analyze_branch_stats(&instructions)
    }

    /// Return all instructions whose address falls within `[query.from_address, query.to_address]`.
    ///
    /// Allows answering "who executed code in this SO segment?" without a
    /// full table scan in the caller — the method iterates once and applies
    /// the address filter, thread filter, and limit in a single pass.

    /// Return all instructions whose address falls within `[query.from_address, query.to_address]`.
    ///
    /// Allows answering "who executed code in this SO segment?" without a
    /// full table scan in the caller — the method iterates once and applies
    /// the address filter, thread filter, and limit in a single pass.
    pub fn query_address_range_instructions(
        &self,
        query: crate::analyzer::AddressRangeQuery,
    ) -> Vec<crate::analyzer::InstructionHit> {
        let instructions = self.instructions.all_instructions();
        crate::analyzer::query_address_range(&instructions, &query)
    }
}
