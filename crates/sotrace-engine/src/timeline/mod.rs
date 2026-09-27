//! Timeline — the core abstraction for time-ordered trace data
//!
//! A trace IS a timeline. Every event (instruction execution, memory write,
//! register change, function call, thread switch) happens at a specific
//! point in time, identified by a sequence number (step).
//!
//! The Timeline ties all delta stores together:
//! - InstructionStore: what instruction executed at step N
//! - RegisterStore: what registers changed at step N
//! - MemoryStore: what memory was written at step N
//! - CallStore: what call event occurred at step N
//! - ThreadStore: which thread was active at step N
//!
//! # Query Acceleration via Timeline
//!
//! The Timeline maintains a **StepIndex** that maps:
//! - step → { instruction, register_delta, memory_delta, call_event, thread }
//!
//! This allows queries to:
//! 1. Skip steps that don't affect the query target
//! 2. Jump directly to the relevant delta records
//! 3. Reconstruct state at any step in O(snapshot_distance + K) not O(total_steps)

use anyhow::Result;

use crate::delta_store::delta_index::{AddressIndex, SkipListIndex, ThreadIndex, FunctionIndex};
use crate::delta_store::types::DeltaStoreConfig;

/// Timeline — the core abstraction that ties all trace stores together
///
/// Every trace session has exactly one Timeline. The Timeline:
/// 1. Assigns monotonically increasing step numbers to events
/// 2. Maintains indexes for fast queries across all store types
/// 3. Coordinates snapshots across all stores (consistent checkpoint)
/// 4. Provides the unified query interface
pub struct Timeline {
    /// Unique timeline ID
    id: u64,
    /// SO file ID this timeline belongs to
    so_file_id: u64,
    /// Current step number (monotonically increasing)
    current_step: u64,
    /// Total number of steps in this timeline
    total_steps: u64,
    /// Delta store configuration (shared across all stores)
    config: DeltaStoreConfig,
    /// Step index: `(step, metadata)` in ascending step order.
    ///
    /// Import is almost always chronological, so this is a vector with an
    /// O(1) append. Out-of-order steps binary-search and insert. Range queries
    /// binary-search both ends.
    step_index: Vec<(u64, StepMetadata)>,
    /// Skip list index for fast snapshot lookup
    snapshot_index: SkipListIndex,
    /// Address index for spatial queries
    address_index: AddressIndex,
    /// Thread index for thread-scoped queries
    thread_index: ThreadIndex,
    /// Function index for function-scoped queries
    function_index: FunctionIndex,
}

/// Metadata for a single step — what happened at this step
#[derive(Debug, Clone)]
pub struct StepMetadata {
    /// Step number
    pub step: u64,
    /// Thread ID active at this step
    pub thread_id: u32,
    /// Instruction address executed at this step
    pub instruction_address: u64,
    /// Whether this step has register changes
    pub has_register_delta: bool,
    /// Whether this step has memory writes
    pub has_memory_delta: bool,
    /// Whether this step has a call event
    pub has_call_event: bool,
    /// Whether this step has a JNI call
    pub has_jni_call: bool,
    /// Whether this step has a thread event (create/exit/state change)
    pub has_thread_event: bool,
    /// Whether this step has a synchronization event (mutex/futex/condvar)
    pub has_sync_event: bool,
    /// Whether this step has a context switch
    pub has_context_switch: bool,
}

/// Timeline query parameters
#[derive(Debug, Clone)]
pub struct TimelineQuery {
    /// Start step (inclusive)
    pub start_step: u64,
    /// End step (inclusive)
    pub end_step: u64,
    /// Optional thread filter
    pub thread_id: Option<u32>,
    /// Optional address range filter
    pub address_range: Option<(u64, u64)>,
    /// Optional function filter
    pub function_id: Option<u64>,
    /// Maximum number of results
    pub limit: Option<u64>,
}

/// Timeline query result
#[derive(Debug, Clone)]
pub struct TimelineResult {
    /// Matching step metadata
    pub steps: Vec<StepMetadata>,
    /// Total matching steps (before limit)
    pub total_count: u64,
    /// Whether there are more results
    pub has_more: bool,
}

fn merge_step_flags(existing: &mut StepMetadata, meta: &StepMetadata) {
    existing.has_register_delta |= meta.has_register_delta;
    existing.has_memory_delta |= meta.has_memory_delta;
    existing.has_call_event |= meta.has_call_event;
    existing.has_jni_call |= meta.has_jni_call;
    existing.has_thread_event |= meta.has_thread_event;
    existing.has_sync_event |= meta.has_sync_event;
    existing.has_context_switch |= meta.has_context_switch;
}

impl Timeline {
    /// Create a new timeline for the given SO file
    pub fn new(id: u64, so_file_id: u64, config: DeltaStoreConfig) -> Self {
        Self {
            id,
            so_file_id,
            current_step: 0,
            total_steps: 0,
            config,
            step_index: Vec::new(),
            snapshot_index: SkipListIndex::new(),
            address_index: AddressIndex::new(),
            thread_index: ThreadIndex::new(),
            function_index: FunctionIndex::new(),
        }
    }

    /// Advance the timeline to the next step
    ///
    /// Returns the new step number. All stores should write their
    /// delta records for this step.
    pub fn advance(&mut self) -> u64 {
        self.current_step += 1;
        self.total_steps = self.current_step;
        self.current_step
    }

    /// Record metadata for a step
    ///
    /// If metadata already exists for this step, the flags are merged (OR'd)
    /// so that multiple stores can contribute to the same step's metadata.
    /// Reserve room for `additional` newly inserted steps (in-order appends).
    pub fn reserve_steps(&mut self, additional: usize) {
        self.step_index.reserve(additional);
    }

    #[inline]
    pub fn record_step(&mut self, meta: StepMetadata) {
        // Update indexes
        self.address_index.register(meta.instruction_address, meta.step);
        self.thread_index.register(meta.thread_id, meta.step);
        self.upsert_step(meta);
    }

    fn upsert_step(&mut self, meta: StepMetadata) {
        // Merge with existing metadata if present. Keep the first
        // instruction_address and thread_id; OR the per-store flags.
        match self.step_index.last_mut() {
            Some((last, existing)) if *last == meta.step => {
                merge_step_flags(existing, &meta);
                return;
            }
            Some((last, _)) if *last < meta.step => {
                self.step_index.push((meta.step, meta));
                return;
            }
            _ => {}
        }
        let step = meta.step;
        let pos = self.step_index.partition_point(|(existing, _)| *existing < step);
        if pos < self.step_index.len() && self.step_index[pos].0 == step {
            merge_step_flags(&mut self.step_index[pos].1, &meta);
        } else {
            self.step_index.insert(pos, (step, meta));
        }
    }

    /// Record a function call event
    pub fn record_function_call(&mut self, func_id: u64, call_step: u64, return_step: Option<u64>) {
        self.function_index.register_call(func_id, call_step, return_step);
    }

    /// Record a snapshot checkpoint
    pub fn record_snapshot(&mut self, step: u64, snapshot_id: u64) {
        self.snapshot_index.register_snapshot(step, snapshot_id);
    }

    /// Check if a coordinated snapshot should be created
    pub fn should_snapshot(&self) -> bool {
        self.current_step > 0 && self.current_step % self.config.snapshot_interval == 0
    }

    /// Get the current step number
    pub fn current_step(&self) -> u64 {
        self.current_step
    }

    /// Get the total number of steps
    pub fn total_steps(&self) -> u64 {
        self.total_steps
    }

    /// Query the timeline
    pub fn query(&self, query: TimelineQuery) -> TimelineResult {
        // If a function filter is set, resolve it once to the sorted step list
        // of steps where that function was called (recorded via
        // `record_function_call` → FunctionIndex). `StepMetadata` does not carry
        // a function id, so the filter cannot be applied per-record from the
        // metadata alone — it is the call log that ties a step to a function.
        // Without this, `function_id` would be silently ignored (returning
        // steps for every function), a real correctness gap.
        let func_steps: Option<&[u64]> = query
            .function_id
            .map(|fid| self.function_index.find_steps_for_function(fid));
        let in_func = |step: u64| -> bool {
            func_steps.map_or(true, |steps| {
                steps.binary_search(&step).is_ok()
            })
        };

        let start = self
            .step_index
            .partition_point(|(step, _)| *step < query.start_step);
        let end = self
            .step_index
            .partition_point(|(step, _)| *step <= query.end_step);
        let mut results: Vec<StepMetadata> = self.step_index[start..end]
            .iter()
            .map(|(_, meta)| meta.clone())
            .filter(|meta| {
                // Apply thread filter
                if let Some(tid) = query.thread_id {
                    if meta.thread_id != tid {
                        return false;
                    }
                }
                // Apply address range filter
                if let Some((lo, hi)) = query.address_range {
                    if meta.instruction_address < lo || meta.instruction_address > hi {
                        return false;
                    }
                }
                // Apply function filter (steps where the function was called)
                if !in_func(meta.step) {
                    return false;
                }
                true
            })
            .collect();

        let total_count = results.len() as u64;
        let has_more = if let Some(limit) = query.limit {
            if results.len() > limit as usize {
                results.truncate(limit as usize);
                true
            } else {
                false
            }
        } else {
            false
        };

        TimelineResult {
            steps: results,
            total_count,
            has_more,
        }
    }

    /// Find the nearest snapshot before a target step — O(log N)
    pub fn find_snapshot_before(&self, target_step: u64) -> Option<(u64, u64)> {
        self.snapshot_index.find_before(target_step)
    }

    /// Find all steps where a specific address was touched
    pub fn find_steps_for_address(&self, address: u64) -> &[u64] {
        self.address_index.find_steps_for_address(address)
    }

    /// Find all steps for a specific thread
    pub fn find_steps_for_thread(&self, thread_id: u32) -> &[u64] {
        self.thread_index.find_steps_for_thread(thread_id)
    }

    /// Find all steps for a specific function
    pub fn find_steps_for_function(&self, func_id: u64) -> &[u64] {
        self.function_index.find_steps_for_function(func_id)
    }

    /// Get step metadata
    pub fn get_step(&self, step: u64) -> Option<&StepMetadata> {
        let pos = self.step_index.partition_point(|(existing, _)| *existing < step);
        self.step_index
            .get(pos)
            .filter(|(existing, _)| *existing == step)
            .map(|(_, meta)| meta)
    }

    /// Get the timeline ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the SO file ID
    pub fn so_file_id(&self) -> u64 {
        self.so_file_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeline() -> Timeline {
        Timeline::new(1, 0, DeltaStoreConfig::default())
    }

    /// A minimal step metadata at `step` on `thread` executing `addr`.
    fn step(step: u64, thread: u32, addr: u64) -> StepMetadata {
        StepMetadata {
            step,
            thread_id: thread,
            instruction_address: addr,
            has_register_delta: false,
            has_memory_delta: false,
            has_call_event: false,
            has_jni_call: false,
            has_thread_event: false,
            has_sync_event: false,
            has_context_switch: false,
        }
    }

    /// A `TimelineQuery` over the full range with no filters.
    fn all_query() -> TimelineQuery {
        TimelineQuery {
            start_step: 0,
            end_step: u64::MAX,
            thread_id: None,
            address_range: None,
            function_id: None,
            limit: None,
        }
    }

    #[test]
    fn test_query_thread_filter() {
        let mut t = timeline();
        t.record_step(step(1, 1, 0x1000));
        t.record_step(step(2, 2, 0x2000));
        t.record_step(step(3, 1, 0x3000));

        let mut q = all_query();
        q.thread_id = Some(1);
        let r = t.query(q);
        assert_eq!(r.steps.len(), 2);
        assert!(r.steps.iter().all(|m| m.thread_id == 1));
    }

    #[test]
    fn test_query_address_range_filter() {
        let mut t = timeline();
        t.record_step(step(1, 1, 0x1000));
        t.record_step(step(2, 1, 0x2000));
        t.record_step(step(3, 1, 0x3000));

        let mut q = all_query();
        q.address_range = Some((0x1500, 0x2500));
        let r = t.query(q);
        assert_eq!(r.steps.len(), 1);
        assert_eq!(r.steps[0].instruction_address, 0x2000);
    }

    /// `function_id` must actually filter: only steps where that function was
    /// called (via `record_function_call`) are returned. Before the fix the
    /// field was silently ignored, so the query returned steps for every
    /// function — a real correctness gap, since the caller asked for one
    /// function and got them all.
    #[test]
    fn test_query_function_filter_is_applied() {
        let mut t = timeline();
        t.record_step(step(1, 1, 0x1000));
        t.record_step(step(2, 1, 0x2000));
        t.record_step(step(3, 1, 0x3000));
        // Function 0xA is called at step 2 only.
        t.record_function_call(0xA, 2, None);
        // Function 0xB is called at step 1 and step 3.
        t.record_function_call(0xB, 1, None);
        t.record_function_call(0xB, 3, None);

        let mut q = all_query();
        q.function_id = Some(0xA);
        let r = t.query(q);
        assert_eq!(r.steps.len(), 1, "only the step where func 0xA was called");
        assert_eq!(r.steps[0].step, 2);

        let mut q = all_query();
        q.function_id = Some(0xB);
        let r = t.query(q);
        assert_eq!(r.steps.len(), 2);
        let steps: Vec<u64> = r.steps.iter().map(|m| m.step).collect();
        assert_eq!(steps, vec![1, 3]);

        // Unknown function → empty (not "all steps").
        let mut q = all_query();
        q.function_id = Some(0xDEAD);
        let r = t.query(q);
        assert!(r.steps.is_empty());
    }

    #[test]
    fn test_query_limit_truncates_and_flags_has_more() {
        let mut t = timeline();
        for s in 1..=5 {
            t.record_step(step(s, 1, 0x1000 + s));
        }
        let mut q = all_query();
        q.limit = Some(3);
        let r = t.query(q);
        assert_eq!(r.steps.len(), 3);
        assert_eq!(r.total_count, 5, "total_count is before the limit");
        assert!(r.has_more);
    }

    #[test]
    fn test_query_empty_range() {
        let mut t = timeline();
        t.record_step(step(5, 1, 0x1000));
        let mut q = all_query();
        q.start_step = 10;
        q.end_step = 20;
        let r = t.query(q);
        assert!(r.steps.is_empty());
        assert_eq!(r.total_count, 0);
        assert!(!r.has_more);
    }
}
