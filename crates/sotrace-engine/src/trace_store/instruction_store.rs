//! Instruction store — stores instruction execution records using delta encoding
//!
//! Instructions in a trace are highly sequential and repetitive:
//! - Addresses often increase by 4 (ARM64 instruction width)
//! - The same basic blocks repeat (loops)
//! - Thread IDs are highly repetitive (few unique threads)
//!
//! Delta encoding strategy:
//! - **Address**: NumericDelta (most addresses are prev + 4)
//! - **Thread ID**: DictionaryRef (few unique values)
//! - **Branch info**: ByteLevel (only 2 bits change: is_branch + branch_taken)
//! - **Opcode**: DictionaryRef (same instructions repeat in loops)
//! - **Timestamp**: NumericDelta (monotonically increasing)

use anyhow::Result;

use sotrace_core::models::instruction_trace::{InstructionTrace, InstructionBatch};

use crate::delta_store::delta_log::EventLog;
use crate::delta_store::delta_index::{AddressIndex, ThreadIndex};
use crate::delta_store::types::*;

/// Instruction store — uses delta encoding for compact instruction trace storage
///
/// Key insight: in a typical ARM64 trace, instructions execute sequentially
/// within basic blocks. The address delta is almost always +4 (instruction width),
/// making NumericDelta extremely efficient.
pub struct InstructionStore {
    /// Event log for instruction records.
    ///
    /// `seq` comes from the caller's `trace.seq` (the adapter / native
    /// envelope), not an engine-assigned counter, so it is NOT guaranteed
    /// unique — a multi-threaded adapter could assign two threads' instructions
    /// the same `seq`, and a hand-written native JSON could repeat one. A keyed
    /// `DeltaLog` would keep only the last, silently dropping the others on
    /// both persistence (`all_instructions`) and indexed queries. `EventLog`
    /// retains every same-step instruction; range queries flatten them in
    /// insertion order.
    delta_log: EventLog<InstructionTrace>,
    /// Address index: instruction address → steps that executed at this address
    address_index: AddressIndex,
    /// Thread index: thread_id → steps that executed on this thread
    thread_index: ThreadIndex,
    /// Total instructions stored
    total_count: u64,
}

impl InstructionStore {
    /// Create a new instruction store
    pub fn new(config: DeltaStoreConfig) -> Self {
        // `config.compression` configures the EventLog; the rest is not retained.
        Self {
            delta_log: EventLog::new(config.compression),
            address_index: AddressIndex::new(),
            thread_index: ThreadIndex::new(),
            total_count: 0,
        }
    }

    /// Write a single instruction trace record
    #[inline]
    pub fn write(&mut self, trace: InstructionTrace) -> Result<()> {
        // Index by address for fast lookup
        self.address_index.register_dedup(trace.address, trace.seq);
        // Index by thread for thread-scoped queries
        self.thread_index.register(trace.thread_id, trace.seq);

        // The current storage format is full-value. Keep the incoming record
        // as the log payload instead of cloning it just to retain a `prev`
        // value that no encoding path reads. This avoids a needless deep-copy
        // and allocation/deallocation cycle for every imported instruction
        // (including any opcode bytes).
        let record = DeltaRecord {
            step: trace.seq,
            encoding: DeltaEncoding::FullValue,
            payload: DeltaPayload::FullValue(trace),
            prev_hash: None,
        };

        self.delta_log.append(record)?;
        self.total_count += 1;
        Ok(())
    }

    /// Reserve room for `additional` in-order instruction records.
    pub fn reserve_batch(&mut self, additional: usize) {
        self.delta_log.reserve(additional);
    }

    /// Write a batch of instruction traces (for high-throughput import)
    pub fn write_batch(&mut self, batch: InstructionBatch) -> Result<()> {
        self.delta_log.reserve(batch.records.len());
        for trace in batch.records {
            self.write(trace)?;
        }
        Ok(())
    }

    /// Query instructions at a specific step.
    ///
    /// Returns every instruction recorded at `step` in insertion order. A step
    /// normally holds one instruction (the adapter assigns a unique `seq`), but
    /// `seq` is caller-supplied and not guaranteed unique — two threads can
    /// share a `seq`, or a hand-written native JSON can repeat one. Callers
    /// that indexed their way to `step` should iterate all returned records;
    /// callers wanting a single representative instruction (e.g.
    /// [`TraceEngine::query_instruction`]) take the last, matching the
    /// pre-EventLog DeltaLog overwrite behavior.
    pub fn get_at_step(&self, step: u64) -> Vec<&InstructionTrace> {
        self.delta_log
            .get_all(step)
            .iter()
            .filter_map(|record| match &record.payload {
                DeltaPayload::FullValue(trace) => Some(trace),
                _ => None, // TODO: handle delta reconstruction
            })
            .collect()
    }

    /// Query instructions in a step range. Same-step instructions are
    /// flattened in insertion order (see [`Self::get_at_step`]).
    pub fn query_range(&self, start: u64, end: u64) -> Vec<&InstructionTrace> {
        self.delta_log.get_range(start, end)
            .into_iter()
            .filter_map(|record| {
                match &record.payload {
                    DeltaPayload::FullValue(trace) => Some(trace),
                    _ => None,
                }
            })
            .collect()
    }

    /// Find all steps that executed an instruction at a specific address
    /// Uses the AddressIndex for O(log N) lookup instead of scanning all records
    pub fn find_by_address(&self, address: u64) -> &[u64] {
        self.address_index.find_steps_for_address(address)
    }

    /// Find all steps where a specific thread executed instructions
    /// Uses the ThreadIndex for O(log K) lookup where K = steps on this thread
    pub fn find_by_thread(&self, thread_id: u32) -> &[u64] {
        self.thread_index.find_steps_for_thread(thread_id)
    }

    /// Query instructions by thread ID in a step range
    ///
    /// Returns instructions where thread_id matches, within [start, end].
    /// Uses ThreadIndex to skip steps not on this thread. A step may hold
    /// instructions from several threads (two threads sharing one `seq`), so
    /// `get_at_step` results must be filtered by `thread_id` — otherwise this
    /// would leak other threads' instructions into the result despite the
    /// "by thread" name.
    pub fn query_by_thread_range(&self, thread_id: u32, start: u64, end: u64) -> Vec<&InstructionTrace> {
        let steps = self.thread_index.find_steps_for_thread(thread_id);
        // Binary search for steps in range
        let lo = steps.partition_point(|&s| s < start);
        let hi = steps.partition_point(|&s| s <= end);
        steps[lo..hi].iter()
            .flat_map(|&step| self.get_at_step(step))
            .filter(|instr| instr.thread_id == thread_id)
            .collect()
    }

    /// Get the total number of instructions stored
    pub fn total_count(&self) -> u64 {
        self.total_count
    }

    /// All instructions (sorted by step), for snapshot/persistence.
    pub fn all_instructions(&self) -> Vec<InstructionTrace> {
        self.delta_log
            .all_records_sorted()
            .into_iter()
            .filter_map(|r| match r.payload {
                crate::delta_store::types::DeltaPayload::FullValue(t) => Some(t),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta_store::types::DeltaStoreConfig;
    use sotrace_core::models::instruction_trace::InstructionTrace;

    fn instr(seq: u64, tid: u32, addr: u64) -> InstructionTrace {
        InstructionTrace {
            seq,
            thread_id: tid,
            address: addr,
            timestamp: None,
            is_branch: false,
            branch_taken: false,
            opcode: None,
        }
    }

    /// `find_by_address` must not return a duplicated step when the same
    /// (address, step) is written twice. The EventLog retains both records, but
    /// the index collapses to a single step — otherwise `query_threads_at_address`
    /// (which does `find_by_address(addr).iter().flat_map(get_at_step)`) would
    /// emit the same (thread, step) pair twice via the doubled step.
    #[test]
    fn test_find_by_address_dedups_repeated_step() {
        let mut s = InstructionStore::new(DeltaStoreConfig::default());
        s.write(instr(5, 1, 0x1000)).unwrap();
        s.write(instr(5, 2, 0x1000)).unwrap(); // same (addr, step), both retained in EventLog
        s.write(instr(9, 1, 0x2000)).unwrap();

        assert_eq!(s.find_by_address(0x1000), &[5], "no duplicated step");
        assert_eq!(s.find_by_address(0x2000), &[9]);
    }

    /// `find_by_thread` likewise dedups: two instructions on the same thread
    /// sharing a `seq` register (thread, step) twice, but the step list must
    /// hold one entry so range queries don't double-emit.
    #[test]
    fn test_find_by_thread_dedups_repeated_step() {
        let mut s = InstructionStore::new(DeltaStoreConfig::default());
        s.write(instr(5, 1, 0x1000)).unwrap();
        s.write(instr(5, 1, 0x2000)).unwrap(); // same thread, same seq, different addr
        s.write(instr(7, 1, 0x3000)).unwrap();

        assert_eq!(s.find_by_thread(1), &[5, 7], "no duplicated step");
    }

    /// Two instructions sharing a `seq` (multi-threaded adapter assigning the
    /// same step to two threads) must both survive in the EventLog — a keyed
    /// DeltaLog would keep only the last. `get_at_step` returns both in
    /// insertion order; `query_range` flattens them; `all_instructions`
    /// persists both.
    #[test]
    fn test_same_seq_two_instructions_both_survive() {
        let mut s = InstructionStore::new(DeltaStoreConfig::default());
        s.write(instr(5, 1, 0x1000)).unwrap();
        s.write(instr(5, 2, 0x2000)).unwrap(); // same seq, different thread/addr
        s.write(instr(9, 1, 0x3000)).unwrap();

        // get_at_step returns both same-seq instructions in insertion order.
        let at_5: Vec<u32> = s.get_at_step(5).iter().map(|i| i.thread_id).collect();
        assert_eq!(at_5, vec![1, 2], "both same-seq instructions survive");
        assert_eq!(s.get_at_step(9).len(), 1);

        // query_range flattens same-seq records in order.
        let range: Vec<u32> = s.query_range(0, 10).iter().map(|i| i.thread_id).collect();
        assert_eq!(range, vec![1, 2, 1]);

        // Persistence path keeps all three.
        assert_eq!(s.all_instructions().len(), 3);
    }

    /// `query_by_thread_range` must only return the requested thread's
    /// instructions. When two threads share a `seq`, `get_at_step` yields both,
    /// so without a `thread_id` filter the other thread's instruction leaks into
    /// the "by thread" result — a real correctness gap (the method name promises
    /// thread isolation that the index alone cannot enforce).
    #[test]
    fn test_query_by_thread_range_excludes_other_threads() {
        let mut s = InstructionStore::new(DeltaStoreConfig::default());
        s.write(instr(5, 1, 0x1000)).unwrap();
        s.write(instr(5, 2, 0x2000)).unwrap(); // same seq, different thread
        s.write(instr(9, 1, 0x3000)).unwrap();

        // Thread 1's range must not include thread 2's instruction at seq 5.
        let t1: Vec<u32> = s
            .query_by_thread_range(1, 0, 10)
            .iter()
            .map(|i| i.thread_id)
            .collect();
        assert_eq!(t1, vec![1, 1], "no other-thread instructions leak in");

        // Thread 2's range is only its seq-5 instruction.
        let t2: Vec<u32> = s
            .query_by_thread_range(2, 0, 10)
            .iter()
            .map(|i| i.thread_id)
            .collect();
        assert_eq!(t2, vec![2]);
    }
}
