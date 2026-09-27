//! Call store — call/return event log for call-stack reconstruction
//!
//! Call traces form a tree (the call stack), but the active stack at any step
//! is reconstructed by replaying a thread's call/return events in order (push
//! on Call, pop on Return, replace-on-TailCall) — see [`CallStore::rebuild_call_stack`].
//! That replay is backed by the event log's range iterator, so it visits only
//! the call records in `[0, target_step]` (O(log N + K)) rather than probing
//! every integer step. No nested-set (left/right) precomputation is kept: the
//! previous implementation maintained one but never read it back, so it was
//! pure write-time overhead. If a future query needs "all descendants/ancestors
//! of a finished call", a left/right index can be reintroduced then.
//!
//! Delta encoding for calls:
//! - **Call events**: NumericDelta on callee_address (calls often target same functions)
//! - **Depth**: ByteLevel (small incremental changes)
//! - **Return sequence**: NumericDelta (return step - call step is often small)

use anyhow::Result;

use sotrace_core::models::call_trace::{CallTrace, CallEventType, StackFrame};

use crate::delta_store::delta_log::EventLog;
use crate::delta_store::delta_index::FunctionIndex;
use crate::delta_store::types::*;

/// Call store — call/return event log for call-chain queries
pub struct CallStore {
    /// Delta log for call trace records
    /// Event log for call records. Call events are discrete (not a reducible
    /// delta stream), and `seq` comes from the caller/adapter (`trace.seq`) —
    /// NOT a monotonic engine counter — so two threads can issue a Call at the
    /// same step. `EventLog` keeps a `Vec` per step so same-step calls all
    /// survive (a keyed `DeltaLog` would silently clobber all but the last,
    /// making `rebuild_call_stack` drop frames). Mirrors the thread_store
    /// sync/state/switch logs (#52) and jni_store (#69).
    delta_log: EventLog<CallTrace>,
    /// Function index for function-scoped queries
    function_index: FunctionIndex,
}

impl CallStore {
    /// Create a new call store
    pub fn new(config: DeltaStoreConfig) -> Self {
        // `config.compression` configures the EventLog; the rest is not retained
        // (no query path reads it back). Mirrors the other stores.
        Self {
            delta_log: EventLog::new(config.compression),
            function_index: FunctionIndex::new(),
        }
    }

    /// Write a call trace event
    pub fn write(&mut self, trace: CallTrace) -> Result<()> {
        // Update the function index (callee_func_id is optional).
        if let Some(func_id) = trace.callee_func_id {
            self.function_index.register_call(func_id as u64, trace.seq, trace.return_seq);
        }

        // Create delta record
        let record = DeltaRecord {
            step: trace.seq,
            encoding: DeltaEncoding::FullValue, // MVP: store full events
            payload: DeltaPayload::FullValue(trace),
            prev_hash: None,
        };

        self.delta_log.append(record)?;
        Ok(())
    }

    /// Rebuild the live call stack for a thread at a given step.
    ///
    /// Replays this thread's call/return events in step order up to and
    /// including `target_step`, maintaining a live stack: push on Call, pop on
    /// Return, and replace the top frame on TailCall (a tail call reuses the
    /// caller's frame). The remaining stack is the set of frames still active
    /// at `target_step`, outermost frame first.
    ///
    /// Iteration is backed by [`DeltaLog::get_range`], i.e. the underlying
    /// `BTreeMap` range iterator, so it visits only the call records in
    /// `[0, target_step]` — O(log N + K) where K is the number of such
    /// records — instead of probing every integer step in the range. It also
    /// derives activity from the actual Return events rather than the
    /// (possibly unset) `return_seq` stamped on stored Call records.
    pub fn rebuild_call_stack(
        &self,
        thread_id: u32,
        target_step: u64,
    ) -> Vec<StackFrame> {
        // Build a frame from a CallTrace, but derive `depth` from the live
        // replay position rather than `trace.depth`. The replay maintains the
        // true stack — `stack.len()` *before* the push is exactly the frame's
        // nesting depth (0 = outermost) — so this is correct even when the
        // adapter left `trace.depth` at its default 0 (e.g. a frida-interceptor
        // trace without depth annotations). When the adapter did fill depth,
        // the replay-derived value agrees with it.
        let mut frame_of = |trace: &CallTrace, depth: u16| StackFrame {
            func_id: trace.callee_func_id,
            func_name: None,
            entry_address: trace.callee_address,
            call_site: trace.caller_address,
            call_seq: trace.seq,
            depth,
        };

        let mut stack: Vec<StackFrame> = Vec::new();
        for record in self.delta_log.get_range(0, target_step) {
            let DeltaPayload::FullValue(trace) = &record.payload else {
                continue;
            };
            if trace.thread_id != thread_id {
                continue;
            }
            match trace.event_type {
                CallEventType::Call => {
                    let depth = stack.len() as u16;
                    stack.push(frame_of(trace, depth));
                }
                CallEventType::TailCall => {
                    // The caller does not return; its frame is replaced at the
                    // same depth. pop first so the new frame takes the caller's
                    // slot (depth = stack.len() after pop).
                    stack.pop();
                    let depth = stack.len() as u16;
                    stack.push(frame_of(trace, depth));
                }
                // A return without a matching call (thread observed mid-trace)
                // leaves the stack empty; `pop` on empty is a safe no-op.
                CallEventType::Return => {
                    stack.pop();
                }
            }
        }

        stack
    }

    /// Query call chain for a specific function
    pub fn query_function_calls(&self, func_id: u64) -> &[u64] {
        self.function_index.find_steps_for_function(func_id)
    }

    /// Get the call events recorded at exactly `step` (in insertion order).
    /// Returns a Vec because multiple calls can share a step (different
    /// threads issuing a Call at the same `seq`).
    pub fn get_at_step(&self, step: u64) -> Vec<&CallTrace> {
        self.delta_log.get_all(step).iter().filter_map(|record| {
            match &record.payload {
                DeltaPayload::FullValue(trace) => Some(trace),
                _ => None,
            }
        }).collect()
    }

    /// All call traces (sorted by step), for snapshot/persistence.
    pub fn all_calls(&self) -> Vec<CallTrace> {
        self.delta_log
            .all_records_sorted()
            .into_iter()
            .filter_map(|r| match r.payload {
                DeltaPayload::FullValue(t) => Some(t),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> CallStore {
        CallStore::new(DeltaStoreConfig::default())
    }

    fn call(id: u64, thread_id: u32, seq: u64, callee: u64, depth: u16) -> CallTrace {
        CallTrace {
            id,
            thread_id,
            event_type: CallEventType::Call,
            caller_address: callee - 0x10,
            callee_address: callee,
            callee_func_id: Some(callee as u32),
            seq,
            depth,
            return_seq: None,
        }
    }

    fn ret(id: u64, thread_id: u32, seq: u64, depth: u16) -> CallTrace {
        CallTrace {
            id,
            thread_id,
            event_type: CallEventType::Return,
            caller_address: 0,
            callee_address: 0,
            callee_func_id: None,
            seq,
            depth,
            return_seq: None,
        }
    }

    /// Nested calls that have not yet returned form the live stack, outermost
    /// frame first.
    #[test]
    fn test_rebuild_call_stack_nested_active() {
        let mut s = store();
        s.write(call(1, 1, 1, 0x1000, 0)).unwrap();
        s.write(call(2, 1, 2, 0x2000, 1)).unwrap();
        s.write(call(3, 1, 3, 0x3000, 2)).unwrap();

        let stack = s.rebuild_call_stack(1, 3);
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0].entry_address, 0x1000);
        assert_eq!(stack[1].entry_address, 0x2000);
        assert_eq!(stack[2].entry_address, 0x3000);
    }

    /// `depth` is derived from the replay position, not `trace.depth` — so a
    /// trace whose depth annotations are all 0 (e.g. frida-interceptor without
    /// depth) still yields frames with correct nesting 0,1,2,… matching their
    /// position in the rebuilt stack.
    #[test]
    fn test_rebuild_call_stack_depth_derived_from_replay_position() {
        let mut s = store();
        // All depth=0 (simulating an adapter that doesn't annotate depth).
        s.write(call(1, 1, 1, 0x1000, 0)).unwrap();
        s.write(call(2, 1, 2, 0x2000, 0)).unwrap();
        s.write(call(3, 1, 3, 0x3000, 0)).unwrap();

        let stack = s.rebuild_call_stack(1, 3);
        assert_eq!(stack.len(), 3);
        // Depths follow the replay stack position, not the (zeroed) trace.depth.
        assert_eq!(stack[0].depth, 0);
        assert_eq!(stack[1].depth, 1);
        assert_eq!(stack[2].depth, 2);

        // After a return pops the top, the remaining frame keeps depth 0.
        s.write(ret(4, 1, 4, 0)).unwrap();
        let at4 = s.rebuild_call_stack(1, 4);
        assert_eq!(at4.len(), 2);
        assert_eq!(at4[0].depth, 0);
        assert_eq!(at4[1].depth, 1);
    }

    /// A tail call replaces the top frame at the SAME depth (the caller's
    /// slot), so the new frame inherits the popped frame's depth.
    #[test]
    fn test_rebuild_call_stack_tail_call_keeps_depth() {
        use sotrace_core::models::call_trace::CallEventType;
        let mut s = store();
        s.write(call(1, 1, 1, 0x1000, 0)).unwrap(); // depth 0
        s.write(call(2, 1, 2, 0x2000, 0)).unwrap(); // depth 1
        // Tail call: replaces 0x2000 frame with 0x3000 at depth 1.
        s.write(CallTrace {
            id: 3, thread_id: 1,
            event_type: CallEventType::TailCall,
            caller_address: 0x2000, callee_address: 0x3000,
            callee_func_id: None, seq: 3, depth: 0, return_seq: None,
        }).unwrap();

        let stack = s.rebuild_call_stack(1, 3);
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0].entry_address, 0x1000);
        assert_eq!(stack[0].depth, 0);
        assert_eq!(stack[1].entry_address, 0x3000);
        assert_eq!(stack[1].depth, 1); // inherited the replaced frame's depth
    }

    /// A Return pops the matching frame; querying at an earlier step still sees
    /// it on the stack.
    #[test]
    fn test_rebuild_call_stack_return_pops() {
        let mut s = store();
        s.write(call(1, 1, 1, 0x1000, 0)).unwrap();
        s.write(call(2, 1, 2, 0x2000, 1)).unwrap();
        s.write(ret(3, 1, 3, 1)).unwrap(); // return from 0x2000

        // At step 3 only the outer frame remains.
        let at3 = s.rebuild_call_stack(1, 3);
        assert_eq!(at3.len(), 1);
        assert_eq!(at3[0].entry_address, 0x1000);

        // At step 2 both frames are still active.
        let at2 = s.rebuild_call_stack(1, 2);
        assert_eq!(at2.len(), 2);
        assert_eq!(at2[1].entry_address, 0x2000);
    }

    /// Only the queried thread's frames appear in its stack.
    #[test]
    fn test_rebuild_call_stack_thread_isolation() {
        let mut s = store();
        s.write(call(1, 1, 1, 0x1000, 0)).unwrap();
        s.write(call(2, 2, 2, 0xa000, 0)).unwrap();
        s.write(call(3, 1, 3, 0x2000, 1)).unwrap();

        let t1 = s.rebuild_call_stack(1, 10);
        assert_eq!(t1.len(), 2);
        assert!(t1.iter().all(|f| f.entry_address == 0x1000 || f.entry_address == 0x2000));

        let t2 = s.rebuild_call_stack(2, 10);
        assert_eq!(t2.len(), 1);
        assert_eq!(t2[0].entry_address, 0xa000);
    }

    /// Two threads issuing a Call at the SAME seq must both be retained. The
    /// old `DeltaLog` (keyed insert) silently clobbered the first, so
    /// `rebuild_call_stack` for the thread whose record was dropped would miss
    /// a frame. `EventLog` keeps both; the per-thread replay then picks its own.
    #[test]
    fn test_rebuild_call_stack_same_step_two_threads() {
        let mut s = store();
        // Both threads call at seq 5 — a keyed log would keep only one.
        s.write(call(10, 1, 5, 0x1000, 0)).unwrap();
        s.write(call(11, 2, 5, 0xA000, 0)).unwrap();

        let t1 = s.rebuild_call_stack(1, 10);
        assert_eq!(t1.len(), 1, "thread 1's same-step frame must survive");
        assert_eq!(t1[0].entry_address, 0x1000);

        let t2 = s.rebuild_call_stack(2, 10);
        assert_eq!(t2.len(), 1, "thread 2's same-step frame must survive");
        assert_eq!(t2[0].entry_address, 0xA000);

        // Persistence path also keeps both.
        assert_eq!(s.all_calls().len(), 2);
    }

    /// A tail call replaces the caller's frame rather than nesting under it.
    #[test]
    fn test_rebuild_call_stack_tail_call_replaces_top() {
        let mut s = store();
        s.write(call(1, 1, 1, 0x1000, 0)).unwrap();
        s.write(call(2, 1, 2, 0x2000, 1)).unwrap();
        let mut tc = call(3, 1, 3, 0x3000, 1);
        tc.event_type = CallEventType::TailCall;
        s.write(tc).unwrap();

        let stack = s.rebuild_call_stack(1, 3);
        // 0x2000's frame was replaced by 0x3000; 0x1000 stays.
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0].entry_address, 0x1000);
        assert_eq!(stack[1].entry_address, 0x3000);
    }

    /// A return with no matching call (thread observed mid-trace) is a safe
    /// no-op, not a panic or underflow.
    #[test]
    fn test_rebuild_call_stack_unmatched_return_is_noop() {
        let mut s = store();
        s.write(ret(1, 1, 1, 0)).unwrap();
        s.write(call(2, 1, 2, 0x1000, 0)).unwrap();

        let stack = s.rebuild_call_stack(1, 10);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].entry_address, 0x1000);
    }

    /// `query_function_calls` must not duplicate a step when two threads call
    /// the same function at the same `seq` (both register (func_id, step)
    /// twice). A duplicated step would make `get_at_step(step)`-based consumers
    /// — like the call_chain HTTP handler's `flat_map(get_at_step(seq))` —
    /// emit each matching call twice. The step list collapses to one entry;
    /// the actual call multiplicity is preserved by the EventLog, so
    /// `get_at_step(5)` still returns both real calls.
    #[test]
    fn test_query_function_calls_dedups_same_step() {
        let mut s = store();
        // func_id 0x1000 called by two threads at seq 5; 0x2000 once at seq 9.
        s.write(call(10, 1, 5, 0x1000, 0)).unwrap();
        s.write(call(11, 2, 5, 0x1000, 0)).unwrap();
        s.write(call(12, 1, 9, 0x2000, 0)).unwrap();

        // No duplicate step 5 in the index.
        assert_eq!(s.query_function_calls(0x1000), &[5]);
        // Yet both real calls survive in the keyed log.
        let calls_at_5 = s.get_at_step(5);
        assert_eq!(calls_at_5.len(), 2, "both same-step calls must survive");
        assert_eq!(s.get_at_step(5).iter().map(|c| c.thread_id).collect::<Vec<_>>(), vec![1, 2]);
    }
}
