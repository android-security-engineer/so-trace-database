//! Trace engine — unified engine that coordinates all trace stores
//!
//! The TraceEngine is the main entry point for all trace operations.
//! It holds all stores (instruction, register, memory, call, thread, JNI),
//! the Timeline, and the ThreadAnalyzer, coordinating:
//! - Write operations (import trace data)
//! - Snapshot creation (coordinated across all stores)
//! - Query operations (cross-store queries via timeline)
//! - Thread analysis (race detection, deadlock detection, data flow)
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                   TraceEngine                          │
//! │                                                        │
//! │  ┌──────────┐  ┌───────────┐  ┌──────────────────┐  │
//! │  │ Timeline  │  │  Stores   │  │  ThreadAnalyzer  │  │
//! │  │          │  │           │  │                   │  │
//! │  │ - step   │  │ - Instr   │  │ - Race detection │  │
//! │  │ - indexes│  │ - Reg     │  │ - Deadlock det.  │  │
//! │  │ - coords │  │ - Mem     │  │ - Data flow      │  │
//! │  │  snaps   │  │ - Call    │  │ - Thread safety  │  │
//! │  │          │  │ - Thread  │  │                   │  │
//! │  │          │  │ - JNI     │  │                   │  │
//! │  └──────────┘  └───────────┘  └──────────────────┘  │
//! └──────────────────────────────────────────────────────┘
//! ```

use anyhow::Result;

use sotrace_core::models::instruction_trace::{InstructionTrace, InstructionBatch};
use sotrace_core::models::call_trace::CallTrace;
use sotrace_core::models::register_delta::RegisterDelta;
use sotrace_core::models::jni_call::JNICall;
use sotrace_core::models::thread::{
    ThreadInfo, ThreadStateChange, ThreadSyncEvent,
    ContextSwitch, ThreadStats,
};

use crate::delta_store::types::DeltaStoreConfig;
use crate::timeline::{Timeline, StepMetadata, TimelineQuery, TimelineResult};
use crate::trace_store::{
    InstructionStore, RegisterStore, MemoryStore,
    CallStore, ThreadStore, JNIStore,
};
use crate::trace_store::memory_store::{MemoryWrite, MemoryValueResult};
use crate::trace_store::thread_store::ThreadTimeline;
use crate::analyzer::{ThreadAnalyzer, thread_analyzer::ThreadAnalysisResult};

pub mod ingest;
pub use ingest::{IngestStatus, TraceIngestor, WriteMode};

/// Trace engine — unified coordinator for all trace stores and analysis
pub struct TraceEngine {
    /// Timeline — core abstraction tying all stores together
    timeline: Timeline,
    /// Instruction store
    instructions: InstructionStore,
    /// Register store
    registers: RegisterStore,
    /// Memory store
    memory: MemoryStore,
    /// Call store
    calls: CallStore,
    /// Thread store
    threads: ThreadStore,
    /// JNI store
    jni: JNIStore,
    /// Thread analyzer — runs analysis on demand
    analyzer: ThreadAnalyzer,
    /// SO file ID this engine is tracking
    so_file_id: u64,
    /// Function table keyed by SO-relative entry offset, mapping to
    /// `(size, name)`. Kept in a `BTreeMap` so [`Self::function_name`] can do
    /// addr2line-style range resolution: a PC anywhere inside a function's
    /// `[offset, offset + size)` body resolves to that function, not just the
    /// entry address. `size == 0` (stripped/dynsym-recovered symbols) fall back
    /// to exact-entry match.
    function_names: std::collections::BTreeMap<u64, (u32, String)>,
}

impl TraceEngine {
    /// Create a new trace engine for the given SO file
    pub fn new(so_file_id: u64, config: DeltaStoreConfig) -> Self {
        // `config` is forwarded to every sub-store / timeline; it is not
        // retained on the engine itself (no method reads it back).
        Self {
            timeline: Timeline::new(0, so_file_id, config.clone()),
            instructions: InstructionStore::new(config.clone()),
            registers: RegisterStore::new(config.clone()),
            memory: MemoryStore::new(config.clone()),
            calls: CallStore::new(config.clone()),
            threads: ThreadStore::new(config.clone()),
            jni: JNIStore::new(config.clone()),
            analyzer: ThreadAnalyzer::new(),
            so_file_id,
            function_names: std::collections::BTreeMap::new(),
        }
    }

    // ========================================================================
    // Write operations — import trace data
    // ========================================================================

    /// Import a single instruction trace record
    ///
    /// This writes to:
    /// 1. InstructionStore — the instruction itself
    /// 2. Timeline — step metadata (what happened at this step)
    pub fn import_instruction(&mut self, trace: InstructionTrace) -> Result<()> {
        // Keep the metadata before moving the trace into the store. This avoids
        // cloning the full record (which may include an opcode byte vector) on
        // the hot import path.
        let (step, thread_id, address) = (trace.seq, trace.thread_id, trace.address);

        // Write to instruction store
        self.instructions.write(trace)?;

        // Record step metadata in timeline
        // Instruction is the primary event at a step — it sets the step's
        // thread_id and instruction_address. Other import methods will
        // merge their flags into this step via record_step's OR-merge.
        let meta = StepMetadata {
            step,
            thread_id,
            instruction_address: address,
            has_register_delta: false,
            has_memory_delta: false,
            has_call_event: false,
            has_jni_call: false,
            has_thread_event: false,
            has_sync_event: false,
            has_context_switch: false,
        };
        self.timeline.record_step(meta);

        Ok(())
    }

    /// Import a batch of instruction traces
    pub fn import_instruction_batch(&mut self, batch: InstructionBatch) -> Result<()> {
        for trace in batch.records {
            self.import_instruction(trace)?;
        }
        Ok(())
    }

    /// Import a register delta (register changes at a step)
    ///
    /// Updates the timeline's StepMetadata to mark has_register_delta = true
    /// for the step where this delta occurred.
    pub fn import_register_delta(&mut self, delta: RegisterDelta) -> Result<()> {
        let step = delta.seq;
        self.registers.write_delta(delta)?;

        // Update timeline metadata: this step has register changes
        self.timeline.record_step(StepMetadata {
            step,
            thread_id: 0, // RegisterDelta doesn't carry thread_id; will be merged
            instruction_address: 0,
            has_register_delta: true,
            has_memory_delta: false,
            has_call_event: false,
            has_jni_call: false,
            has_thread_event: false,
            has_sync_event: false,
            has_context_switch: false,
        });

        Ok(())
    }

    /// Import a memory write event
    ///
    /// Updates the timeline's StepMetadata to mark has_memory_delta = true.
    pub fn import_memory_write(&mut self, write: MemoryWrite) -> Result<()> {
        let step = write.step;
        let thread_id = write.thread_id;

        // Feed to analyzer for race detection
        self.analyzer.feed_memory_write(step, thread_id, write.address, write.data.len());

        // Write to memory store
        self.memory.write(write)?;

        // Update timeline metadata: this step has memory changes
        self.timeline.record_step(StepMetadata {
            step,
            thread_id,
            instruction_address: 0,
            has_register_delta: false,
            has_memory_delta: true,
            has_call_event: false,
            has_jni_call: false,
            has_thread_event: false,
            has_sync_event: false,
            has_context_switch: false,
        });

        Ok(())
    }

    /// Import a call trace event (function call/return)
    ///
    /// Updates the timeline's StepMetadata to mark has_call_event = true.
    pub fn import_call_trace(&mut self, trace: CallTrace) -> Result<()> {
        let step = trace.seq;
        let thread_id = trace.thread_id;

        // Feed to analyzer for thread-function association
        self.analyzer.feed_call_event(step, thread_id, trace.callee_address);

        // Write to call store
        self.calls.write(trace)?;

        // Update timeline metadata: this step has a call event
        self.timeline.record_step(StepMetadata {
            step,
            thread_id,
            instruction_address: 0,
            has_register_delta: false,
            has_memory_delta: false,
            has_call_event: true,
            has_jni_call: false,
            has_thread_event: false,
            has_sync_event: false,
            has_context_switch: false,
        });

        Ok(())
    }

    /// Import a JNI call record
    ///
    /// Updates the timeline's StepMetadata to mark has_jni_call = true.
    pub fn import_jni_call(&mut self, call: JNICall) -> Result<()> {
        let step = call.seq;
        let thread_id = call.thread_id;

        // Feed the analyzer so JNI boundary analysis has data. Without this the
        // call is written to the store but invisible to `analyze_jni_boundary`.
        self.analyzer.feed_jni_call(call.clone());

        self.jni.write(call)?;

        // Update timeline metadata: this step has a JNI call
        self.timeline.record_step(StepMetadata {
            step,
            thread_id,
            instruction_address: 0,
            has_register_delta: false,
            has_memory_delta: false,
            has_call_event: false,
            has_jni_call: true,
            has_thread_event: false,
            has_sync_event: false,
            has_context_switch: false,
        });

        Ok(())
    }

    // ========================================================================
    // Thread-specific write operations
    // ========================================================================

    /// Register a new thread
    pub fn register_thread(&mut self, info: ThreadInfo) -> Result<()> {
        // Feed to analyzer
        self.analyzer.feed_thread_info(info.clone());

        self.threads.register_thread(info)?;

        // Update timeline metadata: thread creation event
        // Note: thread creation may not correspond to an instruction step,
        // but we still record it in the timeline for completeness.
        Ok(())
    }

    /// Record a thread state change
    ///
    /// Updates the timeline's StepMetadata to mark has_thread_event = true.
    pub fn record_thread_state_change(&mut self, change: ThreadStateChange) -> Result<()> {
        let step = change.step;
        let thread_id = change.thread_id;

        // Feed the analyzer so state-residency analysis has data. Without this
        // the change is written to the store but invisible to `analyze_thread_states`.
        self.analyzer.feed_state_change(change.clone());

        self.threads.write(change)?;

        // Update timeline metadata: this step has a thread event
        self.timeline.record_step(StepMetadata {
            step,
            thread_id,
            instruction_address: 0,
            has_register_delta: false,
            has_memory_delta: false,
            has_call_event: false,
            has_jni_call: false,
            has_thread_event: true,
            has_sync_event: false,
            has_context_switch: false,
        });

        Ok(())
    }

    /// Record a thread synchronization event (mutex/futex/condvar)
    ///
    /// Updates the timeline's StepMetadata to mark has_sync_event = true.
    pub fn record_sync_event(&mut self, event: ThreadSyncEvent) -> Result<()> {
        let step = event.step;
        let thread_id = event.thread_id;

        // Feed to analyzer for race/deadlock/contention detection
        self.analyzer.feed_sync_event(event.clone());

        self.threads.write_sync_event(event)?;

        // Update timeline metadata: this step has a sync event
        self.timeline.record_step(StepMetadata {
            step,
            thread_id,
            instruction_address: 0,
            has_register_delta: false,
            has_memory_delta: false,
            has_call_event: false,
            has_jni_call: false,
            has_thread_event: false,
            has_sync_event: true,
            has_context_switch: false,
        });

        Ok(())
    }

    /// Record a context switch
    ///
    /// Updates the timeline's StepMetadata to mark has_context_switch = true.
    pub fn record_context_switch(&mut self, switch: ContextSwitch) -> Result<()> {
        let step = switch.step;

        // Feed to analyzer
        self.analyzer.feed_context_switch(switch.clone());

        self.threads.write_context_switch(switch)?;

        // Update timeline metadata: this step has a context switch
        self.timeline.record_step(StepMetadata {
            step,
            thread_id: 0, // Context switch involves two threads; not a single owner
            instruction_address: 0,
            has_register_delta: false,
            has_memory_delta: false,
            has_call_event: false,
            has_jni_call: false,
            has_thread_event: false,
            has_sync_event: false,
            has_context_switch: true,
        });

        Ok(())
    }

    // ========================================================================
    // Unified event ingestion (single source of truth for all entry paths)
    // ========================================================================

    /// Feed a single normalized [`TraceEvent`] into the engine, dispatching to
    /// the per-type import method.
    ///
    /// This is the **single dispatch table** shared by every entry path — CLI
    /// `feed_events`, MCP `import_trace`, and HTTP `import_trace`/`load_trace`.
    /// Keeping it in the engine (rather than duplicated as a `match` in each
    /// caller) means a new `TraceEvent` variant only has to be wired once, and
    /// the three paths cannot drift apart.
    pub fn feed_event(&mut self, event: sotrace_core::adapters::TraceEvent) -> Result<()> {
        use sotrace_core::adapters::TraceEvent;
        match event {
            TraceEvent::Thread(t) => self.register_thread(t),
            TraceEvent::Instruction(i) => self.import_instruction(i),
            TraceEvent::Register(d) => self.import_register_delta(d),
            TraceEvent::Call(c) => self.import_call_trace(c),
            TraceEvent::JniCall(j) => self.import_jni_call(j),
            TraceEvent::MemoryWrite { step, thread_id, address, data } => {
                self.import_memory_write(MemoryWrite { step, thread_id, address, data })
            }
            TraceEvent::MemoryRead { step, thread_id, address, size } => {
                self.feed_memory_read(step, thread_id, address, size);
                Ok(())
            }
            TraceEvent::Sync(s) => self.record_sync_event(s),
            TraceEvent::ContextSwitch(s) => self.record_context_switch(s),
            TraceEvent::StateChange(c) => self.record_thread_state_change(c),
        }
    }

    /// Feed a batch of events, sorted by step first.
    ///
    /// Sorting matters because several stores stamp live state in ingestion
    /// order (`thread_states`, `current_thread`) — feeding out of step order
    /// would leave that state reflecting an older event. `sort_by_key` is
    /// stable, so events that share a step keep their incoming order. A batch
    /// that is already non-decreasing skips that sort. This is the canonical
    /// ingestion path; CLI/MCP/HTTP should all funnel through it.
    pub fn feed_events(&mut self, events: impl IntoIterator<Item = sotrace_core::adapters::TraceEvent>) -> Result<()> {
        let mut sorted: Vec<sotrace_core::adapters::TraceEvent> = events.into_iter().collect();
        if !sorted.is_sorted_by_key(|e| e.step()) {
            sorted.sort_by_key(|e| e.step());
        }
        self.apply_events(sorted)
    }

    /// Apply an owned event batch without cloning each event.
    ///
    /// Consecutive instructions are written into the instruction store together
    /// with timeline metadata; other variants use [`Self::feed_event`]. Used by
    /// high-throughput ingest. Does **not** sort — callers that need
    /// chronological order (CLI replay) go through [`Self::feed_events`].
    pub fn apply_events(&mut self, events: Vec<sotrace_core::adapters::TraceEvent>) -> Result<()> {
        self.apply_event_iter(events)
    }

    /// Apply events borrowed from a buffer the caller still needs (the durable
    /// encode path). Each event is cloned into the store that owns it.
    pub(crate) fn apply_events_ref(&mut self, events: &[sotrace_core::adapters::TraceEvent]) -> Result<()> {
        self.apply_event_iter(events.iter().cloned())
    }

    fn apply_event_iter(
        &mut self,
        events: impl IntoIterator<Item = sotrace_core::adapters::TraceEvent>,
    ) -> Result<()> {
        use sotrace_core::adapters::TraceEvent;
        let mut instrs: Vec<InstructionTrace> = Vec::new();
        for ev in events {
            match ev {
                TraceEvent::Instruction(i) => instrs.push(i),
                other => {
                    self.flush_instruction_run(&mut instrs)?;
                    self.feed_event(other)?;
                }
            }
        }
        self.flush_instruction_run(&mut instrs)
    }

    fn flush_instruction_run(&mut self, instrs: &mut Vec<InstructionTrace>) -> Result<()> {
        if instrs.is_empty() {
            return Ok(());
        }
        let records = std::mem::take(instrs);
        let n = records.len();
        self.timeline.reserve_steps(n);
        self.instructions.reserve_batch(n);
        for trace in records {
            let (step, thread_id, address) = (trace.seq, trace.thread_id, trace.address);
            self.timeline.record_step(StepMetadata {
                step,
                thread_id,
                instruction_address: address,
                has_register_delta: false,
                has_memory_delta: false,
                has_call_event: false,
                has_jni_call: false,
                has_thread_event: false,
                has_sync_event: false,
                has_context_switch: false,
            });
            self.instructions.write(trace)?;
        }
        Ok(())
    }

    // ========================================================================
    // Coordinated snapshot operations
    // ========================================================================

    /// Check if all stores should create a coordinated snapshot
    pub fn should_snapshot(&self) -> bool {
        self.timeline.should_snapshot()
    }

    /// Create coordinated snapshots across all stores
    ///
    /// When a snapshot is needed, all stores create a checkpoint at the
    /// same step, ensuring consistent reconstruction across all data types.
    pub fn create_coordinated_snapshot(&mut self) -> Result<u64> {
        let step = self.timeline.current_step();
        let snapshot_id = step; // Use step as snapshot ID for simplicity

        // Create memory snapshot
        self.memory.create_snapshot(step)?;

        // Register snapshot in timeline
        self.timeline.record_snapshot(step, snapshot_id);

        Ok(snapshot_id)
    }

}

include!("query_api.rs");

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
