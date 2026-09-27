//! Release measurement of the shipping import path.
//!
//! CLI `feed_events`, HTTP `POST /api/v1/traces/import`, and MCP `import_trace`
//! all apply batches through `TraceEngine::feed_events`. This binary times
//! that function on one fixed mixed batch (instructions, register deltas, and
//! memory writes from `synthesize_mixed`). It does not time `TraceIngestor`.
//!
//! stdout (one line):
//! `events=<n> seconds=<s> events_per_sec=<r> queryable=<q> batch=<n>`

use std::time::Instant;

use sotrace_engine::delta_store::types::DeltaStoreConfig;
use sotrace_engine::engine::TraceEngine;
use sotrace_engine::trace_codec::synthesize_mixed;

/// Instruction count of the fixed mixed batch. Register deltas and memory
/// writes are added by `synthesize_mixed` on top of this.
const INSTRUCTIONS: usize = 1_000_000;
const THREADS: u32 = 4;

fn main() {
    let batch = synthesize_mixed(INSTRUCTIONS, THREADS);
    let batch_len = batch.len();
    let mut engine = TraceEngine::new(1, DeltaStoreConfig::default());

    let started = Instant::now();
    engine
        .feed_events(batch)
        .expect("feed_events failed");
    let seconds = started.elapsed().as_secs_f64();

    let queryable = engine.instruction_store().total_count()
        + engine.register_store().record_count()
        + engine.memory_store().record_count()
        + engine.thread_store().all_state_changes().len() as u64
        + engine.thread_store().all_sync_events().len() as u64
        + engine.thread_store().all_context_switches().len() as u64
        + engine.call_store().all_calls().len() as u64
        + engine.jni_store().all_jni_calls().len() as u64;

    let rate = if seconds > 0.0 {
        batch_len as f64 / seconds
    } else {
        0.0
    };

    println!(
        "events={batch_len} seconds={seconds:.6} events_per_sec={rate:.0} queryable={queryable} batch={batch_len}"
    );
    if queryable != batch_len as u64 {
        eprintln!("queryable count {queryable} != batch {batch_len}");
        std::process::exit(1);
    }
}
