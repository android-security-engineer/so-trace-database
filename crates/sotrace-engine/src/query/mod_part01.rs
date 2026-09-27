// Query engine — delta-accelerated query engine
//
// # Core Design Principle: Storage is FOR Faster Queries
//
// Delta storage is not just about saving disk space. It enables
// fundamentally faster queries because:
//
// 1. **Skip irrelevant data**: With indexes, we can skip deltas that
//    don't affect the query target. "What is register X at step N?"
//    doesn't require scanning all register deltas — just find the last
//    delta for register X before step N.
//
// 2. **Locality of reference**: Deltas are small and sequential.
//    A single memory page access reads the delta + a few bytes of
//    change data, vs reading the entire page content.
//
// 3. **Content-addressable dedup**: Same content stored once means
//    the query engine only needs to traverse unique content.
//
// 4. **Checkpoint-based reconstruction**: To get state at step N,
//    we find the nearest checkpoint and apply only the deltas between
//    the checkpoint and N — not from step 0.
//
// # Query Types and Acceleration
//
// | Query Type | Without Index | With Index | Acceleration |
// |-----------|--------------|-----------|-------------|
// | Point query (step N) | O(total_deltas) | O(log snapshots + delta_interval) | ~1000x |
// | Address query | O(total_deltas) | O(log unique_addresses) | ~10000x |
// | Thread query | O(total_deltas) | O(log unique_threads) | ~100000x |
// | Function query | O(total_deltas) | O(log unique_functions) | ~10000x |
// | Sync object query | O(total_deltas) | O(log unique_locks) | ~10000x |
// | Range query | O(range_size × delta_per_step) | O(range_size) | ~10x |
//
// # Architecture
//
// The QueryEngine delegates to TraceEngine for actual data access,
// providing a clean query API with parameter validation and result
// transformation. The heavy lifting (index lookup, delta reconstruction)
// is done by the individual stores.
//
// ```text
// ┌──────────────────────────────────────────────────────┐
// │                  Query Engine                         │
// │                                                       │
// │  ┌─────────────────┐  ┌──────────────────────────┐  │
// │  │  Query Planner   │  │  Delta Reconstructor     │  │
// │  │                  │  │                          │  │
// │  │ - Parse query    │  │ - Find nearest snapshot  │  │
// │  │ - Choose index   │  │ - Apply relevant deltas  │  │
// │  │ - Optimize plan  │  │ - Return result          │  │
// │  └─────────────────┘  └──────────────────────────┘  │
// │                                                       │
// │  ┌─────────────────┐  ┌──────────────────────────┐  │
// │  │  Index Router    │  │  Result Cache            │  │
// │  │                  │  │                          │  │
// │  │ - SkipList      │  │ - LRU cache of           │  │
// │  │ - AddressIdx    │  │   reconstructed states   │  │
// │  │ - ThreadIdx     │  │ - Cache key: (step, type) │  │
// │  │ - FunctionIdx   │  │                          │  │
// │  │ - SyncObjIdx    │  │                          │  │
// │  └─────────────────┘  └──────────────────────────┘  │
// └──────────────────────────────────────────────────────┘
// ```

use anyhow::Result;

use sotrace_core::models::instruction_trace::InstructionTrace;
use sotrace_core::models::call_trace::StackFrame;
use sotrace_core::models::thread::{
    ThreadInfo, ThreadState, ThreadSyncEvent, ContextSwitch, ThreadStats,
};

use crate::engine::TraceEngine;
use crate::trace_store::memory_store::MemoryValueResult;
use crate::trace_store::thread_store::ThreadTimeline;
use crate::timeline::{TimelineQuery, TimelineResult};

// ---------------------------------------------------------------------------
// Instruction query
// ---------------------------------------------------------------------------

/// Instruction query parameters
#[derive(Debug, Clone)]
pub struct InstructionQuery {
    /// SO file ID
    pub so_file_id: u64,
    /// Start step (inclusive)
    pub start_step: Option<u64>,
    /// End step (inclusive)
    pub end_step: Option<u64>,
    /// Filter by address range
    pub address_range: Option<(u64, u64)>,
    /// Filter by thread ID
    pub thread_id: Option<u32>,
    /// Maximum results
    pub limit: Option<u64>,
}

// ---------------------------------------------------------------------------
// Memory query
// ---------------------------------------------------------------------------

/// Memory query parameters
#[derive(Debug, Clone)]
pub struct MemoryQuery {
    /// SO file ID
    pub so_file_id: u64,
    /// Virtual address to query
    pub address: u64,
    /// Number of bytes to read
    pub size: usize,
    /// Step number to query at
    pub step: u64,
}

// ---------------------------------------------------------------------------
// Call chain query
// ---------------------------------------------------------------------------

/// Call chain query parameters
#[derive(Debug, Clone)]
pub struct CallChainQuery {
    /// SO file ID
    pub so_file_id: u64,
    /// Thread ID
    pub thread_id: u32,
    /// Step number to query at
    pub step: u64,
}

// ---------------------------------------------------------------------------
// Register query
// ---------------------------------------------------------------------------

/// Register query parameters
#[derive(Debug, Clone)]
pub struct RegisterQuery {
    /// SO file ID
    pub so_file_id: u64,
    /// Register index (0-30 for GPRs, 31=SP, 32=PC, 33=NZCV)
    pub register_id: Option<usize>,
    /// Step number to query at
    pub step: u64,
}

// ---------------------------------------------------------------------------
// Thread query
// ---------------------------------------------------------------------------

/// Thread query parameters
#[derive(Debug, Clone)]
pub struct ThreadQuery {
    /// SO file ID
    pub so_file_id: u64,
    /// Thread ID to query (None = all threads)
    pub thread_id: Option<u32>,
    /// Step number to query state at
    pub step: Option<u64>,
    /// Include thread info (metadata)
    pub include_info: bool,
    /// Include statistics
    pub include_stats: bool,
}

/// Thread query result
#[derive(Debug, Clone)]
pub struct ThreadQueryResult {
    /// Thread info (if requested)
    pub info: Option<ThreadInfo>,
    /// Thread state at the queried step
    pub state: Option<ThreadState>,
    /// Thread statistics (if requested)
    pub stats: Option<ThreadStats>,
}

// ---------------------------------------------------------------------------
// Thread sync query
// ---------------------------------------------------------------------------

/// Thread synchronization query parameters
#[derive(Debug, Clone)]
pub struct ThreadSyncQuery {
    /// SO file ID
    pub so_file_id: u64,
    /// Filter by thread ID
    pub thread_id: Option<u32>,
    /// Filter by sync object address (mutex/futex/condvar address)
    pub sync_object_addr: Option<u64>,
    /// Start step (inclusive)
    pub start_step: u64,
    /// End step (inclusive)
    pub end_step: u64,
}

/// Thread sync query result
#[derive(Debug, Clone)]
pub struct ThreadSyncQueryResult {
    /// Matching sync events
    pub events: Vec<ThreadSyncEvent>,
    /// Total count (before any limit)
    pub total_count: u64,
}

// ---------------------------------------------------------------------------
// Context switch query
// ---------------------------------------------------------------------------

/// Context switch query parameters
#[derive(Debug, Clone)]
pub struct ContextSwitchQuery {
    /// SO file ID
    pub so_file_id: u64,
    /// Start step (inclusive)
    pub start_step: u64,
    /// End step (inclusive)
    pub end_step: u64,
    /// Filter by thread (involved as from or to)
    pub thread_id: Option<u32>,
}

/// Context switch query result
#[derive(Debug, Clone)]
pub struct ContextSwitchQueryResult {
    /// Matching context switches
    pub switches: Vec<ContextSwitch>,
    /// Total count
    pub total_count: u64,
}

/// Thread-instruction association query parameters
#[derive(Debug, Clone)]
pub struct ThreadInstructionQuery {
    /// SO file ID
    pub so_file_id: u64,
    /// Thread ID
    pub thread_id: u32,
    /// Start step (inclusive, None = 0)
    pub start_step: Option<u64>,
    /// End step (inclusive, None = u64::MAX)
    pub end_step: Option<u64>,
    /// Optional address range filter (lo, hi)
    pub address_range: Option<(u64, u64)>,
    /// Maximum results
    pub limit: Option<u64>,
}

/// Thread-instruction query result — which threads touched which addresses
#[derive(Debug, Clone)]
pub struct ThreadAddressResult {
    /// Address
    pub address: u64,
    /// (thread_id, step) pairs for this address
    pub accesses: Vec<(u32, u64)>,
}

// ---------------------------------------------------------------------------
// Query engine implementation
// ---------------------------------------------------------------------------

/// Query engine — provides high-level query API backed by delta-accelerated indexes
///
/// The QueryEngine is a stateless facade that delegates to TraceEngine.
/// It provides:
/// - Parameter validation and normalization
/// - Consistent result types
/// - Future: caching, query planning, parallel execution
pub struct QueryEngine;
