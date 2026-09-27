//! Thread analyzer — high-level analysis for Android SO reverse engineering
//!
//! This module provides analysis capabilities that combine data from multiple
//! stores (ThreadStore, MemoryStore, CallStore, InstructionStore) to detect
//! patterns that are critical for SO security analysis:
//!
//! 1. **Race condition detection** — two threads accessing same memory without sync
//! 2. **Deadlock detection** — lock ordering violations (A→B vs B→A)
//! 3. **Lock contention analysis** — which locks are hot, who contends
//! 4. **Thread-function association** — which threads called which functions
//! 5. **Thread data flow** — how data flows between threads via shared memory
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    ThreadAnalyzer                             │
//! │                                                               │
//! │  ┌─────────────────┐  ┌──────────────────────────────────┐  │
//! │  │  Race Detector   │  │  Deadlock Detector               │  │
//! │  │                  │  │                                   │  │
//! │  │ - Memory access  │  │ - Lock graph (wait-for graph)    │  │
//! │  │   overlap        │  │ - Cycle detection                │  │
//! │  │ - No sync check  │  │ - Lock ordering analysis         │  │
//! │  └─────────────────┘  └──────────────────────────────────┘  │
//! │                                                               │
//! │  ┌─────────────────┐  ┌──────────────────────────────────┐  │
//! │  │  Contention      │  │  Thread-Function                 │  │
//! │  │  Analyzer        │  │  Association                     │  │
//! │  │                  │  │                                   │  │
//! │  │ - Hot locks      │  │ - Per-thread call stats          │  │
//! │  │ - Wait time      │  │ - Thread safety classification   │  │
//! │  │ - Contention %   │  │ - JNI boundary mapping           │  │
//! │  └─────────────────┘  └──────────────────────────────────┘  │
//! │                                                               │
//! │  ┌─────────────────────────────────────────────────────────┐ │
//! │  │  Data Flow Analyzer                                      │ │
//! │  │                                                          │ │
//! │  │ - Shared memory write → read across threads              │ │
//! │  │ - Producer-consumer pattern detection                    │ │
//! │  │ - Thread-local vs shared data classification             │ │
//! │  └─────────────────────────────────────────────────────────┘ │
//! └──────────────────────────────────────────────────────────────┘
//! ```

pub mod thread_analyzer;
pub mod performance_analyzer;

pub use thread_analyzer::ThreadAnalyzer;
pub use performance_analyzer::{
    HotPathEntry, HotPathsResult, BranchStat, BranchStatsResult,
    InstructionHit, AddressRangeQuery,
    analyze_hot_paths, analyze_branch_stats, query_address_range,
};
