//! Generic Delta Store — The core incremental storage engine
//!
//! ALL storage in SO Trace Database is built on top of this module.
//! Whether it's register values, memory pages, instruction addresses,
//! or thread states — everything uses the delta (incremental) approach.
//!
//! # Core Idea
//!
//! Trace data is inherently sequential and highly repetitive.
//! Instead of storing full state at every step, we store:
//! 1. Periodic **snapshots** (full state checkpoints)
//! 2. **Deltas** (changes between steps)
//!
//! This gives us both: compact storage AND fast reconstruction at any point.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │              DeltaStore<T> (Generic)                 │
//! │                                                      │
//! │  ┌───────────┐   ┌────────────┐   ┌──────────────┐ │
//! │  │ Snapshot   │   │ Delta Log  │   │ Delta Index  │ │
//! │  │ Manager    │   │ (append)   │   │ (accelerate  │ │
//! │  │            │   │            │   │  queries)    │ │
//! │  │ - periodic │   │ - per-step │   │ - skip list  │ │
//! │  │   full     │   │   changes  │   │ - page addr  │ │
//! │  │   state    │   │ - compact  │   │ - func addr  │ │
//! │  │ - CAS dedup│   │   encoding │   │ - reg name   │ │
//! │  └───────────┘   └────────────┘   └──────────────┘ │
//! └─────────────────────────────────────────────────────┘
//! ```

pub mod snapshot;
pub mod delta_log;
pub mod delta_index;
pub mod encoding;
pub mod types;

pub use types::*;
