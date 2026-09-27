//! SO Trace Database — Core Engine
//!
//! This crate contains the core engine components:
//! - `delta_store` — Generic incremental (delta) storage engine, the foundation of all storage
//! - `trace_store` — Trace-specific stores (instructions, calls, registers, memory, JNI)
//! - `timeline` — Timeline management, the core abstraction for time-ordered trace data
//! - `storage` — Low-level storage: mmap, column store, compression, WAL, segments
//! - `query` — Query engine with delta-accelerated indexes
//! - `engine` — TraceEngine: unified engine coordinating all stores and Timeline
//! - `analyzer` — Thread analyzer: race condition, deadlock, contention analysis

pub mod delta_store;
pub mod trace_store;
pub mod timeline;
pub mod storage;
pub mod query;
pub mod elf;
pub mod engine;
pub mod analyzer;
pub mod persistence;

pub use timeline::Timeline;
pub use engine::{IngestStatus, TraceEngine, TraceIngestor, WriteMode};
pub use analyzer::ThreadAnalyzer;
pub use persistence::trace_codec;
