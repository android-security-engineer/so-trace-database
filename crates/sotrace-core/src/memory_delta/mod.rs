//! Memory delta engine — incremental storage for program memory state
//!
//! This module implements the Checkpoint + Delta + Page-Granularity scheme
//! for efficiently storing memory state changes during program execution.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                Memory Delta Engine                    │
//! │                                                      │
//! │  ┌────────────────┐  ┌──────────────────────────┐  │
//! │  │ Checkpoint Mgr  │  │ Page Content Store (CAS) │  │
//! │  │                │  │                          │  │
//! │  │ - Periodic     │  │ - SHA-256 content hash   │  │
//! │  │   snapshots    │  │ - Deduplication          │  │
//! │  │ - Configurable │  │ - Reference counting     │  │
//! │  │   interval     │  │                          │  │
//! │  └────────────────┘  └──────────────────────────┘  │
//! │                                                      │
//! │  ┌────────────────┐  ┌──────────────────────────┐  │
//! │  │ Delta Encoder   │  │ Snapshot Rebuilder       │  │
//! │  │                │  │                          │  │
//! │  │ - BYTE_LEVEL   │  │ - Full snapshot rebuild  │  │
//! │  │ - PAGE_DELTA   │  │ - Single address query   │  │
//! │  │ - FULL_PAGE    │  │ - Memory history query   │  │
//! │  └────────────────┘  └──────────────────────────┘  │
//! └─────────────────────────────────────────────────────┘
//! ```

pub mod checkpoint;
pub mod delta_encoder;
pub mod page_store;
pub mod snapshot;
pub mod types;

pub use types::*;
