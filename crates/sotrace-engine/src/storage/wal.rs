//! Write-Ahead Log (WAL).
//!
//! The engine and core expose the same framed WAL implementation. Keeping one
//! format avoids a subtle recovery mismatch when the higher-level engine uses
//! the low-level storage crate.

pub use sotrace_core::storage::wal::WAL;
