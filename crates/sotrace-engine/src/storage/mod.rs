//! Low-level storage — mmap, column store, compression, WAL, segments
//!
//! This module provides the physical storage layer used by delta_store
//! and trace_store. It handles:
//! - Memory-mapped file I/O (zero-copy reads)
//! - Columnar storage with compression
//! - Write-Ahead Log for durability
//! - Segment management for data partitioning

pub mod mmap_store;
pub mod column_store;
pub mod compression;
pub mod segment;
pub mod wal;

// Re-export from sotrace-core storage types (these will be migrated over time)
pub use mmap_store::{MmapStore, MmapRegion};
pub use column_store::{ColumnType, CompressionCodec, ColumnMeta};
pub use compression::{
    delta_encode_u64, delta_decode_u64, encode_varint, decode_varint,
    encode_varint_into, encode_signed_varint_into, pack_bits, unpack_bits,
};
pub use segment::Segment;
pub use wal::WAL;
