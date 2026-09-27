//! Segment manager — manages trace data segments
//!
//! Each segment contains a fixed number of records (default: 1,000,000)
//! and stores all trace tables for that range. Segments enable:
//! - Efficient range queries (only load relevant segments)
//! - Parallel processing (each segment is independent)
//! - Data lifecycle management (archive/delete old segments)

/// A segment of trace data
pub struct Segment {
    /// Segment ID
    pub id: u64,
    /// Start sequence number
    pub start_seq: u64,
    /// End sequence number
    pub end_seq: u64,
    /// Number of records in this segment
    pub record_count: u64,
}

/// Default number of records per segment
pub const DEFAULT_SEGMENT_SIZE: u64 = 1_000_000;
