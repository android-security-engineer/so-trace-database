//! Segment manager — manages trace data segments

/// A segment of trace data
///
/// Each segment contains a fixed number of records (default: 1,000,000)
/// and stores all trace tables for that range.
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
