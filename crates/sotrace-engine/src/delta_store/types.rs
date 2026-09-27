//! Delta store types and core abstractions

use serde::{Deserialize, Serialize};
use std::hash::Hash;

/// Page size for memory-based delta stores (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Default snapshot interval (every N steps)
pub const DEFAULT_SNAPSHOT_INTERVAL: u64 = 100_000;

/// Maximum byte-level changes before upgrading to full snapshot
pub const BYTE_LEVEL_THRESHOLD: usize = 64;

/// Delta encoding type — applicable to ALL stored entities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaEncoding {
    /// Full value stored (used for snapshots and first occurrence)
    FullValue,
    /// Only the changed bytes/fields stored
    ByteLevel,
    /// Binary diff between current and previous value (bsdiff/VCDIFF)
    BinaryDiff,
    /// Numeric delta (current - previous), for monotonically increasing values
    NumericDelta,
    /// Dictionary reference (value matches a previously stored value)
    DictionaryRef,
}

/// A single delta record — the universal unit of storage
///
/// Every stored entity (register, memory page, instruction, thread state)
/// is represented as a DeltaRecord. This is the atom of our storage system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaRecord<V> {
    /// Step number (sequence number in the timeline)
    pub step: u64,
    /// Which encoding was used for this delta
    pub encoding: DeltaEncoding,
    /// The actual delta payload
    pub payload: DeltaPayload<V>,
    /// Hash of the previous value (for verification and rollback)
    pub prev_hash: Option<[u8; 32]>,
}

/// Delta payload — what actually gets stored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeltaPayload<V> {
    /// Full value (snapshot or first occurrence)
    FullValue(V),
    /// Byte-level changes within a value
    /// For memory: [(offset, size, new_bytes), ...]
    /// For registers: bitmask + changed values
    ByteChanges(Vec<ByteChange>),
    /// Binary diff (bsdiff/VCDIFF format)
    BinaryDiff(Vec<u8>),
    /// Numeric delta: value = previous + delta
    NumericDelta(i64),
    /// Reference to a previously stored value by hash
    DictionaryRef([u8; 32]),
}

/// A single byte-level change within a value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteChange {
    /// Offset within the value (0-based)
    pub offset: u16,
    /// Size of the change in bytes
    pub size: u8,
    /// New value bytes
    pub new_bytes: Vec<u8>,
}

/// Snapshot of full state at a checkpoint step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot<V> {
    /// Snapshot ID
    pub id: u64,
    /// Step number at which this snapshot was taken
    pub step: u64,
    /// Full state at this step
    pub state: V,
    /// Hash of the state (for deduplication and verification)
    pub state_hash: [u8; 32],
}

/// Query result with reconstruction info
#[derive(Debug, Clone)]
pub struct DeltaQueryResult<V> {
    /// The reconstructed value
    pub value: V,
    /// How many deltas were applied to reconstruct (for performance tracking)
    pub deltas_applied: u64,
    /// Which snapshot was used as the base
    pub base_snapshot_step: u64,
    /// Time taken to reconstruct (microseconds)
    pub reconstruction_time_us: u64,
}

/// Configuration for a delta store
#[derive(Debug, Clone)]
pub struct DeltaStoreConfig {
    /// Interval between full snapshots (in steps)
    pub snapshot_interval: u64,
    /// Maximum number of byte-level changes before upgrading to FullValue
    pub byte_level_threshold: usize,
    /// Whether to enable content-addressable deduplication
    pub enable_dedup: bool,
    /// Whether to enable delta indexes for fast queries
    pub enable_indexes: bool,
    /// Compression algorithm for delta payloads
    pub compression: CompressionConfig,
}

impl Default for DeltaStoreConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
            byte_level_threshold: BYTE_LEVEL_THRESHOLD,
            enable_dedup: true,
            enable_indexes: true,
            compression: CompressionConfig::Zstd,
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionConfig {
    None,
    Lz4,
    Zstd,
}

/// Align address down to page boundary
#[inline]
pub fn page_align(addr: u64) -> u64 {
    addr & !(PAGE_SIZE as u64 - 1)
}

/// Calculate offset within a page
#[inline]
pub fn page_offset(addr: u64) -> usize {
    (addr & (PAGE_SIZE as u64 - 1)) as usize
}

/// Compute SHA-256 hash
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
