//! Memory delta types and constants

use serde::{Deserialize, Serialize};

/// Memory page size (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Default checkpoint interval (number of instructions)
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 100_000;

/// Maximum byte-level changes per page before upgrading to FULL_PAGE
pub const BYTE_LEVEL_MAX_CHANGES: usize = 64;

/// Delta encoding type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaType {
    /// Full page content (4KB)
    /// Used for first write of a page or when delta exceeds 50% of page size
    FullPage,
    /// Binary diff of page content (bsdiff/VCDIFF format)
    /// Used when the same page is modified multiple times and delta < 50% of page
    PageDelta,
    /// Byte-level changes within a page
    /// Used when only a few bytes change (≤ 64 bytes)
    ByteLevel,
}

/// A single byte-level change within a page
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteChange {
    /// Offset within the page (0..4095)
    pub offset: u16,
    /// Size of the change in bytes
    pub size: u8,
    /// New value bytes
    pub value: Vec<u8>,
}

/// A memory delta record — records a change to a single memory page
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDelta {
    /// Unique ID (primary key)
    pub id: u64,
    /// Instruction sequence number when this change occurred
    pub seq: u64,
    /// Thread ID
    pub thread_id: u32,
    /// Page-aligned virtual address of the changed page
    pub page_address: u64,
    /// Delta encoding type
    pub delta_type: DeltaType,
    /// Delta data (format depends on delta_type)
    pub delta_data: DeltaData,
    /// SHA-256 hash of page content BEFORE this change (for verification and rollback)
    pub prev_content_hash: [u8; 32],
}

/// Delta data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeltaData {
    /// Full 4KB page content
    FullPage(Vec<u8>),
    /// Binary diff (bsdiff/VCDIFF format)
    PageDelta(Vec<u8>),
    /// Byte-level changes
    ByteLevel(Vec<ByteChange>),
}

/// A memory checkpoint — full snapshot at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCheckpoint {
    /// Unique ID (primary key)
    pub id: u64,
    /// Instruction sequence number at checkpoint time
    pub seq: u64,
    /// Number of mapped pages in this checkpoint
    pub page_count: u32,
    /// Page references (virtual address → content hash + storage ref)
    pub pages: Vec<PageRef>,
}

/// Reference to a page's content in the content-addressable store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRef {
    /// Page-aligned virtual address
    pub virtual_address: u64,
    /// SHA-256 hash of page content (used for deduplication)
    pub content_hash: [u8; 32],
    /// Storage reference ID (offset into the page content store)
    pub storage_ref: u64,
}

/// Align an address down to page boundary
#[inline]
pub fn page_align(addr: u64) -> u64 {
    addr & !(PAGE_SIZE as u64 - 1)
}

/// Calculate page offset within a page
#[inline]
pub fn page_offset(addr: u64) -> usize {
    (addr & (PAGE_SIZE as u64 - 1)) as usize
}

/// Check if an address is page-aligned
#[inline]
pub fn is_page_aligned(addr: u64) -> bool {
    (addr & (PAGE_SIZE as u64 - 1)) == 0
}
