//! SO segment model

use serde::{Deserialize, Serialize};

/// ELF segment type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentType {
    Null,
    Load,
    Dynamic,
    Interpreter,
    Note,
    Shlib,
    Phdr,
    Other(u32),
}

/// A segment within an SO file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SOSegment {
    /// Unique ID (primary key)
    pub id: u64,
    /// Foreign key → SOFile
    pub so_file_id: u64,
    /// Segment name (e.g., ".text", ".data", ".rodata")
    pub name: String,
    /// Segment type
    pub seg_type: SegmentType,
    /// File offset
    pub offset: u64,
    /// Virtual address
    pub vaddr: u64,
    /// Segment size
    pub size: u64,
    /// Segment flags (readable/writable/executable)
    pub flags: u32,
}
