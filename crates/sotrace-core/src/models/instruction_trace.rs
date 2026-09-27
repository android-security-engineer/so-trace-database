//! Instruction trace record model

use serde::{Deserialize, Serialize};

/// A single instruction execution record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionTrace {
    /// Global monotonically increasing sequence number (primary key)
    pub seq: u64,
    /// Thread ID
    pub thread_id: u32,
    /// Instruction virtual address (relative to SO base)
    pub address: u64,
    /// Nanosecond timestamp (optional, depends on trace source)
    pub timestamp: Option<u64>,
    /// Whether this is a branch instruction
    pub is_branch: bool,
    /// Whether the branch was taken (only valid if is_branch)
    pub branch_taken: bool,
    /// Instruction machine code bytes (optional)
    pub opcode: Option<Vec<u8>>,
}

/// Batch of instruction traces for efficient writing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionBatch {
    /// SO file ID this batch belongs to
    pub so_file_id: u64,
    /// Instruction records
    pub records: Vec<InstructionTrace>,
}
