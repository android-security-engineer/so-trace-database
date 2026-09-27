//! Register delta record model

use serde::{Deserialize, Serialize};

/// A register value change record (delta encoding)
///
/// Only stores registers that have changed since the last recorded state.
/// The `change_mask` bitfield indicates which registers changed,
/// and `values` contains the new values in order of register index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDelta {
    /// Instruction sequence number when this change occurred
    pub seq: u64,
    /// Bitmask indicating which registers changed (1 bit per register)
    /// ARM64: bits 0-30 = x0-x30, bit 31 = SP, bit 32 = PC, bit 33 = NZCV
    pub change_mask: u64,
    /// New register values, in order of register index (only for set bits in mask)
    pub values: Vec<u64>,
}

/// Complete register state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterState {
    /// Sequence number
    pub seq: u64,
    /// General purpose registers (ARM64: x0-x30)
    pub gp_regs: [u64; 31],
    /// Stack pointer
    pub sp: u64,
    /// Program counter
    pub pc: u64,
    /// Condition flags (NZCV)
    pub nzcv: u32,
}
