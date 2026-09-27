//! Call trace record model

use serde::{Deserialize, Serialize};

/// Call event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallEventType {
    /// Function call
    Call,
    /// Function return
    Return,
    /// Tail call (optimized call+return)
    TailCall,
}

/// A function call/return event record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallTrace {
    /// Unique ID (primary key)
    pub id: u64,
    /// Thread ID
    pub thread_id: u32,
    /// Event type (CALL / RETURN / TAIL_CALL)
    pub event_type: CallEventType,
    /// Caller instruction address
    pub caller_address: u64,
    /// Callee function entry address
    pub callee_address: u64,
    /// Callee function ID (foreign key → SOFunction, optional)
    pub callee_func_id: Option<u32>,
    /// Sequence number when this event occurred
    pub seq: u64,
    /// Call stack depth at this event
    pub depth: u16,
    /// Sequence number when the corresponding RETURN occurs (filled later)
    pub return_seq: Option<u64>,
}

/// Reconstructed stack frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    /// Function ID
    pub func_id: Option<u32>,
    /// Function name (if known)
    pub func_name: Option<String>,
    /// Function entry address
    pub entry_address: u64,
    /// Call site address (where this function was called from)
    pub call_site: u64,
    /// Call sequence number
    pub call_seq: u64,
    /// Stack depth
    pub depth: u16,
}
