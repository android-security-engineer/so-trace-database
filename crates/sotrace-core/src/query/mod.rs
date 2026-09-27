//! Query engine — handles all trace query operations

use crate::models::call_trace::StackFrame;
use crate::models::instruction_trace::InstructionTrace;
use crate::storage::StorageEngine;

/// Query engine
pub struct QueryEngine {
    _storage: StorageEngine,
}

impl QueryEngine {
    /// Create a new query engine
    pub fn new(storage: &StorageEngine) -> Self {
        Self {
            _storage: storage.clone(),
        }
    }

    /// Query instructions by address
    pub fn query_instructions_by_address(
        &self,
        _so_id: u64,
        _address: u64,
    ) -> anyhow::Result<Vec<InstructionTrace>> {
        anyhow::bail!(
            "instruction trace queries are unavailable until trace storage is connected"
        )
    }

    /// Rebuild call stack at a given sequence number
    pub fn rebuild_call_stack(
        &self,
        _so_id: u64,
        _seq: u64,
    ) -> anyhow::Result<Vec<StackFrame>> {
        anyhow::bail!(
            "call-stack queries are unavailable until trace storage is connected"
        )
    }
}
