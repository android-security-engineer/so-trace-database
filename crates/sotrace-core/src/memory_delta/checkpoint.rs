//! Checkpoint manager — periodic full memory snapshots
//!
//! Manages the creation and storage of memory checkpoints.
//! A checkpoint captures the complete memory state at a given instruction
//! sequence number by recording references to all mapped pages.

use anyhow::Result;

use super::types::*;

/// Configuration for checkpoint behavior
#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    /// Number of instructions between checkpoints
    pub interval: u64,
    /// Whether to enable adaptive intervals based on dirty page rate
    pub adaptive: bool,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_CHECKPOINT_INTERVAL,
            adaptive: false,
        }
    }
}

/// Checkpoint manager
pub struct CheckpointManager {
    config: CheckpointConfig,
    /// Last checkpoint sequence number
    last_checkpoint_seq: u64,
    /// Number of dirty pages since last checkpoint
    dirty_page_count: u64,
}

impl CheckpointManager {
    /// Create a new checkpoint manager with the given configuration
    pub fn new(config: CheckpointConfig) -> Self {
        Self {
            config,
            last_checkpoint_seq: 0,
            dirty_page_count: 0,
        }
    }

    /// Check if a checkpoint should be created at the given sequence number
    pub fn should_checkpoint(&self, current_seq: u64) -> bool {
        current_seq - self.last_checkpoint_seq >= self.config.interval
    }

    /// Record that pages have been dirtied since the last checkpoint
    pub fn record_dirty_pages(&mut self, count: u64) {
        self.dirty_page_count += count;
    }

    /// Mark that a checkpoint has been created at the given sequence number
    pub fn checkpoint_created(&mut self, seq: u64) {
        self.last_checkpoint_seq = seq;
        self.dirty_page_count = 0;
    }

    /// Get the sequence number of the last checkpoint
    pub fn last_checkpoint_seq(&self) -> u64 {
        self.last_checkpoint_seq
    }

    /// Find the nearest checkpoint before or at the given sequence number
    ///
    /// This queries the storage to find the checkpoint that allows
    /// reconstructing memory state at `target_seq`.
    pub fn find_checkpoint_before(
        &self,
        _target_seq: u64,
    ) -> Result<Option<MemoryCheckpoint>> {
        // TODO: Implement checkpoint lookup from storage
        todo!("Implement checkpoint lookup from storage engine")
    }
}
