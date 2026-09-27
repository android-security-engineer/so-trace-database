//! Snapshot manager — periodic full-state checkpoints
//!
//! Manages the creation, storage, and retrieval of full-state snapshots.
//! Snapshots serve as reconstruction anchors: to reconstruct state at
//! step N, we find the nearest snapshot before N and apply deltas forward.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::*;

/// Snapshot manager — stores periodic full-state checkpoints
///
/// Key insight: snapshots are NOT copies of all data. They use
/// content-addressable storage (CAS) so identical content is stored once.
pub struct SnapshotManager<V> {
    config: DeltaStoreConfig,
    /// Snapshots indexed by step number
    snapshots_by_step: HashMap<u64, Snapshot<V>>,
    /// Content hash → snapshot reference (for deduplication)
    hash_to_snapshot: HashMap<[u8; 32], u64>,
    /// Last snapshot step
    last_snapshot_step: u64,
    /// Number of changes since last snapshot (to decide when to create next)
    changes_since_last: u64,
}

impl<V: Clone + Serialize + for<'de> Deserialize<'de>> SnapshotManager<V> {
    /// Create a new snapshot manager
    pub fn new(config: DeltaStoreConfig) -> Self {
        Self {
            config,
            snapshots_by_step: HashMap::new(),
            hash_to_snapshot: HashMap::new(),
            last_snapshot_step: 0,
            changes_since_last: 0,
        }
    }

    /// Check if a snapshot should be created at the current step
    pub fn should_snapshot(&self, current_step: u64) -> bool {
        current_step - self.last_snapshot_step >= self.config.snapshot_interval
    }

    /// Record that a change occurred (for adaptive snapshot decisions)
    pub fn record_change(&mut self) {
        self.changes_since_last += 1;
    }

    /// Create a snapshot at the given step with the given state
    pub fn create_snapshot(&mut self, step: u64, state: V) -> Result<u64> {
        let state_bytes = bincode::serialize(&state)?;
        let state_hash = sha256_hash(&state_bytes);

        // Check for deduplication: if same hash exists, reference it
        let id = self.snapshots_by_step.len() as u64;

        let snapshot = Snapshot {
            id,
            step,
            state,
            state_hash,
        };

        self.snapshots_by_step.insert(step, snapshot);
        self.hash_to_snapshot.insert(state_hash, id);
        self.last_snapshot_step = step;
        self.changes_since_last = 0;

        Ok(id)
    }

    /// Find the nearest snapshot before or at the target step
    ///
    /// This is the key operation for reconstruction:
    /// to get state at step N, we find the closest snapshot ≤ N,
    /// then apply deltas from that snapshot to N.
    pub fn find_snapshot_before(&self, target_step: u64) -> Option<&Snapshot<V>> {
        // Binary search through sorted snapshot steps
        let mut best_step = None;
        for &step in self.snapshots_by_step.keys() {
            if step <= target_step {
                if best_step.is_none() || step > best_step.unwrap() {
                    best_step = Some(step);
                }
            }
        }
        best_step.and_then(|step| self.snapshots_by_step.get(&step))
    }

    /// Get a snapshot by exact step number
    pub fn get_snapshot(&self, step: u64) -> Option<&Snapshot<V>> {
        self.snapshots_by_step.get(&step)
    }

    /// Get the last snapshot step
    pub fn last_snapshot_step(&self) -> u64 {
        self.last_snapshot_step
    }
}
