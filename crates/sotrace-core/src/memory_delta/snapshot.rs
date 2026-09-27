//! Snapshot rebuilder — reconstruct memory state at any point in time
//!
//! Implements the algorithm for rebuilding memory snapshots from
//! checkpoints and deltas.

use anyhow::Result;
use std::collections::HashMap;

use super::checkpoint::CheckpointManager;
use super::page_store::PageStore;
use super::types::*;

/// Memory snapshot at a point in time
pub struct MemorySnapshot {
    /// Instruction sequence number of this snapshot
    pub seq: u64,
    /// Page-aligned virtual address → page content
    pub pages: HashMap<u64, Vec<u8>>,
}

/// Snapshot rebuilder
pub struct SnapshotRebuilder<'a> {
    checkpoint_mgr: &'a CheckpointManager,
    page_store: &'a PageStore,
}

impl<'a> SnapshotRebuilder<'a> {
    /// Create a new snapshot rebuilder
    pub fn new(checkpoint_mgr: &'a CheckpointManager, page_store: &'a PageStore) -> Self {
        Self {
            checkpoint_mgr,
            page_store,
        }
    }

    /// Rebuild the complete memory state at the given sequence number
    ///
    /// Algorithm:
    /// 1. Find the nearest checkpoint before `target_seq`
    /// 2. Load all pages from the checkpoint
    /// 3. Apply all deltas from checkpoint to target_seq in order
    pub fn rebuild_snapshot(&self, target_seq: u64) -> Result<MemorySnapshot> {
        // Find nearest checkpoint
        let checkpoint = self.checkpoint_mgr.find_checkpoint_before(target_seq)?;

        let mut pages = HashMap::new();

        if let Some(cp) = &checkpoint {
            // Load checkpoint pages
            for page_ref in &cp.pages {
                let content = self.page_store.get_page(page_ref.storage_ref)?;
                pages.insert(page_ref.virtual_address, content);
            }

            // Apply deltas from checkpoint to target
            self.apply_deltas(&mut pages, cp.seq, target_seq)?;
        }

        Ok(MemorySnapshot {
            seq: target_seq,
            pages,
        })
    }

    /// Query a single memory address value at the given sequence number
    ///
    /// This is more efficient than rebuilding the entire snapshot
    /// because it only processes deltas for the relevant page.
    pub fn query_address(&self, address: u64, target_seq: u64) -> Result<Option<Vec<u8>>> {
        let page_addr = page_align(address);
        let offset = page_offset(address);

        // Find nearest checkpoint
        let checkpoint = self.checkpoint_mgr.find_checkpoint_before(target_seq)?;

        // Get base page content from checkpoint
        let mut page_content = None;

        if let Some(cp) = &checkpoint {
            // Find the page in the checkpoint
            for page_ref in &cp.pages {
                if page_ref.virtual_address == page_addr {
                    page_content = Some(self.page_store.get_page(page_ref.storage_ref)?);
                    break;
                }
            }

            // Apply only deltas for this specific page
            if let Some(content) = &mut page_content {
                self.apply_deltas_for_page(content, page_addr, cp.seq, target_seq)?;
            }
        }

        Ok(page_content.map(|content| {
            // Extract the specific address value (determine size from context)
            // For now, return the byte at the offset
            content[offset..].to_vec()
        }))
    }

    /// Apply all deltas in a range to the page map
    fn apply_deltas(
        &self,
        pages: &mut HashMap<u64, Vec<u8>>,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<()> {
        // TODO: Query delta records from storage and apply them
        // let deltas = storage.query_deltas_range(start_seq, end_seq)?;
        // for delta in deltas {
        //     self.apply_delta(pages, &delta)?;
        // }
        Ok(())
    }

    /// Apply deltas for a specific page only
    fn apply_deltas_for_page(
        &self,
        page: &mut Vec<u8>,
        page_addr: u64,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<()> {
        // TODO: Query delta records for this page from storage
        // let deltas = storage.query_deltas_for_page(page_addr, start_seq, end_seq)?;
        // for delta in deltas {
        //     self.apply_delta_to_page(page, &delta)?;
        // }
        Ok(())
    }

    /// Apply a single delta to the page map
    fn apply_delta(
        &self,
        pages: &mut HashMap<u64, Vec<u8>>,
        delta: &MemoryDelta,
    ) -> Result<()> {
        let page = pages
            .entry(delta.page_address)
            .or_insert_with(|| vec![0u8; PAGE_SIZE]);

        match &delta.delta_data {
            DeltaData::FullPage(content) => {
                page.copy_from_slice(content);
            }
            DeltaData::ByteLevel(changes) => {
                for change in changes {
                    let offset = change.offset as usize;
                    if offset + change.size as usize <= PAGE_SIZE {
                        page[offset..offset + change.size as usize]
                            .copy_from_slice(&change.value);
                    }
                }
            }
            DeltaData::PageDelta(_diff) => {
                // TODO: Apply bsdiff/VCDIFF patch
                anyhow::bail!("PAGE_DELTA not yet implemented");
            }
        }

        Ok(())
    }
}
