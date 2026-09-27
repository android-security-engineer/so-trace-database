//! Delta encoder — encodes memory changes as compact delta records
//!
//! Implements the three-level delta encoding strategy:
//! 1. BYTE_LEVEL: for small changes (≤ 64 bytes) within a page
//! 2. PAGE_DELTA: for medium changes (bsdiff/VCDIFF binary diff)
//! 3. FULL_PAGE: for large changes or first-time page writes

use anyhow::Result;

use super::types::*;

/// Delta encoder for memory page changes
pub struct DeltaEncoder {
    /// Previous page contents cache (page_address → content)
    /// Used to compute deltas and determine encoding strategy
    prev_pages: std::collections::HashMap<u64, Vec<u8>>,
}

impl DeltaEncoder {
    /// Create a new delta encoder
    pub fn new() -> Self {
        Self {
            prev_pages: std::collections::HashMap::new(),
        }
    }

    /// Encode a memory write as a delta record
    ///
    /// # Arguments
    /// * `seq` - Instruction sequence number
    /// * `thread_id` - Thread ID
    /// * `address` - Write address (may not be page-aligned)
    /// * `data` - Written data bytes
    ///
    /// # Returns
    /// The encoded delta record, or an error
    pub fn encode_write(
        &mut self,
        seq: u64,
        thread_id: u32,
        address: u64,
        data: &[u8],
    ) -> Result<MemoryDelta> {
        let page_addr = page_align(address);
        let offset = page_offset(address);

        // Compute previous content hash
        let prev_hash = self.prev_pages
            .get(&page_addr)
            .map(|p| sha256_hash(p))
            .unwrap_or([0u8; 32]);

        // Determine the best encoding strategy
        let delta_type = self.choose_encoding(page_addr, offset, data);
        let delta_data = match delta_type {
            DeltaType::ByteLevel => self.encode_byte_level(offset, data),
            DeltaType::PageDelta => self.encode_page_delta(page_addr, offset, data)?,
            DeltaType::FullPage => self.encode_full_page(page_addr, offset, data),
        };

        // Update the previous page content cache
        self.update_page_cache(page_addr, offset, data);

        Ok(MemoryDelta {
            id: 0, // Assigned by storage engine
            seq,
            thread_id,
            page_address: page_addr,
            delta_type,
            delta_data,
            prev_content_hash: prev_hash,
        })
    }

    /// Choose the best delta encoding strategy for this write
    fn choose_encoding(&self, page_addr: u64, offset: usize, data: &[u8]) -> DeltaType {
        // If we have no previous content for this page, must use FULL_PAGE
        if !self.prev_pages.contains_key(&page_addr) {
            return DeltaType::FullPage;
        }

        // If the change is small enough, use BYTE_LEVEL
        if data.len() <= BYTE_LEVEL_MAX_CHANGES {
            return DeltaType::ByteLevel;
        }

        // For larger changes, estimate if PAGE_DELTA would be worthwhile
        // (MVP: always use FULL_PAGE for larger changes, PAGE_DELTA deferred)
        DeltaType::FullPage
    }

    /// Encode as byte-level changes
    fn encode_byte_level(&self, offset: usize, data: &[u8]) -> DeltaData {
        DeltaData::ByteLevel(vec![
            ByteChange {
                offset: offset as u16,
                size: data.len() as u8,
                value: data.to_vec(),
            }
        ])
    }

    /// Encode as page-level binary diff (bsdiff/VCDIFF)
    fn encode_page_delta(
        &self,
        _page_addr: u64,
        _offset: usize,
        _data: &[u8],
    ) -> Result<DeltaData> {
        // TODO: Implement bsdiff/VCDIFF encoding (Phase 2)
        // For MVP, this should not be reached (choose_encoding won't select it)
        anyhow::bail!("PAGE_DELTA encoding not yet implemented")
    }

    /// Encode as full page content
    fn encode_full_page(&self, page_addr: u64, offset: usize, data: &[u8]) -> DeltaData {
        let mut page = self.prev_pages
            .get(&page_addr)
            .cloned()
            .unwrap_or_else(|| vec![0u8; PAGE_SIZE]);

        // Apply the write to the page
        page[offset..offset + data.len()].copy_from_slice(data);

        DeltaData::FullPage(page)
    }

    /// Update the page content cache after a write
    fn update_page_cache(&mut self, page_addr: u64, offset: usize, data: &[u8]) {
        let page = self.prev_pages
            .entry(page_addr)
            .or_insert_with(|| vec![0u8; PAGE_SIZE]);

        if offset + data.len() <= PAGE_SIZE {
            page[offset..offset + data.len()].copy_from_slice(data);
        }
    }
}

impl Default for DeltaEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-256 hash of page content
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
