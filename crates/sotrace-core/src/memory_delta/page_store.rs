//! Page content store — content-addressable storage for memory page contents
//!
//! Implements deduplication of identical page contents using SHA-256 hashing.
//! Pages with identical content are stored only once and referenced by hash.

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

use super::types::*;

/// Content-addressable page content store
pub struct PageStore {
    /// Base directory for page content files
    base_dir: std::path::PathBuf,
    /// In-memory index: SHA-256 hash → storage reference
    hash_to_ref: HashMap<[u8; 32], u64>,
    /// Reference counting: storage ref → count
    ref_counts: HashMap<u64, u64>,
    /// Next storage reference ID
    next_ref: u64,
}

impl PageStore {
    /// Open or create a page store at the given directory
    pub fn open(base_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(base_dir)?;
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
            hash_to_ref: HashMap::new(),
            ref_counts: HashMap::new(),
            next_ref: 0,
        })
    }

    /// Store a page's content, returning a PageRef
    ///
    /// If the same content already exists (same SHA-256 hash), returns
    /// the existing reference and increments the reference count.
    pub fn store_page(&mut self, virtual_address: u64, content: &[u8]) -> Result<PageRef> {
        let content_hash = sha256_hash(content);

        // Check if we already have this content
        if let Some(&storage_ref) = self.hash_to_ref.get(&content_hash) {
            // Increment reference count
            *self.ref_counts.entry(storage_ref).or_insert(0) += 1;

            return Ok(PageRef {
                virtual_address,
                content_hash,
                storage_ref,
            });
        }

        // New content — store it
        let storage_ref = self.next_ref;
        self.next_ref += 1;

        // Write content to file
        let file_path = self.page_file_path(storage_ref);
        // TODO: Use mmap store for actual I/O
        std::fs::write(&file_path, content)?;

        // Update indices
        self.hash_to_ref.insert(content_hash, storage_ref);
        self.ref_counts.insert(storage_ref, 1);

        Ok(PageRef {
            virtual_address,
            content_hash,
            storage_ref,
        })
    }

    /// Retrieve a page's content by storage reference
    pub fn get_page(&self, storage_ref: u64) -> Result<Vec<u8>> {
        let file_path = self.page_file_path(storage_ref);
        let content = std::fs::read(&file_path)?;
        Ok(content)
    }

    /// Release a reference to a page. Returns true if the page was deleted.
    pub fn release_page(&mut self, storage_ref: u64) -> Result<bool> {
        if let Some(count) = self.ref_counts.get_mut(&storage_ref) {
            *count -= 1;
            if *count == 0 {
                self.ref_counts.remove(&storage_ref);
                // Also remove from hash index
                self.hash_to_ref.retain(|_, &mut v| v != storage_ref);
                // Delete file
                let file_path = self.page_file_path(storage_ref);
                if file_path.exists() {
                    std::fs::remove_file(&file_path)?;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Get the file path for a page content file
    fn page_file_path(&self, storage_ref: u64) -> std::path::PathBuf {
        self.base_dir.join(format!("page_{:016x}.bin", storage_ref))
    }
}

/// Compute SHA-256 hash
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
