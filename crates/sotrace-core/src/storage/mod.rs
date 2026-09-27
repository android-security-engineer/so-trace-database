//! Storage engine — columnar storage with mmap backend

pub mod column_store;
pub mod compression;
pub mod mmap_store;
pub mod segment;
pub mod wal;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::models::so_file::SOFile;

/// Core storage engine
#[derive(Debug, Clone)]
pub struct StorageEngine {
    /// Base data directory
    base_dir: std::path::PathBuf,
}

impl StorageEngine {
    /// Open or create a storage engine at the given path
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        Ok(Self {
            base_dir: path.to_path_buf(),
        })
    }

    /// Write SO file metadata
    pub fn write_so_file(&mut self, so_file: &SOFile) -> Result<u64> {
        let mut index = self.load_so_index()?;
        let id = index.next_id;
        index.next_id = id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("SO file ID exhausted"))?;

        let mut stored = so_file.clone();
        stored.id = id;
        index.files.push(stored);
        self.save_so_index(&index)?;
        Ok(id)
    }

    /// Load one persisted SO metadata record.
    pub fn read_so_file(&self, id: u64) -> Result<Option<SOFile>> {
        Ok(self.load_so_index()?.files.into_iter().find(|file| file.id == id))
    }

    /// List persisted SO metadata records in ID order.
    pub fn list_so_files(&self) -> Result<Vec<SOFile>> {
        let mut files = self.load_so_index()?.files;
        files.sort_unstable_by_key(|file| file.id);
        Ok(files)
    }

    /// Close the storage engine gracefully
    pub fn close(self) -> Result<()> {
        Ok(())
    }

    fn so_index_path(&self) -> std::path::PathBuf {
        self.base_dir.join("so_files.json")
    }

    fn load_so_index(&self) -> Result<SoFileIndex> {
        let path = self.so_index_path();
        if !path.exists() {
            return Ok(SoFileIndex::default());
        }
        let bytes = std::fs::read(&path)?;
        let mut index: SoFileIndex = serde_json::from_slice(&bytes)?;
        let max_id = index.files.iter().map(|file| file.id).max().unwrap_or(0);
        if index.next_id <= max_id {
            index.next_id = max_id
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("SO file ID exhausted"))?;
        }
        if index.next_id == 0 {
            index.next_id = 1;
        }
        Ok(index)
    }

    fn save_so_index(&self, index: &SoFileIndex) -> Result<()> {
        let path = self.so_index_path();
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(index)?;
        std::fs::write(&temporary, bytes)?;
        std::fs::rename(&temporary, &path)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SoFileIndex {
    #[serde(default = "first_so_id")]
    next_id: u64,
    #[serde(default)]
    files: Vec<SOFile>,
}

fn first_so_id() -> u64 {
    1
}

impl Default for SoFileIndex {
    fn default() -> Self {
        Self {
            next_id: first_so_id(),
            files: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: u64) -> SOFile {
        SOFile {
            id,
            path: format!("lib{}.so", id),
            build_id: None,
            arch: crate::models::so_file::Architecture::AArch64,
            file_size: 10,
            md5: [id as u8; 16],
            sha256: [id as u8; 32],
            loaded_base_address: 0,
            created_at: id,
        }
    }

    #[test]
    fn assigns_ids_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = StorageEngine::open(dir.path()).unwrap();
        assert_eq!(storage.write_so_file(&sample(99)).unwrap(), 1);
        assert_eq!(storage.write_so_file(&sample(100)).unwrap(), 2);
        assert_eq!(storage.read_so_file(1).unwrap().unwrap().id, 1);
        drop(storage);

        let storage = StorageEngine::open(dir.path()).unwrap();
        let files = storage.list_so_files().unwrap();
        assert_eq!(files.iter().map(|file| file.id).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(files[0].path, "lib99.so");
    }

    #[test]
    fn missing_record_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let storage = StorageEngine::open(dir.path()).unwrap();
        assert!(storage.read_so_file(7).unwrap().is_none());
    }
}
