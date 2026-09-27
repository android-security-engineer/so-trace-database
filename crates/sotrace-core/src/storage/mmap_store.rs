//! Memory-mapped storage backend
//!
//! Provides zero-copy read and append-only write access to data files
//! using the operating system's mmap facility.

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Default region size for mmap allocations (256MB)
const DEFAULT_REGION_SIZE: u64 = 256 * 1024 * 1024;

/// A memory-mapped region
pub struct MmapRegion {
    /// Memory-mapped data
    mmap: memmap2::MmapMut,
    /// Underlying file
    file: std::fs::File,
    /// File path
    path: PathBuf,
    /// Start offset of this mapping
    offset: u64,
    /// Length of this mapping
    len: u64,
    /// Current write position within the region
    write_pos: u64,
}

impl MmapRegion {
    /// Create a new mmap region from a file
    pub fn open(path: &Path, offset: u64, len: u64) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        // Ensure file is large enough
        file.set_len(offset + len)?;

        let mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };

        Ok(Self {
            mmap,
            file,
            path: path.to_path_buf(),
            offset,
            len,
            write_pos: 0,
        })
    }

    /// Get a read-only slice of the mapped data
    pub fn as_slice(&self) -> &[u8] {
        &self.mmap
    }

    /// Get a mutable slice of the mapped data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.mmap
    }

    /// Write data at the current position (append-only)
    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        if self.write_pos + data.len() as u64 > self.len {
            anyhow::bail!("MmapRegion: write beyond region boundary");
        }
        let start = self.write_pos as usize;
        let end = start + data.len();
        self.mmap[start..end].copy_from_slice(data);
        self.write_pos += data.len() as u64;
        Ok(())
    }

    /// Get remaining capacity in this region
    pub fn remaining(&self) -> u64 {
        self.len - self.write_pos
    }

    /// Flush changes to disk (msync)
    pub fn sync(&self) -> Result<()> {
        self.mmap.flush()?;
        Ok(())
    }

    /// Get the current write position
    pub fn write_pos(&self) -> u64 {
        self.write_pos
    }
}

/// Memory-mapped storage manager
pub struct MmapStore {
    /// Base directory for data files
    base_dir: PathBuf,
    /// Size of each mmap region
    region_size: u64,
    /// Active write regions
    active_regions: Vec<MmapRegion>,
}

impl MmapStore {
    /// Open or create an mmap store
    pub fn open(base_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(base_dir)?;
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
            region_size: DEFAULT_REGION_SIZE,
            active_regions: Vec::new(),
        })
    }

    /// Allocate a new region for writing
    pub fn allocate_region(&mut self) -> Result<&mut MmapRegion> {
        let region_id = self.active_regions.len() as u64;
        let path = self.base_dir.join(format!("region_{:016x}.dat", region_id));
        let region = MmapRegion::open(&path, 0, self.region_size)?;
        self.active_regions.push(region);
        Ok(self.active_regions.last_mut().unwrap())
    }

    /// Get a read-only view of a region
    pub fn get_readonly(&self, region_id: u64) -> Result<&[u8]> {
        let region = self.active_regions
            .get(region_id as usize)
            .ok_or_else(|| anyhow::anyhow!("Region {} not found", region_id))?;
        Ok(region.as_slice())
    }

    /// Sync all active regions to disk
    pub fn sync_all(&self) -> Result<()> {
        for region in &self.active_regions {
            region.sync()?;
        }
        Ok(())
    }

    /// Set the region size for new allocations
    pub fn set_region_size(&mut self, size: u64) {
        self.region_size = size;
    }
}
