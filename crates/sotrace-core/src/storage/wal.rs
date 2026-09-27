//! Write-Ahead Log (WAL)
//!
//! Ensures durability of write operations. All writes are first
//! recorded in the WAL before being applied to in-memory structures.

use anyhow::{bail, Context, Result};
use std::io::{self, Read, Write};
use std::path::Path;

/// A frame marker makes an empty/new WAL distinguishable from arbitrary data.
/// The version is part of the marker so a future format can fail explicitly
/// instead of silently replaying incompatible bytes.
const MAGIC: [u8; 8] = *b"SOTWAL01";
const HEADER_LEN: usize = MAGIC.len() + 8 + 4;

/// WAL entries are operation records, not trace blobs.  Capping their size
/// prevents a damaged length field from causing an unbounded allocation during
/// recovery while still allowing a generously-sized serialized operation.
const MAX_ENTRY_SIZE: u64 = 256 * 1024 * 1024;

/// Write-Ahead Log
pub struct WAL {
    /// WAL file path
    path: std::path::PathBuf,
    /// WAL file handle
    file: Option<std::fs::File>,
}

impl WAL {
    /// Open or create a WAL file
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
        })
    }

    /// Append an entry to the WAL
    pub fn append(&mut self, entry: &[u8]) -> Result<()> {
        let length = u64::try_from(entry.len()).context("WAL entry length overflow")?;
        if length > MAX_ENTRY_SIZE {
            bail!("WAL entry is too large: {} bytes (maximum {})", length, MAX_ENTRY_SIZE);
        }

        let checksum = crc32fast::hash(entry);
        let mut header = [0u8; HEADER_LEN];
        header[..MAGIC.len()].copy_from_slice(&MAGIC);
        header[MAGIC.len()..MAGIC.len() + 8].copy_from_slice(&length.to_le_bytes());
        header[MAGIC.len() + 8..].copy_from_slice(&checksum.to_le_bytes());

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("WAL file is closed"))?;
        file.write_all(&header).context("failed to write WAL header")?;
        file.write_all(entry).context("failed to write WAL entry")?;
        Ok(())
    }

    /// Sync the WAL to disk
    pub fn sync(&self) -> Result<()> {
        if let Some(file) = &self.file {
            file.sync_all()?;
        }
        Ok(())
    }

    /// Replay the WAL to recover after a crash
    pub fn replay(&self) -> Result<Vec<Vec<u8>>> {
        let file = std::fs::File::open(&self.path)
            .with_context(|| format!("failed to open WAL for replay: {}", self.path.display()))?;
        let mut reader = io::BufReader::new(file);
        let mut entries = Vec::new();

        loop {
            let mut header = [0u8; HEADER_LEN];
            // A crash can leave a partial final frame.  It is safe to discard
            // that frame because its checksum was never fully committed; all
            // complete preceding frames remain replayable.
            if !read_frame_part(&mut reader, &mut header)? {
                break;
            }

            if header[..MAGIC.len()] != MAGIC {
                bail!("invalid WAL magic at frame {}", entries.len());
            }

            let mut length_bytes = [0u8; 8];
            length_bytes.copy_from_slice(&header[MAGIC.len()..MAGIC.len() + 8]);
            let length = u64::from_le_bytes(length_bytes);
            if length > MAX_ENTRY_SIZE {
                bail!(
                    "invalid WAL entry length {} at frame {} (maximum {})",
                    length,
                    entries.len(),
                    MAX_ENTRY_SIZE
                );
            }

            let mut checksum_bytes = [0u8; 4];
            checksum_bytes.copy_from_slice(&header[MAGIC.len() + 8..]);
            let expected_checksum = u32::from_le_bytes(checksum_bytes);
            let mut entry = vec![0u8; length as usize];
            if !read_frame_part(&mut reader, &mut entry)? {
                break;
            }

            let actual_checksum = crc32fast::hash(&entry);
            if actual_checksum != expected_checksum {
                bail!(
                    "WAL checksum mismatch at frame {}: expected {:08x}, got {:08x}",
                    entries.len(),
                    expected_checksum,
                    actual_checksum
                );
            }

            entries.push(entry);
        }

        Ok(entries)
    }

    /// Truncate the WAL (after successful checkpoint)
    pub fn truncate(&mut self) -> Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("WAL file is closed"))?;
        file.set_len(0).context("failed to truncate WAL")?;
        file.sync_all().context("failed to sync truncated WAL")?;
        Ok(())
    }
}

/// Read one fixed-size frame component.  Returns `false` only for EOF before
/// the component is complete; that is the crash-tolerant partial-tail case.
fn read_frame_part<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<bool> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) => return Ok(false),
            Ok(read) => offset += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use tempfile::tempdir;

    #[test]
    fn round_trip_multiple_entries_and_empty_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trace.wal");
        let mut wal = WAL::open(&path).unwrap();
        wal.append(b"first").unwrap();
        wal.append(&[]).unwrap();
        wal.append(&[0, 1, 2, 255]).unwrap();
        wal.sync().unwrap();

        assert_eq!(wal.replay().unwrap(), vec![b"first".to_vec(), vec![], vec![0, 1, 2, 255]]);
    }

    #[test]
    fn incomplete_final_frame_is_ignored_during_replay() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trace.wal");
        let mut wal = WAL::open(&path).unwrap();
        wal.append(b"complete").unwrap();
        wal.append(b"torn").unwrap();
        wal.sync().unwrap();
        drop(wal);

        let length = std::fs::metadata(&path).unwrap().len();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(length - 2).unwrap();

        let wal = WAL::open(&path).unwrap();
        assert_eq!(wal.replay().unwrap(), vec![b"complete".to_vec()]);
    }

    #[test]
    fn complete_frame_with_bad_checksum_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trace.wal");
        let mut wal = WAL::open(&path).unwrap();
        wal.append(b"payload").unwrap();
        wal.sync().unwrap();
        drop(wal);

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();

        let wal = WAL::open(&path).unwrap();
        let error = wal.replay().unwrap_err().to_string();
        assert!(error.contains("checksum mismatch"), "unexpected error: {error}");
    }

    #[test]
    fn truncate_removes_entries_and_wal_can_be_reused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trace.wal");
        let mut wal = WAL::open(&path).unwrap();
        wal.append(b"old").unwrap();
        wal.truncate().unwrap();
        assert!(wal.replay().unwrap().is_empty());
        wal.append(b"new").unwrap();
        assert_eq!(wal.replay().unwrap(), vec![b"new".to_vec()]);
    }

    #[test]
    fn invalid_frame_length_is_rejected_before_allocation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trace.wal");
        let mut bytes = Vec::from(MAGIC);
        bytes.extend_from_slice(&(MAX_ENTRY_SIZE + 1).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();

        let wal = WAL::open(&path).unwrap();
        let error = wal.replay().unwrap_err().to_string();
        assert!(error.contains("invalid WAL entry length"), "unexpected error: {error}");
    }
}
