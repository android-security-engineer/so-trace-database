//! SO Trace Database main entry point

use anyhow::Result;
use std::path::Path;

use crate::models::so_file::SOFile;
use crate::query::QueryEngine;
use crate::storage::StorageEngine;

/// Main database handle
pub struct SoTraceDB {
    storage: StorageEngine,
    query: QueryEngine,
}

impl SoTraceDB {
    /// Open or create a database at the given path
    pub fn open(path: &Path) -> Result<Self> {
        let storage = StorageEngine::open(path)?;
        let query = QueryEngine::new(&storage);
        Ok(Self { storage, query })
    }

    /// Import an SO file and return its ID
    pub fn import_so_file(&mut self, path: &Path) -> Result<u64> {
        let so_file = SOFile::from_elf(path)?;
        self.storage.write_so_file(&so_file)
    }

    /// Read one imported SO file's metadata.
    pub fn read_so_file(&self, id: u64) -> Result<Option<SOFile>> {
        self.storage.read_so_file(id)
    }

    /// List imported SO files in ID order.
    pub fn list_so_files(&self) -> Result<Vec<SOFile>> {
        self.storage.list_so_files()
    }

    /// Query instruction traces by SO-relative address.
    pub fn query_instructions_by_address(
        &self,
        so_id: u64,
        address: u64,
    ) -> Result<Vec<crate::models::instruction_trace::InstructionTrace>> {
        self.query.query_instructions_by_address(so_id, address)
    }

    /// Rebuild a call stack at a trace sequence number.
    pub fn rebuild_call_stack(
        &self,
        so_id: u64,
        seq: u64,
    ) -> Result<Vec<crate::models::call_trace::StackFrame>> {
        self.query.rebuild_call_stack(so_id, seq)
    }

    /// Close the database gracefully
    pub fn close(self) -> Result<()> {
        self.storage.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_imports_and_reopens_a_real_elf() {
        let candidates = [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
        ];
        let Some(path) = candidates.iter().map(Path::new).find(|path| path.exists()) else {
            return;
        };

        let dir = tempfile::tempdir().unwrap();
        let id = {
            let mut db = SoTraceDB::open(dir.path()).unwrap();
            let id = db.import_so_file(path).unwrap();
            assert_eq!(id, 1);
            let imported = db.read_so_file(id).unwrap().unwrap();
            assert_eq!(imported.path, path.to_string_lossy());
            assert_eq!(db.list_so_files().unwrap().len(), 1);
            id
        };

        let db = SoTraceDB::open(dir.path()).unwrap();
        assert_eq!(db.read_so_file(id).unwrap().unwrap().id, id);
    }

    #[test]
    fn unsupported_trace_queries_return_errors_instead_of_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let db = SoTraceDB::open(dir.path()).unwrap();
        assert!(db.query_instructions_by_address(1, 0x1000).is_err());
        assert!(db.rebuild_call_stack(1, 1).is_err());
    }
}
