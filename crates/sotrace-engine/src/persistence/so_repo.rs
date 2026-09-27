// SO metadata repository. Included in the persistence module.
impl SoRepository {
    /// Open a repository rooted at `data_dir`, creating the `so/` subdirectory
    /// if needed. The data directory itself is not created here.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let root = data_dir.as_ref().join("so");
        std::fs::create_dir_all(&root)
            .with_context(|| format!("failed to create SO dir: {}", root.display()))?;
        Ok(Self { root })
    }

    fn bincode_path(&self, id: u64) -> PathBuf {
        self.root.join(format!("{}.bincode", id))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    /// Load the index, or return an empty one if the file doesn't exist yet.
    fn load_index(&self) -> Result<SoIndex> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(SoIndex::default());
        }
        let raw = std::fs::read(&path)
            .with_context(|| format!("failed to read SO index: {}", path.display()))?;
        let idx: SoIndex = serde_json::from_slice(&raw)
            .with_context(|| format!("failed to parse SO index: {}", path.display()))?;
        // Repair legacy indices written before 0 became a reserved sentinel:
        // bump a too-low counter past every existing id so future allocations
        // never collide with 0 or any in-use id.
        let max_id = idx.summaries.iter().map(|s| s.id).max().unwrap_or(0);
        let mut idx = idx;
        if idx.next_id <= max_id {
            idx.next_id = max_id + 1;
        }
        if idx.next_id < 1 {
            idx.next_id = 1;
        }
        Ok(idx)
    }

    /// Persist the index atomically (write to temp, rename).
    fn save_index(&self, idx: &SoIndex) -> Result<()> {
        let path = self.index_path();
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(idx).context("failed to serialize SO index")?;
        std::fs::write(&tmp, &data)
            .with_context(|| format!("failed to write SO index temp: {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("failed to rename SO index: {}", path.display()))?;
        Ok(())
    }

    /// Save a parsed SO file, assigning it a new ID.
    ///
    /// If a SO with the same SHA-256 already exists, it is returned unchanged
    /// (dedup-by-hash) — the bytes are not re-written. Returns a
    /// [`SaveOutcome`] whose `id` is the assigned (or existing) SO ID and whose
    /// `deduped` flag is the authoritative dedup signal straight from the
    /// index lookup.
    pub fn save(&self, parsed: &ParsedSoFile) -> Result<SaveOutcome> {
        let sha256_hex = to_hex(&parsed.so_file.sha256);
        let mut idx = self.load_index()?;

        // Dedup: same content → reuse existing id, no rewrite.
        if let Some(existing) = idx.find_by_sha256(&sha256_hex) {
            return Ok(SaveOutcome { id: existing.id, deduped: true });
        }

        let id = idx.next_id;
        idx.next_id += 1;

        // Write the bincode blob first; if it fails we haven't touched the index.
        let blob_path = self.bincode_path(id);
        let blob = bincode::serialize(parsed)
            .context("failed to serialize ParsedSoFile to bincode")?;
        std::fs::write(&blob_path, &blob)
            .with_context(|| format!("failed to write SO blob: {}", blob_path.display()))?;

        let summary = SoSummary::from_parsed(id, parsed, &sha256_hex);
        idx.summaries.push(summary);
        self.save_index(&idx)?;

        Ok(SaveOutcome { id, deduped: false })
    }

    /// Load a parsed SO file by ID.
    pub fn load(&self, id: u64) -> Result<ParsedSoFile> {
        let path = self.bincode_path(id);
        let blob = std::fs::read(&path)
            .with_context(|| format!("failed to read SO blob: {}", path.display()))?;
        let parsed: ParsedSoFile = bincode::deserialize(&blob)
            .with_context(|| format!("failed to deserialize SO blob: {}", path.display()))?;
        Ok(parsed)
    }

    /// Look up a SO by SHA-256 hash (lowercase hex), loading it if found.
    pub fn find_by_sha256(&self, sha256_hex: &str) -> Result<Option<(u64, ParsedSoFile)>> {
        let idx = self.load_index()?;
        match idx.find_by_sha256(sha256_hex) {
            Some(s) => {
                let parsed = self.load(s.id)?;
                Ok(Some((s.id, parsed)))
            }
            None => Ok(None),
        }
    }

    /// List all imported SOs (summaries only, no blob reads).
    pub fn list(&self) -> Result<Vec<SoSummary>> {
        Ok(self.load_index()?.summaries)
    }

    /// Get the summary for a specific SO ID.
    pub fn summary(&self, id: u64) -> Result<Option<SoSummary>> {
        Ok(self.load_index()?.summaries.into_iter().find(|s| s.id == id))
    }

    /// Delete a SO by ID (blob + index entry). Returns true if it existed.
    pub fn delete(&self, id: u64) -> Result<bool> {
        let mut idx = self.load_index()?;
        let before = idx.summaries.len();
        idx.summaries.retain(|s| s.id != id);
        if idx.summaries.len() == before {
            return Ok(false);
        }
        let blob = self.bincode_path(id);
        if blob.exists() {
            std::fs::remove_file(&blob)
                .with_context(|| format!("failed to remove SO blob: {}", blob.display()))?;
        }
        self.save_index(&idx)?;
        Ok(true)
    }
}
