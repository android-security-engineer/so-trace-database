impl TraceRepository {

    /// Create an empty SOTC blob and index entry so later [`Self::append_events`]
    /// calls are append-only. `metadata.trace_id == 0` assigns a new id.
    pub fn create_sotc(&self, mut metadata: TraceStreamMetadata) -> Result<u64> {
        let mut idx = self.load_index()?;
        let id = if metadata.trace_id == 0 {
            let id = idx.next_id;
            idx.next_id = id
                .checked_add(1)
                .ok_or_else(|| anyhow!("trace ID exhausted"))?;
            metadata.trace_id = id;
            id
        } else {
            if metadata.trace_id >= idx.next_id {
                idx.next_id = metadata.trace_id
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("trace ID exhausted"))?;
            }
            metadata.trace_id
        };
        let header = trace_codec::SotcHeader {
            trace_id: id,
            so_file_id: metadata.so_file_id,
            source: metadata.source.clone(),
            base_addr: metadata.base_addr,
            created_at: metadata.created_at,
        };
        let blob_path = self.blob_path(id);
        let mut file = File::create(&blob_path)
            .with_context(|| format!("failed to create SOTC blob: {}", blob_path.display()))?;
        trace_codec::write_sotc_header(&mut file, &header)?;
        file.flush()?;
        let summary = TraceSummary {
            trace_id: id,
            so_file_id: metadata.so_file_id,
            source: metadata.source,
            base_addr: metadata.base_addr,
            event_count: 0,
            events_sorted: true,
            created_at: metadata.created_at,
        };
        if let Some(existing) = idx.summaries.iter_mut().find(|s| s.trace_id == id) {
            *existing = summary;
        } else {
            idx.summaries.push(summary);
        }
        self.save_index(&idx)?;
        Ok(id)
    }

    /// List all persisted traces (summaries only).

    /// List all persisted traces (summaries only).
    pub fn list(&self) -> Result<Vec<TraceSummary>> {
        Ok(self.load_index()?.summaries)
    }

    /// Get the summary for a trace id.

    /// Get the summary for a trace id.
    pub fn summary(&self, id: u64) -> Result<Option<TraceSummary>> {
        Ok(self.load_index()?.summaries.into_iter().find(|s| s.trace_id == id))
    }

    /// Delete a trace by id. Returns true if it existed.

    /// Delete a trace by id. Returns true if it existed.
    pub fn delete(&self, id: u64) -> Result<bool> {
        let mut idx = self.load_index()?;
        let before = idx.summaries.len();
        idx.summaries.retain(|s| s.trace_id != id);
        if idx.summaries.len() == before {
            return Ok(false);
        }
        let blob = self.blob_path(id);
        if blob.exists() {
            std::fs::remove_file(&blob)
                .with_context(|| format!("failed to remove trace blob: {}", blob.display()))?;
        }
        // Also clean up any legacy uncompressed blob.
        let legacy = self.legacy_blob_path(id);
        if legacy.exists() {
            let _ = std::fs::remove_file(&legacy);
        }
        self.save_index(&idx)?;
        Ok(true)
    }
}
