fn sync_path(path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("failed to open for sync: {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

/// Flush `tmp` and the published file, then flush the parent directory,
/// before the caller may report success.
fn publish_durable(tmp: &Path, final_path: &Path) -> Result<()> {
    sync_path(tmp)?;
    std::fs::rename(tmp, final_path)
        .with_context(|| format!("failed to publish {}", final_path.display()))?;
    sync_path(final_path)?;
    if let Some(parent) = final_path.parent() {
        sync_path(parent)?;
    }
    Ok(())
}

impl TraceRepository {
    /// Open a trace repository under `<data_dir>/trace/`, creating the dir.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let root = data_dir.as_ref().join("trace");
        std::fs::create_dir_all(&root)
            .with_context(|| format!("failed to create trace dir: {}", root.display()))?;
        Ok(Self { root })
    }

    /// Compressed blob path for a trace id (the canonical write location).

    /// Compressed blob path for a trace id (the canonical write location).
    fn blob_path(&self, id: u64) -> PathBuf {
        self.root.join(format!("{}.bincode.zst", id))
    }

    /// Legacy uncompressed blob path (only used for backward-compatible reads).

    /// Legacy uncompressed blob path (only used for backward-compatible reads).
    fn legacy_blob_path(&self, id: u64) -> PathBuf {
        self.root.join(format!("{}.bincode", id))
    }


    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }


    fn load_index(&self) -> Result<TraceIndex> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(TraceIndex::default());
        }
        let raw = std::fs::read(&path)
            .with_context(|| format!("failed to read trace index: {}", path.display()))?;
        let mut idx: TraceIndex = serde_json::from_slice(&raw)
            .with_context(|| format!("failed to parse trace index: {}", path.display()))?;
        // Repair indexes written before trace id 0 was reserved as the
        // auto-assignment sentinel. Also repair a stale counter that could
        // otherwise collide with an existing summary.
        let max_id = idx.summaries.iter().map(|summary| summary.trace_id).max().unwrap_or(0);
        if idx.next_id <= max_id {
            idx.next_id = max_id
                .checked_add(1)
                .ok_or_else(|| anyhow!("trace ID exhausted"))?;
        }
        if idx.next_id == 0 {
            idx.next_id = 1;
        }
        Ok(idx)
    }


    fn save_index(&self, idx: &TraceIndex) -> Result<()> {
        let path = self.index_path();
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(idx).context("failed to serialize trace index")?;
        std::fs::write(&tmp, &data)
            .with_context(|| format!("failed to write trace index temp: {}", tmp.display()))?;
        publish_durable(&tmp, &path)?;
        Ok(())
    }

    /// Save a trace. If `trace.trace_id` is 0, a new id is assigned; otherwise
    /// the given id is used (overwriting any existing blob with that id).

    /// Save a trace. If `trace.trace_id` is 0, a new id is assigned; otherwise
    /// the given id is used (overwriting any existing blob with that id).
    pub fn save(&self, mut trace: PersistedTrace) -> Result<u64> {
        let mut idx = self.load_index()?;
        let id = if trace.trace_id == 0 {
            let id = idx.next_id;
            idx.next_id = id
                .checked_add(1)
                .ok_or_else(|| anyhow!("trace ID exhausted"))?;
            trace.trace_id = id;
            id
        } else {
            // Ensure next_id stays ahead of any explicit id.
            if trace.trace_id >= idx.next_id {
                idx.next_id = trace.trace_id
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("trace ID exhausted"))?;
            }
            trace.trace_id
        };

        // New blobs are always chronological, allowing replay_sorted to feed
        // them directly without first materializing and sorting another event
        // vector. `sort_by_key` is stable, preserving source order for ties.
        trace.events.sort_by_key(|event| event.step());

        let header = trace_codec::SotcHeader {
            trace_id: id,
            so_file_id: trace.so_file_id,
            source: trace.source.clone(),
            base_addr: trace.base_addr,
            created_at: trace.created_at,
        };
        let blob_path = self.blob_path(id);
        let tmp = blob_path.with_extension("bincode.zst.tmp");
        let write_result = (|| -> Result<()> {
            let bytes = trace_codec::encode_sotc(
                &header,
                &trace.events,
                trace_codec::DEFAULT_CHUNK_EVENTS,
            )?;
            std::fs::write(&tmp, &bytes)
                .with_context(|| format!("failed to write trace blob temp: {}", tmp.display()))?;
            publish_durable(&tmp, &blob_path)?;
            Ok(())
        })();
        if let Err(err) = write_result {
            // Best-effort cleanup only affects our exact temporary path; an
            // existing canonical blob (for an overwrite) remains intact.
            let _ = std::fs::remove_file(&tmp);
            return Err(err);
        }
        // Drop any legacy uncompressed blob so loads don't see a stale copy.
        let legacy = self.legacy_blob_path(id);
        if legacy.exists() {
            let _ = std::fs::remove_file(&legacy);
        }

        // Upsert the summary.
        let summary = TraceSummary {
            trace_id: id,
            so_file_id: trace.so_file_id,
            source: trace.source.clone(),
            base_addr: trace.base_addr,
            event_count: trace.events.len(),
            events_sorted: true,
            created_at: trace.created_at,
        };
        if let Some(existing) = idx.summaries.iter_mut().find(|s| s.trace_id == id) {
            *existing = summary;
        } else {
            idx.summaries.push(summary);
        }
        self.save_index(&idx)?;
        Ok(id)
    }

    /// Save a trace while the producer emits events one at a time.
    ///
    /// `event_count` is required because bincode prefixes every sequence with
    /// its length. The producer is invoked while the compressed blob is being
    /// serialized, so no event vector or uncompressed staging buffer is
    /// created. The resulting six-field representation is identical to
    /// [`Self::save`]. The summary marks the blob as sorted only if the
    /// producer emits nondecreasing event steps.

    /// Save a trace while the producer emits events one at a time.
    ///
    /// `event_count` is required because bincode prefixes every sequence with
    /// its length. The producer is invoked while the compressed blob is being
    /// serialized, so no event vector or uncompressed staging buffer is
    /// created. The resulting six-field representation is identical to
    /// [`Self::save`]. The summary marks the blob as sorted only if the
    /// producer emits nondecreasing event steps.
    pub fn save_stream<P>(
        &self,
        mut metadata: TraceStreamMetadata,
        event_count: usize,
        producer: P,
    ) -> Result<(u64, ImportStats)>
    where
        P: FnOnce(&mut dyn FnMut(TraceEvent) -> Result<()>) -> Result<ImportStats>,
    {
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
        let tmp = blob_path.with_extension("bincode.zst.tmp");
        let mut written = 0usize;
        let mut sorted = true;
        let mut previous_step: Option<u64> = None;
        let mut chunk: Vec<TraceEvent> = Vec::new();
        let write_result = (|| -> Result<ImportStats> {
            let mut file = File::create(&tmp)
                .with_context(|| format!("failed to create trace blob temp: {}", tmp.display()))?;
            trace_codec::write_sotc_header(&mut file, &header)?;
            let mut emit = |event: TraceEvent| -> Result<()> {
                if written >= event_count {
                    return Err(anyhow!("stream producer emitted more events than declared"));
                }
                if let Some(previous) = previous_step {
                    if event.step() < previous {
                        sorted = false;
                    }
                }
                previous_step = Some(event.step());
                chunk.push(event);
                written += 1;
                if chunk.len() >= trace_codec::DEFAULT_CHUNK_EVENTS {
                    trace_codec::write_chunk(&mut file, &chunk)?;
                    chunk.clear();
                }
                Ok(())
            };
            let stats = producer(&mut emit)?;
            if !chunk.is_empty() {
                trace_codec::write_chunk(&mut file, &chunk)?;
                chunk.clear();
            }
            if written != event_count || stats.events != event_count {
                return Err(anyhow!(
                    "stream event count mismatch: expected {}, wrote {}, reported {}",
                    event_count,
                    written,
                    stats.events,
                ));
            }
            file.flush()?;
            drop(file);
            publish_durable(&tmp, &blob_path)?;
            Ok(stats)
        })();
        let stats = match write_result {
            Ok(stats) => stats,
            Err(err) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(err);
            }
        };

        let legacy = self.legacy_blob_path(id);
        if legacy.exists() {
            let _ = std::fs::remove_file(&legacy);
        }

        let summary = TraceSummary {
            trace_id: id,
            so_file_id: header.so_file_id,
            source: header.source,
            base_addr: header.base_addr,
            event_count,
            events_sorted: sorted,
            created_at: header.created_at,
        };
        if let Some(existing) = idx.summaries.iter_mut().find(|s| s.trace_id == id) {
            *existing = summary;
        } else {
            idx.summaries.push(summary);
        }
        self.save_index(&idx)?;
        Ok((id, stats))
    }

    /// Load a persisted trace by id.
    ///
    /// Reads the zstd-compressed `.bincode.zst` blob if present; otherwise
    /// falls back to a legacy uncompressed `.bincode` blob for files written
    /// by older versions. Both paths deserialize directly from the file
    /// stream, avoiding a second full-size uncompressed byte buffer alongside
    /// the reconstructed event vector. Returns an error if neither exists.

    /// Load a persisted trace by id.
    ///
    /// Reads the zstd-compressed `.bincode.zst` blob if present; otherwise
    /// falls back to a legacy uncompressed `.bincode` blob for files written
    /// by older versions. Both paths deserialize directly from the file
    /// stream, avoiding a second full-size uncompressed byte buffer alongside
    /// the reconstructed event vector. Returns an error if neither exists.
    pub fn load(&self, id: u64) -> Result<PersistedTrace> {
        let compressed = self.blob_path(id);
        if compressed.exists() {
            let mut file = File::open(&compressed)
                .with_context(|| format!("failed to open trace blob: {}", compressed.display()))?;
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic)
                .with_context(|| format!("failed to read blob magic: {}", compressed.display()))?;
            file.seek(SeekFrom::Start(0))?;
            if magic == trace_codec::MAGIC {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                let (header, events) = trace_codec::decode_sotc(&bytes)?;
                return Ok(PersistedTrace {
                    trace_id: header.trace_id,
                    so_file_id: header.so_file_id,
                    source: header.source,
                    base_addr: header.base_addr,
                    events,
                    created_at: header.created_at,
                });
            }
            let mut decoder = zstd::stream::read::Decoder::new(file)
                .with_context(|| format!("failed to initialize zstd decoder: {}", compressed.display()))?;
            bincode::deserialize_from(&mut decoder)
                .with_context(|| format!("failed to deserialize compressed trace blob for id {}", id))
        } else {
            let legacy = self.legacy_blob_path(id);
            let file = File::open(&legacy)
                .with_context(|| format!("failed to open trace blob (neither {} nor {} found)", compressed.display(), legacy.display()))?;
            bincode::deserialize_from(file)
                .with_context(|| format!("failed to deserialize legacy trace blob for id {}", id))
        }
    }

    /// Replay a newly-saved, chronologically ordered trace without allocating
    /// its complete event vector.
    ///
    /// The index's `events_sorted` marker is deliberately required: old
    /// indexes cannot prove their associated blobs are chronological, so
    /// callers must use [`Self::load`] and sort those traces in memory for
    /// compatibility. The bincode blob layout itself is unchanged.

    /// Replay a newly-saved, chronologically ordered trace without allocating
    /// its complete event vector.
    ///
    /// The index's `events_sorted` marker is deliberately required: old
    /// indexes cannot prove their associated blobs are chronological, so
    /// callers must use [`Self::load`] and sort those traces in memory for
    /// compatibility. The bincode blob layout itself is unchanged.
    pub fn replay_sorted<T, Start, Event>(
        &self,
        id: u64,
        start: Start,
        on_event: Event,
    ) -> Result<(T, TraceReplayResult)>
    where
        Start: FnOnce(&TraceReplayStart) -> Result<T>,
        Event: FnMut(&mut T, TraceEvent) -> Result<()>,
    {
        let summary = self
            .summary(id)?
            .with_context(|| format!("no persisted trace with id {}", id))?;
        if !summary.events_sorted {
            anyhow::bail!(
                "trace {} does not declare chronologically ordered events; use the compatibility replay path",
                id
            );
        }

        let mut on_event = on_event;
        let compressed = self.blob_path(id);
        if compressed.exists() {
            let mut file = File::open(&compressed)
                .with_context(|| format!("failed to open trace blob: {}", compressed.display()))?;
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic)
                .with_context(|| format!("failed to read blob magic: {}", compressed.display()))?;
            file.seek(SeekFrom::Start(0))?;
            if magic == trace_codec::MAGIC {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                let (header, events) = trace_codec::decode_sotc(&bytes)?;
                let replay_start = TraceReplayStart {
                    trace_id: header.trace_id,
                    so_file_id: header.so_file_id,
                    source: header.source,
                    base_addr: header.base_addr,
                };
                let mut state = start(&replay_start)?;
                let mut event_count = 0usize;
                for event in events {
                    on_event(&mut state, event)?;
                    event_count += 1;
                }
                return Ok((
                    state,
                    TraceReplayResult {
                        start: replay_start,
                        event_count,
                        created_at: header.created_at,
                    },
                ));
            }
            let seed = TraceReplaySeed { start, on_event };
            let mut decoder = zstd::stream::read::Decoder::new(file)
                .with_context(|| format!("failed to initialize zstd decoder: {}", compressed.display()))?;
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .deserialize_from_seed(seed, &mut decoder)
                .with_context(|| format!("failed to stream-replay compressed trace blob for id {}", id))
        } else {
            let seed = TraceReplaySeed { start, on_event };
            let legacy = self.legacy_blob_path(id);
            let file = File::open(&legacy)
                .with_context(|| format!("failed to open trace blob (neither {} nor {} found)", compressed.display(), legacy.display()))?;
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .deserialize_from_seed(seed, file)
                .with_context(|| format!("failed to stream-replay legacy trace blob for id {}", id))
        }
    }

    /// Append `events` as a new SOTC chunk. The prefix of the blob is not rewritten.
    ///
    /// The blob must already exist in SOTC form (created by [`Self::save`] /
    /// [`Self::save_stream`] / a previous append). Returns the new total event
    /// count recorded in the index.

    /// Append `events` as a new SOTC chunk. The prefix of the blob is not rewritten.
    ///
    /// The blob must already exist in SOTC form (created by [`Self::save`] /
    /// [`Self::save_stream`] / a previous append). Returns the new total event
    /// count recorded in the index.
    pub fn append_events(&self, id: u64, events: &[TraceEvent]) -> Result<usize> {
        if events.is_empty() {
            return Ok(self.summary(id)?.map(|s| s.event_count).unwrap_or(0));
        }
        let payload = trace_codec::compress_chunk(events)?;
        self.append_compressed_chunk(id, events.len(), &payload)
    }

    /// Append one already-compressed SOTC chunk. `payload` is the zstd body
    /// produced by [`trace_codec::compress_chunk`]; the chunk header is written
    /// here. Same on-disk layout as [`Self::append_events`].
    pub fn append_compressed_chunk(
        &self,
        id: u64,
        event_count: usize,
        payload: &[u8],
    ) -> Result<usize> {
        if event_count == 0 {
            return Ok(self.summary(id)?.map(|s| s.event_count).unwrap_or(0));
        }
        let blob_path = self.blob_path(id);
        if !blob_path.exists() {
            anyhow::bail!("cannot append: no SOTC blob for trace {id}");
        }
        let mut file = File::open(&blob_path)
            .with_context(|| format!("failed to open trace blob: {}", blob_path.display()))?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        drop(file);
        if magic != trace_codec::MAGIC {
            anyhow::bail!("cannot append to a legacy bincode/zstd blob (trace {id})");
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&blob_path)
            .with_context(|| format!("failed to append trace blob: {}", blob_path.display()))?;
        file.write_all(&(event_count as u32).to_le_bytes())?;
        file.write_all(&(payload.len() as u32).to_le_bytes())?;
        file.write_all(payload)?;
        file.flush()?;

        let mut idx = self.load_index()?;
        let new_count = if let Some(existing) = idx.summaries.iter_mut().find(|s| s.trace_id == id) {
            existing.event_count = existing
                .event_count
                .checked_add(event_count)
                .ok_or_else(|| anyhow!("event count overflow"))?;
            existing.event_count
        } else {
            anyhow::bail!("cannot append: no index entry for trace {id}");
        };
        self.save_index(&idx)?;
        Ok(new_count)
    }
}
