// Persistence layer — on-disk storage for SO metadata and trace event streams.
//
// This is a pragmatic, dependency-free persistence layer: each SO is
// bincode-serialized to `<data_dir>/so/<id>.bincode`, with a small JSON index
// `<data_dir>/so/index.json` holding summaries (id, path, sha256, build_id,
// function counts) for fast listing and dedup-by-hash.
//
// No embedded database (sled/rocksdb) is introduced — the volume of SO
// metadata per file is modest (segments + symbols + functions), so flat
// bincode files + a JSON sidecar index are sufficient and keep the build
// lean. Trace event streams are larger and highly compressible (repeated
// addresses, sequential steps, run-length-ish memory bytes), so each trace
// blob is stored as an append-only SOTC (columnar + zstd chunks) file at
// `<data_dir>/trace/<id>.bincode.zst`. `load` sniffs SOTC magic, otherwise
// decompresses the previous whole-blob bincode+zstd layout, and also falls
// back to a legacy uncompressed `.bincode` blob so older writes remain readable.

use std::cell::{Cell, RefCell};
use std::fs::{File, OpenOptions};
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use bincode::Options;
use serde::de::{DeserializeSeed, Error as _, SeqAccess, Visitor};
use serde::ser::{Error as _, SerializeSeq, SerializeTuple};
use serde::{Deserialize, Serialize};

use sotrace_core::adapters::{ImportStats, TraceEvent};
use sotrace_core::elf::ParsedSoFile;

pub mod trace_codec;

/// Summary of an imported SO, stored in the index file for fast listing/dedup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoSummary {
    /// Assigned SO file ID.
    pub id: u64,
    /// Original file path at import time.
    pub path: String,
    /// Architecture.
    pub arch: String,
    /// File size in bytes.
    pub file_size: u64,
    /// SHA-256 hash (lowercase hex).
    pub sha256: String,
    /// GNU Build ID (lowercase hex), if present.
    pub build_id: Option<String>,
    /// Total function count.
    pub function_count: usize,
    /// JNI function count.
    pub jni_function_count: usize,
    /// Exported function count.
    pub exported_function_count: usize,
    /// Import timestamp (Unix epoch seconds).
    pub created_at: u64,
}

/// Outcome of [`SoRepository::save`]: the assigned (or reused) SO ID plus
/// whether the save was a dedup hit (an entry with the same SHA-256 already
/// existed and was reused unchanged).
///
/// `deduped` is the authoritative signal straight from the save's internal
/// index lookup — callers must NOT re-derive it by comparing `summary` fields
/// against the freshly parsed bytes (that heuristic breaks when two parses land
/// in the same wall-clock second, since `created_at` is second-grained).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SaveOutcome {
    /// Assigned (new import) or reused (dedup hit) SO ID.
    pub id: u64,
    /// `true` when an existing entry with the same SHA-256 was reused; `false`
    /// when a new entry was written.
    pub deduped: bool,
}

/// On-disk repository for SO files.
///
/// All operations are synchronous (blocking) — appropriate for CLI use and
/// for one-shot imports inside an async handler via `tokio::task::spawn_blocking`.
pub struct SoRepository {
    root: PathBuf,
}

/// The JSON index file: a counter for ID allocation plus a list of summaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SoIndex {
    /// Next SO ID to assign (monotonic). Starts at 1 — 0 is reserved as the
    /// "no SO" sentinel used by `PersistedTrace.so_file_id` and the CLI/HTTP/
    /// MCP `so_file_id > 0` guards, so a real SO can never be ID 0.
    next_id: u64,
    summaries: Vec<SoSummary>,
}

/// `Default` seeds `next_id` at 1 (not 0) so the first saved SO gets ID 1 and
/// 0 stays a usable "no SO" sentinel. Deserialization of an old index that
/// predates this rule is repaired by [`SoRepository::load_index`].
impl Default for SoIndex {
    fn default() -> Self {
        SoIndex { next_id: 1, summaries: Vec::new() }
    }
}

impl SoIndex {
    fn find_by_sha256(&self, sha256: &str) -> Option<&SoSummary> {
        self.summaries.iter().find(|s| s.sha256 == sha256)
    }
}

include!("so_repo.rs");

impl SoSummary {
    fn from_parsed(id: u64, parsed: &ParsedSoFile, sha256_hex: &str) -> Self {
        let so = &parsed.so_file;
        Self {
            id,
            path: so.path.clone(),
            arch: format!("{:?}", so.arch),
            file_size: so.file_size,
            sha256: sha256_hex.to_string(),
            build_id: so.build_id.as_ref().map(|b| to_hex(b)),
            function_count: parsed.functions.len(),
            jni_function_count: parsed.jni_function_count(),
            exported_function_count: parsed.exported_function_count(),
            created_at: so.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Trace persistence
// ---------------------------------------------------------------------------

/// A persisted trace: the normalized event stream plus bookkeeping, serialized
/// as bincode. Loading replays the events into a fresh TraceEngine, rebuilding
/// all indexes — so no index or derived state is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTrace {
    pub trace_id: u64,
    pub so_file_id: u64,
    /// Source format label (e.g. "frida:interceptor", "native", "dynamorio:drcachesim").
    pub source: String,
    /// SO base address used when parsing (for address conversion).
    pub base_addr: u64,
    /// The normalized event stream, sorted by step.
    pub events: Vec<sotrace_core::adapters::TraceEvent>,
    /// Import timestamp (Unix epoch seconds).
    pub created_at: u64,
}

/// Summary of a persisted trace, stored in the trace index for fast listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    pub trace_id: u64,
    pub so_file_id: u64,
    pub source: String,
    pub base_addr: u64,
    pub event_count: usize,
    /// Whether `events` are stably ordered by `TraceEvent::step` in the blob.
    ///
    /// Older indexes do not carry this field and deserialize as `false`, so
    /// callers can safely fall back to the compatibility replay path that
    /// collects and sorts the whole event vector.
    #[serde(default)]
    pub events_sorted: bool,
    pub created_at: u64,
}

/// Metadata available before a persisted event stream is replayed.
///
/// [`TraceRepository::replay_sorted`] exposes this to its setup callback so a
/// caller can construct a destination (for example a `TraceEngine`) before
/// events are deserialized one at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceReplayStart {
    pub trace_id: u64,
    pub so_file_id: u64,
    pub source: String,
    pub base_addr: u64,
}

/// Metadata returned after a streaming trace replay has completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceReplayResult {
    pub start: TraceReplayStart,
    pub event_count: usize,
    pub created_at: u64,
}

/// Metadata for a trace whose events are supplied by a streaming producer.
#[derive(Debug, Clone)]
pub struct TraceStreamMetadata {
    pub trace_id: u64,
    pub so_file_id: u64,
    pub source: String,
    pub base_addr: u64,
    pub created_at: u64,
}

/// On-disk repository for trace event streams.
///
/// Layout: `<data_dir>/trace/<id>.bincode.zst` (SOTC columnar chunks) +
/// `index.json`. Like [`SoRepository`] but for traces; dedup is by trace_id.
/// New writes are append-only SOTC chunks (later batches do not rewrite
/// earlier records). [`Self::load`] sniffs SOTC magic, otherwise reads the
/// previous whole-blob bincode+zstd layout, and also tolerates a legacy
/// uncompressed `.bincode` blob.
pub struct TraceRepository {
    root: PathBuf,
}

/// zstd compression level used for trace blobs.
///
/// Level 3 is zstd's default and a good speed/ratio trade-off for trace data,
/// which is dominated by repeated addresses and sequential steps. Trace blobs
/// are written once and read many times (on every `load`), so spending a
/// little extra compression effort up front is worthwhile.
const TRACE_ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TraceIndex {
    next_id: u64,
    summaries: Vec<TraceSummary>,
}

impl Default for TraceIndex {
    fn default() -> Self {
        // 0 is the input sentinel for "assign an id". Keep it out of the
        // persisted namespace so an automatically assigned id is never
        // ambiguous with an omitted id.
        Self { next_id: 1, summaries: Vec::new() }
    }
}
