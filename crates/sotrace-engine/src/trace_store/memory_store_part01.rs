// Memory store — stores memory page changes using byte-level delta encoding
//
// Memory is the most data-intensive part of a trace. A typical instruction
// may write only 4-8 bytes, but memory is organized in 4KB pages.
//
// Delta encoding strategy (Checkpoint + Delta + Page-Granularity):
// 1. **Snapshots**: Full memory state at periodic checkpoints
// 2. **Page-level deltas**: Only pages that changed between steps
// 3. **Byte-level deltas within pages**: Only changed bytes within a page
//
// Storage estimation for 1亿 instructions:
// - ~420MB total (vs impossible full storage of ~400GB)
// - Snapshots: ~10 checkpoints × 100MB active pages = 1GB (CAS dedup reduces this)
// - Deltas: ~2 bytes changed per instruction × 100M = 200MB compressed
//
// Query acceleration:
// - PageAddressIndex: page_address → [steps that modified this page]
// - For "what is at address X at step N?", find the page containing X,
//   find the last delta for that page before step N, and apply

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use std::collections::BTreeMap;

use crate::delta_store::delta_log::EventLog;
use crate::delta_store::snapshot::SnapshotManager;
use crate::delta_store::types::*;

/// Memory page data (4KB)
pub type MemoryPage = [u8; PAGE_SIZE];

/// Memory store — byte-level delta encoding for memory state
///
/// This is the most complex store because memory is both the largest
/// and the most queried data type in trace analysis.
pub struct MemoryStore {
    /// Per-page delta logs: page_addr → event log of that page's deltas.
    ///
    /// Keyed by page, NOT by a single global step, because step numbers come
    /// from the caller's `trace.seq` and are not unique: one memory write can
    /// straddle several pages (all recorded at the same step), and two writes
    /// can share a step. A single step-keyed `DeltaLog` would clobber all but
    /// the last colliding record, so folding one page would replay ANOTHER
    /// page's delta and reconstruct the wrong bytes. `EventLog` also keeps a
    /// `Vec` per step, so two writes to the *same* page at the same step are
    /// both replayed (in insertion order) rather than one dropped.
    page_logs: HashMap<u64, EventLog<Vec<u8>>>,
    /// Snapshot manager for periodic full-state checkpoints
    snapshot_manager: SnapshotManager<HashMap<u64, Vec<u8>>>,
    /// Page cache: page_addr → current page content (for delta encoding)
    page_cache: HashMap<u64, Vec<u8>>,
    /// Content-addressable page store: hash → page data (for dedup)
    page_cas: HashMap<[u8; 32], Vec<u8>>,
    /// Original writes keyed by step, in insertion order.
    ///
    /// Page logs keep byte deltas and cannot be listed without an address.
    /// This index is the step-only view: the address and bytes recorded at
    /// that step, not a reconstruction of earlier writes.
    step_writes: BTreeMap<u64, Vec<(u64, Vec<u8>)>>,
    /// Configuration
    config: DeltaStoreConfig,
}

/// A memory write event
#[derive(Debug, Clone)]
pub struct MemoryWrite {
    /// Step number when this write occurred
    pub step: u64,
    /// Thread that performed the write
    pub thread_id: u32,
    /// Virtual address of the write
    pub address: u64,
    /// Data written
    pub data: Vec<u8>,
}

/// Memory value query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryValueResult {
    /// The value at the queried address/step
    pub value: Vec<u8>,
    /// How many deltas were applied to reconstruct
    pub deltas_applied: u64,
    /// The page that contains this address
    pub page_address: u64,
}

impl MemoryStore {
    /// Create a new memory store
    pub fn new(config: DeltaStoreConfig) -> Self {
        Self {
            page_logs: HashMap::new(),
            snapshot_manager: SnapshotManager::new(config.clone()),
            page_cache: HashMap::new(),
            page_cas: HashMap::new(),
            step_writes: BTreeMap::new(),
            config,
        }
    }

    /// Memory writes whose step is exactly `step`, in insertion order.
    ///
    /// Earlier writes are not included. Listing them does not require the address.
    pub fn writes_at_step(&self, step: u64) -> Vec<(u64, Vec<u8>)> {
        self.step_writes.get(&step).cloned().unwrap_or_default()
    }

    /// Record a memory write event
    ///
    /// The write may span multiple pages. For each affected page,
    /// we compute a byte-level delta from the previous page content.
    pub fn write(&mut self, write: MemoryWrite) -> Result<()> {
        let recorded = (write.address, write.data.clone());
        let recorded_step = write.step;
        // Copied out of `self.config` so the per-page log can be created inside
        // the loop without holding a borrow of `self` across `page_logs`.
        let compression = self.config.compression;
        let threshold = self.config.byte_level_threshold;
        let mut offset = 0usize;
        let mut addr = write.address;

        while offset < write.data.len() {
            let page_addr = page_align(addr);
            let page_off = page_offset(addr);

            // How many bytes fit in this page from current offset
            let bytes_in_page = std::cmp::min(
                write.data.len() - offset,
                PAGE_SIZE - page_off,
            );
            let src = &write.data[offset..offset + bytes_in_page];

            // The page cache is the previous content. A write only differs
            // inside this window, so the delta is that window compared in
            // place — not a scan/clone of the whole 4KB page.
            let payload = {
                let page = self
                    .page_cache
                    .entry(page_addr)
                    .or_insert_with(|| vec![0u8; PAGE_SIZE]);
                let mut changes: Vec<ByteChange> = Vec::new();
                let mut i = 0;
                while i < src.len() {
                    if page[page_off + i] != src[i] {
                        let start = i;
                        i += 1;
                        while i < src.len() && page[page_off + i] != src[i] {
                            i += 1;
                        }
                        // `ByteChange::size` is a u8. Split long runs so fold
                        // applies every changed byte (a single cast would keep
                        // only the low 8 bits of the length).
                        let mut s = start;
                        while s < i {
                            let n = (i - s).min(255);
                            changes.push(ByteChange {
                                offset: (page_off + s) as u16,
                                size: n as u8,
                                new_bytes: src[s..s + n].to_vec(),
                            });
                            s += n;
                        }
                    } else {
                        i += 1;
                    }
                }
                let total_changed: usize = changes.iter().map(|c| c.size as usize).sum();
                page[page_off..page_off + bytes_in_page].copy_from_slice(src);
                if total_changed <= threshold {
                    DeltaPayload::ByteChanges(changes)
                } else {
                    DeltaPayload::FullValue(page.clone())
                }
            };

            let record = DeltaRecord {
                step: write.step,
                encoding: match &payload {
                    DeltaPayload::FullValue(_) => DeltaEncoding::FullValue,
                    DeltaPayload::ByteChanges(_) => DeltaEncoding::ByteLevel,
                    DeltaPayload::BinaryDiff(_) => DeltaEncoding::BinaryDiff,
                    _ => DeltaEncoding::FullValue,
                },
                payload,
                prev_hash: None,
            };

            self.page_logs
                .entry(page_addr)
                .or_insert_with(|| EventLog::new(compression))
                .append(record)?;

            // Advance to the next page. `checked_add`: once the cursor reaches
            // the end of the address space, the remaining bytes of this write
            // have nowhere legal to live — saturating would keep the cursor on
            // the final page and overwrite its tail, while a plain `+=` would
            // wrap to a low page (release) or panic (debug). Stopping instead
            // drops only the bytes that fall past u64::MAX (a malformed input
            // that cannot be stored anyway). `offset` advancing first keeps the
            // loop terminating.
            offset += bytes_in_page;
            match addr.checked_add(bytes_in_page as u64) {
                Some(next) => addr = next,
                None => break,
            }
        }
        self.step_writes.entry(recorded_step).or_default().push(recorded);

        Ok(())
    }

    /// Number of per-page delta records retained.
    ///
    /// A write that stays inside one page appends exactly one record, so this
    /// matches the accepted `MemoryWrite` count for single-page writes.
    pub fn record_count(&self) -> u64 {
        self.page_logs.values().map(|log| log.total_count()).sum()
    }

    /// Query memory value at a specific address and step
    ///
    /// This is the key query: "what was at address X at step N?"
    ///
    /// Optimization path:
    /// 1. Find the page containing address X
    /// 2. Fold every delta for this page up to step N (via the page index)
    /// 3. Return the bytes at the offset within the reconstructed page
    ///
    /// When the read spans a page boundary, the bytes from each covered page
    /// are concatenated — a never-modified interior page contributes zero
    /// bytes (mirroring `reconstruct_page`'s zero-page semantics), so a
    /// straddling read never silently truncates. Returns `None` only when the
    /// *first* page was never modified at or before `target_step` (preserving
    /// the "no write at this address yet" contract).
    pub fn query_value(
        &self,
        address: u64,
        size: usize,
        target_step: u64,
    ) -> Option<MemoryValueResult> {
        let first_page_addr = page_align(address);
        let first_page_off = page_offset(address);

        // Reconstruct the whole page by replaying ALL deltas up to the step.
        // Byte-level deltas only record bytes changed relative to the previous
        // page content, so folding just the last delta onto a zero page would
        // silently drop earlier writes to untouched bytes.
        let (first_page, applied0) = self.fold_page_up_to(first_page_addr, target_step)?;

        // Fast path: the read fits in the first page.
        if first_page_off + size <= PAGE_SIZE {
            let end = first_page_off + size;
            return Some(MemoryValueResult {
                value: first_page[first_page_off..end].to_vec(),
                deltas_applied: applied0,
                page_address: first_page_addr,
            });
        }

        // Slow path: the read straddles one or more page boundaries. Stitch
        // the trailing bytes of the first page together with the leading bytes
        // of each subsequent page. A page that was never modified contributes
        // zero bytes (not `None`) so the caller still gets a full `size`-byte
        // value — matching `reconstruct_page`'s zero-page contract.
        let mut value = first_page[first_page_off..].to_vec();
        let mut deltas_applied = applied0;
        let mut remaining = size - (PAGE_SIZE - first_page_off);
        // `checked_add` mirrors the write path (#86): once the cursor would
        // pass u64::MAX there is no legal page beyond it, so the remaining
        // bytes have nowhere to live. Fill them with zeros (the never-modified
        // page contract) and stop, rather than panicking on overflow — a
        // straddling read near the top of the address space is valid input.
        let mut addr = match first_page_addr.checked_add(PAGE_SIZE as u64) {
            Some(next) => next,
            None => {
                value.extend(std::iter::repeat(0u8).take(remaining));
                return Some(MemoryValueResult {
                    value,
                    deltas_applied,
                    page_address: first_page_addr,
                });
            }
        };

        while remaining > 0 {
            let take = std::cmp::min(remaining, PAGE_SIZE);
            match self.fold_page_up_to(addr, target_step) {
                Some((page, applied)) => {
                    value.extend_from_slice(&page[..take]);
                    deltas_applied += applied;
                }
                None => {
                    // Page never modified at/before target_step → zero bytes.
                    value.extend(std::iter::repeat(0u8).take(take));
                }
            }
            remaining -= take;
            addr = match addr.checked_add(PAGE_SIZE as u64) {
                Some(next) => next,
                None => {
                    // Address space exhausted: pad the rest with zeros and stop.
                    value.extend(std::iter::repeat(0u8).take(remaining));
                    break;
                }
            };
        }

        Some(MemoryValueResult {
            value,
            deltas_applied,
            page_address: first_page_addr,
        })
    }

    /// Reconstruct a full page at a specific step.
    ///
    /// Unlike [`Self::query_value`], a never-modified page yields a zero page
    /// (`Some`) rather than `None`.
    pub fn reconstruct_page(&self, page_addr: u64, target_step: u64) -> Option<Vec<u8>> {
        match self.fold_page_up_to(page_addr, target_step) {
            Some((page, _)) => Some(page),
            // Page was never modified, return zero page
            None => Some(vec![0u8; PAGE_SIZE]),
        }
    }

    /// Fold every delta for `page_addr` up to `target_step` onto a zero page.
    ///
    /// Returns the reconstructed page and how many deltas were applied, or
    /// `None` if the page was never modified at or before `target_step`.
    ///
    /// The page's `EventLog` keeps its records in step order (and insertion
    /// order within a step), so `get_range(0, target_step)` yields exactly the
    /// deltas to replay, already ordered — no other page's deltas can leak in,
    /// because each page has its own log.
    fn fold_page_up_to(&self, page_addr: u64, target_step: u64) -> Option<(Vec<u8>, u64)> {
        let log = self.page_logs.get(&page_addr)?;
        let records = log.get_range(0, target_step);

        if records.is_empty() {
            return None;
        }

        let mut page = vec![0u8; PAGE_SIZE];
        let mut applied = 0u64;
        for record in records {
            match &record.payload {
                DeltaPayload::FullValue(data) => {
                    if data.len() == PAGE_SIZE {
                        page.copy_from_slice(data);
                    }
                }
                DeltaPayload::ByteChanges(changes) => {
                    for change in changes {
                        let off = change.offset as usize;
                        let size = change.size as usize;
                        if off + size <= PAGE_SIZE {
                            page[off..off + size].copy_from_slice(&change.new_bytes);
                        }
                    }
                }
                _ => {}
            }
            applied += 1;
        }

        Some((page, applied))
    }

    /// Create a memory snapshot at the current step (coordinated with Timeline)
    pub fn create_snapshot(&mut self, step: u64) -> Result<u64> {
        self.snapshot_manager.create_snapshot(step, self.page_cache.clone())
    }

    /// Get the page cache (for current state queries)
    pub fn current_page(&self, page_addr: u64) -> Option<&Vec<u8>> {
        self.page_cache.get(&page_addr)
    }
}
