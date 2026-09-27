//! Delta log — append-only log of incremental changes
//!
//! All changes are appended to the delta log in step order.
//! This is the primary storage for all trace data between snapshots.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::types::*;

/// Delta log — append-only log of incremental changes for entity type V
///
/// Each entry is a `DeltaRecord<V>` recording what changed at each step.
/// The log is purely append-only — no updates or deletes.
pub struct DeltaLog<V> {
    /// All delta records, keyed by step number. A `BTreeMap` keeps records in
    /// step order so `get_range` is an O(log N + K) range scan (K = records in
    /// range) instead of an O(N log N) filter-and-sort over every record.
    records_by_step: BTreeMap<u64, DeltaRecord<V>>,
    /// Total number of records
    total_count: u64,
    /// Compression config
    compression: CompressionConfig,
}

impl<V: Clone + Serialize + for<'de> Deserialize<'de>> DeltaLog<V> {
    /// Create a new delta log
    pub fn new(compression: CompressionConfig) -> Self {
        Self {
            records_by_step: BTreeMap::new(),
            total_count: 0,
            compression,
        }
    }

    /// Append a delta record to the log
    pub fn append(&mut self, record: DeltaRecord<V>) -> Result<()> {
        self.records_by_step.insert(record.step, record);
        self.total_count += 1;
        Ok(())
    }

    /// Append multiple delta records (batch write for performance)
    pub fn append_batch(&mut self, records: Vec<DeltaRecord<V>>) -> Result<()> {
        for record in records {
            self.records_by_step.insert(record.step, record);
            self.total_count += 1;
        }
        Ok(())
    }

    /// Get a delta record by step number
    pub fn get(&self, step: u64) -> Option<&DeltaRecord<V>> {
        self.records_by_step.get(&step)
    }

    /// Get all delta records in a step range [start, end], sorted by step.
    ///
    /// Backed by the `BTreeMap` range iterator, so this scans only the records
    /// in `[start_step, end_step]` (already in step order) rather than every
    /// record in the log.
    pub fn get_range(&self, start_step: u64, end_step: u64) -> Vec<&DeltaRecord<V>> {
        self.records_by_step
            .range(start_step..=end_step)
            .map(|(_, record)| record)
            .collect()
    }

    /// Get the total number of records
    pub fn total_count(&self) -> u64 {
        self.total_count
    }

    /// Iterate over all records in step order (the `BTreeMap` keeps them sorted).
    pub fn iter_records(&self) -> impl Iterator<Item = &DeltaRecord<V>> {
        self.records_by_step.values()
    }

    /// All records sorted by step, as owned clones (for snapshot/persistence).
    pub fn all_records_sorted(&self) -> Vec<DeltaRecord<V>>
    where
        V: Clone,
    {
        // `records_by_step` is a BTreeMap, so `values()` is already step-ordered.
        self.records_by_step.values().cloned().collect()
    }
}

/// Event log — an append-only log that retains **every** record at a step.
///
/// `DeltaLog` keeps a single `DeltaRecord` per step (keyed insert), which is
/// correct for true delta streams where a step is one timeline position with
/// one delta (instruction / register / page delta). Event streams are
/// different: step numbers come from the caller (`trace.seq`) and are **not**
/// guaranteed unique — two threads can emit a sync event, state change, or
/// context switch at the same step, and a single memory write can straddle
/// pages. For those, a keyed insert silently clobbers all but the last record
/// at a colliding step, losing data on both persistence (`all_records_sorted`)
/// and indexed queries. `EventLog` retains same-step records in insertion
/// order, but stores the common one-record case inline to avoid a heap
/// allocation for every unique step.
pub struct EventLog<V> {
    /// Records grouped by ascending step.
    ///
    /// Trace import normally arrives in step order (the CLI normalizes it
    /// before feeding the engine), so a contiguous vector avoids one tree
    /// allocation per unique step and appends in O(1). The out-of-order case
    /// remains correct: `append` finds the bucket with binary search and
    /// inserts it at the ordered position.
    ///
    /// Most trace streams have one record per step, so `EventBucket::One`
    /// also avoids allocating a `Vec` for every unique step.
    records_by_step: Vec<(u64, EventBucket<V>)>,
    /// Total number of records across all steps.
    total_count: u64,
    /// Compression config (parity with `DeltaLog`).
    compression: CompressionConfig,
}

/// Records that share one step in an [`EventLog`].
///
/// A bucket upgrades to `Many` only when a second record is appended at the
/// same step. Both variants preserve insertion order.
enum EventBucket<V> {
    One(DeltaRecord<V>),
    Many(Vec<DeltaRecord<V>>),
}

impl<V> EventBucket<V> {
    fn as_slice(&self) -> &[DeltaRecord<V>] {
        match self {
            Self::One(record) => std::slice::from_ref(record),
            Self::Many(records) => records.as_slice(),
        }
    }

    fn iter(&self) -> std::slice::Iter<'_, DeltaRecord<V>> {
        self.as_slice().iter()
    }

    fn push(&mut self, record: DeltaRecord<V>) {
        match self {
            Self::One(_) => {
                let first = match std::mem::replace(self, Self::Many(Vec::with_capacity(2))) {
                    Self::One(first) => first,
                    Self::Many(_) => unreachable!("one-record bucket was replaced by many-record bucket"),
                };
                let Self::Many(records) = self else {
                    unreachable!("event bucket upgrade must produce a many-record bucket");
                };
                records.push(first);
                records.push(record);
            }
            Self::Many(records) => records.push(record),
        }
    }
}

impl<V: Clone + Serialize + for<'de> Deserialize<'de>> EventLog<V> {
    /// Create a new event log.
    pub fn new(compression: CompressionConfig) -> Self {
        Self {
            records_by_step: Vec::new(),
            total_count: 0,
            compression,
        }
    }

    /// Reserve room for `additional` new step buckets (in-order appends).
    pub fn reserve(&mut self, additional: usize) {
        self.records_by_step.reserve(additional);
    }

    /// Append a record, retaining any existing records at the same step.
    #[inline]
    pub fn append(&mut self, record: DeltaRecord<V>) -> Result<()> {
        let step = record.step;
        match self.records_by_step.last_mut() {
            // The overwhelmingly common normalized-input case: append a new
            // step without binary search or shifting existing records.
            Some((last_step, _)) if *last_step < step => {
                self.records_by_step.push((step, EventBucket::One(record)));
            }
            // Same-step events preserve insertion order in their bucket.
            Some((last_step, bucket)) if *last_step == step => bucket.push(record),
            _ => {
                let pos = self
                    .records_by_step
                    .partition_point(|(existing_step, _)| *existing_step < step);
                if pos < self.records_by_step.len()
                    && self.records_by_step[pos].0 == step
                {
                    self.records_by_step[pos].1.push(record);
                } else {
                    self.records_by_step.insert(pos, (step, EventBucket::One(record)));
                }
            }
        }
        self.total_count += 1;
        Ok(())
    }

    /// All records recorded at exactly `step`, in insertion order (empty slice
    /// if none). Callers that indexed their way to `step` filter these by the
    /// record's own identity (thread_id / sync_object_addr) to pick theirs.
    pub fn get_all(&self, step: u64) -> &[DeltaRecord<V>] {
        let pos = self
            .records_by_step
            .partition_point(|(existing_step, _)| *existing_step < step);
        self.records_by_step
            .get(pos)
            .filter(|(existing_step, _)| *existing_step == step)
            .map(|(_, bucket)| bucket.as_slice())
            .unwrap_or(&[])
    }

    /// All records whose step is in `[start_step, end_step]`, flattened in step
    /// order (and insertion order within a step).
    pub fn get_range(&self, start_step: u64, end_step: u64) -> Vec<&DeltaRecord<V>> {
        let start = self
            .records_by_step
            .partition_point(|(step, _)| *step < start_step);
        let end = self
            .records_by_step
            .partition_point(|(step, _)| *step <= end_step);
        self.records_by_step
            .get(start..end)
            .unwrap_or(&[])
            .iter()
            .flat_map(|(_, records)| records.iter())
            .collect()
    }

    /// Total number of records.
    pub fn total_count(&self) -> u64 {
        self.total_count
    }

    /// Iterate over all records in step order (insertion order within a step).
    pub fn iter_records(&self) -> impl Iterator<Item = &DeltaRecord<V>> {
        self.records_by_step
            .iter()
            .flat_map(|(_, records)| records.iter())
    }

    /// All records sorted by step, as owned clones (for snapshot/persistence).
    pub fn all_records_sorted(&self) -> Vec<DeltaRecord<V>> {
        self.records_by_step
            .iter()
            .flat_map(|(_, records)| records.iter().cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(step: u64) -> DeltaRecord<u64> {
        DeltaRecord {
            step,
            encoding: DeltaEncoding::FullValue,
            payload: DeltaPayload::FullValue(step),
            prev_hash: None,
        }
    }

    #[test]
    fn test_get_range_is_sorted_and_inclusive() {
        let mut log: DeltaLog<u64> = DeltaLog::new(CompressionConfig::None);
        // Append out of step order; the BTreeMap must still return sorted output.
        for step in [50u64, 10, 30, 20, 40] {
            log.append(rec(step)).unwrap();
        }

        // Range bounds are inclusive on both ends.
        let steps: Vec<u64> = log.get_range(20, 40).iter().map(|r| r.step).collect();
        assert_eq!(steps, vec![20, 30, 40]);

        // Full span returns everything in order regardless of insertion order.
        let all: Vec<u64> = log.get_range(0, u64::MAX).iter().map(|r| r.step).collect();
        assert_eq!(all, vec![10, 20, 30, 40, 50]);
    }

    #[test]
    fn test_get_range_empty_and_singleton() {
        let mut log: DeltaLog<u64> = DeltaLog::new(CompressionConfig::None);
        for step in [100u64, 200, 300] {
            log.append(rec(step)).unwrap();
        }

        // A range hitting no records is empty.
        assert!(log.get_range(101, 199).is_empty());
        // A range covering exactly one record returns just it.
        let one: Vec<u64> = log.get_range(200, 200).iter().map(|r| r.step).collect();
        assert_eq!(one, vec![200]);
    }

    #[test]
    fn test_records_are_step_ordered_after_out_of_order_append() {
        let mut log: DeltaLog<u64> = DeltaLog::new(CompressionConfig::None);
        for step in [3u64, 1, 2] {
            log.append(rec(step)).unwrap();
        }
        let iter_steps: Vec<u64> = log.iter_records().map(|r| r.step).collect();
        assert_eq!(iter_steps, vec![1, 2, 3]);
        let sorted_steps: Vec<u64> = log.all_records_sorted().iter().map(|r| r.step).collect();
        assert_eq!(sorted_steps, vec![1, 2, 3]);
        assert_eq!(log.total_count(), 3);
    }

    /// A payload-tagged record so we can tell same-step records apart.
    fn tagged(step: u64, tag: u64) -> DeltaRecord<u64> {
        DeltaRecord {
            step,
            encoding: DeltaEncoding::FullValue,
            payload: DeltaPayload::FullValue(tag),
            prev_hash: None,
        }
    }

    fn tag_of(record: &DeltaRecord<u64>) -> u64 {
        match &record.payload {
            DeltaPayload::FullValue(v) => *v,
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_event_log_retains_same_step_records() {
        let mut log: EventLog<u64> = EventLog::new(CompressionConfig::None);
        // Three distinct records all at step 100 — a DeltaLog would keep only the
        // last; an EventLog keeps all three in insertion order.
        log.append(tagged(100, 1)).unwrap();
        log.append(tagged(100, 2)).unwrap();
        log.append(tagged(100, 3)).unwrap();
        // A record at another step to prove flattening spans steps.
        log.append(tagged(50, 9)).unwrap();

        assert_eq!(log.total_count(), 4);
        let at_100: Vec<u64> = log.get_all(100).iter().map(tag_of).collect();
        assert_eq!(at_100, vec![1, 2, 3], "all same-step records retained in order");
        assert!(log.get_all(999).is_empty());

        // all_records_sorted / iter flatten in step order, insertion order within.
        let all: Vec<u64> = log.all_records_sorted().iter().map(tag_of).collect();
        assert_eq!(all, vec![9, 1, 2, 3]);
        let iter: Vec<u64> = log.iter_records().map(tag_of).collect();
        assert_eq!(iter, vec![9, 1, 2, 3]);
    }

    #[test]
    fn test_event_log_uses_inline_bucket_until_a_step_collides() {
        let mut log: EventLog<u64> = EventLog::new(CompressionConfig::None);

        log.append(tagged(100, 1)).unwrap();
        assert!(matches!(
            log.records_by_step.iter().find(|(step, _)| *step == 100),
            Some((_, EventBucket::One(_)))
        ));

        log.append(tagged(100, 2)).unwrap();
        assert!(matches!(
            log.records_by_step.iter().find(|(step, _)| *step == 100),
            Some((_, EventBucket::Many(records))) if records.len() == 2
        ));
    }

    #[test]
    fn test_event_log_get_range_flattens_same_step() {
        let mut log: EventLog<u64> = EventLog::new(CompressionConfig::None);
        for (step, tag) in [(10u64, 1u64), (20, 2), (20, 3), (30, 4)] {
            log.append(tagged(step, tag)).unwrap();
        }
        // Inclusive range that includes the doubled step 20 returns both.
        let in_range: Vec<u64> = log.get_range(20, 30).iter().map(|r| tag_of(r)).collect();
        assert_eq!(in_range, vec![2, 3, 4]);
        // A range excluding step 20 sees neither of its records.
        let excl: Vec<u64> = log.get_range(25, 35).iter().map(|r| tag_of(r)).collect();
        assert_eq!(excl, vec![4]);
    }
}
