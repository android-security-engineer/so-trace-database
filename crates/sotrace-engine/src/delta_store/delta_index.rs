// Delta index — accelerated query indexes built on delta storage
//
// The key insight: delta storage gives us compact storage, but naive
// reconstruction is O(delta_count). Indexes allow us to skip deltas
// and jump directly to the relevant ones, making queries O(log N).
//
// # Index Types
//
// 1. **SkipListIndex** — for timeline-based queries: "find nearest snapshot before step N"
// 2. **AddressIndex** — for spatial queries: "which steps touched address X?"
// 3. **ThreadIndex** — for thread-scoped queries: "all deltas for thread T"
// 4. **FunctionIndex** — for function-scoped queries: "all deltas related to function F"
//
// # How Delta Indexes Accelerate Queries
//
// Without indexes, reconstructing state at step N requires:
//   1. Find nearest snapshot (linear scan) → O(S) where S = snapshot count
//   2. Apply all deltas from snapshot to N → O(D) where D = delta count per interval
//
// With indexes:
//   1. Find nearest snapshot (skip list) → O(log S)
//   2. Find relevant deltas (address/thread/function index) → O(log D)
//   3. Apply only relevant deltas → O(K) where K = actual changes to target entity

use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hasher};

/// Integer hasher for the step indexes.
///
/// Address and thread indexes are touched once per imported event. `std`'s
/// default hasher is SipHash, which dominates that loop. This mixer is a
/// multiply-xor over a per-map random seed so a remote client cannot precompute
/// colliding keys (the import endpoint accepts caller-supplied addresses).
#[derive(Clone)]
struct IndexBuildHasher {
    seed: u64,
}

impl Default for IndexBuildHasher {
    fn default() -> Self {
        Self { seed: index_hash_seed() }
    }
}

impl BuildHasher for IndexBuildHasher {
    type Hasher = IndexHasher;

    fn build_hasher(&self) -> Self::Hasher {
        IndexHasher {
            hash: self.seed,
            seed: self.seed,
        }
    }
}

struct IndexHasher {
    hash: u64,
    seed: u64,
}

impl Hasher for IndexHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(b as u64);
        }
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.hash = (self.hash ^ i).wrapping_mul(0x517cc1b727220a95) ^ self.seed;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

fn index_hash_seed() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0x9e3779b97f4a7c15);
    // Mix a process-local counter with the address of this function so two
    // indexes in one process do not share a seed an importer could learn.
    let n = COUNTER.fetch_add(0x6a09e667f3bcc909, Ordering::Relaxed);
    n ^ (index_hash_seed as *const () as usize as u64).rotate_left(17)
}

type IndexMap<K, V> = HashMap<K, V, IndexBuildHasher>;

/// Insert `step` into a per-key step list, keeping it sorted ascending.
///
/// The common case is an in-order feed (`step` >= last), which is an O(1)
/// push; only out-of-order arrivals pay an O(K) shift. Keeping every list
/// sorted lets lookups binary-search instead of relying on the feed happening
/// to arrive in step order (which trace adapters do not guarantee).
#[inline]
pub(crate) fn insert_step_sorted(steps: &mut Vec<u64>, step: u64) {
    match steps.last() {
        Some(&last) if step < last => {
            let pos = steps.partition_point(|&s| s <= step);
            steps.insert(pos, step);
        }
        _ => steps.push(step),
    }
}

/// Insert `step` into a per-key step list, keeping it sorted ascending AND
/// deduplicated.
///
/// Use this instead of `insert_step_sorted` when the index's `find_steps_for_*`
/// consumers iterate over steps and would double-count a repeated step (e.g.
/// `ThreadIndex`/`FunctionIndex` feeding `query_function_calls` →
/// `get_at_step(seq)` — the same step registered twice expands into two
/// results). `AddressIndex` deliberately keeps duplicates (two writes to the
/// same address at the same step are both real events), so it uses the
/// non-deduplicating variant.
#[inline]
pub(crate) fn insert_step_sorted_dedup(steps: &mut Vec<u64>, step: u64) {
    match steps.last() {
        Some(&last) if step < last => {
            let pos = steps.partition_point(|&s| s <= step);
            // partition_point lands on the first element > step, so an equal
            // step sits at pos-1. Skip the insert when already present.
            if pos > 0 && steps[pos - 1] == step {
                return;
            }
            steps.insert(pos, step);
        }
        Some(&last) if step == last => return, // already present (tail)
        _ => steps.push(step),
    }
}

/// Skip list index — for fast timeline traversal
///
/// Allows O(log N) lookup of:
/// - Nearest snapshot before step N
/// - Deltas in a step range
/// - Total state at any step (by reconstruction chain)
pub struct SkipListIndex {
    /// B-tree mapping step → snapshot ID
    /// O(log N) range queries
    snapshot_steps: BTreeMap<u64, u64>,
    /// Skip list levels for faster traversal (future optimization)
    levels: Vec<BTreeMap<u64, u64>>,
}

impl SkipListIndex {
    /// Create a new skip list index
    pub fn new() -> Self {
        Self {
            snapshot_steps: BTreeMap::new(),
            levels: Vec::new(),
        }
    }

    /// Register a snapshot at a given step
    pub fn register_snapshot(&mut self, step: u64, snapshot_id: u64) {
        self.snapshot_steps.insert(step, snapshot_id);
    }

    /// Find the nearest snapshot before or at target_step — O(log N)
    pub fn find_before(&self, target_step: u64) -> Option<(u64, u64)> {
        // BTreeMap::range gives us O(log N) lookup
        self.snapshot_steps
            .range(..=target_step)
            .next_back()
            .map(|(step, id)| (*step, *id))
    }

    /// Find all steps in a range — O(log N + K)
    pub fn find_range(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        self.snapshot_steps
            .range(start..=end)
            .map(|(step, id)| (*step, *id))
            .collect()
    }
}

impl Default for SkipListIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Address index — for fast spatial queries
///
/// Maps addresses (memory, function entry, instruction) to the step numbers
/// where they were modified. This is the core index for all "what touched X?" queries.
///
/// Without this index: scan ALL deltas → O(total_deltas)
/// With this index: look up address → O(log A + K) where A = unique addresses, K = changes to that address
pub struct AddressIndex {
    /// Address → sorted list of step numbers where this address was involved
    address_to_steps: IndexMap<u64, Vec<u64>>,
}

impl AddressIndex {
    /// Create a new address index
    pub fn new() -> Self {
        Self {
            address_to_steps: IndexMap::default(),
        }
    }

    /// Register that an address was modified at a given step
    #[inline]
    pub fn register(&mut self, address: u64, step: u64) {
        insert_step_sorted(self.address_to_steps.entry(address).or_default(), step);
    }

    /// Deduplicating variant of [`register`](Self::register).
    ///
    /// Use this when the (address, step) pair has function/instruction-entry
    /// semantics — i.e. a repeated registration at the same step is the same
    /// event being indexed twice (a DeltaLog overwrite, or two threads sharing
    /// a `seq`), not two distinct writes. `register` itself preserves
    /// duplicates (real memory-write multiplicity); instruction/jni stores
    /// want one step entry per (address, step) so `find_steps_for_address`
    /// consumers don't double-count.
    #[inline]
    pub fn register_dedup(&mut self, address: u64, step: u64) {
        insert_step_sorted_dedup(self.address_to_steps.entry(address).or_default(), step);
    }

    /// Find all steps where a specific address was modified — O(log K)
    pub fn find_steps_for_address(&self, address: u64) -> &[u64] {
        self.address_to_steps.get(&address).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Find the LAST step where an address was modified before target_step
    /// This is critical for single-address queries: we don't reconstruct all state,
    /// just find when this address last changed.
    pub fn find_last_modification(&self, address: u64, target_step: u64) -> Option<u64> {
        self.address_to_steps.get(&address).and_then(|steps| {
            // `steps` is kept sorted by `register`, so binary-search for the
            // last step <= target_step. O(log K) instead of an O(K) scan.
            let idx = steps.partition_point(|&s| s <= target_step);
            (idx > 0).then(|| steps[idx - 1])
        })
    }
}

impl Default for AddressIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread index — maps thread IDs to their activity steps
pub struct ThreadIndex {
    /// Thread ID → sorted step numbers.
    ///
    /// The thread currently being imported is held in `hot_steps` instead of
    /// the map. A trace stays on one thread for long runs, so this avoids a
    /// hash lookup per event; readers check `hot_id` before the map.
    thread_to_steps: IndexMap<u32, Vec<u64>>,
    hot_id: u32,
    hot_steps: Vec<u64>,
    hot_live: bool,
}

impl ThreadIndex {
    pub fn new() -> Self {
        Self {
            thread_to_steps: IndexMap::default(),
            hot_id: 0,
            hot_steps: Vec::new(),
            hot_live: false,
        }
    }

    #[inline]
    pub fn register(&mut self, thread_id: u32, step: u64) {
        // Dedup: a thread can have several events sharing a `seq` (e.g. a sync
        // event and a state change logged at the same step). The step list
        // feeds `find_steps_for_thread`, whose consumers (e.g. instruction
        // range queries, thread-state reconstruction) iterate steps and call
        // `get_at_step(step)` / `get_all(step)` per entry — a repeated step
        // would double-count. Each step needs to appear once; the per-step
        // event multiplicity is preserved by the EventLog, not here.
        self.promote(thread_id);
        insert_step_sorted_dedup(&mut self.hot_steps, step);
    }

    #[inline]
    fn promote(&mut self, thread_id: u32) {
        if self.hot_live && self.hot_id == thread_id {
            return;
        }
        if self.hot_live {
            let steps = std::mem::take(&mut self.hot_steps);
            self.thread_to_steps.insert(self.hot_id, steps);
        }
        self.hot_steps = self.thread_to_steps.remove(&thread_id).unwrap_or_default();
        self.hot_id = thread_id;
        self.hot_live = true;
    }

    pub fn find_steps_for_thread(&self, thread_id: u32) -> &[u64] {
        if self.hot_live && self.hot_id == thread_id {
            return self.hot_steps.as_slice();
        }
        self.thread_to_steps.get(&thread_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

}

impl Default for ThreadIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Function index — maps function addresses to their activity steps
pub struct FunctionIndex {
    /// Function ID → sorted step numbers where this function was active
    func_to_steps: IndexMap<u64, Vec<u64>>,
    /// Function ID → (call_step, return_step) pairs
    func_call_pairs: IndexMap<u64, Vec<(u64, u64)>>,
}

impl FunctionIndex {
    pub fn new() -> Self {
        Self {
            func_to_steps: IndexMap::default(),
            func_call_pairs: IndexMap::default(),
        }
    }

    pub fn register_call(&mut self, func_id: u64, call_step: u64, return_step: Option<u64>) {
        // Dedup call steps: two threads calling the same function at the same
        // `seq` register the same (func_id, step) twice. `find_steps_for_function`
        // consumers (e.g. call_chain handler → `get_at_step(step)`) would
        // otherwise emit each matching call twice. The call multiplicity is
        // preserved by the EventLog (one CallTrace per actual call), not by
        // repeating the step here.
        insert_step_sorted_dedup(self.func_to_steps.entry(func_id).or_default(), call_step);
        if let Some(ret) = return_step {
            self.func_call_pairs.entry(func_id).or_default().push((call_step, ret));
        }
    }

    pub fn find_steps_for_function(&self, func_id: u64) -> &[u64] {
        self.func_to_steps.get(&func_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn find_call_pairs(&self, func_id: u64) -> &[(u64, u64)] {
        self.func_call_pairs.get(&func_id).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

impl Default for FunctionIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_index_keeps_steps_sorted_out_of_order() {
        let mut idx = AddressIndex::new();
        // Feed steps out of order — the index must still store them sorted.
        for step in [50u64, 10, 30, 20, 40] {
            idx.register(0xdead, step);
        }
        assert_eq!(idx.find_steps_for_address(0xdead), &[10, 20, 30, 40, 50]);
    }

    #[test]
    fn test_address_find_last_modification_is_correct_binary_search() {
        let mut idx = AddressIndex::new();
        for step in [50u64, 10, 30, 20, 40] {
            idx.register(0xbeef, step);
        }
        // Exact hit returns that step.
        assert_eq!(idx.find_last_modification(0xbeef, 30), Some(30));
        // Between two steps returns the earlier one.
        assert_eq!(idx.find_last_modification(0xbeef, 35), Some(30));
        // Past the end returns the last.
        assert_eq!(idx.find_last_modification(0xbeef, 999), Some(50));
        // Before the first returns None.
        assert_eq!(idx.find_last_modification(0xbeef, 5), None);
        // Unknown address returns None.
        assert_eq!(idx.find_last_modification(0x1234, 100), None);
    }

    #[test]
    fn test_address_index_duplicate_steps_preserved() {
        let mut idx = AddressIndex::new();
        // Two writes at the same step on the same address (e.g. a write split
        // across an unaligned page boundary) — both are recorded.
        idx.register(0xaa, 5);
        idx.register(0xaa, 5);
        idx.register(0xaa, 3);
        assert_eq!(idx.find_steps_for_address(0xaa), &[3, 5, 5]);
        assert_eq!(idx.find_last_modification(0xaa, 5), Some(5));
    }

    #[test]
    fn test_address_index_register_dedup_collapses_repeated_step() {
        // instruction/jni stores index function/instruction-entry addresses,
        // where a repeated (address, step) is the same event indexed twice
        // (DeltaLog overwrite, or two threads sharing a seq) — not two writes.
        // register_dedup must collapse it so consumers don't double-count.
        let mut idx = AddressIndex::new();
        idx.register_dedup(0x1000, 5);
        idx.register_dedup(0x1000, 5); // same (addr, step)
        idx.register_dedup(0x1000, 3);
        idx.register_dedup(0x1000, 5); // again, out of tail order
        assert_eq!(idx.find_steps_for_address(0x1000), &[3, 5]);
    }

    #[test]
    fn test_thread_index_keeps_steps_sorted_out_of_order() {
        let mut idx = ThreadIndex::new();
        for step in [7u64, 1, 5, 3] {
            idx.register(42, step);
        }
        assert_eq!(idx.find_steps_for_thread(42), &[1, 3, 5, 7]);
        // Consumers binary-search this slice, so a range partition must be exact.
        let steps = idx.find_steps_for_thread(42);
        let lo = steps.partition_point(|&s| s < 3);
        let hi = steps.partition_point(|&s| s <= 5);
        assert_eq!(&steps[lo..hi], &[3, 5]);
    }

    #[test]
    fn test_function_index_keeps_call_steps_sorted_out_of_order() {
        let mut idx = FunctionIndex::new();
        idx.register_call(0xf, 9, None);
        idx.register_call(0xf, 2, None);
        idx.register_call(0xf, 6, None);
        assert_eq!(idx.find_steps_for_function(0xf), &[2, 6, 9]);
    }

    #[test]
    fn test_thread_index_dedups_repeated_step() {
        // A thread with several events sharing one `seq` registers the same
        // (thread, step) multiple times. The step list must collapse to one
        // entry so `find_steps_for_thread` consumers don't double-count.
        let mut idx = ThreadIndex::new();
        idx.register(42, 5);
        idx.register(42, 5); // same step, different event at same seq
        idx.register(42, 3);
        idx.register(42, 7);
        idx.register(42, 5); // again, out of tail position
        assert_eq!(idx.find_steps_for_thread(42), &[3, 5, 7]);
    }

    #[test]
    fn test_function_index_dedups_repeated_call_step() {
        // Two threads calling the same function at the same `seq` register the
        // same (func_id, step) twice — the step must appear once. The actual
        // call multiplicity lives in the EventLog, not the index.
        let mut idx = FunctionIndex::new();
        idx.register_call(0xf, 5, None);
        idx.register_call(0xf, 5, None); // second caller, same seq
        idx.register_call(0xf, 3, None);
        idx.register_call(0xf, 5, None); // third caller, same seq, out of order
        assert_eq!(idx.find_steps_for_function(0xf), &[3, 5]);
        // Call pairs are NOT deduplicated — each real call records its own pair.
        idx.register_call(0xf, 5, Some(8));
        assert_eq!(idx.find_call_pairs(0xf), &[(5, 8)]);
    }
}
