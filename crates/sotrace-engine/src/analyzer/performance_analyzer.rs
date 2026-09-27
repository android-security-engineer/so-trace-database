//! Performance analyzer — instruction frequency, branch statistics, address range queries

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use sotrace_core::models::instruction_trace::InstructionTrace;

// ============================================================================
// Hot Paths
// ============================================================================

/// A single entry in the hot-path ranking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPathEntry {
    /// SO-relative address of the instruction.
    pub address: u64,
    /// How many times this address was executed across all threads.
    pub hit_count: u64,
    /// Which thread IDs executed this address.
    pub thread_ids: Vec<u64>,
    /// Whether the instruction at this address is a branch.
    pub is_branch: bool,
}

/// Result of `analyze_hot_paths`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPathsResult {
    /// Top-N entries, sorted by `hit_count` descending.
    pub entries: Vec<HotPathEntry>,
    /// Total number of instructions in the trace.
    pub total_instructions: u64,
    /// Number of distinct addresses executed.
    pub unique_addresses: u64,
    /// The `top_n` value that was requested.
    pub top_n: usize,
}

/// Aggregate instruction execution counts across all threads.
pub fn analyze_hot_paths(instructions: &[InstructionTrace], top_n: usize) -> HotPathsResult {
    // addr → (hit_count, thread_set, is_branch)
    let mut counts: HashMap<u64, (u64, HashSet<u32>, bool)> = HashMap::new();

    for insn in instructions {
        let entry = counts.entry(insn.address).or_insert((0, HashSet::new(), insn.is_branch));
        entry.0 += 1;
        entry.1.insert(insn.thread_id);
        if insn.is_branch {
            entry.2 = true;
        }
    }

    let total_instructions = instructions.len() as u64;
    let unique_addresses = counts.len() as u64;

    let mut entries: Vec<HotPathEntry> = counts
        .into_iter()
        .map(|(address, (hit_count, thread_set, is_branch))| {
            let mut thread_ids: Vec<u64> = thread_set.into_iter().map(|t| t as u64).collect();
            thread_ids.sort_unstable();
            HotPathEntry { address, hit_count, thread_ids, is_branch }
        })
        .collect();

    entries.sort_unstable_by(|a, b| b.hit_count.cmp(&a.hit_count));
    entries.truncate(top_n);

    HotPathsResult { entries, total_instructions, unique_addresses, top_n }
}

// ============================================================================
// Branch Statistics
// ============================================================================

/// Statistics for a single branch address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchStat {
    /// Address of the branch instruction.
    pub address: u64,
    /// Total times this branch was reached.
    pub total: u64,
    /// Times the branch was taken.
    pub taken: u64,
    /// Times the branch was not taken.
    pub not_taken: u64,
    /// Fraction taken (taken / total), 0.0–1.0.
    pub taken_ratio: f64,
}

/// Result of `analyze_branch_stats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchStatsResult {
    /// All branch stats, sorted by `total` descending.
    pub branches: Vec<BranchStat>,
    /// Total branch executions across all addresses.
    pub total_branches: u64,
    /// Branches that were always taken (taken_ratio == 1.0).
    pub always_taken: u64,
    /// Branches that were never taken (taken_ratio == 0.0).
    /// These are interesting for anti-debug detection (ptrace branch never fires).
    pub always_not_taken: u64,
    /// Branches with variable behaviour (0.0 < taken_ratio < 1.0).
    pub variable: u64,
}

/// Compute taken/not-taken statistics for every branch instruction in the trace.
pub fn analyze_branch_stats(instructions: &[InstructionTrace]) -> BranchStatsResult {
    // addr → (taken, not_taken)
    let mut counts: HashMap<u64, (u64, u64)> = HashMap::new();

    for insn in instructions {
        if !insn.is_branch {
            continue;
        }
        let entry = counts.entry(insn.address).or_insert((0, 0));
        if insn.branch_taken {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }

    let mut total_branches = 0u64;
    let mut always_taken = 0u64;
    let mut always_not_taken = 0u64;
    let mut variable = 0u64;

    let mut branches: Vec<BranchStat> = counts
        .into_iter()
        .map(|(address, (taken, not_taken))| {
            let total = taken + not_taken;
            let taken_ratio = if total == 0 { 0.0 } else { taken as f64 / total as f64 };

            total_branches += total;
            if taken_ratio >= 1.0 {
                always_taken += 1;
            } else if taken_ratio <= 0.0 {
                always_not_taken += 1;
            } else {
                variable += 1;
            }

            BranchStat { address, total, taken, not_taken, taken_ratio }
        })
        .collect();

    branches.sort_unstable_by(|a, b| b.total.cmp(&a.total));

    BranchStatsResult { branches, total_branches, always_taken, always_not_taken, variable }
}

// ============================================================================
// Address Range Query
// ============================================================================

/// Parameters for a range-based instruction query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRangeQuery {
    /// Inclusive lower bound (SO-relative address).
    pub from_address: u64,
    /// Inclusive upper bound (SO-relative address).
    pub to_address: u64,
    /// If set, only return instructions from this thread.
    pub thread_id: Option<u64>,
    /// Maximum number of results (default: 10_000).
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize { 10_000 }

impl Default for AddressRangeQuery {
    fn default() -> Self {
        Self {
            from_address: 0,
            to_address: u64::MAX,
            thread_id: None,
            limit: default_limit(),
        }
    }
}

/// A single instruction execution record returned by an address-range query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionHit {
    pub seq: u64,
    pub thread_id: u64,
    pub address: u64,
    pub is_branch: bool,
    pub branch_taken: bool,
}

/// Filter instructions by address range (and optionally by thread), returning
/// up to `query.limit` results sorted by `seq`.
pub fn query_address_range(instructions: &[InstructionTrace], query: &AddressRangeQuery) -> Vec<InstructionHit> {
    let mut hits: Vec<InstructionHit> = instructions
        .iter()
        .filter(|i| {
            i.address >= query.from_address
                && i.address <= query.to_address
                && query.thread_id.map_or(true, |tid| i.thread_id as u64 == tid)
        })
        .map(|i| InstructionHit {
            seq: i.seq,
            thread_id: i.thread_id as u64,
            address: i.address,
            is_branch: i.is_branch,
            branch_taken: i.branch_taken,
        })
        .collect();

    hits.sort_unstable_by_key(|h| h.seq);
    hits.truncate(query.limit);
    hits
}
