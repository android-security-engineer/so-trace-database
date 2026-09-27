//! Performance and coverage analysis handlers
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/api/v1/traces/{id}/analyze/hot-paths` | Top-N most executed addresses |
//! | GET | `/api/v1/traces/{id}/analyze/branches` | Branch taken/not-taken statistics |
//! | GET | `/api/v1/traces/{id}/instructions/range` | Instructions within an address range |

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::app::AppState;

/// Query params for hot-paths
#[derive(Debug, Deserialize)]
pub struct HotPathsQuery {
    /// Number of top entries to return (default 20, max 200)
    #[serde(default = "default_top")]
    pub top: usize,
}
fn default_top() -> usize {
    20
}

/// Query params for address-range instruction query
#[derive(Debug, Deserialize)]
pub struct InstructionRangeQuery {
    /// Inclusive start address (SO offset, decimal or hex with 0x prefix)
    pub from: Option<u64>,
    /// Inclusive end address (SO offset)
    pub to: Option<u64>,
    /// Filter by thread_id
    pub thread_id: Option<u32>,
    /// Max results (default 1000, max 10000)
    #[serde(default = "default_limit")]
    pub limit: usize,
}
fn default_limit() -> usize {
    1000
}

/// One entry in the hot-paths response
#[derive(Debug, Serialize)]
struct HotPathEntry {
    address: u64,
    hit_count: usize,
    is_branch: bool,
}

pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route(
            "/api/v1/traces/:id/analyze/hot-paths",
            axum::routing::get(hot_paths),
        )
        .route(
            "/api/v1/traces/:id/analyze/branches",
            axum::routing::get(branch_stats),
        )
        .route(
            "/api/v1/traces/:id/instructions/range",
            axum::routing::get(instructions_in_range),
        )
}

/// GET /api/v1/traces/:id/analyze/hot-paths?top=20
///
/// Returns the top-N most frequently executed instruction addresses.
async fn hot_paths(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
    Query(params): Query<HotPathsQuery>,
) -> impl IntoResponse {
    let top = params.top.min(200).max(1);
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    // Collect all instructions and count hits per address
    let all = engine.query_instructions_range(0, u64::MAX);
    let total_instructions = all.len();

    // address → (hit_count, is_branch)
    let mut counts: HashMap<u64, (usize, bool)> = HashMap::new();
    for insn in &all {
        let entry = counts.entry(insn.address).or_insert((0, insn.is_branch));
        entry.0 += 1;
        if insn.is_branch {
            entry.1 = true;
        }
    }

    let unique_addresses = counts.len();

    let mut entries: Vec<HotPathEntry> = counts
        .into_iter()
        .map(|(address, (hit_count, is_branch))| HotPathEntry {
            address,
            hit_count,
            is_branch,
        })
        .collect();

    // Sort descending by hit count
    entries.sort_by(|a, b| b.hit_count.cmp(&a.hit_count));
    entries.truncate(top);

    Json(serde_json::json!({
        "trace_id": trace_id,
        "top_n": top,
        "total_instructions": total_instructions,
        "unique_addresses": unique_addresses,
        "entries": entries,
    }))
}

/// GET /api/v1/traces/:id/analyze/branches
///
/// For every branch instruction, returns taken/not-taken counts.
/// Branches that are always-not-taken may indicate anti-debugging checks.
async fn branch_stats(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let all = engine.query_instructions_range(0, u64::MAX);
    let total_instructions = all.len();

    // address → (taken, not_taken)
    let mut branch_map: HashMap<u64, (u64, u64)> = HashMap::new();
    let mut total_branches: u64 = 0;

    for insn in &all {
        if !insn.is_branch {
            continue;
        }
        total_branches += 1;
        let entry = branch_map.entry(insn.address).or_insert((0, 0));
        if insn.branch_taken {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }

    let mut always_taken: u64 = 0;
    let mut always_not_taken: u64 = 0;
    let mut variable: u64 = 0;

    let branches: Vec<serde_json::Value> = {
        let mut v: Vec<serde_json::Value> = branch_map
            .iter()
            .map(|(addr, (taken, not_taken))| {
                let total = taken + not_taken;
                let taken_ratio = if total > 0 {
                    *taken as f64 / total as f64
                } else {
                    0.0
                };
                if *not_taken == 0 {
                    always_taken += 1;
                } else if *taken == 0 {
                    always_not_taken += 1;
                } else {
                    variable += 1;
                }
                serde_json::json!({
                    "address": addr,
                    "total": total,
                    "taken": taken,
                    "not_taken": not_taken,
                    "taken_ratio": (taken_ratio * 1000.0).round() / 1000.0,
                })
            })
            .collect();
        // Sort by total descending
        v.sort_by(|a, b| {
            b["total"].as_u64().unwrap_or(0).cmp(&a["total"].as_u64().unwrap_or(0))
        });
        v
    };

    Json(serde_json::json!({
        "trace_id": trace_id,
        "total_instructions": total_instructions,
        "total_branches": total_branches,
        "unique_branch_addresses": branches.len(),
        "always_taken": always_taken,
        "always_not_taken": always_not_taken,
        "variable": variable,
        "branches": branches,
    }))
}

/// GET /api/v1/traces/:id/instructions/range?from=0x1000&to=0x2000&thread_id=1&limit=1000
///
/// Returns all instruction executions whose address falls within [from, to].
/// Results are ordered by step (seq) ascending.
async fn instructions_in_range(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
    Query(params): Query<InstructionRangeQuery>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let from = params.from.unwrap_or(0);
    let to = params.to.unwrap_or(u64::MAX);
    let limit = params.limit.min(10_000).max(1);

    let all = engine.query_instructions_range(0, u64::MAX);

    let mut results: Vec<serde_json::Value> = all
        .into_iter()
        .filter(|insn| {
            insn.address >= from
                && insn.address <= to
                && params.thread_id.map_or(true, |tid| insn.thread_id == tid)
        })
        .take(limit)
        .map(|insn| {
            serde_json::json!({
                "seq": insn.seq,
                "thread_id": insn.thread_id,
                "address": insn.address,
                "is_branch": insn.is_branch,
                "branch_taken": insn.branch_taken,
            })
        })
        .collect();

    // already in step order from query_instructions_range (BTreeMap traversal)
    results.sort_by_key(|v| v["seq"].as_u64().unwrap_or(0));

    Json(serde_json::json!({
        "trace_id": trace_id,
        "from_address": from,
        "to_address": to,
        "thread_id": params.thread_id,
        "count": results.len(),
        "limit": limit,
        "instructions": results,
    }))
}
