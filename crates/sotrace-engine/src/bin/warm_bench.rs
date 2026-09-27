//! Warm-engine benchmark — the latency the server actually serves.
//!
//! The CLI one-shot `query`/`analyze` commands pay a cold-start cost: each
//! process replays every persisted event to rebuild the engine before running
//! any point query (`TraceRepository::replay_sorted`). The deliverable product
//! (Axum server) instead keeps a warm engine pool, so its per-request latency is
//! *warm*: the actual point query / analysis on an already-built engine.
//!
//! This binary measures exactly that warm path so release-readiness decisions
//! are based on the number users actually hit:
//!   1. cold replay (index rebuild) time — the one-shot CLI / cold-server cost;
//!   2. warm point-query latency (address / instruction-range / memory / register
//!      / timeline) averaged over many trials;
//!   3. full 12-dimension `analyze_threads` latency on the warm engine.
//!
//! Usage:
//!   cargo run --release --bin warm_bench -- <data_dir> <trace_id> [trials]
//!   e.g. keep a trace created by trace-storm bench.sh, then:
//!   cargo run --release --bin warm_bench -- /tmp/bench1m/data 1 50
//!
//! SO symbol registration is skipped (pure engine timing); function-name
//! back-fill on analysis is a minor constant on top.

use std::time::{Duration, Instant};

use sotrace_engine::delta_store::types::DeltaStoreConfig;
use sotrace_engine::engine::TraceEngine;
use sotrace_engine::persistence::TraceRepository;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: warm_bench <data_dir> <trace_id> [trials]");
        std::process::exit(2);
    }
    let data_dir = std::path::Path::new(&args[1]);
    let trace_id: u64 = args[2].parse().map_err(|_| anyhow::anyhow!("bad trace_id"))?;
    let trials: usize = args.get(3).map(|s| s.parse().unwrap_or(50)).unwrap_or(50);

    let repo = TraceRepository::open(data_dir)?;
    let summary = repo
        .summary(trace_id)?
        .ok_or_else(|| anyhow::anyhow!("no persisted trace id {}", trace_id))?;
    if !summary.events_sorted {
        anyhow::bail!("trace {} is not chronological (older index); not benchmarkable", trace_id);
    }

    // ---- 1. cold replay (index rebuild) ----
    let replay_start = Instant::now();
    let (engine, replay) = repo.replay_sorted(
        trace_id,
        |start| {
            let e = TraceEngine::new(start.so_file_id, DeltaStoreConfig::default());
            anyhow::Ok(e)
        },
        |engine, event| {
            engine.feed_event(event)?;
            anyhow::Ok(())
        },
    )?;
    let replay_sec = replay_start.elapsed().as_secs_f64();
    eprintln!("cold replay: {:.3}s for {} events ({:.0} ev/s)",
        replay_sec, replay.event_count, replay.event_count as f64 / replay_sec);

    let engine = engine;
    let n_ev = replay.event_count as u64;

    // ---- helper to bench a closure ----
    fn bench<F: FnMut()>(trials: usize, mut f: F) -> Duration {
        // warm up (page faults, lazy init)
        for _ in 0..5 {
            f();
        }
        let mut s: Vec<f64> = (0..trials)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed().as_secs_f64()
            })
            .collect();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Duration::from_secs_f64(s[s.len() / 2])
    }

    // ---- 2. warm point queries ----
    // address query
    let addr = 0x1000u64;
    let addr_d = bench(trials, || {
        let _ = engine.query_instructions_by_address(addr);
    });
    // instruction range: mid trace
    let half = n_ev / 2;
    let range_d = bench(trials, || {
        let _ = engine.query_instructions_range(half, (half + 1000).min(n_ev));
    });
    // memory value reconstruction
    let mem_d = bench(trials, || {
        let _ = engine.query_memory_value(0x2000, 8, half);
    });
    // register history
    let reg_d = bench(trials, || {
        let _ = engine.query_register_history(0, 0, n_ev.min(10_000));
    });
    // timeline
    let tid = engine.all_thread_ids().into_iter().next().unwrap_or(0);
    let tl_d = bench(trials, || {
        let _ = engine.query_thread_timeline(tid, 0, n_ev);
    });

    // ---- 3. full 12-dimension thread analysis (heavy) ----
    let mut eng = engine;
    let analysis_start = Instant::now();
    let _ = eng.analyze_threads();
    let analysis_sec = analysis_start.elapsed().as_secs_f64();

    println!("warm-engine benchmark (trace={}, events={}, trials={})", trace_id, n_ev, trials);
    println!("  cold_replay_seconds     : {:.3}", replay_sec);
    println!("  cold_replay_event_sec   : {:.0}", n_ev as f64 / replay_sec);
    println!("  warm_addr_query_p50_ms  : {:.3}", addr_d.as_secs_f64() * 1e3);
    println!("  warm_range_query_p50_ms : {:.3}", range_d.as_secs_f64() * 1e3);
    println!("  warm_memory_query_p50_ms: {:.3}", mem_d.as_secs_f64() * 1e3);
    println!("  warm_register_p50_ms    : {:.3}", reg_d.as_secs_f64() * 1e3);
    println!("  warm_timeline_p50_ms    : {:.3}", tl_d.as_secs_f64() * 1e3);
    println!("  full_analysis_seconds   : {:.3}", analysis_sec);
    Ok(())
}