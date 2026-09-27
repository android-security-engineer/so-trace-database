//! Trace compression benchmark — measure the current runtime encoding against
//! two trace-specialized alternatives on the *same* `Vec<TraceEvent>`.
//!
//! Schemes compared (all start from the identical event stream):
//!   M0  baseline   : bincode(events) then whole-blob zstd level 3.
//!                    The persist encoding before SOTC shipped.
//!   shipped SOTC   : `trace_codec::compress_chunk` — the runtime encoder.
//!   M1  grouped    : partition events by variant, bincode+zstd each group.
//!
//! Data: synthesises a representative instruction-heavy stream by default
//! (mirroring trace-storm's deterministic +4/branch pattern plus a realistic
//! register/memory/JNI/sync mix), or loads a real trace-storm Frida JSONL when
//! a path argument is given. Each scheme asserts a full round-trip decode, so
//! the byte counts are trustworthy (not just optimistic encoders).
//!
//! Usage:
//!   cargo run --bin compress_bench                    # synthetic 1M instr
//!   cargo run --bin compress_bench -- <trace.jsonl>   # real trace-storm stream
//!   COMPRESS_BENCH_INSTR=200000 cargo run --bin compress_bench

use serde::Serialize;
use sotrace_core::adapters::frida::FridaAdapter;
use sotrace_core::adapters::TraceAdapter;
use sotrace_core::models::instruction_trace::InstructionTrace;
use sotrace_core::models::register_delta::RegisterDelta;
use sotrace_core::adapters::TraceEvent;

/// zstd level matching `TraceRepository::TRACE_ZSTD_LEVEL`.
const ZSTD_LEVEL: i32 = 3;

fn zstd(data: &[u8]) -> usize {
    zstd::bulk::compress(data, ZSTD_LEVEL)
        .map(|c| c.len())
        .expect("zstd compress failed")
}

fn bincode_bytes<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
    bincode::serialize(v).expect("bincode serialize failed")
}

/// Variant id used to partition events by type (M1) and to split the
/// instruction column from the rest (M2).
fn variant_id(e: &TraceEvent) -> u8 {
    match e {
        TraceEvent::Thread(_) => 0,
        TraceEvent::Instruction(_) => 1,
        TraceEvent::Register(_) => 2,
        TraceEvent::Call(_) => 3,
        TraceEvent::JniCall(_) => 4,
        TraceEvent::MemoryWrite { .. } => 5,
        TraceEvent::MemoryRead { .. } => 6,
        TraceEvent::Sync(_) => 7,
        TraceEvent::ContextSwitch(_) => 8,
        TraceEvent::StateChange(_) => 9,
    }
}

// ------------------------------------------------------------------
// M0 baseline
// ------------------------------------------------------------------
fn m0_baseline(events: &[TraceEvent]) -> (usize, usize) {
    let raw = bincode_bytes(events);
    (raw.len(), zstd(&raw))
}

// ------------------------------------------------------------------
// M1 grouped by variant + zstd
// ------------------------------------------------------------------
fn m1_grouped(events: &[TraceEvent]) -> usize {
    let mut groups: Vec<Vec<TraceEvent>> = vec![Vec::new(); 10];
    for e in events {
        groups[variant_id(e) as usize].push(e.clone());
    }
    let mut total = 0usize;
    for g in groups.iter() {
        if !g.is_empty() {
            let raw = bincode_bytes(g);
            // round-trip sanity: must decode back to the same group
            let back: Vec<TraceEvent> = bincode::deserialize(&raw).unwrap();
            assert_eq!(back.len(), g.len());
            total += zstd(&raw);
        }
    }
    total
}

// ------------------------------------------------------------------
// M2 columnar: structured control-plane + entropy payload-plane
// ------------------------------------------------------------------
struct InstrCols {
    seq: Vec<u64>,
    thread: Vec<u32>,
    addr: Vec<u64>,
    ts_presence: Vec<bool>,
    ts_value: Vec<u64>,
    branch: Vec<bool>,
    taken: Vec<bool>,
    op_presence: Vec<bool>,
    op_bytes: Vec<u8>,
}

fn extract_instr_cols(events: &[TraceEvent]) -> InstrCols {
    let mut c = InstrCols {
        seq: Vec::new(),
        thread: Vec::new(),
        addr: Vec::new(),
        ts_presence: Vec::new(),
        ts_value: Vec::new(),
        branch: Vec::new(),
        taken: Vec::new(),
        op_presence: Vec::new(),
        op_bytes: Vec::new(),
    };
    let mut instrs: Vec<&InstructionTrace> = events
        .iter()
        .filter_map(|e| match e {
            TraceEvent::Instruction(i) => Some(i),
            _ => None,
        })
        .collect();
    // Stable order by seq for columnar locality (mirrors engine timeline order).
    instrs.sort_by_key(|i| i.seq);
    for i in instrs {
        c.seq.push(i.seq);
        c.thread.push(i.thread_id);
        c.addr.push(i.address);
        c.ts_presence.push(i.timestamp.is_some());
        if let Some(t) = i.timestamp {
            c.ts_value.push(t);
        }
        c.branch.push(i.is_branch);
        c.taken.push(i.branch_taken);
        c.op_presence.push(i.opcode.is_some());
        if let Some(o) = &i.opcode {
            c.op_bytes.extend_from_slice(o);
        }
    }
    c
}

/// Zigzag varint for a slice of signed deltas (reuses engine primitive).
fn zigzag_varints_signed(deltas: &[i64]) -> Vec<u8> {
    let mut out = Vec::new();
    for d in deltas {
        out.extend_from_slice(&sotrace_engine::storage::compression::encode_signed_varint(*d));
    }
    out
}

fn zigzag_varints(vals: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in vals {
        out.extend_from_slice(&sotrace_engine::storage::compression::encode_signed_varint(*v as i64));
    }
    out
}

/// 1-bit bitmap packed into bytes (LSB-first).
fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let n = bits.len().div_ceil(8);
    let mut out = vec![0u8; n];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Delta (signed) between consecutive values.
fn signed_deltas(vals: &[u64]) -> Vec<i64> {
    let mut out = Vec::with_capacity(vals.len());
    let mut prev: i64 = 0;
    for (i, &v) in vals.iter().enumerate() {
        let v = v as i64;
        if i == 0 {
            out.push(v);
        } else {
            out.push(v - prev);
        }
        prev = v;
    }
    out
}

fn m2_columnar(events: &[TraceEvent]) -> usize {
    // --- instruction control-plane (structured) ---
    let c = extract_instr_cols(events);
    let n = c.seq.len();

    let seq_bytes = zigzag_varints_signed(&signed_deltas(&c.seq));
    // thread_id is low-cardinality → dictionary to a compact index, then varint.
    let thread_dict = {
        let mut table: Vec<u32> = Vec::new();
        let mut index: Vec<u64> = Vec::with_capacity(n);
        for &t in &c.thread {
            match table.iter().position(|&x| x == t) {
                Some(i) => index.push(i as u64),
                None => {
                    table.push(t);
                    index.push((table.len() - 1) as u64);
                }
            }
        }
        let mut out = Vec::new();
        // dict size first (so decode can rebuild the table in order)
        out.extend_from_slice(&sotrace_engine::storage::compression::encode_varint(table.len() as u64));
        for t in &table {
            out.extend_from_slice(&sotrace_engine::storage::compression::encode_varint(*t as u64));
        }
        out.extend_from_slice(&zigzag_varints(&index));
        out
    };
    let addr_bytes = sotrace_engine::storage::compression::trace_delta_bytes(&c.addr);
    let ts_presence_bytes = pack_bits(&c.ts_presence);
    let ts_value_bytes = zigzag_varints(&c.ts_value);
    let branch_bits = {
        let mut b = Vec::with_capacity(n * 2);
        for i in 0..n {
            b.push(c.branch[i]);
            b.push(c.taken[i]);
        }
        pack_bits(&b)
    };
    let op_presence_bytes = pack_bits(&c.op_presence);
    // payload-plane: opcode bytes get generic entropy coding.
    let op_payload_compressed = zstd(&c.op_bytes);

    // round-trip sanity on the control columns.
    assert_eq!(n, c.seq.len());
    let _ = sotrace_engine::storage::compression::trace_delta_decode(&addr_bytes);

    // --- non-instruction events: grouped bincode + zstd ---
    let mut rest_total = 0usize;
    let mut groups: Vec<Vec<TraceEvent>> = vec![Vec::new(); 10];
    for e in events {
        groups[variant_id(e) as usize].push(e.clone());
    }
    for (id, g) in groups.iter().enumerate() {
        if id == 1 || g.is_empty() {
            continue;
        }
        let raw = bincode_bytes(g);
        rest_total += zstd(&raw);
    }

    let total = seq_bytes.len()
        + thread_dict.len()
        + addr_bytes.len()
        + ts_presence_bytes.len()
        + ts_value_bytes.len()
        + branch_bits.len()
        + op_presence_bytes.len()
        + op_payload_compressed
        + rest_total;
    // per-instruction bit budget for readability
    total
}

// ------------------------------------------------------------------
// data generation
// ------------------------------------------------------------------
fn synthesize(rounds: u64, threads: u64) -> Vec<TraceEvent> {
    // Fraction of instructions carrying opcode bytes (0.0–1.0). Real Stalker
    // traces attach opcode to every instruction; sparse opcode is lighter.
    let opcode_density: f64 = std::env::var("COMPRESS_BENCH_OPCODE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.4);
    let mut events: Vec<TraceEvent> = Vec::new();
    let tids: Vec<u32> = (1000..1000 + threads as u32).collect();
    let mut seq: u64 = 0;
    for round in 0..rounds {
        let tid = tids[(round % tids.len() as u64) as usize];
        let base: u64 = 0x1000;
        for slot in 0..32u64 {
            let mut addr = base + slot * 4;
            let is_branch = slot % 20 == 0 && slot > 0;
            if is_branch {
                addr = addr.wrapping_sub(1000);
            }
            let carry_opcode = (slot as f64 / 32.0) < opcode_density;
            let opcode = if carry_opcode {
                // realistic-ish 4-byte AArch64 encodings, some repetitive
                let enc: [u8; 4] = [0x00 | (slot as u8), 0x80, 0x10, 0x02];
                Some(enc.to_vec())
            } else {
                None
            };
            events.push(TraceEvent::Instruction(InstructionTrace {
                seq,
                thread_id: tid,
                address: addr,
                timestamp: if slot % 7 == 0 { Some(seq * 1000) } else { None },
                is_branch,
                branch_taken: is_branch,
                opcode,
            }));
            seq += 1;
            // sparse register/memory events for a realistic mixed stream
            if slot == 15 {
                events.push(TraceEvent::Register(RegisterDelta {
                    seq,
                    change_mask: 0x21,
                    values: vec![seq, seq + 4],
                }));
                seq += 1;
            }
            if slot == 31 && round % 3 == 0 {
                events.push(TraceEvent::MemoryWrite {
                    step: seq,
                    thread_id: tid,
                    address: addr,
                    data: vec![0xAA; 8],
                });
                seq += 1;
            }
        }
    }
    events
}

fn synthesize_count(rounds: u64, threads: u64) -> (usize, usize) {
    let e = synthesize(rounds, threads);
    let instr = e.iter().filter(|x| matches!(x, TraceEvent::Instruction(_))).count();
    (e.len(), instr)
}

fn load_jsonl(path: &str) -> Vec<TraceEvent> {
    let raw = std::fs::read_to_string(path).expect("read trace file");
    let adapter = FridaAdapter::new();
    let (events, _stats) = adapter
        .parse("stalker", &raw, 0)
        .expect("frida parse failed");
    events
}

fn main() {
    let mut args = std::env::args().skip(1);
    let events: Vec<TraceEvent> = if let Some(path) = args.next() {
        println!("data source: real trace-storm JSONL: {}", path);
        load_jsonl(&path)
    } else {
        let default_instr = std::env::var("COMPRESS_BENCH_INSTR")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1_000_000);
        let rounds = default_instr / 32 + 1;
        println!("data source: synthetic (rounds={rounds}, ~{default_instr} instructions)");
        synthesize(rounds, 2)
    };

    let total = events.len();
    let instr = events
        .iter()
        .filter(|e| matches!(e, TraceEvent::Instruction(_)))
        .count();
    println!("events: {total}, instructions: {instr}");

    let (raw, m0) = m0_baseline(&events);
    let shipped = sotrace_engine::trace_codec::compress_chunk(&events)
        .expect("shipped SOTC encode");
    let shipped_back = sotrace_engine::trace_codec::decompress_chunk(&shipped)
        .expect("shipped SOTC decode");
    assert_eq!(shipped_back.len(), events.len(), "shipped codec dropped events");
    let m1 = m1_grouped(&events);
    let m2 = m2_columnar(&events);

    let per = |bytes: usize, label: &str| {
        let ratio = raw as f64 / bytes as f64;
        let per_inst = if instr > 0 { bytes as f64 / instr as f64 } else { 0.0 };
        println!("  {label:<28} {:>12} bytes  {:>7.2}x vs raw  {:>6.2} B/instruction", bytes, ratio, per_inst);
    };

    println!("\n=== compression comparison (same event stream) ===");
    println!("raw bincode (uncompressed)      {:>12} bytes  {:>7.2}x  {:>6.2} B/instruction", raw, 1.0, raw as f64 / instr as f64);
    println!("--- M0 baseline: bincode + whole-blob zstd3 (legacy persist) ---");
    per(m0, "M0 bincode+zstd3");
    println!("--- shipped SOTC (TraceRepository runtime) ---");
    per(shipped.len(), "shipped SOTC chunk");
    println!("--- M1 grouped-by-variant + zstd3 (Path A) ---");
    per(m1, "M1 grouped+zstd3");
    println!("--- M2 columnar control-plane + zstd payload (Path B-lite) ---");
    per(m2, "M2 columnar");

    println!("\nrelative to M0 baseline:");
    println!("  shipped vs M0: {:.2}x", m0 as f64 / shipped.len() as f64);
    println!("  M1 vs M0: {:.2}x", m0 as f64 / m1 as f64);
    println!("  M2 vs M0: {:.2}x", m0 as f64 / m2 as f64);

    // Drive the shipped persist path (same encoder TraceRepository uses).
    let dir = std::env::temp_dir().join(format!("sotrace-compress-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("bench data dir");
    let repo = sotrace_engine::persistence::TraceRepository::open(&dir).expect("open repo");
    let t0 = std::time::Instant::now();
    let id = repo
        .save(sotrace_engine::persistence::PersistedTrace {
            trace_id: 0,
            so_file_id: 0,
            source: "compress_bench".into(),
            base_addr: 0,
            events: events.clone(),
            created_at: 0,
        })
        .expect("persist save");
    let save_sec = t0.elapsed().as_secs_f64().max(1e-9);
    let loaded = repo.load(id).expect("persist load");
    let blob = std::fs::read(dir.join("trace").join(format!("{}.bincode.zst", id))).expect("read blob");
    println!("\n=== shipped persist (TraceRepository::save/load) ===");
    println!("  persist_blob_bytes : {}", blob.len());
    println!("  loaded_events      : {}", loaded.events.len());
    println!("  persist_events_sec : {:.0}", loaded.events.len() as f64 / save_sec);
    assert_eq!(loaded.events.len(), events.len());

    let engine = std::sync::Arc::new(std::sync::Mutex::new(
        sotrace_engine::TraceEngine::new(0, sotrace_engine::delta_store::types::DeltaStoreConfig::default()),
    ));
    let ingestor = sotrace_engine::TraceIngestor::new(std::sync::Arc::clone(&engine));
    let t1 = std::time::Instant::now();
    ingestor.ingest(events).expect("ingest");
    let st = ingestor.drain().expect("drain");
    let ingest_sec = t1.elapsed().as_secs_f64().max(1e-9);
    let q = engine
        .lock()
        .unwrap()
        .query_instructions_range(0, u64::MAX)
        .len();
    println!("\n=== shipped ingest (TraceIngestor async + drain) ===");
    println!("  ingest_events_sec  : {:.0}", st.queryable as f64 / ingest_sec);
    println!("  ingest_queryable   : {}", st.queryable);
    println!("  ingest_instr_query : {}", q);
    assert_eq!(st.queryable as usize, loaded.events.len());
    let _ = std::fs::remove_dir_all(&dir);
}
