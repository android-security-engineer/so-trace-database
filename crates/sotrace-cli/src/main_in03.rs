
/// List all persisted SOs in the data directory.
fn run_so_list(data_dir: &Path) -> Result<()> {
    let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
        .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
    let list = repo.list()?;
    if list.is_empty() {
        println!("No SOs persisted in {}.", data_dir.join("so").display());
        return Ok(());
    }
    println!("{:<6} {:<10} {:<8} {:<10} {:<40} PATH", "ID", "ARCH", "FUNCS", "JNI", "SHA256(prefix)");
    for s in list {
        println!(
            "{:<6} {:<10} {:<8} {:<10} {:<40} {}",
            s.id, s.arch, s.function_count, s.jni_function_count,
            &s.sha256[..12.min(s.sha256.len())], s.path,
        );
    }
    Ok(())
}

/// Show details of a persisted SO by ID.
fn run_so_show(data_dir: &Path, so_id: u64) -> Result<()> {
    let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
        .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
    let parsed = repo.load(so_id)
        .with_context(|| format!("no persisted SO with id {} in {}", so_id, data_dir.display()))?;
    let so = &parsed.so_file;
    println!("SO id: {}", so_id);
    println!("  path         : {}", so.path);
    println!("  architecture : {:?}", so.arch);
    if let Some(bid) = &so.build_id {
        println!("  build_id     : {}", hex(bid));
    } else {
        println!("  build_id     : (none)");
    }
    println!("  file size    : {} bytes", so.file_size);
    println!("  sha256       : {}", hex(&so.sha256));
    println!("  segments     : {}", parsed.segments.len());
    println!("  symbols      : {}", parsed.symbols.len());
    println!("  functions    : {}", parsed.functions.len());
    println!("    JNI        : {}", parsed.jni_function_count());
    println!("    exported   : {}", parsed.exported_function_count());
    Ok(())
}

/// Delete a persisted SO by ID.
fn run_so_delete(data_dir: &Path, so_id: u64) -> Result<()> {
    let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
        .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
    if repo.delete(so_id)? {
        println!("Deleted SO id={}.", so_id);
    } else {
        println!("No SO with id={} found.", so_id);
    }
    Ok(())
}

/// Persist a trace's normalized event stream so it can be replayed later via
/// `analyze`/`query --trace-id` without re-parsing the source file.
fn run_trace_save(
    data_dir: &Path,
    trace_file: PathBuf,
    so_id: u64,
    format: TraceFormat,
    base_addr: u64,
    so: Option<PathBuf>,
    created_at: u64,
) -> Result<()> {
    // If --so is given, persist the SO first and use its (possibly deduped) ID
    // as the trace's so_file_id, so replays can backfill function names.
    let resolved_so_id = if let Some(so_path) = &so {
        let parsed = sotrace_engine::elf::parse_elf(so_path)
            .with_context(|| format!("failed to parse SO file: {}", so_path.display()))?;
        let so_repo = sotrace_engine::persistence::SoRepository::open(data_dir)
            .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
        so_repo.save(&parsed)?.id
    } else {
        so_id
    };

    // Compute the source label before `format` is moved into load_engine.
    let source = format
        .adapter()
        .map(|(a, t)| format!("{}:{}", a, t))
        .unwrap_or_else(|| "native".to_string());

    // Load (parse) the trace into events + an engine we discard. quiet=true so
    // stdout stays clean for the trace_id line.
    let (_engine, _imported, events) = load_engine(
        data_dir,
        Some(&trace_file),
        None,
        resolved_so_id,
        format,
        base_addr,
        &None, // SO already persisted above; load_engine will load it by id.
        true,
    )?;

    let trace = sotrace_engine::persistence::PersistedTrace {
        trace_id: 0, // auto-assigned by the repository
        so_file_id: resolved_so_id,
        source,
        base_addr,
        events,
        created_at,
    };

    let trace_repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
        .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
    let id = trace_repo.save(trace)?;

    println!("{}", id);
    Ok(())
}

/// List all persisted traces in the data directory.
fn run_trace_list(data_dir: &Path) -> Result<()> {
    let repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
        .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
    let list = repo.list()?;
    if list.is_empty() {
        println!("No traces persisted in {}.", data_dir.join("trace").display());
        return Ok(());
    }
    println!("{:<6} {:<8} {:<24} {:<12} {:<12} CREATED", "ID", "SO_ID", "SOURCE", "EVENTS", "BASE_ADDR");
    for s in list {
        println!(
            "{:<6} {:<8} {:<24} {:<12} 0x{:<10x} {}",
            s.trace_id, s.so_file_id, s.source, s.event_count, s.base_addr, s.created_at,
        );
    }
    Ok(())
}

/// Show details of a persisted trace by ID.
fn run_trace_show(data_dir: &Path, trace_id: u64) -> Result<()> {
    let repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
        .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
    let summary = repo.summary(trace_id)?
        .ok_or_else(|| anyhow::anyhow!("no persisted trace with id {} in {}", trace_id, data_dir.display()))?;
    println!("Trace id: {}", summary.trace_id);
    println!("  so_file_id   : {}", summary.so_file_id);
    println!("  source       : {}", summary.source);
    println!("  base_addr    : 0x{:x}", summary.base_addr);
    println!("  event_count  : {}", summary.event_count);
    println!("  created_at   : {}", summary.created_at);
    Ok(())
}

/// Delete a persisted trace by ID.
fn run_trace_delete(data_dir: &Path, trace_id: u64) -> Result<()> {
    let repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
        .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
    if repo.delete(trace_id)? {
        println!("Deleted trace id={}.", trace_id);
    } else {
        println!("No trace with id={} found.", trace_id);
    }
    Ok(())
}

/// Lowercase hex encoding of a byte slice (no 0x prefix).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Feed adapter-produced events into the engine in chronological order.
///
/// Takes a borrowed slice so the caller may keep the events (e.g. to persist
/// them via `TraceRepository`). A sorted owned copy is made internally.
fn feed_events(
    engine: &mut TraceEngine,
    events: &[TraceEvent],
    imported: &mut ImportedCounts,
) -> Result<()> {
    // Chronological batch apply: `TraceEngine::feed_events` sorts by step
    // (stable; skipped when the slice is already non-decreasing) and writes
    // each instruction into the instruction store. Counts come from the
    // borrowed slice; they do not depend on order.
    engine.feed_events(events.iter().cloned())?;
    for ev in events {
        match ev {
            TraceEvent::Thread(_) => imported.threads += 1,
            TraceEvent::Instruction(_) => imported.instructions += 1,
            TraceEvent::Register(_) => imported.register_deltas += 1,
            TraceEvent::Call(_) => imported.calls += 1,
            TraceEvent::JniCall(_) => imported.jni_calls += 1,
            TraceEvent::MemoryWrite { .. } => imported.memory_writes += 1,
            TraceEvent::MemoryRead { .. } => imported.memory_reads += 1,
            TraceEvent::Sync(_) => imported.sync_events += 1,
            TraceEvent::ContextSwitch(_) => imported.context_switches += 1,
            TraceEvent::StateChange(_) => imported.state_changes += 1,
        }
    }
    Ok(())
}

/// Convert a parsed native envelope into a uniform `TraceEvent` stream.
///
/// This is the persistence pivot: the same event vector is (a) fed to the
/// engine via [`feed_events`] for live analysis, and (b) serialized by
/// `TraceRepository` for later replay. Only envelope fields that exist are
/// converted (native envelopes carry no JNI events).
fn envelope_to_events(envelope: &TraceEnvelope) -> Result<Vec<TraceEvent>> {
    let mut events = Vec::new();
    for t in &envelope.threads {
        events.push(TraceEvent::Thread(t.clone()));
    }
    for i in &envelope.instructions {
        events.push(TraceEvent::Instruction(i.clone()));
    }
    for r in &envelope.register_deltas {
        events.push(TraceEvent::Register(r.clone()));
    }
    for c in &envelope.calls {
        events.push(TraceEvent::Call(c.clone()));
    }
    for w in &envelope.memory_writes {
        let mw = parse_memory_write(w)?;
        events.push(TraceEvent::MemoryWrite {
            step: mw.step,
            thread_id: mw.thread_id,
            address: mw.address,
            data: mw.data,
        });
    }
    for r in &envelope.memory_reads {
        let (step, thread_id, address, size) = parse_memory_read(r)?;
        events.push(TraceEvent::MemoryRead { step, thread_id, address, size });
    }
    for e in &envelope.sync_events {
        events.push(TraceEvent::Sync(e.clone()));
    }
    for s in &envelope.context_switches {
        events.push(TraceEvent::ContextSwitch(s.clone()));
    }
    for c in &envelope.state_changes {
        events.push(TraceEvent::StateChange(c.clone()));
    }
    for j in &envelope.jni_calls {
        events.push(TraceEvent::JniCall(j.clone()));
    }
    Ok(events)
}

#[derive(Default)]
struct ImportedCounts {
    threads: usize,
    instructions: usize,
    register_deltas: usize,
    calls: usize,
    jni_calls: usize,
    memory_writes: usize,
    memory_reads: usize,
    sync_events: usize,
    context_switches: usize,
    state_changes: usize,
}

fn parse_addr_arg(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn parse_memory_write(v: &Value) -> Result<MemoryWrite> {
    let step = v.get("step").and_then(|x| x.as_u64())
        .context("memory_write missing 'step'")?;
    let thread_id = v.get("thread_id").and_then(|x| x.as_u64())
        .context("memory_write missing 'thread_id'")? as u32;
    let address = v.get("address").and_then(|x| x.as_u64())
        .context("memory_write missing 'address'")?;
    let data: Vec<u8> = v.get("data")
        .and_then(|x| serde_json::from_value(x.clone()).ok())
        .unwrap_or_default();
    Ok(MemoryWrite { step, thread_id, address, data })
}

fn parse_memory_read(v: &Value) -> Result<(u64, u32, u64, usize)> {
    let step = v.get("step").and_then(|x| x.as_u64())
        .context("memory_read missing 'step'")?;
    let thread_id = v.get("thread_id").and_then(|x| x.as_u64())
        .context("memory_read missing 'thread_id'")? as u32;
    let address = v.get("address").and_then(|x| x.as_u64())
        .context("memory_read missing 'address'")?;
    let size = v.get("size").and_then(|x| x.as_u64()).unwrap_or(1) as usize;
    Ok((step, thread_id, address, size))
}

fn build_json_output(engine: &mut TraceEngine, only: Option<AnalysisDim>) -> Result<Value> {
    use serde_json::json;
    Ok(match only {
        None => serde_json::to_value(engine.analyze_threads())?,
        Some(AnalysisDim::Races) => json!({ "race_conditions": engine.detect_race_conditions() }),
        Some(AnalysisDim::Deadlocks) => json!({ "deadlock_risks": engine.detect_deadlocks() }),
        Some(AnalysisDim::Contentions) => json!({ "lock_contentions": engine.analyze_lock_contention() }),
        Some(AnalysisDim::Safety) => json!({ "function_safety": engine.classify_function_thread_safety() }),
        Some(AnalysisDim::FunctionAssoc) => json!({ "thread_function_assocs": engine.analyze_thread_function_assoc() }),
        Some(AnalysisDim::DataFlows) => json!({ "data_flows": engine.analyze_data_flows() }),
        Some(AnalysisDim::ProducerConsumer) => json!({ "producer_consumer_patterns": engine.detect_producer_consumer() }),
        Some(AnalysisDim::Scheduling) => json!({ "scheduling": engine.analyze_scheduling() }),
        Some(AnalysisDim::Lifecycle) => json!({ "lifecycle": engine.analyze_thread_lifecycle() }),
        Some(AnalysisDim::ThreadStates) => json!({ "state_stats": engine.analyze_thread_states() }),
        Some(AnalysisDim::CriticalSections) => json!({ "critical_sections": engine.analyze_critical_sections() }),
        Some(AnalysisDim::JniBoundary) => json!({ "jni_boundary": engine.analyze_jni_boundary() }),
    })
}

fn print_human_report(engine: &mut TraceEngine, only: Option<AnalysisDim>) -> Result<()> {
    match only {
        Some(AnalysisDim::Races) => print_races(&engine.detect_race_conditions()),
        Some(AnalysisDim::Deadlocks) => print_deadlocks(&engine.detect_deadlocks()),
        Some(AnalysisDim::Contentions) => print_contentions(&engine.analyze_lock_contention()),
        Some(AnalysisDim::Safety) => print_safety(&engine.classify_function_thread_safety()),
        Some(AnalysisDim::FunctionAssoc) => print_function_assoc(&engine.analyze_thread_function_assoc()),
        Some(AnalysisDim::DataFlows) => print_data_flows(&engine.analyze_data_flows()),
        Some(AnalysisDim::ProducerConsumer) => print_producer_consumer(&engine.detect_producer_consumer()),
        Some(AnalysisDim::Scheduling) => print_scheduling(&engine.analyze_scheduling()),
        Some(AnalysisDim::Lifecycle) => print_lifecycle(&engine.analyze_thread_lifecycle()),
        Some(AnalysisDim::ThreadStates) => print_thread_states(&engine.analyze_thread_states()),
        Some(AnalysisDim::CriticalSections) => print_critical_sections(&engine.analyze_critical_sections()),
        Some(AnalysisDim::JniBoundary) => print_jni_boundary(&engine.analyze_jni_boundary()),
        None => {
            let result = engine.analyze_threads();
            print_races(&result.race_conditions);
            print_deadlocks(&result.deadlock_risks);
            print_contentions(&result.lock_contentions);
            print_safety(&result.function_safety);
            print_function_assoc(&result.thread_function_assocs);
            print_data_flows(&result.data_flows);
            print_producer_consumer(&result.producer_consumer_patterns);
            print_scheduling(&result.scheduling);
            print_lifecycle(&result.lifecycle);
            print_thread_states(&result.state_stats);
            print_critical_sections(&result.critical_sections);
            print_jni_boundary(&result.jni_boundary);
            println!(
                "\nSummary: {} races, {} deadlocks, {} contended locks, {} functions classified, {} data flows, {} producer-consumer patterns, {} threads scheduled, {} threads tracked, {} threads state-profiled, {} locks hold-profiled, {} threads with JNI activity",
                result.race_conditions.len(),
                result.deadlock_risks.len(),
                result.lock_contentions.iter().filter(|c| c.contention_count > 0).count(),
                result.function_safety.len(),
                result.data_flows.len(),
                result.producer_consumer_patterns.len(),
                result.scheduling.len(),
                result.lifecycle.len(),
                result.state_stats.len(),
                result.critical_sections.len(),
                result.jni_boundary.iter().filter(|j| j.total_crossings > 0 || j.is_jni_attached).count()
            );
        }
    }
    Ok(())
}

fn print_races(races: &[sotrace_engine::analyzer::thread_analyzer::RaceCondition]) {
    println!("\n=== Race Conditions ({}) ===", races.len());
    for (i, r) in races.iter().enumerate() {
        let first = if r.first_is_write { "write" } else { "read" };
        let second = if r.second_is_write { "write" } else { "read" };
        println!(
            "  [{}] addr=0x{:x}  T{} {} ({}B) @ step {}  →  T{} {} ({}B) @ step {}  conflict=0x{:x}+{}B",
            i, r.address, r.first_thread, first, r.first_access_size, r.first_step,
            r.second_thread, second, r.second_access_size, r.second_step,
            r.overlap_address, r.overlap_size,
        );
    }
}

fn print_deadlocks(dl: &[sotrace_engine::analyzer::thread_analyzer::DeadlockRisk]) {
    println!("\n=== Deadlock Risks ({}) ===", dl.len());
    for (i, d) in dl.iter().enumerate() {
        let cycle: Vec<String> = d.lock_cycle.iter()
            .map(|m| format!("0x{:x} ({:?})", m.addr, m.kind)).collect();
        let threads: Vec<String> = d.threads.iter().map(|t| format!("T{}", t)).collect();
        println!("  [{}] locks=[{}] threads=[{}]", i, cycle.join(" → "), threads.join(", "));
        println!("       {}", d.description);
    }
}

fn print_contentions(cs: &[sotrace_engine::analyzer::thread_analyzer::LockContentionInfo]) {
    println!("\n=== Lock Contentions ({}) ===", cs.len());
    for (i, c) in cs.iter().enumerate() {
        println!(
            "  [{}] lock=0x{:x} ({:?})  acquires={} contended={} ({:.0}%) avg_wait={}ns",
            i, c.lock_address.addr, c.lock_address.kind, c.acquire_count, c.contention_count,
            c.contention_ratio * 100.0, c.avg_wait_ns
        );
    }
}

fn print_safety(fs: &[sotrace_engine::analyzer::thread_analyzer::FunctionThreadSafety]) {
    println!("\n=== Function Thread Safety ({}) ===", fs.len());
    for (i, f) in fs.iter().enumerate() {
        let threads: Vec<String> = f.calling_threads.iter().map(|t| format!("T{}", t)).collect();
        let name = f.function_name.as_deref().unwrap_or("");
        println!(
            "  [{}] 0x{:x} {} {:?}  callers=[{}] races={} sync={}",
            i, f.function_address, name, f.safety, threads.join(", "),
            f.race_count, f.sync_event_count
        );
    }
}

fn print_function_assoc(asocs: &[sotrace_engine::analyzer::thread_analyzer::ThreadFunctionAssoc]) {
    println!("\n=== Thread-Function Associations ({}) ===", asocs.len());
    for (i, a) in asocs.iter().enumerate() {
        let name = a.function_name.as_deref().unwrap_or("");
        println!(
            "  [{}] T{} 0x{:x} {}  calls={} first@{} last@{}",
            i, a.thread_id, a.function_address, name, a.call_count, a.first_call_step, a.last_call_step
        );
    }
}

fn print_data_flows(flows: &[sotrace_engine::analyzer::thread_analyzer::ThreadDataFlow]) {
    println!("\n=== Thread Data Flows ({}) ===", flows.len());
    for (i, f) in flows.iter().enumerate() {
        let sync = if f.is_synchronized { "sync" } else { "unsync" };
        println!(
            "  [{}] T{} write ({}B) @ step {}  →  T{} read ({}B) @ step {}  transfer=0x{:x}+{}B  [{}]",
            i, f.from_thread, f.write_size, f.write_step,
            f.to_thread, f.read_size, f.read_step,
            f.overlap_address, f.overlap_size, sync
        );
    }
}
