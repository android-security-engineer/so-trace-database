
fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone();
    // Take the import timestamp once per invocation; passed into trace-save so
    // tests can pin it via a fixed value through the same code path.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match cli.command {
        Commands::Analyze {
            trace_file,
            trace_id,
            so_id,
            format,
            base_addr,
            only,
            so,
            json,
        } => run_analyze(&data_dir, trace_file, trace_id, so_id, format, base_addr, only, so, json),
        Commands::Query {
            trace_file,
            trace_id,
            so_id,
            format,
            base_addr,
            so,
            query,
        } => run_query(&data_dir, trace_file, trace_id, so_id, format, base_addr, so, query),
        Commands::ImportSo { path, save } => run_import_so(&data_dir, path, save),
        Commands::SoList => run_so_list(&data_dir),
        Commands::SoShow { so_id } => run_so_show(&data_dir, so_id),
        Commands::SoDelete { so_id } => run_so_delete(&data_dir, so_id),
        Commands::TraceSave { trace_file, so_id, format, base_addr, so } => {
            run_trace_save(&data_dir, trace_file, so_id, format, base_addr, so, now)
        }
        Commands::TraceList => run_trace_list(&data_dir),
        Commands::TraceShow { trace_id } => run_trace_show(&data_dir, trace_id),
        Commands::TraceDelete { trace_id } => run_trace_delete(&data_dir, trace_id),
    }
}

/// Load a trace into a fresh in-memory TraceEngine.
///
/// Two load sources, mutually exclusive:
/// - `trace_id = Some(id)`: replay a persisted trace from `TraceRepository`.
///   The original trace file is not re-parsed; the saved event stream is fed
///   back through [`feed_events`], and the associated SO (by `so_file_id`) is
///   loaded from `SoRepository` for function-name backfill.
/// - `trace_id = None` + `trace_file = Some(path)`: parse the trace file
///   (native envelope or adapter format) into events, then feed them.
///
/// Returns the engine, import counts, and the event vector. The event vector
/// is returned even on file parse so callers (e.g. `trace-save`) can persist
/// it without re-parsing. Progress goes to stderr so stdout stays clean.
///
/// SO source priority:
/// 1. `--so <path>` — parse the ELF file directly (in-memory, not persisted).
/// 2. else if `so_file_id > 0` — load the persisted SO with that ID from
///    `data_dir`. On trace-id replay, `so_file_id` comes from the persisted
///    trace (authoritative); otherwise from `--so-id` / the envelope.
fn load_engine(
    data_dir: &Path,
    trace_file: Option<&PathBuf>,
    trace_id: Option<u64>,
    so_id: u64,
    format: TraceFormat,
    base_addr: u64,
    so: &Option<PathBuf>,
    quiet: bool,
) -> Result<(TraceEngine, ImportedCounts, Vec<TraceEvent>)> {
    // For trace-id replay, the persisted trace's so_file_id is authoritative
    // and overrides the caller's --so-id.
    let mut resolved_so_file_id = so_id;
    let events: Vec<TraceEvent>;
    let mut imported = ImportedCounts::default();

    if let Some(id) = trace_id {
        // Replay path: load persisted trace, replay its event stream.
        let trace_repo = sotrace_engine::persistence::TraceRepository::open(data_dir)
            .with_context(|| format!("failed to open trace repository at {}", data_dir.display()))?;
        let persisted = trace_repo
            .load(id)
            .with_context(|| format!("no persisted trace with id {} in {}", id, data_dir.display()))?;
        resolved_so_file_id = persisted.so_file_id;
        events = persisted.events;
        if !quiet {
            eprintln!(
                "Replaying trace {} (so_file_id={}, source={:?}, base_addr=0x{:x}): {} events",
                id, resolved_so_file_id, persisted.source, persisted.base_addr, events.len()
            );
        }
    } else {
        let trace_file = trace_file
            .context("either --trace-id or a trace file path must be provided")?;
        let raw = std::fs::read_to_string(trace_file)
            .with_context(|| format!("failed to read trace file: {}", trace_file.display()))?;

        if let Some((adapter_name, trace_type)) = format.adapter() {
            // Adapter path: Frida / DynamoRIO / Pin
            use sotrace_core::adapters::TraceAdapter;
            let adapter: Box<dyn TraceAdapter> = match adapter_name {
                "frida" => Box::new(sotrace_core::adapters::frida::FridaAdapter::new()),
                "dynamorio" => Box::new(sotrace_core::adapters::dynamorio::DynamoRioAdapter::new()),
                "pin" => Box::new(sotrace_core::adapters::pin::PinAdapter::new()),
                other => anyhow::bail!("unknown adapter '{}'", other),
            };
            let (parsed_events, stats) = adapter
                .parse(trace_type, &raw, base_addr)
                .with_context(|| format!("failed to parse {} {} trace", adapter_name, trace_type))?;
            events = parsed_events;
            if !quiet {
                eprintln!(
                    "Loaded {} {} trace (so_file_id={}, base_addr=0x{:x}): {} events ({} skipped)",
                    adapter_name, trace_type, resolved_so_file_id, base_addr,
                    events.len(), stats.skipped
                );
            }
        } else {
            // Native envelope path
            let envelope: TraceEnvelope = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse trace JSON: {}", trace_file.display()))?;
            let trace_id = envelope.trace_id.unwrap_or(1);
            if let Some(env_so_id) = envelope.so_file_id {
                resolved_so_file_id = env_so_id;
            }
            events = envelope_to_events(&envelope)?;
            if !quiet {
                eprintln!(
                    "Loaded trace {} (so_file_id={}): {} events",
                    trace_id, resolved_so_file_id, events.len()
                );
            }
        }
    }

    let mut engine = TraceEngine::new(resolved_so_file_id, Default::default());

    // Resolve the SO source: explicit --so path takes priority; otherwise fall
    // back to loading a persisted SO by ID from the data directory.
    let so_source: Option<ParsedSoFile> = if let Some(so_path) = so {
        Some(
            sotrace_engine::elf::parse_elf(so_path)
                .with_context(|| format!("failed to parse SO file: {}", so_path.display()))?,
        )
    } else if resolved_so_file_id > 0 {
        let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
            .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
        repo.load(resolved_so_file_id).ok()
    } else {
        None
    };

    if let Some(parsed) = &so_source {
        engine.register_parsed_so(parsed);
        if !quiet {
            eprintln!(
                "Loaded SO {:?}, {} bytes, {} functions ({} JNI, {} exported)",
                parsed.so_file.arch,
                parsed.so_file.file_size,
                parsed.functions.len(),
                parsed.jni_function_count(),
                parsed.exported_function_count(),
            );
        }
    }

    feed_events(&mut engine, &events, &mut imported)?;

    Ok((engine, imported, events))
}

fn run_analyze(
    data_dir: &Path,
    trace_file: Option<PathBuf>,
    trace_id: Option<u64>,
    so_id: u64,
    format: TraceFormat,
    base_addr: u64,
    only: Option<AnalysisDim>,
    so: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let (mut engine, _imported, _events) = load_engine(
        data_dir, trace_file.as_ref(), trace_id, so_id, format, base_addr, &so, json,
    )?;

    // --- Run analysis ---
    if json {
        let out = build_json_output(&mut engine, only)?;
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    print_human_report(&mut engine, only)?;
    Ok(())
}

fn run_query(
    data_dir: &Path,
    trace_file: Option<PathBuf>,
    trace_id: Option<u64>,
    so_id: u64,
    format: TraceFormat,
    base_addr: u64,
    so: Option<PathBuf>,
    query: QueryCmd,
) -> Result<()> {
    // `query` always emits JSON to stdout; load progress goes to stderr.
    let (engine, _imported, _events) =
        load_engine(data_dir, trace_file.as_ref(), trace_id, so_id, format, base_addr, &so, true)?;
    // Borrow immutably for all read-only queries.
    let engine = engine;

    let out: Value = match &query {
        QueryCmd::Threads => {
            let ids = engine.all_thread_ids();
            let stats = engine.all_thread_stats();
            let mut entries = Vec::with_capacity(ids.len());
            for tid in ids {
                let info = engine.get_thread_info(tid).cloned();
                let st = stats.iter().find(|s| s.thread_id == tid).cloned();
                entries.push(serde_json::json!({
                    "thread_id": tid,
                    "info": info,
                    "stats": st,
                }));
            }
            serde_json::json!({ "threads": entries })
        }
        QueryCmd::Thread { thread_id } => {
            let info = engine.get_thread_info(*thread_id).cloned();
            let stats = engine.get_thread_stats(*thread_id);
            serde_json::json!({
                "thread_id": thread_id,
                "info": info,
                "stats": stats,
            })
        }
        QueryCmd::Timeline { thread_id, start, end } => {
            let tl = engine.query_thread_timeline(*thread_id, *start, *end);
            serde_json::json!({ "timeline": tl })
        }
        QueryCmd::Instruction { step } => {
            let inst = engine.query_instruction(*step).cloned();
            serde_json::json!({ "step": step, "instruction": inst })
        }
        QueryCmd::Instructions { start, end } => {
            let insts: Vec<_> = engine
                .query_instructions_range(*start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({ "start": start, "end": end, "count": insts.len(), "instructions": insts })
        }
        QueryCmd::Address { address } => {
            let steps: Vec<u64> = engine.query_instructions_by_address(*address).to_vec();
            let threads = engine.query_threads_at_address(*address);
            serde_json::json!({
                "address": address,
                "step_count": steps.len(),
                "steps": steps,
                // `query_threads_at_address` returns (thread_id, step) pairs —
                // each entry is "thread T executed this address at step S", not
                // a count. Emitting `step` (not a mislabeled `count`) keeps the
                // field name honest and lets callers see exactly when each
                // thread touched the address.
                "thread_accesses": threads.iter().map(|(t, s)| serde_json::json!({"thread_id": t, "step": s})).collect::<Vec<_>>(),
            })
        }
        QueryCmd::Memory { address, step, size } => {
            let res = engine.query_memory_value(*address, *size, *step);
            serde_json::json!({
                "address": address,
                "step": step,
                "size": size,
                "result": res,
            })
        }
        QueryCmd::Sync { thread_id, start, end } => {
            let events: Vec<_> = engine
                .query_thread_sync_events(*thread_id, *start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({
                "thread_id": thread_id,
                "start": start,
                "end": end,
                "count": events.len(),
                "sync_events": events,
            })
        }
        QueryCmd::Lock { address, start, end } => {
            let events: Vec<_> = engine
                .query_lock_contentions(*address, *start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({
                "lock_address": address,
                "start": start,
                "end": end,
                "count": events.len(),
                "contentions": events,
            })
        }
        QueryCmd::Switches { start, end } => {
            let switches: Vec<_> = engine
                .query_context_switches(*start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({
                "start": start,
                "end": end,
                "count": switches.len(),
                "context_switches": switches,
            })
        }
        QueryCmd::Snapshot { step } => {
            let snap = engine.query_step_snapshot(*step);
            serde_json::to_value(&snap).expect("step snapshot is serializable")
        }
        QueryCmd::Register { register_id, step } => {
            let value = engine.query_register(*register_id, *step);
            serde_json::json!({
                "register_id": register_id,
                "step": step,
                "value": value,
                "value_hex": value.map(|v| format!("0x{v:x}")),
            })
        }
        QueryCmd::RegisterState { step } => {
            let state = engine.reconstruct_register_state(*step);
            serde_json::json!({
                "step": step,
                "state": state,
            })
        }
        QueryCmd::RegisterHistory { register_id, start, end } => {
            let steps = engine.query_register_history(*register_id, *start, *end);
            serde_json::json!({
                "register_id": register_id,
                "start": start,
                "end": end,
                "change_count": steps.len(),
                "steps": steps,
            })
        }
        QueryCmd::CallStack { thread_id, step } => {
            let frames = engine.rebuild_call_stack(*thread_id, *step);
            serde_json::json!({
                "thread_id": thread_id,
                "step": step,
                "depth": frames.len(),
                "frames": frames,
            })
        }
        QueryCmd::JniCalls { address, start, end } => {
            let calls: Vec<_> = engine
                .query_jni_calls_by_address(*address, *start, *end)
                .into_iter()
                .cloned()
                .collect();
            serde_json::json!({
                "native_address": address,
                "start": start,
                "end": end,
                "count": calls.len(),
                "jni_calls": calls,
            })
        }
    };

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn run_import_so(data_dir: &Path, path: PathBuf, save: bool) -> Result<()> {
    let parsed = sotrace_engine::elf::parse_elf(&path)
        .with_context(|| format!("failed to parse SO file: {}", path.display()))?;
    let so = &parsed.so_file;

    // If --save, persist to the data dir (dedup by SHA-256) and print the ID.
    let assigned_id = if save {
        let repo = sotrace_engine::persistence::SoRepository::open(data_dir)
            .with_context(|| format!("failed to open SO repository at {}", data_dir.display()))?;
        let outcome = repo.save(&parsed)?;
        // deduped is the authoritative signal from save's index lookup — no
        // second-grained created_at heuristic (which broke on same-second
        // re-imports).
        if outcome.deduped {
            eprintln!("SO already imported (dedup by sha256): reusing id={}", outcome.id);
        } else {
            eprintln!("Saved SO id={} to {}", outcome.id, data_dir.join("so").display());
        }
        Some(outcome.id)
    } else {
        None
    };

    println!("SO file: {}", so.path);
    if let Some(id) = assigned_id {
        println!("  so_id        : {}", id);
    }
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

    // List the first few function symbols (skip PLT/imported stubs).
    let named: Vec<_> = parsed.functions.iter()
        .filter(|f| !f.is_imported)
        .take(20)
        .collect();
    if !named.is_empty() {
        println!("\n  Sample functions (first {}):", named.len());
        for f in named {
            let tag = if f.is_jni { " [JNI]" } else { "" };
            println!("    0x{:08x}  {} ({} bytes){}", f.offset, f.name, f.size, tag);
        }
        let total = parsed.functions.len();
        if total > 20 {
            println!("    ... and {} more", total - 20);
        }
    }
    Ok(())
}
