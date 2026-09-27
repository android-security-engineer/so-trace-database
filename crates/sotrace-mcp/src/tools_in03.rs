
async fn tool_analyze_thread_lifecycle(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let lifecycle = engine.analyze_thread_lifecycle();
    Ok(json!({ "trace_id": trace_id, "thread_count": lifecycle.len(), "lifecycle": lifecycle }))
}

async fn tool_analyze_thread_states(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let state_stats = engine.analyze_thread_states();
    Ok(json!({ "trace_id": trace_id, "thread_count": state_stats.len(), "state_stats": state_stats }))
}

async fn tool_analyze_critical_sections(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let critical_sections = engine.analyze_critical_sections();
    Ok(json!({ "trace_id": trace_id, "lock_count": critical_sections.len(), "critical_sections": critical_sections }))
}

async fn tool_analyze_jni_boundary(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let jni_boundary = engine.analyze_jni_boundary();
    Ok(json!({ "trace_id": trace_id, "thread_count": jni_boundary.len(), "jni_boundary": jni_boundary }))
}

// ===========================================================================
// Persistence tools
// ===========================================================================

/// Feed a single normalized event into an engine. Used by load_trace to replay
/// a persisted event stream. Thin wrapper over the engine's own `feed_event`
/// dispatch table so all entry paths share one source of truth.
fn feed_event(engine: &mut TraceEngine, event: sotrace_core::adapters::TraceEvent) -> Result<(), ToolError> {
    engine.feed_event(event).map_err(|e| ToolError::new(e.to_string()))
}

/// Require a data directory; return it or an error if persistence is disabled.
fn require_data_dir(server: &McpServer) -> Result<std::path::PathBuf, ToolError> {
    server.data_dir()
        .map(std::path::PathBuf::from)
        .ok_or_else(|| ToolError::new("persistence is disabled: server was not started with a data directory (set SOTRACE_DATA_DIR)"))
}

/// Load the persisted SO file `so_file_id` and register its function table
/// into `engine`, so analysis resolves function names instead of bare offsets.
/// Mirrors CLI `load_engine` and the HTTP `register_so_for_engine` helper.
///
/// `so_file_id == 0` is the "no SO" sentinel and skips registration. A load
/// failure is logged and swallowed (the trace is still usable, just with
/// `None` function names) — matching CLI's `.ok()` graceful degradation.
/// Requires `data_dir`; returns a `ToolError` if persistence is disabled and a
/// SO was actually requested.
async fn register_so_for_engine(
    server: &McpServer,
    so_file_id: u64,
    engine: &tokio::sync::Mutex<TraceEngine>,
) -> Result<(), ToolError> {
    if so_file_id == 0 {
        return Ok(());
    }
    let data_dir = require_data_dir(server)?;
    let parsed = tokio::task::spawn_blocking(move || {
        sotrace_engine::persistence::SoRepository::open(&data_dir)
            .and_then(|repo| repo.load(so_file_id))
    })
    .await;
    match parsed {
        Ok(Ok(parsed)) => {
            engine.lock().await.register_parsed_so(&parsed);
        }
        Ok(Err(e)) => {
            eprintln!(
                "so-trace: warning: failed to load so_file_id {} for function-name resolution ({}); \
                 analysis will show bare offsets",
                so_file_id, e
            );
        }
        Err(e) => {
            eprintln!(
                "so-trace: warning: so load task for so_file_id {} join failed ({}); \
                 analysis will show bare offsets",
                so_file_id, e
            );
        }
    }
    Ok(())
}

async fn tool_save_trace(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let data_dir = require_data_dir(server)?;
    let so_file_id = args.get("so_file_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("mcp").to_string();

    let events = server.take_event_buffer(trace_id).await
        .ok_or_else(|| ToolError::new(format!("no in-memory trace with id {} to save (import_trace first)", trace_id)))?;

    // spawn_blocking: bincode serialization + file I/O shouldn't block the async runtime.
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let trace = sotrace_engine::persistence::PersistedTrace {
        trace_id: 0, // auto-assigned
        so_file_id,
        source,
        base_addr: 0,
        events,
        created_at,
    };
    let persisted_id = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.save(trace).map_err(|e| ToolError::new(e.to_string()))
    }).await
        .map_err(|e| ToolError::new(format!("save task failed: {}", e)))??;

    Ok(json!({
        "status": "ok",
        "persisted_id": persisted_id,
        "source_trace_id": trace_id,
    }))
}

async fn tool_load_trace(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let persisted_id = args.get("persisted_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'persisted_id'"))?;
    let data_dir = require_data_dir(server)?;

    let persisted = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.load(persisted_id).map_err(|e| ToolError::new(e.to_string()))
    }).await
        .map_err(|e| ToolError::new(format!("load task failed: {}", e)))??;

    let event_count = persisted.events.len();
    let so_file_id = persisted.so_file_id;
    let engine = server.get_or_create_engine(persisted_id).await;
    let mut guard = engine.lock().await;
    // Replay in chronological order.
    let mut sorted = persisted.events;
    sorted.sort_by_key(|e| e.step());
    for ev in sorted {
        feed_event(&mut guard, ev)?;
    }
    drop(guard);
    // After replay, load the SO function table (if the trace references one)
    // so analysis resolves function names instead of bare offsets. Mirrors CLI
    // load_engine and import_trace's post-feed registration.
    register_so_for_engine(server, so_file_id, &engine).await?;
    server.store_event_buffer(persisted_id, Vec::new()).await;

    Ok(json!({
        "status": "ok",
        "persisted_id": persisted_id,
        "so_file_id": so_file_id,
        "event_count": event_count,
    }))
}

async fn tool_list_persisted_traces(server: &McpServer) -> Result<Value, ToolError> {
    let data_dir = require_data_dir(server)?;
    let summaries = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.list().map_err(|e| ToolError::new(e.to_string()))
    }).await
        .map_err(|e| ToolError::new(format!("list task failed: {}", e)))??;

    let traces: Vec<Value> = summaries.iter().map(|s| json!({
        "trace_id": s.trace_id,
        "so_file_id": s.so_file_id,
        "source": s.source,
        "base_addr": s.base_addr,
        "event_count": s.event_count,
        "created_at": s.created_at,
    })).collect();

    Ok(json!({
        "trace_count": traces.len(),
        "traces": traces,
    }))
}

async fn tool_delete_persisted_trace(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let data_dir = require_data_dir(server)?;

    let deleted = tokio::task::spawn_blocking(move || {
        let repo = sotrace_engine::persistence::TraceRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.delete(trace_id).map_err(|e| ToolError::new(e.to_string()))
    }).await
        .map_err(|e| ToolError::new(format!("delete task failed: {}", e)))??;

    Ok(json!({
        "status": if deleted { "deleted" } else { "not_found" },
        "trace_id": trace_id,
    }))
}

// ===========================================================================
// SO management tools — mirror the HTTP /so-files endpoints and CLI
// import-so/so-list/so-show/so-delete so all three access paths expose the
// same CRUD. The ELF bytes travel base64-encoded inside JSON-RPC args (raw
// bytes cannot be carried in JSON).
// ===========================================================================

/// Upload + parse + persist an SO file (base64 ELF bytes).
///
/// Mirrors HTTP `POST /api/v1/so-files`. Parses, saves (dedup by SHA-256), and
/// returns the assigned `so_id` plus a summary. The `deduped` flag is true when
/// the saved summary differs from the freshly parsed bytes (existing copy
/// reused) — matching the HTTP handler's byte-for-byte logic.
async fn tool_import_so(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    use base64::Engine;
    let data_dir = require_data_dir(server)?;

    let bytes_str = args.get("bytes")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::new("missing or invalid 'bytes' (expected base64 string)"))?;
    let path_label = args.get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("upload")
        .to_string();

    let data = base64::engine::general_purpose::STANDARD
        .decode(bytes_str)
        .map_err(|e| ToolError::new(format!("invalid base64: {}", e)))?;
    if data.is_empty() {
        return Err(ToolError::new("empty body: expected base64-encoded ELF bytes in 'bytes'"));
    }

    // Parse + save + summary all on one blocking task: parsing is CPU-heavy and
    // save/summary do file I/O, so keep them off the async runtime together.
    let result = tokio::task::spawn_blocking(move || -> Result<_, ToolError> {
        let parsed = sotrace_engine::elf::parse_elf_bytes(&data, &path_label)
            .map_err(|e| ToolError::new(format!("failed to parse ELF: {}", e)))?;
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        let outcome = repo.save(&parsed).map_err(|e| ToolError::new(e.to_string()))?;
        let summary = repo.summary(outcome.id)
            .map_err(|e| ToolError::new(e.to_string()))?
            .ok_or_else(|| ToolError::new(format!("SO id {} missing from index after save", outcome.id)))?;
        Ok((outcome, summary))
    })
    .await
    .map_err(|e| ToolError::new(format!("import_so task failed: {}", e)))??;

    let (outcome, summary) = result;
    // deduped is the authoritative signal from save's index lookup — no
    // second-grained created_at heuristic (which broke on same-second
    // re-imports). Mirrors HTTP so_file.rs.
    Ok(json!({
        "so_id": outcome.id,
        "deduped": outcome.deduped,
        "summary": serde_json::to_value(&summary)
            .map_err(|e| ToolError::new(format!("summary serialization failed: {}", e)))?,
    }))
}

/// List all persisted SO files (summaries only). Mirrors HTTP
/// `GET /api/v1/so-files`.
async fn tool_list_so_files(server: &McpServer) -> Result<Value, ToolError> {
    let data_dir = require_data_dir(server)?;
    let list = tokio::task::spawn_blocking(move || -> Result<_, ToolError> {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.list().map_err(|e| ToolError::new(e.to_string()))
    })
    .await
    .map_err(|e| ToolError::new(format!("list_so_files task failed: {}", e)))??;

    let so_files: Vec<Value> = list.iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();
    Ok(json!({
        "so_files": so_files,
        "count": list.len(),
    }))
}

/// Get a single persisted SO file's summary by ID. Mirrors HTTP
/// `GET /api/v1/so-files/:id`.
async fn tool_get_so_file(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let so_id = get_so_id(args)?;
    let data_dir = require_data_dir(server)?;
    let summary = tokio::task::spawn_blocking(move || -> Result<_, ToolError> {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.summary(so_id).map_err(|e| ToolError::new(e.to_string()))
    })
    .await
    .map_err(|e| ToolError::new(format!("get_so_file task failed: {}", e)))??;

    match summary {
        Some(summary) => Ok(json!({
            "so_file": serde_json::to_value(&summary)
                .map_err(|e| ToolError::new(format!("summary serialization failed: {}", e)))?,
        })),
        None => Err(ToolError::new(format!("not found: no SO file with id {}", so_id))),
    }
}

/// Delete a persisted SO file by ID. Mirrors HTTP `DELETE /api/v1/so-files/:id`
/// (added together with this tool to close the CRUD symmetry).
async fn tool_delete_so(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let so_id = get_so_id(args)?;
    let data_dir = require_data_dir(server)?;
    let deleted = tokio::task::spawn_blocking(move || -> Result<_, ToolError> {
        let repo = sotrace_engine::persistence::SoRepository::open(&data_dir)
            .map_err(|e| ToolError::new(e.to_string()))?;
        repo.delete(so_id).map_err(|e| ToolError::new(e.to_string()))
    })
    .await
    .map_err(|e| ToolError::new(format!("delete_so task failed: {}", e)))??;

    Ok(json!({
        "status": if deleted { "deleted" } else { "not_found" },
        "so_id": so_id,
    }))
}

/// Lowercase hex encoding of a byte slice, matching the HTTP memory handler.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

async fn tool_query_register(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let register_id = args.get("register_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'register_id' (expected integer)"))?
        as usize;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let value = engine.query_register(register_id, step);

    Ok(json!({
        "trace_id": trace_id,
        "register_id": register_id,
        "step": step,
        "value": value,
        "value_hex": value.map(|v| format!("0x{:x}", v)),
    }))
}

async fn tool_query_register_state(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let state = engine.reconstruct_register_state(step);

    Ok(json!({
        "trace_id": trace_id,
        "step": step,
        "state": state,
    }))
}

async fn tool_query_register_history(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let register_id = args.get("register_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'register_id' (expected integer)"))?
        as usize;
    let start = args.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let steps = engine.query_register_history(register_id, start, end);

    Ok(json!({
        "trace_id": trace_id,
        "register_id": register_id,
        "start": start,
        "end": end,
        "change_count": steps.len(),
        "steps": steps,
    }))
}

async fn tool_query_memory_value(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let address = args.get("address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'address' (expected integer)"))?;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(8) as usize;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let result = engine.query_memory_value(address, size, step);
    let value_hex = result.as_ref().map(|r| hex(&r.value));

    Ok(json!({
        "trace_id": trace_id,
        "address": address,
        "step": step,
        "size": size,
        "result": result,
        "value_hex": value_hex,
    }))
}
