
/// Dispatch a tool call to its handler
pub async fn dispatch_tool(
    server: &McpServer,
    name: &str,
    args: &Value,
) -> Result<Value, ToolError> {
    match name {
        "import_trace" => tool_import_trace(server, args).await,
        "list_traces" => tool_list_traces(server).await,
        "list_threads" => tool_list_threads(server, args).await,
        "query_instructions" => tool_query_instructions(server, args).await,
        "query_sync_events" => tool_query_sync_events(server, args).await,
        "query_context_switches" => tool_query_context_switches(server, args).await,
        "analyze_threads" => tool_analyze_threads(server, args).await,
        "detect_races" => tool_detect_races(server, args).await,
        "detect_deadlocks" => tool_detect_deadlocks(server, args).await,
        "analyze_contentions" => tool_analyze_contentions(server, args).await,
        "classify_function_safety" => tool_classify_function_safety(server, args).await,
        "analyze_function_assoc" => tool_analyze_function_assoc(server, args).await,
        "analyze_data_flows" => tool_analyze_data_flows(server, args).await,
        "detect_producer_consumer" => tool_detect_producer_consumer(server, args).await,
        "analyze_scheduling" => tool_analyze_scheduling(server, args).await,
        "analyze_thread_lifecycle" => tool_analyze_thread_lifecycle(server, args).await,
        "analyze_thread_states" => tool_analyze_thread_states(server, args).await,
        "analyze_critical_sections" => tool_analyze_critical_sections(server, args).await,
        "analyze_jni_boundary" => tool_analyze_jni_boundary(server, args).await,
        "save_trace" => tool_save_trace(server, args).await,
        "load_trace" => tool_load_trace(server, args).await,
        "list_persisted_traces" => tool_list_persisted_traces(server).await,
        "delete_persisted_trace" => tool_delete_persisted_trace(server, args).await,
        "import_so" => tool_import_so(server, args).await,
        "list_so_files" => tool_list_so_files(server).await,
        "get_so_file" => tool_get_so_file(server, args).await,
        "delete_so" => tool_delete_so(server, args).await,
        "query_register" => tool_query_register(server, args).await,
        "query_register_state" => tool_query_register_state(server, args).await,
        "query_register_history" => tool_query_register_history(server, args).await,
        "query_memory_value" => tool_query_memory_value(server, args).await,
        "query_memory_page" => tool_query_memory_page(server, args).await,
        "query_call_stack" => tool_query_call_stack(server, args).await,
        "query_jni_calls" => tool_query_jni_calls(server, args).await,
        "query_threads_at_address" => tool_query_threads_at_address(server, args).await,
        other => Err(ToolError::new(format!("unknown tool: {}", other))),
    }
}

// --- Helper: extract trace_id from args ---
fn get_trace_id(args: &Value) -> Result<u64, ToolError> {
    args.get("trace_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'trace_id' (expected integer)"))
}

// --- Helper: extract so_id from args ---
fn get_so_id(args: &Value) -> Result<u64, ToolError> {
    args.get("so_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'so_id' (expected integer)"))
}

// ===========================================================================
// Tool handlers
// ===========================================================================

async fn tool_import_trace(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    use sotrace_core::adapters::TraceEvent;
    let trace_id = get_trace_id(args)?;

    // Phase 1: parse every category into a uniform `TraceEvent` stream WITHOUT
    // touching the engine. Ingestion order used to follow category order
    // (threads, then instructions, then memory_writes, …) rather than step
    // order, so a `state_change` at step 50 fed after a `state_change` at step
    // 100 would leave `thread_states`/`current_thread` stamped with the older
    // state — the very fields #91/#92 made order-sensitive. Sorting the whole
    // stream by step before ingestion (mirroring CLI `feed_events`) keeps the
    // engine's order-dependent state consistent regardless of how the caller
    // arranged the JSON arrays.
    let mut events: Vec<TraceEvent> = Vec::new();

    // Threads
    if let Some(threads) = args.get("threads").and_then(|v| v.as_array()) {
        for t in threads {
            let info: ThreadInfo = serde_json::from_value(t.clone())
                .map_err(|e| ToolError::new(format!("invalid thread: {}", e)))?;
            events.push(TraceEvent::Thread(info));
        }
    }

    // Instructions
    if let Some(instrs) = args.get("instructions").and_then(|v| v.as_array()) {
        for i in instrs {
            let trace: InstructionTrace = serde_json::from_value(i.clone())
                .map_err(|e| ToolError::new(format!("invalid instruction: {}", e)))?;
            events.push(TraceEvent::Instruction(trace));
        }
    }

    // Memory writes
    if let Some(writes) = args.get("memory_writes").and_then(|v| v.as_array()) {
        for w in writes {
            let step = w.get("step").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_write missing 'step'"))?;
            let thread_id = w.get("thread_id").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_write missing 'thread_id'"))? as u32;
            let address = w.get("address").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_write missing 'address'"))?;
            let data: Vec<u8> = w.get("data")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            events.push(TraceEvent::MemoryWrite { step, thread_id, address, data });
        }
    }

    // Memory reads — fed to the analyzer for write→read race detection.
    // Reads are not persisted into the memory store (only writes affect
    // memory state), but are kept in the event stream so save/load replays
    // them into the analyzer on reload.
    if let Some(reads) = args.get("memory_reads").and_then(|v| v.as_array()) {
        for r in reads {
            let step = r.get("step").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_read missing 'step'"))?;
            let thread_id = r.get("thread_id").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_read missing 'thread_id'"))? as u32;
            let address = r.get("address").and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("memory_read missing 'address'"))?;
            let size = r.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            events.push(TraceEvent::MemoryRead { step, thread_id, address, size });
        }
    }

    // Sync events
    if let Some(events_arr) = args.get("sync_events").and_then(|v| v.as_array()) {
        for e in events_arr {
            let event: ThreadSyncEvent = serde_json::from_value(e.clone())
                .map_err(|err| ToolError::new(format!("invalid sync_event: {}", err)))?;
            events.push(TraceEvent::Sync(event));
        }
    }

    // Context switches
    if let Some(switches) = args.get("context_switches").and_then(|v| v.as_array()) {
        for s in switches {
            let switch: ContextSwitch = serde_json::from_value(s.clone())
                .map_err(|e| ToolError::new(format!("invalid context_switch: {}", e)))?;
            events.push(TraceEvent::ContextSwitch(switch));
        }
    }

    // State changes
    if let Some(changes) = args.get("state_changes").and_then(|v| v.as_array()) {
        for c in changes {
            let change: ThreadStateChange = serde_json::from_value(c.clone())
                .map_err(|e| ToolError::new(format!("invalid state_change: {}", e)))?;
            events.push(TraceEvent::StateChange(change));
        }
    }

    // JNI calls
    if let Some(calls) = args.get("jni_calls").and_then(|v| v.as_array()) {
        for c in calls {
            let call: JNICall = serde_json::from_value(c.clone())
                .map_err(|e| ToolError::new(format!("invalid jni_call: {}", e)))?;
            events.push(TraceEvent::JniCall(call));
        }
    }

    // Register deltas
    if let Some(deltas) = args.get("register_deltas").and_then(|v| v.as_array()) {
        for d in deltas {
            let delta: RegisterDelta = serde_json::from_value(d.clone())
                .map_err(|e| ToolError::new(format!("invalid register_delta: {}", e)))?;
            events.push(TraceEvent::Register(delta));
        }
    }

    // Call traces (call/return events for call-stack reconstruction)
    if let Some(calls) = args.get("calls").and_then(|v| v.as_array()) {
        for c in calls {
            let call: CallTrace = serde_json::from_value(c.clone())
                .map_err(|e| ToolError::new(format!("invalid call: {}", e)))?;
            events.push(TraceEvent::Call(call));
        }
    }

    // Phase 2: `TraceEngine::feed_events` sorts by step (stable; skipped when
    // the buffer is already non-decreasing) and applies the batch. The sorted
    // buffer is what gets persisted.
    events.sort_by_key(|e| e.step());

    let engine = server.get_or_create_engine(trace_id).await;
    let mut guard = engine.lock().await;
    guard.feed_events(events.iter().cloned()).map_err(|e| ToolError::new(e.to_string()))?;

    let mut counts = json!({
        "threads": 0, "instructions": 0, "memory_writes": 0, "memory_reads": 0,
        "sync_events": 0, "context_switches": 0, "state_changes": 0, "jni_calls": 0,
        "register_deltas": 0, "calls": 0,
    });
    for ev in &events {
        match ev {
            TraceEvent::Thread(_) => {
                counts["threads"] = json!(counts["threads"].as_u64().unwrap() + 1);
            }
            TraceEvent::Instruction(_) => {
                counts["instructions"] = json!(counts["instructions"].as_u64().unwrap() + 1);
            }
            TraceEvent::MemoryWrite { .. } => {
                counts["memory_writes"] = json!(counts["memory_writes"].as_u64().unwrap() + 1);
            }
            TraceEvent::MemoryRead { .. } => {
                counts["memory_reads"] = json!(counts["memory_reads"].as_u64().unwrap() + 1);
            }
            TraceEvent::Sync(_) => {
                counts["sync_events"] = json!(counts["sync_events"].as_u64().unwrap() + 1);
            }
            TraceEvent::ContextSwitch(_) => {
                counts["context_switches"] = json!(counts["context_switches"].as_u64().unwrap() + 1);
            }
            TraceEvent::StateChange(_) => {
                counts["state_changes"] = json!(counts["state_changes"].as_u64().unwrap() + 1);
            }
            TraceEvent::JniCall(_) => {
                counts["jni_calls"] = json!(counts["jni_calls"].as_u64().unwrap() + 1);
            }
            TraceEvent::Register(_) => {
                counts["register_deltas"] = json!(counts["register_deltas"].as_u64().unwrap() + 1);
            }
            TraceEvent::Call(_) => {
                counts["calls"] = json!(counts["calls"].as_u64().unwrap() + 1);
            }
        }
    }

    drop(guard);
    let so_file_id = args.get("so_file_id").and_then(|v| v.as_u64()).unwrap_or(0);
    // so_file_id == 0 → no SO requested, returns Ok(()) without requiring
    // data_dir. A real load failure is warned + swallowed (trace stays usable).
    register_so_for_engine(server, so_file_id, &engine).await?;
    server.store_event_buffer(trace_id, events).await;

    Ok(json!({
        "status": "ok",
        "trace_id": trace_id,
        "imported": counts,
    }))
}

async fn tool_list_traces(server: &McpServer) -> Result<Value, ToolError> {
    let engines = server.engines_for_read().await;
    let trace_ids: Vec<u64> = engines.keys().copied().collect();
    Ok(json!({
        "trace_count": trace_ids.len(),
        "traces": trace_ids,
    }))
}

async fn tool_list_threads(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let include_stats = args.get("include_stats").and_then(|v| v.as_bool()).unwrap_or(false);
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let threads: Vec<Value> = engine.all_thread_ids()
        .into_iter()
        .filter_map(|tid| engine.get_thread_info(tid).cloned())
        .map(|info| serde_json::to_value(&info).unwrap_or(Value::Null))
        .collect();

    // #115: mirror HTTP's `?include_stats=true` so the MCP path can surface
    // ThreadStats (lock_acquire_count / lock_release_count / …) — keeping the
    // three access paths (CLI / HTTP / MCP) symmetric. Default false preserves
    // the prior response shape for callers that don't request stats.
    let mut response = serde_json::json!({
        "trace_id": trace_id,
        "thread_count": threads.len(),
        "threads": threads,
    });
    if include_stats {
        response["stats"] = serde_json::to_value(engine.all_thread_stats())
            .unwrap_or(serde_json::Value::Null);
    }

    Ok(response)
}

async fn tool_query_instructions(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let start = args.get("start_step").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end_step").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    let thread_id = args.get("thread_id").and_then(|v| v.as_u64()).map(|v| v as u32);
    let address = args.get("address").and_then(|v| v.as_u64());
    let limit = args.get("limit").and_then(|v| v.as_u64());

    let mut results: Vec<InstructionTrace> = engine.query_instructions_range(start, end)
        .into_iter()
        .filter(|t| thread_id.map_or(true, |tid| t.thread_id == tid))
        .filter(|t| address.map_or(true, |addr| t.address == addr))
        .cloned()
        .collect();

    if let Some(lim) = limit {
        results.truncate(lim as usize);
    }

    Ok(json!({
        "trace_id": trace_id,
        "instruction_count": results.len(),
        "instructions": results,
    }))
}

async fn tool_query_sync_events(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let start = args.get("start_step").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end_step").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    let thread_id = args.get("thread_id").and_then(|v| v.as_u64()).map(|v| v as u32);
    let sync_addr = args.get("sync_object_addr").and_then(|v| v.as_u64());

    let events: Vec<ThreadSyncEvent> = if let Some(addr) = sync_addr {
        engine.query_lock_contentions(addr, start, end)
            .into_iter()
            .filter(|e| thread_id.map_or(true, |tid| e.thread_id == tid))
            .cloned()
            .collect()
    } else if let Some(tid) = thread_id {
        engine.query_thread_sync_events(tid, start, end)
            .into_iter()
            .cloned()
            .collect()
    } else {
        let mut all = Vec::new();
        for tid in engine.all_thread_ids() {
            all.extend(engine.query_thread_sync_events(tid, start, end).into_iter().cloned());
        }
        all.sort_by_key(|e| e.step);
        all
    };

    let count = events.len();
    Ok(json!({
        "trace_id": trace_id,
        "event_count": count,
        "events": events,
    }))
}

async fn tool_query_context_switches(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let start = args.get("start_step").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end_step").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    let thread_id = args.get("thread_id").and_then(|v| v.as_u64()).map(|v| v as u32);

    let switches: Vec<ContextSwitch> = engine.query_context_switches(start, end)
        .into_iter()
        .filter(|s| thread_id.map_or(true, |tid| s.from_thread == tid || s.to_thread == tid))
        .cloned()
        .collect();

    let count = switches.len();
    Ok(json!({
        "trace_id": trace_id,
        "switch_count": count,
        "context_switches": switches,
    }))
}

async fn tool_analyze_threads(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let result = engine.analyze_threads();
    Ok(json!({ "trace_id": trace_id, "analysis": result }))
}

async fn tool_detect_races(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let races = engine.detect_race_conditions();
    Ok(json!({ "trace_id": trace_id, "race_count": races.len(), "races": races }))
}

async fn tool_detect_deadlocks(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let deadlocks = engine.detect_deadlocks();
    Ok(json!({ "trace_id": trace_id, "deadlock_count": deadlocks.len(), "deadlocks": deadlocks }))
}

async fn tool_analyze_contentions(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let contentions = engine.analyze_lock_contention();
    Ok(json!({ "trace_id": trace_id, "contention_count": contentions.len(), "contentions": contentions }))
}

async fn tool_classify_function_safety(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let safety = engine.classify_function_thread_safety();
    Ok(json!({ "trace_id": trace_id, "function_count": safety.len(), "function_safety": safety }))
}

async fn tool_analyze_function_assoc(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let assocs = engine.analyze_thread_function_assoc();
    Ok(json!({ "trace_id": trace_id, "assoc_count": assocs.len(), "thread_function_assocs": assocs }))
}

async fn tool_analyze_data_flows(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let flows = engine.analyze_data_flows();
    Ok(json!({ "trace_id": trace_id, "flow_count": flows.len(), "data_flows": flows }))
}

async fn tool_detect_producer_consumer(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let patterns = engine.detect_producer_consumer();
    Ok(json!({ "trace_id": trace_id, "pattern_count": patterns.len(), "producer_consumer_patterns": patterns }))
}

async fn tool_analyze_scheduling(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let engine = server.get_or_create_engine(trace_id).await;
    let mut engine = engine.lock().await;
    let scheduling = engine.analyze_scheduling();
    Ok(json!({ "trace_id": trace_id, "thread_count": scheduling.len(), "scheduling": scheduling }))
}
