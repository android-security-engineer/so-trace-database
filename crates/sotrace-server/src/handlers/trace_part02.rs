
/// Import a trace batch into the engine for the given trace_id
async fn import_trace(
    State(state): State<AppState>,
    Json(req): Json<TraceImportRequest>,
) -> impl IntoResponse {
    use sotrace_core::adapters::TraceEvent;
    let trace_id = req.trace_id;

    let result = ImportResult {
        trace_id,
        threads_imported: req.threads.len(),
        instructions_imported: req.instructions.len(),
        sync_events_imported: req.sync_events.len(),
        context_switches_imported: req.context_switches.len(),
        state_changes_imported: req.state_changes.len(),
        memory_writes_imported: req.memory_writes.len(),
        memory_reads_imported: req.memory_reads.len(),
        jni_calls_imported: req.jni_calls.len(),
        register_deltas_imported: req.register_deltas.len(),
        calls_imported: req.calls.len(),
    };

    // Phase 1: flatten every category into a uniform `TraceEvent` stream.
    // Ingestion used to follow category order (threads, then instructions,
    // then memory_writes, …) rather than step order, so a `state_change` at
    // step 50 fed after one at step 100 would leave `thread_states`/
    // `current_thread` stamped with the older state — the fields #91/#92 made
    // order-sensitive. `TraceEngine::feed_events` sorts by step and applies the
    // batch (instruction runs via `write_batch`). Mirrors CLI `feed_events`
    // and MCP `tool_import_trace`.
    let mut events: Vec<TraceEvent> = Vec::new();
    for info in req.threads { events.push(TraceEvent::Thread(info)); }
    for trace in req.instructions { events.push(TraceEvent::Instruction(trace)); }
    for mw in req.memory_writes {
        events.push(TraceEvent::MemoryWrite {
            step: mw.step, thread_id: mw.thread_id, address: mw.address, data: mw.data,
        });
    }
    for mr in req.memory_reads {
        events.push(TraceEvent::MemoryRead {
            step: mr.step, thread_id: mr.thread_id, address: mr.address, size: mr.size,
        });
    }
    for event in req.sync_events { events.push(TraceEvent::Sync(event)); }
    for switch in req.context_switches { events.push(TraceEvent::ContextSwitch(switch)); }
    for change in req.state_changes { events.push(TraceEvent::StateChange(change)); }
    for call in req.jni_calls { events.push(TraceEvent::JniCall(call)); }
    for delta in req.register_deltas { events.push(TraceEvent::Register(delta)); }
    for call in req.calls { events.push(TraceEvent::Call(call)); }

    // Phase 2: chronological batch apply. The sorted stream is also what gets
    // persisted (save_trace reads this buffer), so a later save replays events
    // in step order too. `feed_events` sorts again (stable) unless the
    // buffer is already non-decreasing.
    events.sort_by_key(|e| e.step());

    let engine = state.get_or_create_engine(trace_id).await;
    let mut guard = engine.write().await;
    if let Err(detail) = guard.feed_events(events.iter().cloned()) {
        state.record_import_failure();
        return ApiError::bad_request(
            "failed to import event",
            format!("trace id {}: {}", trace_id, detail),
        ).into_response();
    }
    drop(guard);

    // Register the SO function table (if a so_file_id was supplied) so analysis
    // resolves function names instead of bare offsets. Mirrors CLI load_engine.
    register_so_for_engine(&state, req.so_file_id.unwrap_or(0), &engine).await;

    // Persist the step-sorted stream so save_trace can replay it verbatim.
    state.store_event_buffer(trace_id, events).await;

    Json(serde_json::json!({
        "status": "ok",
        "trace_id": trace_id,
        "imported": result,
    })).into_response()
}

/// List all traces that have been imported (have an engine in the pool)
async fn list_traces(State(state): State<AppState>) -> impl IntoResponse {
    let engines = state.engines.lock().await;
    let trace_ids: Vec<u64> = engines.keys().copied().collect();
    Json(serde_json::json!({
        "trace_count": trace_ids.len(),
        "traces": trace_ids,
    }))
}

/// Query instructions in a trace with optional filters
async fn query_instructions(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
    Query(params): Query<InstructionQueryParams>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let engine = engine.read().await;

    let start = params.start_step.unwrap_or(0);
    let end = params.end_step.unwrap_or(u64::MAX);

    let mut results: Vec<InstructionTrace> = engine.query_instructions_range(start, end)
        .into_iter()
        .filter(|t| {
            if let Some(tid) = params.thread_id {
                if t.thread_id != tid { return false; }
            }
            if let Some(addr) = params.address {
                if t.address != addr { return false; }
            }
            true
        })
        .cloned()
        .collect();

    if let Some(limit) = params.limit {
        results.truncate(limit as usize);
    }

    Json(serde_json::json!({
        "trace_id": trace_id,
        "instruction_count": results.len(),
        "instructions": results,
    }))
}
