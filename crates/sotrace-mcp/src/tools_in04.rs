
async fn tool_query_memory_page(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let page_address = args.get("page_address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'page_address' (expected integer)"))?;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let page = engine.rebuild_memory_page(page_address, step);

    Ok(json!({
        "trace_id": trace_id,
        "page_address": page_address,
        "step": step,
        "length": page.as_ref().map(|p| p.len()).unwrap_or(0),
        "bytes_hex": page.as_ref().map(|p| hex(p)),
    }))
}

async fn tool_query_call_stack(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let thread_id = args.get("thread_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'thread_id' (expected integer)"))?
        as u32;
    let step = args.get("step")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'step' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let frames = engine.rebuild_call_stack(thread_id, step);

    Ok(json!({
        "trace_id": trace_id,
        "thread_id": thread_id,
        "step": step,
        "frame_count": frames.len(),
        "frames": frames,
    }))
}

async fn tool_query_jni_calls(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let address = args.get("address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'address' (expected integer)"))?;
    let start = args.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
    let end = args.get("end").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let calls: Vec<_> = engine
        .query_jni_calls_by_address(address, start, end)
        .into_iter()
        .cloned()
        .collect();
    let count = calls.len();

    Ok(json!({
        "trace_id": trace_id,
        "native_address": address,
        "start": start,
        "end": end,
        "count": count,
        "jni_calls": calls,
    }))
}

async fn tool_query_threads_at_address(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let address = args.get("address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::new("missing or invalid 'address' (expected integer)"))?;

    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;
    let accesses = engine.query_threads_at_address(address);
    let step_count = engine.query_instructions_by_address(address).len();

    Ok(json!({
        "trace_id": trace_id,
        "address": address,
        "step_count": step_count,
        // Each entry is (thread_id, step) — the step at which that thread
        // executed the address, NOT an access count.
        "thread_accesses": accesses.iter().map(|(t, s)| json!({"thread_id": t, "step": s})).collect::<Vec<_>>(),
    }))
}

