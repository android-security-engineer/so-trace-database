
/// GET per-lock critical-section / hold-time statistics.
async fn analyze_critical_sections(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let critical_sections = engine.analyze_critical_sections();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "lock_count": critical_sections.len(),
        "critical_sections": critical_sections,
    }))
}

/// `GET /api/v1/traces/:id/analyze/threads/jni-boundary`
async fn analyze_jni_boundary(
    State(state): State<AppState>,
    Path(trace_id): Path<u64>,
) -> impl IntoResponse {
    let engine = state.get_or_create_engine(trace_id).await;
    let mut engine = engine.write().await;

    let jni_boundary = engine.analyze_jni_boundary();

    Json(serde_json::json!({
        "trace_id": trace_id,
        "thread_count": jni_boundary.len(),
        "jni_boundary": jni_boundary,
    }))
}

