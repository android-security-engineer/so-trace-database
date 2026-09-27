    use super::*;
    use crate::app::build_app_with_state;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sotrace_core::models::thread::{SyncEventType, SyncResult};
    use tower::ServiceExt;

    async fn send(router: axum::Router, method: &str, uri: &str, body: Option<String>) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        builder = builder.header(
            "authorization",
            format!("Bearer {}", crate::middleware::auth::TEST_BEARER_TOKEN),
        );
        let request = if let Some(json) = body {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(json)).unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let resp = router.oneshot(request).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn empty_state() -> crate::app::AppState {
        crate::app::AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"))
    }

    /// A state backed by a real tempdir (for persistence tests that hit disk).
    fn temp_state() -> (crate::app::AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::app::AppState::new(dir.path().to_path_buf());
        (state, dir)
    }

    #[tokio::test]
    async fn test_import_trace_and_query() {
        let app = build_app_with_state(empty_state());

        // Build import payload
        let import = serde_json::json!({
            "trace_id": 100,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "instructions": [
                {"seq": 0, "thread_id": 1, "address": 0x4000, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 1, "thread_id": 1, "address": 0x4004, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 2, "thread_id": 1, "address": 0x4008, "timestamp": null,
                 "is_branch": true, "branch_taken": true, "opcode": null},
            ],
        });

        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK, "import failed: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["imported"]["instructions_imported"], 3);
        assert_eq!(json["imported"]["threads_imported"], 1);
    }

    #[tokio::test]
    async fn test_list_traces_empty() {
        let app = build_app_with_state(empty_state());
        let (status, body) = send(app, "GET", "/api/v1/traces", None).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["trace_count"], 0);
    }

    #[tokio::test]
    async fn test_list_traces_after_import() {
        let state = empty_state();
        let app = build_app_with_state(state.clone());

        let import = serde_json::json!({"trace_id": 200, "instructions": []});
        let (status, _) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK);

        // Second app shares the same state
        let app2 = build_app_with_state(state);
        let (status, body) = send(app2, "GET", "/api/v1/traces", None).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["trace_count"], 1);
        assert_eq!(json["traces"][0], 200);
    }

    #[tokio::test]
    async fn test_query_instructions_after_import() {
        let state = empty_state();
        let app = build_app_with_state(state.clone());

        let import = serde_json::json!({
            "trace_id": 300,
            "instructions": [
                {"seq": 0, "thread_id": 1, "address": 0x4000, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 1, "thread_id": 1, "address": 0x4004, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 5, "thread_id": 2, "address": 0x5000, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
            ],
        });
        let (status, _) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK);

        // Query all instructions
        let app2 = build_app_with_state(state.clone());
        let (status, body) = send(app2, "GET", "/api/v1/traces/300/instructions", None).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["instruction_count"], 3);

        // Query by thread filter
        let app3 = build_app_with_state(state);
        let (status, body) = send(app3, "GET", "/api/v1/traces/300/instructions?thread_id=2", None).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["instruction_count"], 1);
    }

    #[tokio::test]
    async fn test_import_memory_reads_then_detect_race() {
        // Closes the HTTP dead-ingest gap (#81): import_trace must accept
        // memory_reads so the analyzer's write→read race detection has a
        // read end to pair with the write. Without the read, no race is
        // reported even though T2 reads an unsynchronized T1 write.
        let state = empty_state();
        let app = build_app_with_state(state.clone());

        let import = serde_json::json!({
            "trace_id": 520,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t1",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t2",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 5, "thread_id": 1, "address": 0x1000, "data": [255, 255, 255, 255]},
            ],
            "memory_reads": [
                {"step": 8, "thread_id": 2, "address": 0x1000, "size": 4},
            ],
            "context_switches": [
                {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0},
            ],
        });
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK, "import: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["imported"]["memory_reads_imported"], 1);

        // Race detection must surface the write@5 → read@8 conflict.
        let app2 = build_app_with_state(state);
        let (status, body) = send(app2, "GET", "/api/v1/traces/520/analyze/threads/races", None).await;
        assert_eq!(status, StatusCode::OK, "races: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let races = json["races"].as_array().expect("races array");
        assert_eq!(races.len(), 1, "expected one write→read race: {}", body);
        assert_eq!(races[0]["address"], 0x1000);
    }

    #[tokio::test]
    async fn test_import_then_analyze_e2e() {
        // End-to-end: import trace data, then run analysis on the same trace
        let state = empty_state();
        let app = build_app_with_state(state.clone());

        let import = serde_json::json!({
            "trace_id": 400,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t1",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t2",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 5, "thread_id": 1, "address": 0x1000, "data": [255, 255, 255, 255]},
            ],
            "sync_events": [
                {"step": 3, "thread_id": 1, "sync_type": "MutexLock",
                 "sync_object_addr": 2882338816u64, "result": "Success", "wait_duration_ns": null},
            ],
            "context_switches": [
                {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0},
            ],
        });

        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK, "import: {}", body);

        // Now run analysis — the engine for trace 400 should be populated
        let app2 = build_app_with_state(state);
        let (status, body) = send(app2, "POST", "/api/v1/traces/400/analyze/threads", None).await;
        assert_eq!(status, StatusCode::OK, "analyze: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["analysis"].is_object());
        assert!(json["analysis"]["lock_contentions"].is_array());
    }

    #[tokio::test]
    async fn test_import_empty_trace() {
        let app = build_app_with_state(empty_state());
        let import = serde_json::json!({"trace_id": 500});
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["imported"]["instructions_imported"], 0);
    }

    #[tokio::test]
    async fn test_import_register_deltas_and_calls_then_query() {
        // Closes the HTTP dead-ingest gap (#78): import_trace must accept
        // register_deltas and calls (MCP already did in #77) so the
        // /registers and /call-chain query endpoints have data to surface.
        let state = empty_state();
        let app = build_app_with_state(state.clone());

        let import = serde_json::json!({
            "trace_id": 510,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "w",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            // x0 (register_id 0): two same-seq deltas at step 5, last wins.
            "register_deltas": [
                {"seq": 5, "change_mask": 1u64, "values": [0xAA]},
                {"seq": 5, "change_mask": 1u64, "values": [0xBB]},
            ],
            // One call at step 3, no return → one frame on the stack.
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call",
                 "caller_address": 0x4000, "callee_address": 0x8000,
                 "callee_func_id": null, "seq": 3, "depth": 0, "return_seq": null},
            ],
        });
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK, "import failed: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["imported"]["register_deltas_imported"], 2);
        assert_eq!(json["imported"]["calls_imported"], 1);

        // query_register x0 @ step 5 → 0xBB (last-writer-wins).
        let app2 = build_app_with_state(state.clone());
        let (status, body) = send(app2, "GET", "/api/v1/traces/510/register/0?step=5", None).await;
        assert_eq!(status, StatusCode::OK, "register query failed: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["value"], 0xBB);

        // call-chain lists the imported call.
        let app3 = build_app_with_state(state);
        let (status, body) = send(app3, "GET", "/api/v1/traces/510/call-chain", None).await;
        assert_eq!(status, StatusCode::OK, "call-chain query failed: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        // The endpoint returns a list of call events; exactly one was imported.
        let calls = json["calls"].as_array().or_else(|| json["call_chain"].as_array())
            .expect("calls array present");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["callee_address"], 0x8000);
    }
    /// `import_trace` must feed events in step order even when the request
    /// body lists them out of order — `ThreadStore.thread_states` (the live
    /// HashMap) is stamped in ingestion order, so a step-100 Blocked change
    /// listed before a step-50 Running change would leave it stuck at Running.
    /// #91/#92 made that field order-sensitive. The fix sorts the stream by
    /// step before feeding, mirroring CLI `feed_events` and MCP import_trace.
    #[tokio::test]
    async fn test_import_trace_sorts_state_changes_by_step() {
        let state = empty_state();
        let app = build_app_with_state(state.clone());

        let import = serde_json::json!({
            "trace_id": 600,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t1",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            // Deliberately out of step order: step 100 before step 50.
            "state_changes": [
                {"step": 100, "thread_id": 1, "new_state": "Blocked",
                 "prev_state": "Running", "prev_running_thread": 1},
                {"step": 50, "thread_id": 1, "new_state": "Running",
                 "prev_state": "Runnable", "prev_running_thread": null},
            ],
        });
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK, "import failed: {}", body);

        // Probe the live `thread_states` map (NOT the replayed query, which
        // re-sorts by step and would hide the bug). Step 100 (Blocked) must be
        // the last-applied state.
        let engine = state.engines.lock().await.get(&600).cloned().expect("engine present");
        let engine = engine.read().await;
        let final_state = engine.thread_store().all_thread_states().get(&1).copied().expect("thread 1");
        assert_eq!(final_state, sotrace_core::models::thread::ThreadState::Blocked,
            "step 100 (Blocked) must win — stream was sorted before feed");
    }

    #[tokio::test]
    async fn test_import_invalid_json() {
        let app = build_app_with_state(empty_state());
        let (status, _body) = send(app, "POST", "/api/v1/traces/import", Some("{not valid json".to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // --- persistence ---

    fn import_payload(trace_id: u64) -> serde_json::Value {
        serde_json::json!({
            "trace_id": trace_id,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "t1",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "instructions": [
                {"seq": 0, "thread_id": 1, "address": 0x4000, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
            ],
            "memory_writes": [
                {"step": 5, "thread_id": 1, "address": 0x1000, "data": [1, 2, 3]},
            ],
        })
    }

    #[tokio::test]
    async fn test_save_without_import_errors() {
        let (state, _dir) = temp_state();
        let app = build_app_with_state(state);
        let (status, body) = send(app, "POST", "/api/v1/traces/77/save", Some("{}".to_string())).await;
        // No prior import → no event buffer → 404, not 200.
        assert_eq!(status, StatusCode::NOT_FOUND);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["error"], "no in-memory trace");
    }

    #[tokio::test]
    async fn test_save_list_get_load_delete_roundtrip() {
        let (state, _dir) = temp_state();

        // Import trace 100.
        let app = build_app_with_state(state.clone());
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import_payload(100).to_string())).await;
        assert_eq!(status, StatusCode::OK, "import: {}", body);

        // Save it.
        let app = build_app_with_state(state.clone());
        let (status, body) = send(app, "POST", "/api/v1/traces/100/save", Some("{}".to_string())).await;
        assert_eq!(status, StatusCode::OK, "save: {}", body);
        let saved: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(saved["status"], "ok");
        let persisted_id = saved["persisted_id"].as_u64().unwrap();

        // List persisted.
        let app = build_app_with_state(state.clone());
        let (status, body) = send(app, "GET", "/api/v1/traces/persisted", None).await;
        assert_eq!(status, StatusCode::OK);
        let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(listed["trace_count"], 1);
        assert_eq!(listed["traces"][0]["trace_id"], persisted_id);
        assert_eq!(listed["traces"][0]["source"], "http");

        // Get single.
        let uri = format!("/api/v1/traces/persisted/{}", persisted_id);
        let app = build_app_with_state(state.clone());
        let (status, body) = send(app, "GET", &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        let got: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(got["event_count"], 3); // 1 thread + 1 instruction + 1 memory write

        // Load (replay) into a fresh engine pool slot.
        let load_uri = format!("/api/v1/traces/persisted/{}/load", persisted_id);
        let app = build_app_with_state(state.clone());
        let (status, body) = send(app, "POST", &load_uri, None).await;
        assert_eq!(status, StatusCode::OK, "load: {}", body);
        let loaded: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(loaded["status"], "ok");
        assert_eq!(loaded["persisted_id"], persisted_id);

        // Delete.
        let app = build_app_with_state(state.clone());
        let (status, body) = send(app, "DELETE", &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        let del: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(del["status"], "deleted");

        // List now empty.
        let app = build_app_with_state(state);
        let (status, body) = send(app, "GET", "/api/v1/traces/persisted", None).await;
        let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(listed["trace_count"], 0);
    }

    #[tokio::test]
    async fn test_load_missing_returns_error() {
        let (state, _dir) = temp_state();
        let app = build_app_with_state(state);
        let (status, body) = send(app, "POST", "/api/v1/traces/persisted/9999/load", None).await;
        // Missing persisted trace → 404, with the not-found error label.
        assert_eq!(status, StatusCode::NOT_FOUND);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["error"], "not found");
    }

    /// Build a minimal ParsedSoFile with one function "decrypt" at offset
    /// 0x4000, size 100, and persist it. Returns the assigned so_file_id.
    /// Mirrors the persistence/mod.rs test helper.
    fn save_decrypt_so(data_dir: &std::path::Path) -> u64 {
        use sotrace_core::elf::ParsedSoFile;
        use sotrace_core::models::so_file::{Architecture, SOFile};
        use sotrace_core::models::so_function::SOFunction;
        use sotrace_core::models::so_segment::{SOSegment, SegmentType};
        use sotrace_core::models::so_symbol::{SOSymbol, SymbolType, SymbolBind};
        let parsed = ParsedSoFile {
            so_file: SOFile {
                id: 0, path: "/fake/libtest.so".into(), build_id: Some(vec![0xab; 20]),
                arch: Architecture::AArch64, file_size: 4096, md5: [1; 16], sha256: [2; 32],
                loaded_base_address: 0, created_at: 1_700_000_000,
            },
            segments: vec![SOSegment {
                id: 0, so_file_id: 0, name: ".text".into(),
                seg_type: SegmentType::Load, offset: 0, vaddr: 0, size: 100, flags: 0,
            }],
            symbols: vec![SOSymbol {
                id: 0, so_file_id: 0, name: "decrypt".into(), value: 0x4000, size: 100,
                sym_type: SymbolType::Func, bind: SymbolBind::Global,
                is_imported: false, is_exported: true,
            }],
            functions: vec![SOFunction {
                id: 0, so_file_id: 0, symbol_id: Some(0), name: "decrypt".into(),
                offset: 0x4000, size: 100, is_jni: false, is_imported: false,
                is_exported: true, is_thunk: false,
            }],
        };
        sotrace_engine::persistence::SoRepository::open(data_dir)
            .and_then(|repo| repo.save(&parsed).map(|o| o.id))
            .expect("save ParsedSoFile")
    }
