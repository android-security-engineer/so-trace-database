
    /// #106: importing a trace with `so_file_id` registers the SO function
    /// table into the engine, so `analyze/threads/function-assoc` resolves
    /// the callee address (a function-internal PC, exercising #105's range
    /// query) to the function name "decrypt" instead of leaving it None.
    #[tokio::test]
    async fn test_import_with_so_file_id_resolves_function_name() {
        let (state, _dir) = temp_state();
        let so_id = save_decrypt_so(&state.data_dir);
        let app = build_app_with_state(state.clone());

        // One call into decrypt at an in-function PC (0x4034, within
        // [0x4000, 0x4064)). function_name(0x4034) must resolve via the
        // range query, not just the exact entry.
        let import = serde_json::json!({
            "trace_id": 700,
            "so_file_id": so_id,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK, "import failed: {}", body);

        let app2 = build_app_with_state(state);
        let (status, body) = send(app2, "GET", "/api/v1/traces/700/analyze/threads/function-assoc", None).await;
        assert_eq!(status, StatusCode::OK, "analyze failed: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let assocs = json["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1, "expected one thread-function assoc");
        assert_eq!(assocs[0]["function_address"], 0x4034);
        assert_eq!(assocs[0]["function_name"], "decrypt",
                   "function name must be backfilled from the registered SO (got {:?})",
                   assocs[0]["function_name"]);
    }

    /// #106 boundary: a missing/zero `so_file_id` must not block import or
    /// registration — the trace imports fine and function_name stays None
    /// (graceful degradation, mirrors CLI's `.ok()`).
    #[tokio::test]
    async fn test_import_without_so_file_id_leaves_names_none() {
        let state = empty_state();
        let app = build_app_with_state(state.clone());
        let import = serde_json::json!({
            "trace_id": 701,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK, "import failed: {}", body);

        let app2 = build_app_with_state(state);
        let (status, body) = send(app2, "GET", "/api/v1/traces/701/analyze/threads/function-assoc", None).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let assocs = json["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1);
        // No SO registered → function_name is None, so the field is skipped
        // (skip_serializing_if = "Option::is_none").
        assert!(assocs[0].get("function_name").is_none() || assocs[0]["function_name"].is_null(),
                "function_name must be absent/null without an SO; got {:?}", assocs[0]);
    }

    /// #106: load_trace round-trip — import with so_file_id, save, then load.
    /// load_trace keys the replayed engine under `persisted_id` (auto-assigned,
    /// distinct from the import trace_id 702), so analyzing `persisted_id`
    /// hits the freshly-replayed engine and proves the SO was re-registered on
    /// load (not just lingering from import).
    #[tokio::test]
    async fn test_load_trace_re_registers_so_function_name() {
        let (state, _dir) = temp_state();
        let so_id = save_decrypt_so(&state.data_dir);
        let app = build_app_with_state(state.clone());

        let import = serde_json::json!({
            "trace_id": 702,
            "so_file_id": so_id,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK, "import: {}", body);

        // Persist (carrying so_file_id). persisted_id is auto-assigned and
        // differs from 702, so the load-replayed engine won't collide with the
        // import-time engine for 702.
        let save = serde_json::json!({"so_file_id": so_id, "source": "test"});
        let app = build_app_with_state(state.clone());
        let (status, body) = send(app, "POST", "/api/v1/traces/702/save", Some(save.to_string())).await;
        assert_eq!(status, StatusCode::OK, "save: {}", body);
        let saved: serde_json::Value = serde_json::from_str(&body).unwrap();
        let persisted_id = saved["persisted_id"].as_u64().unwrap();
        assert_ne!(persisted_id, 702, "persisted_id must be auto-assigned, not the import trace_id");

        // Load into the persisted_id engine (replays events + re-registers SO).
        let app = build_app_with_state(state.clone());
        let (status, body) = send(
            app, "POST",
            &format!("/api/v1/traces/persisted/{}/load", persisted_id),
            None,
        ).await;
        assert_eq!(status, StatusCode::OK, "load: {}", body);

        // Analyze the persisted_id engine — the SO was registered on load, so
        // the in-function callee PC resolves to "decrypt".
        let app = build_app_with_state(state);
        let (status, body) = send(
            app, "GET",
            &format!("/api/v1/traces/{}/analyze/threads/function-assoc", persisted_id),
            None,
        ).await;
        assert_eq!(status, StatusCode::OK, "analyze: {}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let assocs = json["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0]["function_name"], "decrypt",
                   "load_trace must re-register the SO; got {:?}", assocs[0]);
    }

    /// #106 boundary: importing with a non-existent so_file_id must not fail
    /// the import — the SO load is warned + swallowed, names stay None.
    #[tokio::test]
    async fn test_import_with_nonexistent_so_file_id_degrades() {
        let (state, _dir) = temp_state();
        let app = build_app_with_state(state.clone());
        let import = serde_json::json!({
            "trace_id": 703,
            "so_file_id": 999987,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let (status, body) = send(app, "POST", "/api/v1/traces/import", Some(import.to_string())).await;
        assert_eq!(status, StatusCode::OK,
                   "import must succeed despite a bad so_file_id (graceful degradation): {}", body);
    }
