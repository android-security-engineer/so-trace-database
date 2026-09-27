
    #[tokio::test]
    async fn test_analyze_thread_states() {
        let server = McpServer::new();
        // A dedicated trace with an exiting thread and a state-change stream so
        // residency intervals are bounded and measurable.
        let args = json!({
            "trace_id": 11,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": 100, "name": "worker",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "state_changes": [
                {"step": 0, "thread_id": 1, "new_state": "Running", "prev_state": null, "prev_running_thread": null},
                {"step": 30, "thread_id": 1, "new_state": "WaitingForLock", "prev_state": "Running", "prev_running_thread": null},
                {"step": 50, "thread_id": 1, "new_state": "Running", "prev_state": "WaitingForLock", "prev_running_thread": null},
            ],
        });
        dispatch_tool(&server, "import_trace", &args).await.unwrap();

        let result = dispatch_tool(&server, "analyze_thread_states", &json!({"trace_id": 11})).await.unwrap();
        let stats = result["state_stats"].as_array().expect("state_stats array");
        assert_eq!(stats.len(), 1);
        assert_eq!(result["thread_count"], 1);
        let s = &stats[0];
        assert_eq!(s["thread_id"], 1);
        // Running 80 (0→30 + 50→100), WaitingForLock 20 (30→50).
        assert_eq!(s["running_steps"], 80);
        assert_eq!(s["waiting_steps"], 20);
        assert_eq!(s["total_measured_steps"], 100);
        assert_eq!(s["final_state"], "Running");
    }

    #[tokio::test]
    async fn test_analyze_critical_sections() {
        let server = McpServer::new();
        // A trace where thread 1 holds a mutex from step 10 to 40 (hold = 30).
        let args = json!({
            "trace_id": 12,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "worker",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "sync_events": [
                {"step": 10, "thread_id": 1, "sync_type": "MutexLock", "sync_object_addr": LOCK_ADDR, "result": "Success", "wait_duration_ns": null},
                {"step": 40, "thread_id": 1, "sync_type": "MutexUnlock", "sync_object_addr": LOCK_ADDR, "result": "Success", "wait_duration_ns": null},
            ],
        });
        dispatch_tool(&server, "import_trace", &args).await.unwrap();

        let result = dispatch_tool(&server, "analyze_critical_sections", &json!({"trace_id": 12})).await.unwrap();
        let cs = result["critical_sections"].as_array().expect("critical_sections array");
        assert_eq!(cs.len(), 1);
        assert_eq!(result["lock_count"], 1);
        let c = &cs[0];
        assert_eq!(c["lock_address"]["addr"], LOCK_ADDR);
        assert_eq!(c["lock_address"]["kind"], "Mutex");
        assert_eq!(c["hold_count"], 1);
        assert_eq!(c["total_hold_steps"], 30);
        assert_eq!(c["max_hold_steps"], 30);
        assert_eq!(c["longest_hold_thread"], 1);
    }

    #[tokio::test]
    async fn test_analyze_jni_boundary() {
        let server = McpServer::new();
        let args = json!({
            "trace_id": 13,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "jni-worker",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
            ],
            "jni_calls": [
                {"id": 1, "seq": 10, "thread_id": 1, "direction": "JavaToNative",
                 "java_class": "com.app.Foo", "java_method": "doWork", "java_signature": "()V",
                 "native_func_id": null, "native_address": 8192, "jni_env_address": null},
                {"id": 2, "seq": 20, "thread_id": 1, "direction": "NativeToJava",
                 "java_class": "com.app.Bar", "java_method": "callback", "java_signature": "()V",
                 "native_func_id": null, "native_address": 8192, "jni_env_address": null},
            ],
        });
        let imp = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(imp["imported"]["jni_calls"], 2);

        let result = dispatch_tool(&server, "analyze_jni_boundary", &json!({"trace_id": 13})).await.unwrap();
        let stats = result["jni_boundary"].as_array().expect("jni_boundary array");
        assert_eq!(stats.len(), 1);
        assert_eq!(result["thread_count"], 1);
        let s = &stats[0];
        assert_eq!(s["thread_id"], 1);
        assert_eq!(s["is_jni_attached"], true);
        assert_eq!(s["total_crossings"], 2);
        assert_eq!(s["java_to_native_count"], 1);
        assert_eq!(s["native_to_java_count"], 1);
        assert_eq!(s["native_addresses"], serde_json::json!([8192]));
        assert_eq!(s["java_methods"], serde_json::json!(["com.app.Bar.callback", "com.app.Foo.doWork"]));
        // #119: first/last crossing step locate the JNI activity window (seq 10..20).
        assert_eq!(s["first_crossing_step"], 10);
        assert_eq!(s["last_crossing_step"], 20);
    }

    // --- query tools (register / memory / call-stack) ---

    /// Helper: import a trace with register deltas, calls, and a memory write
    /// so the five query_* tools have real data to surface.
    async fn import_query_test_data(server: &McpServer) {
        // x0 (register_id 0) is set to 0xAA at step 5, then 0xBB at step 5
        // (same-seq second delta — last-writer-wins, exercising EventLog).
        // PC (register_id 32) is set at step 6.
        // A call into callee 0x8000 at step 3 (thread 1, depth 0), no return
        // before the query step → one frame on the stack.
        // A 4-byte memory write at 0x2000 step 2 (page 0x2000).
        let args = json!({
            "trace_id": 14,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "q-worker",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 2, "thread_id": 1, "address": 0x2000, "data": [0xde, 0xad, 0xbe, 0xef]},
            ],
            "register_deltas": [
                {"seq": 5, "change_mask": 1u64, "values": [0xAA]},
                {"seq": 5, "change_mask": 1u64, "values": [0xBB]},
                {"seq": 6, "change_mask": 1u64 << 32, "values": [0x40000C00]},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call",
                 "caller_address": 0x4000, "callee_address": 0x8000,
                 "callee_func_id": null, "seq": 3, "depth": 0, "return_seq": null},
            ],
        });
        let imp = dispatch_tool(server, "import_trace", &args).await.unwrap();
        assert_eq!(imp["status"], "ok");
        assert_eq!(imp["imported"]["register_deltas"], 3);
        assert_eq!(imp["imported"]["calls"], 1);
    }

    #[tokio::test]
    async fn test_query_register_returns_last_wins_value() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        // x0 at step 5 → two same-seq deltas, the second (0xBB) wins.
        let r = dispatch_tool(&server, "query_register",
            &json!({"trace_id": 14, "register_id": 0, "step": 5})).await.unwrap();
        assert_eq!(r["register_id"], 0);
        assert_eq!(r["step"], 5);
        assert_eq!(r["value"], 0xBB);
        assert_eq!(r["value_hex"], "0xbb");

        // Before step 5, x0 was never written → None.
        let r = dispatch_tool(&server, "query_register",
            &json!({"trace_id": 14, "register_id": 0, "step": 4})).await.unwrap();
        assert!(r["value"].is_null());

        // PC (register_id 32) set at step 6 is visible at step 6 but not step 5.
        let r = dispatch_tool(&server, "query_register",
            &json!({"trace_id": 14, "register_id": 32, "step": 6})).await.unwrap();
        assert_eq!(r["value"], 0x40000C00);
    }

    #[tokio::test]
    async fn test_query_register_missing_id_errors() {
        let server = McpServer::new();
        import_query_test_data(&server).await;
        let err = dispatch_tool(&server, "query_register",
            &json!({"trace_id": 14, "step": 5})).await.unwrap_err();
        assert!(err.message.contains("register_id"));
    }

    #[tokio::test]
    async fn test_query_register_state_snapshot() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        let r = dispatch_tool(&server, "query_register_state",
            &json!({"trace_id": 14, "step": 6})).await.unwrap();
        assert_eq!(r["trace_id"], 14);
        assert_eq!(r["step"], 6);
        // RegisterState is serialized directly — x0 and pc populated.
        assert_eq!(r["state"]["gp_regs"][0], 0xBB);
        assert_eq!(r["state"]["pc"], 0x40000C00);

        // No deltas at or before step 1 → state is null.
        let r = dispatch_tool(&server, "query_register_state",
            &json!({"trace_id": 14, "step": 1})).await.unwrap();
        assert!(r["state"].is_null());
    }

    #[tokio::test]
    async fn test_query_register_history_lists_change_steps() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        // x0 (register_id 0) was set at step 5 (two same-seq deltas collapse to
        // one index entry). PC (32) was set at step 6.
        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 0})).await.unwrap();
        assert_eq!(r["change_count"], 1);
        assert_eq!(r["steps"], serde_json::json!([5]));

        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 32})).await.unwrap();
        assert_eq!(r["steps"], serde_json::json!([6]));

        // x1 (register_id 1) never changed → empty.
        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 1})).await.unwrap();
        assert_eq!(r["change_count"], 0);

        // Range filter: x0 in [6, max] → empty (x0 only changed at 5).
        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 0, "start": 6})).await.unwrap();
        assert_eq!(r["change_count"], 0);

        // Out-of-range register_id → empty, not an error.
        let r = dispatch_tool(&server, "query_register_history",
            &json!({"trace_id": 14, "register_id": 999})).await.unwrap();
        assert_eq!(r["change_count"], 0);
    }

    #[tokio::test]
    async fn test_query_memory_value_and_page() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        // 4 bytes written at 0x2000 (step 2), readable at step 5.
        let r = dispatch_tool(&server, "query_memory_value",
            &json!({"trace_id": 14, "address": 0x2000, "step": 5, "size": 4})).await.unwrap();
        assert_eq!(r["address"], 0x2000);
        assert_eq!(r["size"], 4);
        assert!(r["result"].is_object());
        assert_eq!(r["value_hex"], "deadbeef");

        // Before the write, the value is absent.
        let r = dispatch_tool(&server, "query_memory_value",
            &json!({"trace_id": 14, "address": 0x2000, "step": 1, "size": 4})).await.unwrap();
        assert!(r["result"].is_null());
        assert!(r["value_hex"].is_null());

        // Page rebuild: page 0x2000 holds the 4 written bytes at step 5.
        let r = dispatch_tool(&server, "query_memory_page",
            &json!({"trace_id": 14, "page_address": 0x2000, "step": 5})).await.unwrap();
        assert_eq!(r["page_address"], 0x2000);
        assert!(r["length"].as_u64().unwrap() >= 4);
        let hex = r["bytes_hex"].as_str().unwrap();
        assert!(hex.starts_with("deadbeef"));
    }

    #[tokio::test]
    async fn test_query_memory_value_straddling_page_boundary() {
        // #80 end-to-end at the MCP tool layer: a single query_memory_value
        // spanning a 4KB page boundary must return the full stitched value,
        // not a silently truncated first-page tail.
        let server = McpServer::new();
        // PAGE_SIZE = 4096 = 0x1000. Write 6 bytes starting 3 bytes before the
        // 0x2000/0x3000 boundary: [0x2FFD, 0x3003) straddles both pages.
        let args = json!({
            "trace_id": 16,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "m",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 2, "thread_id": 1, "address": 0x2FFD, "data": [0x10, 0x20, 0x30, 0x40, 0x50, 0x60]},
            ],
        });
        dispatch_tool(&server, "import_trace", &args).await.unwrap();

        let r = dispatch_tool(&server, "query_memory_value",
            &json!({"trace_id": 16, "address": 0x2FFD, "step": 5, "size": 6})).await.unwrap();
        assert_eq!(r["size"], 6);
        assert!(r["result"].is_object(), "expected a result, got: {}", r);
        // Full 6 bytes stitched across the boundary (not truncated to 3).
        assert_eq!(r["value_hex"], "102030405060");
        assert_eq!(r["result"]["page_address"], 0x2000);
    }

    #[tokio::test]
    async fn test_query_call_stack_one_frame() {
        let server = McpServer::new();
        import_query_test_data(&server).await;

        // A Call at step 3 with no Return before step 10 → exactly one frame.
        let r = dispatch_tool(&server, "query_call_stack",
            &json!({"trace_id": 14, "thread_id": 1, "step": 10})).await.unwrap();
        assert_eq!(r["trace_id"], 14);
        assert_eq!(r["thread_id"], 1);
        assert_eq!(r["step"], 10);
        assert_eq!(r["frame_count"], 1);
        let frame = &r["frames"][0];
        assert_eq!(frame["entry_address"], 0x8000);
        assert_eq!(frame["call_site"], 0x4000);
        assert_eq!(frame["call_seq"], 3);

        // Before the call, the stack is empty.
        let r = dispatch_tool(&server, "query_call_stack",
            &json!({"trace_id": 14, "thread_id": 1, "step": 2})).await.unwrap();
        assert_eq!(r["frame_count"], 0);

        // Wrong thread → empty.
        let r = dispatch_tool(&server, "query_call_stack",
            &json!({"trace_id": 14, "thread_id": 2, "step": 10})).await.unwrap();
        assert_eq!(r["frame_count"], 0);
    }

    #[tokio::test]
    async fn test_query_jni_calls_filters_same_step_sibling() {
        let server = McpServer::new();
        // Two threads share seq 10 but call DIFFERENT native addresses; a
        // third call reaches 0x4000 again at seq 30.
        let args = json!({
            "trace_id": 15,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": null,
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": null,
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
            ],
            "jni_calls": [
                {"id": 1, "seq": 10, "thread_id": 1, "direction": "JavaToNative",
                 "java_class": "com.app.Foo", "java_method": "doWork", "java_signature": "()V",
                 "native_func_id": null, "native_address": 16384, "jni_env_address": null},
                {"id": 2, "seq": 10, "thread_id": 2, "direction": "JavaToNative",
                 "java_class": "com.app.Bar", "java_method": "other", "java_signature": "()V",
                 "native_func_id": null, "native_address": 24576, "jni_env_address": null},
                {"id": 3, "seq": 30, "thread_id": 1, "direction": "NativeToJava",
                 "java_class": "com.app.Bar", "java_method": "callback", "java_signature": "()V",
                 "native_func_id": null, "native_address": 16384, "jni_env_address": null},
            ],
        });
        let imp = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(imp["imported"]["jni_calls"], 3);

        // 0x4000 = 16384: two calls (seq 10 + 30); the 0x6000 sibling at seq 10
        // is excluded despite sharing the step.
        let r = dispatch_tool(&server, "query_jni_calls",
            &json!({"trace_id": 15, "address": 16384})).await.unwrap();
        assert_eq!(r["count"], 2);
        let calls = r["jni_calls"].as_array().unwrap();
        assert_eq!(calls[0]["seq"], 10);
        assert_eq!(calls[1]["seq"], 30);
        assert!(calls.iter().all(|c| c["native_address"] == 16384));

        // Range [0,20] keeps only the seq-10 call.
        let r = dispatch_tool(&server, "query_jni_calls",
            &json!({"trace_id": 15, "address": 16384, "start": 0, "end": 20})).await.unwrap();
        assert_eq!(r["count"], 1);
        assert_eq!(r["jni_calls"][0]["java_method"], "doWork");

        // The 0x6000 sibling is reachable via its own address.
        let r = dispatch_tool(&server, "query_jni_calls",
            &json!({"trace_id": 15, "address": 24576})).await.unwrap();
        assert_eq!(r["count"], 1);
        assert_eq!(r["jni_calls"][0]["thread_id"], 2);

        // Unknown address → empty, no error.
        let r = dispatch_tool(&server, "query_jni_calls",
            &json!({"trace_id": 15, "address": 99999})).await.unwrap();
        assert_eq!(r["count"], 0);
    }

    #[tokio::test]
    async fn test_query_threads_at_address_keeps_both_threads_at_shared_step() {
        let server = McpServer::new();
        let args = json!({
            "trace_id": 16,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": null,
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": null,
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "instructions": [
                {"seq": 7, "thread_id": 1, "address": 4096, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 7, "thread_id": 2, "address": 4096, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 9, "thread_id": 1, "address": 4096, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
            ],
        });
        dispatch_tool(&server, "import_trace", &args).await.unwrap();

        // 0x1000 = 4096: both threads at seq 7 + thread 1 at seq 9 → 3 accesses.
        // Each entry carries `step`, not a mislabeled `count`.
        let r = dispatch_tool(&server, "query_threads_at_address",
            &json!({"trace_id": 16, "address": 4096})).await.unwrap();
        assert_eq!(r["address"], 4096);
        let accesses = r["thread_accesses"].as_array().unwrap();
        assert_eq!(accesses.len(), 3);
        let mut pairs: Vec<(u64, u64)> = accesses.iter()
            .map(|a| (a["thread_id"].as_u64().unwrap(), a["step"].as_u64().unwrap()))
            .collect();
        pairs.sort();
        assert_eq!(pairs, vec![(1, 7), (1, 9), (2, 7)]);

        // Unknown address → empty.
        let r = dispatch_tool(&server, "query_threads_at_address",
            &json!({"trace_id": 16, "address": 99999})).await.unwrap();
        assert!(r["thread_accesses"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_missing_trace_id_returns_error() {
        let server = McpServer::new();
        let result = dispatch_tool(&server, "analyze_threads", &json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("trace_id"));
    }

    #[tokio::test]
    async fn test_empty_trace_analyze() {
        let server = McpServer::new();
        // Analyze a trace with no data — should return empty results, not error
        let result = dispatch_tool(&server, "analyze_threads", &json!({"trace_id": 999})).await.unwrap();
        assert_eq!(result["trace_id"], 999);
        assert!(result["analysis"]["race_conditions"].is_array());
    }

    // --- persistence tools ---

    #[tokio::test]
    async fn test_persistence_disabled_errors() {
        // No data dir → persistence tools must report a clear error.
        let server = McpServer::new();
        let err = dispatch_tool(&server, "save_trace", &json!({"trace_id": 7})).await.unwrap_err();
        assert!(err.message.contains("persistence is disabled"));
        let err = dispatch_tool(&server, "list_persisted_traces", &json!({})).await.unwrap_err();
        assert!(err.message.contains("persistence is disabled"));
    }

    #[tokio::test]
    async fn test_save_trace_without_import_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "save_trace", &json!({"trace_id": 7})).await.unwrap_err();
        // No in-memory trace 7 → error.
        assert!(err.message.contains("no in-memory trace"));
    }
