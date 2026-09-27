    use super::*;
    use crate::server::McpServer;
    use serde_json::json;

    const LOCK_ADDR: u64 = 0xABCD0000;

    /// Import a trace with two threads, a memory write, sync events, and a context switch
    async fn import_test_data(server: &McpServer) {
        let args = json!({
            "trace_id": 7,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "worker-1",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "worker-2",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "instructions": [
                {"seq": 0, "thread_id": 1, "address": 0x4000, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 1, "thread_id": 1, "address": 0x4004, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 2, "thread_id": 2, "address": 0x5000, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
            ],
            "memory_writes": [
                {"step": 5, "thread_id": 1, "address": 0x1000, "data": [255, 255, 255, 255]},
            ],
            "sync_events": [
                {"step": 3, "thread_id": 1, "sync_type": "MutexLock",
                 "sync_object_addr": LOCK_ADDR, "result": "Success", "wait_duration_ns": null},
                {"step": 6, "thread_id": 2, "sync_type": "MutexLock",
                 "sync_object_addr": LOCK_ADDR, "result": "Success", "wait_duration_ns": 1500},
            ],
            "context_switches": [
                {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0},
            ],
        });
        let result = dispatch_tool(server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["imported"]["threads"], 2);
        assert_eq!(result["imported"]["instructions"], 3);
        assert_eq!(result["imported"]["sync_events"], 2);
        assert_eq!(result["imported"]["context_switches"], 1);
    }

    #[tokio::test]
    async fn test_import_and_list_traces() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "list_traces", &json!({})).await.unwrap();
        assert_eq!(result["trace_count"], 1);
        assert_eq!(result["traces"][0], 7);
    }

    #[tokio::test]
    async fn test_list_threads() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "list_threads", &json!({"trace_id": 7})).await.unwrap();
        assert_eq!(result["thread_count"], 2);
        let names: Vec<&str> = result["threads"].as_array().unwrap().iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"worker-1"));
        assert!(names.contains(&"worker-2"));
    }

    /// #115: list_threads with include_stats=true surfaces ThreadStats
    /// (lock_acquire_count / lock_release_count / …), matching HTTP's
    /// `?include_stats=true`. Without the flag, `stats` is absent.
    #[tokio::test]
    async fn test_list_threads_include_stats() {
        let server = McpServer::new();
        import_test_data(&server).await;

        // Without the flag: no stats key in the response.
        let result = dispatch_tool(&server, "list_threads", &json!({"trace_id": 7})).await.unwrap();
        assert!(result.get("stats").is_none(), "stats should be absent without include_stats");

        // With include_stats=true: stats array present, with #114's fields.
        let result = dispatch_tool(&server, "list_threads", &json!({"trace_id": 7, "include_stats": true})).await.unwrap();
        assert!(result["stats"].is_array(), "stats should be present when include_stats=true");
        let stats_arr = result["stats"].as_array().unwrap();
        // Thread stats come from a HashMap, so index 0 is not a stable thread.
        // Thread 1's MutexLock acquire has no wait; thread 2 waited 1500ns.
        let stats = stats_arr.iter()
            .find(|s| s["thread_id"] == 1)
            .expect("thread 1 stats");
        assert!(stats["lock_acquire_count"].is_u64());
        assert!(stats["lock_release_count"].is_u64());
        // #118: max_lock_wait_ns is null (this acquire had no real wait) but present.
        assert!(stats["max_lock_wait_ns"].is_null());
    }

    #[tokio::test]
    async fn test_query_instructions_all() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_instructions", &json!({"trace_id": 7})).await.unwrap();
        assert_eq!(result["instruction_count"], 3);
    }

    #[tokio::test]
    async fn test_query_instructions_by_thread() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_instructions",
            &json!({"trace_id": 7, "thread_id": 1})).await.unwrap();
        assert_eq!(result["instruction_count"], 2);
        assert!(result["instructions"].as_array().unwrap().iter()
            .all(|i| i["thread_id"] == 1));
    }

    #[tokio::test]
    async fn test_query_sync_events_by_lock() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_sync_events",
            &json!({"trace_id": 7, "sync_object_addr": LOCK_ADDR, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["event_count"], 2);
    }

    #[tokio::test]
    async fn test_query_sync_events_by_thread() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_sync_events",
            &json!({"trace_id": 7, "thread_id": 1, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["event_count"], 1);
    }

    #[tokio::test]
    async fn test_query_context_switches() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "query_context_switches",
            &json!({"trace_id": 7, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["switch_count"], 1);
        assert_eq!(result["context_switches"][0]["from_thread"], 1);
        assert_eq!(result["context_switches"][0]["to_thread"], 2);
    }

    #[tokio::test]
    async fn test_query_context_switches_thread_filter() {
        let server = McpServer::new();
        import_test_data(&server).await;

        // Thread 1 is involved
        let result = dispatch_tool(&server, "query_context_switches",
            &json!({"trace_id": 7, "thread_id": 1, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["switch_count"], 1);

        // Thread 99 is not
        let result = dispatch_tool(&server, "query_context_switches",
            &json!({"trace_id": 7, "thread_id": 99, "start_step": 0, "end_step": 100})).await.unwrap();
        assert_eq!(result["switch_count"], 0);
    }

    #[tokio::test]
    async fn test_analyze_threads_full() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "analyze_threads", &json!({"trace_id": 7})).await.unwrap();
        assert_eq!(result["trace_id"], 7);
        assert!(result["analysis"].is_object());
        assert!(result["analysis"]["race_conditions"].is_array());
        assert!(result["analysis"]["deadlock_risks"].is_array());
        assert!(result["analysis"]["lock_contentions"].is_array());
        assert!(result["analysis"]["thread_function_assocs"].is_array());
        assert!(result["analysis"]["function_safety"].is_array());
    }

    /// `import_trace` must ingest events in step order even when the caller's
    /// JSON arrays are out of order. `ThreadStore.thread_states` (the live
    /// HashMap, not the replayed `query_thread_state`) is stamped by each
    /// `record_thread_state_change` in ingestion order — so feeding step 100
    /// (Blocked) before step 50 (Running) would leave it stuck at Running,
    /// the older state. #91/#92 made that field matter (exit `prev_state`,
    /// `current_thread` clearing). The fix sorts the whole event stream by
    /// step before feeding the engine, mirroring CLI `feed_events`.
    #[tokio::test]
    async fn test_import_trace_sorts_state_changes_by_step() {
        let server = McpServer::new();
        let args = json!({
            "trace_id": 9,
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
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["imported"]["state_changes"], 2);

        // Probe the live `thread_states` map — NOT the replayed query, which
        // re-sorts by step itself and would hide the bug. After a step-ordered
        // feed, the largest step (100, Blocked) is the last applied.
        let engine = server.get_or_create_engine(9).await;
        let engine = engine.lock().await;
        let states = engine.thread_store().all_thread_states();
        let final_state = states.get(&1).expect("thread 1 registered");
        assert_eq!(*final_state, sotrace_core::models::thread::ThreadState::Blocked,
            "step 100 (Blocked) must be the last-applied state, not step 50 (Running)");
    }

    #[tokio::test]
    async fn test_detect_races() {
        let server = McpServer::new();
        import_test_data(&server).await;

        // Feed a cross-thread read to create a race (thread 2 reads what thread 1 wrote)
        let engine = server.get_or_create_engine(7).await;
        engine.lock().await.feed_memory_read(8, 2, 0x1000, 4);

        let result = dispatch_tool(&server, "detect_races", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["race_count"].as_u64().unwrap() >= 1);
        assert!(result["races"].as_array().unwrap().iter()
            .any(|r| r["address"] == 0x1000));
        // #112: access sizes and overlap range are present in the JSON
        let race = &result["races"].as_array().unwrap()[0];
        assert!(race["first_access_size"].is_u64());
        assert!(race["second_access_size"].is_u64());
        assert!(race["overlap_address"].is_u64());
        assert!(race["overlap_size"].is_u64());
    }

    #[tokio::test]
    async fn test_import_trace_memory_reads_feeds_race_detection() {
        // #81: import_trace must accept `memory_reads` and feed them to the
        // analyzer — otherwise detect_races has no read end and reports
        // nothing even though T2 reads an unsynchronized T1 write. Before
        // #81, memory_reads could only reach the analyzer via a direct
        // `engine.feed_memory_read` call (as test_detect_races above does),
        // bypassing import entirely.
        let server = McpServer::new();
        let args = json!({
            "trace_id": 15,
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
        let imp = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(imp["imported"]["memory_reads"], 1);

        let result = dispatch_tool(&server, "detect_races", &json!({"trace_id": 15})).await.unwrap();
        assert!(result["race_count"].as_u64().unwrap() >= 1);
        assert!(result["races"].as_array().unwrap().iter()
            .any(|r| r["address"] == 0x1000));
    }

    #[tokio::test]
    async fn test_analyze_contentions() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "analyze_contentions", &json!({"trace_id": 7})).await.unwrap();
        let contentions = result["contentions"].as_array().unwrap();
        assert!(contentions.iter().any(|c| c["lock_address"]["addr"] == LOCK_ADDR));
    }

    #[tokio::test]
    async fn test_detect_deadlocks() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "detect_deadlocks", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["deadlocks"].is_array());
    }

    #[tokio::test]
    async fn test_classify_function_safety() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "classify_function_safety", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["function_safety"].is_array());
    }

    #[tokio::test]
    async fn test_analyze_function_assoc() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "analyze_function_assoc", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["thread_function_assocs"].is_array());
    }

    #[tokio::test]
    async fn test_analyze_data_flows() {
        let server = McpServer::new();
        import_test_data(&server).await;
        // Cross-thread read of the write at 0x1000 creates an inter-thread data flow.
        let engine = server.get_or_create_engine(7).await;
        engine.lock().await.feed_memory_read(8, 2, 0x1000, 4);

        let result = dispatch_tool(&server, "analyze_data_flows", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["data_flows"].is_array());
        assert!(result["data_flows"].as_array().unwrap().iter()
            .any(|f| f["address"] == 0x1000));
        // #113: transfer sizes and overlap range are present in the JSON
        let flow = &result["data_flows"].as_array().unwrap()[0];
        assert!(flow["write_size"].is_u64());
        assert!(flow["read_size"].is_u64());
        assert!(flow["overlap_address"].is_u64());
        assert!(flow["overlap_size"].is_u64());
    }

    #[tokio::test]
    async fn test_detect_producer_consumer() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "detect_producer_consumer", &json!({"trace_id": 7})).await.unwrap();
        assert!(result["producer_consumer_patterns"].is_array());
    }

    /// The typed `sync_mechanism` must surface the primitive kind through the
    /// JSON envelope — the field is now an object `{addr, kind}`, not a bare
    /// number. A mutex producer-consumer rendezvous must report `kind: "Mutex"`.
    #[tokio::test]
    async fn test_detect_producer_consumer_sync_mechanism_typed() {
        let server = McpServer::new();
        const PC_LOCK: u64 = 0xABCD0000;
        let args = json!({
            "trace_id": 7,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "producer",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "consumer",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "memory_writes": [
                {"step": 100, "thread_id": 1, "address": 0x5000, "data": [1, 2, 3, 4]},
                {"step": 200, "thread_id": 1, "address": 0x6000, "data": [5, 6, 7, 8]},
            ],
            "memory_reads": [
                {"step": 130, "thread_id": 2, "address": 0x5000, "size": 4},
                {"step": 230, "thread_id": 2, "address": 0x6000, "size": 4},
            ],
            "sync_events": [
                {"step": 110, "thread_id": 1, "sync_type": "MutexUnlock",
                 "sync_object_addr": PC_LOCK, "result": "Success", "wait_duration_ns": null},
                {"step": 120, "thread_id": 2, "sync_type": "MutexLock",
                 "sync_object_addr": PC_LOCK, "result": "Success", "wait_duration_ns": 1000},
                {"step": 210, "thread_id": 1, "sync_type": "MutexUnlock",
                 "sync_object_addr": PC_LOCK, "result": "Success", "wait_duration_ns": null},
                {"step": 220, "thread_id": 2, "sync_type": "MutexLock",
                 "sync_object_addr": PC_LOCK, "result": "Success", "wait_duration_ns": 1000},
            ],
        });
        let _ = dispatch_tool(&server, "import_trace", &args).await.unwrap();

        let result = dispatch_tool(&server, "detect_producer_consumer", &json!({"trace_id": 7})).await.unwrap();
        let patterns = result["producer_consumer_patterns"].as_array().unwrap();
        assert!(!patterns.is_empty(), "producer-consumer pattern must be detected");
        let pc = patterns.iter()
            .find(|p| p["producer_thread"] == 1 && p["consumer_thread"] == 2)
            .unwrap();
        assert_eq!(pc["sync_mechanism"]["addr"], PC_LOCK);
        assert_eq!(pc["sync_mechanism"]["kind"], "Mutex");
        // #116: shared_addresses entries are objects with address + sizes
        let slots = pc["shared_addresses"].as_array().unwrap();
        assert!(!slots.is_empty(), "shared_addresses must list the slots");
        let slot = slots.iter().find(|s| s["address"] == 0x5000).unwrap();
        assert_eq!(slot["access_size"], 4);
        assert_eq!(slot["overlap_size"], 4);
        // #120: max_latency_steps surfaces the slowest cycle. Both cycles here
        // have equal latency (100→130, 200→230 = 30 each), so max == avg.
        assert_eq!(pc["avg_latency_steps"], 30);
        assert_eq!(pc["max_latency_steps"], 30);
    }

    #[tokio::test]
    async fn test_analyze_scheduling() {
        let server = McpServer::new();
        import_test_data(&server).await;
        // import_test_data feeds a context switch, so scheduling is non-empty.
        let result = dispatch_tool(&server, "analyze_scheduling", &json!({"trace_id": 7})).await.unwrap();
        let sched = result["scheduling"].as_array().expect("scheduling array");
        assert!(!sched.is_empty(), "context switches should yield per-thread scheduling rows");
        assert!(sched.iter().all(|s| s["thread_id"].is_u64()));
        // #117: core_residency is an array of [core, steps] pairs per thread.
        assert!(sched.iter().all(|s| s["core_residency"].is_array()));
    }

    #[tokio::test]
    async fn test_analyze_thread_lifecycle() {
        let server = McpServer::new();
        import_test_data(&server).await;

        let result = dispatch_tool(&server, "analyze_thread_lifecycle", &json!({"trace_id": 7})).await.unwrap();
        let life = result["lifecycle"].as_array().expect("lifecycle array");
        assert_eq!(life.len(), 2, "two registered threads yield two lifecycle rows");
        assert_eq!(result["thread_count"], 2);
        // Both test threads are roots (parent 0), still alive, at depth 0.
        for l in life {
            assert_eq!(l["parent_thread_id"], 0);
            assert_eq!(l["tree_depth"], 0);
            assert_eq!(l["is_alive"], true);
            assert!(l["lifespan"].is_null());
        }
    }
