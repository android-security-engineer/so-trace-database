    use super::*;
    use crate::app::{build_app_with_state, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sotrace_core::models::instruction_trace::InstructionTrace;
    use sotrace_core::models::jni_call::{JNICall, JNICallDirection};
    use sotrace_core::models::thread::{
        ThreadInfo, ThreadSyncEvent, SyncEventType, SyncResult, ContextSwitch, SwitchReason,
        ThreadStateChange, ThreadState,
    };
    use sotrace_engine::TraceEngine;
    use sotrace_engine::trace_store::memory_store::MemoryWrite;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// 0xABCD0000 in decimal — used as a query parameter
    const LOCK_ADDR: u64 = 0xABCD0000;

    /// Build an AppState pre-populated with a trace engine containing test data
    async fn make_app() -> axum::Router {
        let mut engine = TraceEngine::new(42, Default::default());

        // Register two threads
        for tid in [1, 2] {
            engine.register_thread(ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: Some(format!("worker-{}", tid)),
                stack_base: 0x7FFF0000, stack_size: 0x80000, tls_addr: 0, is_jni_attached: false,
            }).unwrap();
        }

        // Instructions on thread 1
        for i in 0..10 {
            engine.import_instruction(InstructionTrace {
                seq: i, thread_id: 1, address: 0x4000 + i * 4,
                timestamp: None, is_branch: false, branch_taken: false, opcode: None,
            }).unwrap();
        }

        // Memory write by thread 1 (race candidate vs thread 2 read)
        engine.import_memory_write(MemoryWrite {
            step: 5, thread_id: 1, address: 0x1000, data: vec![0xFF; 4],
        }).unwrap();
        engine.feed_memory_read(7, 2, 0x1000, 4);

        // Sync events on a shared lock
        engine.record_sync_event(ThreadSyncEvent {
            step: 3, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 6, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR,
            result: SyncResult::Success,
            wait_duration_ns: Some(1500),
        }).unwrap();

        // Context switch
        engine.record_context_switch(ContextSwitch {
            step: 4, from_thread: 1, to_thread: 2,
            switch_reason: SwitchReason::Preemption,
            cpu_core: Some(0),
        }).unwrap();

        // Thread 1 state changes: Running 0→30, then WaitingForLock (trailing,
        // unbounded → contributes nothing). Gives a measurable Running interval.
        engine.record_thread_state_change(ThreadStateChange {
            step: 0, thread_id: 1, new_state: ThreadState::Running,
            prev_state: None, prev_running_thread: None,
        }).unwrap();
        engine.record_thread_state_change(ThreadStateChange {
            step: 30, thread_id: 1, new_state: ThreadState::WaitingForLock,
            prev_state: Some(ThreadState::Running), prev_running_thread: None,
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        state.engines.lock().await.insert(42, Arc::new(tokio::sync::RwLock::new(engine)));
        build_app_with_state(state)
    }

    async fn send(router: axum::Router, method: &str, uri: &str) -> (StatusCode, String) {
        let resp = router
            .oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap())
            .await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn test_list_threads() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread_count"], 2);
        let threads = json["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 2);
        // Both worker names should be present (order is nondeterministic)
        let names: Vec<&str> = threads.iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"worker-1"));
        assert!(names.contains(&"worker-2"));
    }

    #[tokio::test]
    async fn test_list_threads_with_stats() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads?include_stats=true").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["stats"].is_array(), "stats should be present when include_stats=true");
        // #114: lock_release_count is present alongside lock_acquire_count.
        // make_app seeds two MutexLock acquires and no unlock → release_count 0,
        // acquire_count 2 (acquire ≫ release would flag a leak).
        let stats_arr = json["stats"].as_array().unwrap();
        // Thread stats come from a HashMap, so index 0 is not a stable thread.
        // Thread 1's MutexLock acquire has no wait; thread 2 waited 1500ns.
        let stats = stats_arr.iter()
            .find(|s| s["thread_id"] == 1)
            .expect("thread 1 stats");
        assert!(stats["lock_acquire_count"].is_u64());
        assert!(stats["lock_release_count"].is_u64());
        assert_eq!(stats["lock_release_count"], 0);
        // #118: max_lock_wait_ns is null (this acquire had no real wait) but
        // present as a field.
        assert!(stats["max_lock_wait_ns"].is_null());
    }

    #[tokio::test]
    async fn test_get_thread_found() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/1").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread"]["thread_id"], 1);
        assert_eq!(json["thread"]["name"], "worker-1");
    }

    #[tokio::test]
    async fn test_get_thread_not_found() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["error"], "thread not found");
    }

    #[tokio::test]
    async fn test_query_sync_events_by_lock() {
        let app = make_app().await;
        let uri = format!("/api/v1/traces/42/threads/sync-events?sync_object_addr={}&start_step=0&end_step=100", LOCK_ADDR);
        let (status, body) = send(app, "GET", &uri).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["event_count"], 2, "two mutex lock events on this lock");
    }

    #[tokio::test]
    async fn test_query_sync_events_by_thread() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/sync-events?thread_id=1&start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["event_count"], 1, "thread 1 has 1 sync event");
    }

    #[tokio::test]
    async fn test_query_context_switches() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/context-switches?start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["switch_count"], 1);
        assert_eq!(json["context_switches"][0]["from_thread"], 1);
        assert_eq!(json["context_switches"][0]["to_thread"], 2);
    }

    #[tokio::test]
    async fn test_query_context_switches_thread_filter() {
        let app = make_app().await;
        // Thread 1 is involved
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/context-switches?thread_id=1&start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["switch_count"], 1);
    }

    #[tokio::test]
    async fn test_query_context_switches_unrelated_thread() {
        let app = make_app().await;
        // Thread 99 is not involved
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/context-switches?thread_id=99&start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["switch_count"], 0);
    }

    #[tokio::test]
    async fn test_analyze_threads() {
        let app = make_app().await;
        let (status, body) = send(app, "POST", "/api/v1/traces/42/analyze/threads").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["analysis"].is_object());
        assert!(json["analysis"]["race_conditions"].is_array());
        assert!(json["analysis"]["deadlock_risks"].is_array());
        assert!(json["analysis"]["lock_contentions"].is_array());
    }

    #[tokio::test]
    async fn test_detect_races() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/races").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["trace_id"], 42);
        assert!(json["races"].is_array());
        // Thread 1 wrote at step 5, thread 2 read at step 7 with no sync → race
        assert!(!json["races"].as_array().unwrap().is_empty(), "should detect a race");
        // #112: access sizes and overlap range are present in the JSON
        let race = &json["races"].as_array().unwrap()[0];
        assert!(race["first_access_size"].is_u64());
        assert!(race["second_access_size"].is_u64());
        assert!(race["overlap_address"].is_u64());
        assert!(race["overlap_size"].is_u64());
    }

    #[tokio::test]
    async fn test_analyze_contentions() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/contentions").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let contentions = json["contentions"].as_array().unwrap();
        assert!(contentions.iter().any(|c| c["lock_address"]["addr"] == LOCK_ADDR));
    }

    #[tokio::test]
    async fn test_detect_deadlocks() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/deadlocks").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["deadlocks"].is_array());
    }

    #[tokio::test]
    async fn test_classify_function_safety() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/function-safety").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["function_safety"].is_array());
    }

    #[tokio::test]
    async fn test_analyze_function_assoc() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/function-assoc").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["thread_function_assocs"].is_array());
    }

    #[tokio::test]
    async fn test_analyze_data_flows() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/data-flows").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["data_flows"].is_array());
        assert!(!json["data_flows"].as_array().unwrap().is_empty(), "should detect a data flow");
        // #113: transfer sizes and overlap range are present in the JSON
        let flow = &json["data_flows"].as_array().unwrap()[0];
        assert!(flow["write_size"].is_u64());
        assert!(flow["read_size"].is_u64());
        assert!(flow["overlap_address"].is_u64());
        assert!(flow["overlap_size"].is_u64());
    }

    #[tokio::test]
    async fn test_detect_producer_consumer() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/producer-consumer").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["producer_consumer_patterns"].is_array());
    }

    /// The typed `sync_mechanism` must surface the primitive kind through the
    /// JSON envelope — the field is now an object `{addr, kind}`, not a bare
    /// number. A mutex producer-consumer rendezvous must report `kind: "Mutex"`.
    #[tokio::test]
    async fn test_detect_producer_consumer_sync_mechanism_typed() {
        let mut engine = TraceEngine::new(44, Default::default());
        for tid in [1, 2] {
            engine.register_thread(ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: Some(format!("worker-{}", tid)),
                stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
            }).unwrap();
        }
        // Two produce→consume cycles sharing one mutex so detect_producer_consumer
        // (which needs >=2 cycles) reports a pattern with the typed sync mechanism.
        engine.import_memory_write(MemoryWrite {
            step: 100, thread_id: 1, address: 0x5000, data: vec![0xFF; 4],
        }).unwrap();
        engine.feed_memory_read(130, 2, 0x5000, 4);
        engine.import_memory_write(MemoryWrite {
            step: 200, thread_id: 1, address: 0x6000, data: vec![0xFF; 4],
        }).unwrap();
        engine.feed_memory_read(230, 2, 0x6000, 4);
        engine.record_sync_event(ThreadSyncEvent {
            step: 110, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 120, thread_id: 2, sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: Some(1000),
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 210, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 220, thread_id: 2, sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: Some(1000),
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        state.engines.lock().await.insert(44, Arc::new(tokio::sync::RwLock::new(engine)));
        let app = build_app_with_state(state);

        let (status, body) = send(app, "GET", "/api/v1/traces/44/analyze/threads/producer-consumer").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let patterns = json["producer_consumer_patterns"].as_array().unwrap();
        assert!(!patterns.is_empty(), "producer-consumer pattern must be detected");
        let pc = patterns.iter()
            .find(|p| p["producer_thread"] == 1 && p["consumer_thread"] == 2)
            .unwrap();
        assert_eq!(pc["sync_mechanism"]["addr"], LOCK_ADDR);
        assert_eq!(pc["sync_mechanism"]["kind"], "Mutex");
        // #116: shared_addresses entries are objects with address + sizes
        let slots = pc["shared_addresses"].as_array().unwrap();
        assert!(!slots.is_empty(), "shared_addresses must list the slots");
        let slot = slots.iter().find(|s| s["address"] == 0x6000).unwrap();
        assert_eq!(slot["access_size"], 4);
        assert_eq!(slot["overlap_size"], 4);
        // #120: max_latency_steps surfaces the slowest cycle. Both cycles here
        // have equal latency (100→130, 200→230 = 30 each), so max == avg.
        assert_eq!(pc["avg_latency_steps"], 30);
        assert_eq!(pc["max_latency_steps"], 30);
    }

    #[tokio::test]
    async fn test_analyze_scheduling() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/scheduling").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["scheduling"].is_array());
        // #117: each row carries core_residency as an array of [core, steps].
        let sched = json["scheduling"].as_array().unwrap();
        assert!(sched.iter().all(|s| s["core_residency"].is_array()));
    }

    #[tokio::test]
    async fn test_analyze_thread_lifecycle() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/lifecycle").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let life = json["lifecycle"].as_array().unwrap();
        assert_eq!(life.len(), 2);
        assert_eq!(json["thread_count"], 2);
        // Both fixture threads are roots (parent 0), alive, at depth 0.
        for l in life {
            assert_eq!(l["parent_thread_id"], 0);
            assert_eq!(l["tree_depth"], 0);
            assert_eq!(l["is_alive"], true);
        }
    }

    #[tokio::test]
    async fn test_analyze_thread_states() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/analyze/threads/states").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let stats = json["state_stats"].as_array().unwrap();
        // Only thread 1 has state changes in the fixture.
        let t1 = stats.iter().find(|s| s["thread_id"] == 1).expect("thread 1 state stats");
        // Running interval 0→30 is bounded; the trailing WaitingForLock is open.
        assert_eq!(t1["running_steps"], 30);
        assert_eq!(t1["total_measured_steps"], 30);
        assert_eq!(t1["final_state"], "WaitingForLock");
        assert_eq!(t1["transition_count"], 2);
    }

    #[tokio::test]
    async fn test_analyze_critical_sections() {
        // Self-contained trace (not the shared fixture, whose locks are never
        // released): thread 1 holds LOCK_ADDR from step 10 to 40 (hold = 30).
        let mut engine = TraceEngine::new(43, Default::default());
        engine.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some("worker".into()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 40, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: LOCK_ADDR, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        state.engines.lock().await.insert(43, Arc::new(tokio::sync::RwLock::new(engine)));
        let app = build_app_with_state(state);

        let (status, body) = send(app, "GET", "/api/v1/traces/43/analyze/threads/critical-sections").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["lock_count"], 1);
        let cs = json["critical_sections"].as_array().unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0]["lock_address"]["addr"], LOCK_ADDR);
        assert_eq!(cs[0]["hold_count"], 1);
        assert_eq!(cs[0]["total_hold_steps"], 30);
        assert_eq!(cs[0]["max_hold_steps"], 30);
        assert_eq!(cs[0]["longest_hold_thread"], 1);
    }
