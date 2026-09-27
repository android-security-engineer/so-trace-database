
    #[tokio::test]
    async fn test_analyze_jni_boundary() {
        // Self-contained trace: thread 1 (JNI-attached) makes two crossings.
        let mut engine = TraceEngine::new(44, Default::default());
        engine.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some("jni-worker".into()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: true,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 1, seq: 10, thread_id: 1, direction: JNICallDirection::JavaToNative,
            java_class: "com.app.Foo".into(), java_method: "doWork".into(),
            java_signature: "()V".into(), native_func_id: None,
            native_address: 8192, jni_env_address: None,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 2, seq: 20, thread_id: 1, direction: JNICallDirection::NativeToJava,
            java_class: "com.app.Bar".into(), java_method: "callback".into(),
            java_signature: "()V".into(), native_func_id: None,
            native_address: 8192, jni_env_address: None,
        }).unwrap();

        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        state.engines.lock().await.insert(44, Arc::new(tokio::sync::RwLock::new(engine)));
        let app = build_app_with_state(state);

        let (status, body) = send(app, "GET", "/api/v1/traces/44/analyze/threads/jni-boundary").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread_count"], 1);
        let stats = json["jni_boundary"].as_array().unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0]["thread_id"], 1);
        assert_eq!(stats[0]["is_jni_attached"], true);
        assert_eq!(stats[0]["total_crossings"], 2);
        assert_eq!(stats[0]["java_to_native_count"], 1);
        assert_eq!(stats[0]["native_to_java_count"], 1);
        assert_eq!(stats[0]["native_addresses"], serde_json::json!([8192]));
        assert_eq!(stats[0]["java_methods"], serde_json::json!(["com.app.Bar.callback", "com.app.Foo.doWork"]));
        // #119: first/last crossing step locate the JNI activity window (seq 10..20).
        assert_eq!(stats[0]["first_crossing_step"], 10);
        assert_eq!(stats[0]["last_crossing_step"], 20);
    }

    #[tokio::test]
    async fn test_get_thread_timeline() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/1/timeline?start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread_id"], 1);
        assert!(json["timeline"].is_object());
    }

    #[tokio::test]
    async fn test_get_thread_sync_events() {
        let app = make_app().await;
        let (status, body) = send(app, "GET", "/api/v1/traces/42/threads/1/sync-events?start_step=0&end_step=100").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["event_count"], 1);
    }

    #[tokio::test]
    async fn test_empty_trace_list_threads() {
        // A trace with no data should return an empty thread list
        let state = AppState::new(std::path::PathBuf::from("/tmp/sotrace-test"));
        let app = build_app_with_state(state);
        let (status, body) = send(app, "GET", "/api/v1/traces/999/threads").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["thread_count"], 0);
    }
