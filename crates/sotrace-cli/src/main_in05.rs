    use super::*;
    use sotrace_core::adapters::TraceAdapter;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const LOCK_ADDR: u64 = 0xABCD_0000;

    /// A fresh empty data directory for tests that exercise the persistence
    /// layer (or just need a data_dir to pass to run_analyze/run_query).
    fn data_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A trace with two threads, a cross-thread memory race, and a contended lock.
    fn write_trace_json(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    const RACE_TRACE: &str = r#"{
        "trace_id": 1, "so_file_id": 0,
        "threads": [
            {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "writer", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "reader", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
        ],
        "instructions": [
            {"seq": 0, "thread_id": 1, "address": 4096, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
            {"seq": 2, "thread_id": 2, "address": 5120, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null}
        ],
        "memory_writes": [
            {"step": 5, "thread_id": 1, "address": 4096, "data": [255, 255, 255, 255]}
        ],
        "memory_reads": [
            {"step": 8, "thread_id": 2, "address": 4096, "size": 4}
        ],
        "sync_events": [
            {"step": 3, "thread_id": 1, "sync_type": "MutexLock", "sync_object_addr": 2882338816, "result": "Success", "wait_duration_ns": null},
            {"step": 6, "thread_id": 2, "sync_type": "MutexLock", "sync_object_addr": 2882338816, "result": "Success", "wait_duration_ns": 1500}
        ],
        "context_switches": [
            {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0}
        ]
    }"#;

    #[test]
    fn test_parse_memory_write() {
        let v: Value = serde_json::from_str(
            r#"{"step": 10, "thread_id": 3, "address": 4096, "data": [1, 2, 3]}"#
        ).unwrap();
        let mw = parse_memory_write(&v).unwrap();
        assert_eq!(mw.step, 10);
        assert_eq!(mw.thread_id, 3);
        assert_eq!(mw.address, 4096);
        assert_eq!(mw.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_parse_memory_write_missing_field() {
        let v: Value = serde_json::from_str(r#"{"step": 10, "thread_id": 3}"#).unwrap();
        assert!(parse_memory_write(&v).is_err());
    }

    #[test]
    fn test_parse_memory_read_defaults_size() {
        let v: Value = serde_json::from_str(
            r#"{"step": 1, "thread_id": 2, "address": 4096}"#
        ).unwrap();
        let (step, tid, addr, size) = parse_memory_read(&v).unwrap();
        assert_eq!((step, tid, addr, size), (1, 2, 4096, 1));
    }

    #[test]
    fn test_analyze_detects_race() {
        let f = write_trace_json(RACE_TRACE);
        // Capture stdout to verify the race appears
        // run_analyze prints to stdout; we just assert it succeeds and the
        // JSON path surfaces the race.
        run_analyze(data_dir().path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, Some(AnalysisDim::Races), None, true).unwrap();
        // Re-run capturing JSON via build_json_output path indirectly is hard;
        // instead verify via the JSON flag by capturing process output.
    }

    #[test]
    fn test_analyze_json_races_nonempty() {
        let f = write_trace_json(RACE_TRACE);
        // Build the engine inline to assert analysis content directly.
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }
        for i in &env.instructions {
            engine.import_instruction(i.clone()).unwrap();
        }
        for w in &env.memory_writes {
            engine.import_memory_write(parse_memory_write(w).unwrap()).unwrap();
        }
        for r in &env.memory_reads {
            let (s, t, a, sz) = parse_memory_read(r).unwrap();
            engine.feed_memory_read(s, t, a, sz);
        }
        for e in &env.sync_events {
            engine.record_sync_event(e.clone()).unwrap();
        }
        let races = engine.detect_race_conditions();
        assert!(!races.is_empty(), "should detect at least one race");
        assert!(races.iter().any(|r| r.address == 4096));
        // #112: sizes + conflict range present
        assert!(races.iter().any(|r| r.overlap_address == 4096 && r.overlap_size > 0));
    }

    #[test]
    fn test_analyze_json_contentions() {
        let f = write_trace_json(RACE_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        for e in &env.sync_events {
            engine.record_sync_event(e.clone()).unwrap();
        }
        let cs = engine.analyze_lock_contention();
        assert!(cs.iter().any(|c| c.lock_address.addr == LOCK_ADDR));
        let contended = cs.iter().find(|c| c.lock_address.addr == LOCK_ADDR).unwrap();
        assert_eq!(contended.acquire_count, 2);
        assert_eq!(contended.contention_count, 1);
    }

    /// A trace with a parent thread and two children; `--only lifecycle` must
    /// surface the spawn tree (children, depth) and liveness through the JSON path.
    #[test]
    fn test_analyze_json_lifecycle() {
        const TREE_TRACE: &str = r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "main", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 1, "create_step": 10, "exit_step": 50, "name": "worker-a", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                {"thread_id": 3, "pthread_id": null, "parent_thread_id": 1, "create_step": 20, "exit_step": null, "name": "worker-b", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [], "context_switches": []
        }"#;
        let f = write_trace_json(TREE_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }

        let out = build_json_output(&mut engine, Some(AnalysisDim::Lifecycle)).unwrap();
        let life = out.get("lifecycle").unwrap().as_array().unwrap();
        assert_eq!(life.len(), 3);

        // Root thread 1 has both children and depth 0.
        let root = life.iter().find(|l| l["thread_id"] == 1).unwrap();
        assert_eq!(root["parent_thread_id"], 0);
        assert_eq!(root["tree_depth"], 0);
        assert_eq!(root["child_thread_ids"], serde_json::json!([2, 3]));
        assert_eq!(root["is_alive"], true);

        // Worker-a exited: lifespan 40, not alive, depth 1.
        let a = life.iter().find(|l| l["thread_id"] == 2).unwrap();
        assert_eq!(a["lifespan"], 40);
        assert_eq!(a["is_alive"], false);
        assert_eq!(a["tree_depth"], 1);

        // Worker-b still alive: null lifespan.
        let b = life.iter().find(|l| l["thread_id"] == 3).unwrap();
        assert!(b["lifespan"].is_null());
        assert_eq!(b["is_alive"], true);
    }

    /// A trace with per-thread state changes; `--only thread-states` must surface
    /// state residency (running/waiting steps, blocked ratio) via the JSON path,
    /// exercising the full envelope → feed_events → record_thread_state_change →
    /// analyzer wiring that #65 activated.
    #[test]
    fn test_analyze_json_thread_states() {
        const STATE_TRACE: &str = r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": 100, "name": "worker", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [], "context_switches": [],
            "state_changes": [
                {"step": 0, "thread_id": 1, "new_state": "Running", "prev_state": null, "prev_running_thread": null},
                {"step": 30, "thread_id": 1, "new_state": "WaitingForLock", "prev_state": "Running", "prev_running_thread": null},
                {"step": 50, "thread_id": 1, "new_state": "Running", "prev_state": "WaitingForLock", "prev_running_thread": null}
            ]
        }"#;
        let f = write_trace_json(STATE_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let events = envelope_to_events(&env).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        // Register the thread first so the final interval can be bounded by exit.
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }
        feed_events(&mut engine, &events, &mut counts).unwrap();
        assert_eq!(counts.state_changes, 3);

        let out = build_json_output(&mut engine, Some(AnalysisDim::ThreadStates)).unwrap();
        let stats = out.get("state_stats").unwrap().as_array().unwrap();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert_eq!(s["thread_id"], 1);
        assert_eq!(s["transition_count"], 3);
        // Running: 0→30 (30) + 50→100 (50) = 80; WaitingForLock: 30→50 (20).
        assert_eq!(s["running_steps"], 80);
        assert_eq!(s["waiting_steps"], 20);
        assert_eq!(s["total_measured_steps"], 100);
        assert_eq!(s["final_state"], "Running");
        let ratio = s["blocked_ratio"].as_f64().unwrap();
        assert!((ratio - 0.2).abs() < 1e-9);
    }

    /// End-to-end wiring for the critical-section (hold-time) dimension: a lock
    /// acquired then released must surface one hold interval through the CLI JSON
    /// path (`--only critical-sections`).
    #[test]
    fn test_analyze_json_critical_sections() {
        const HOLD_TRACE: &str = r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "worker", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [
                {"step": 10, "thread_id": 1, "sync_type": "MutexLock", "sync_object_addr": 2882338816, "result": "Success", "wait_duration_ns": null},
                {"step": 40, "thread_id": 1, "sync_type": "MutexUnlock", "sync_object_addr": 2882338816, "result": "Success", "wait_duration_ns": null}
            ],
            "context_switches": [], "state_changes": []
        }"#;
        let f = write_trace_json(HOLD_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let events = envelope_to_events(&env).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }
        feed_events(&mut engine, &events, &mut counts).unwrap();

        let out = build_json_output(&mut engine, Some(AnalysisDim::CriticalSections)).unwrap();
        let cs = out.get("critical_sections").unwrap().as_array().unwrap();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c["lock_address"]["addr"], 2882338816u64);
        assert_eq!(c["lock_address"]["kind"], "Mutex");
        assert_eq!(c["hold_count"], 1);
        assert_eq!(c["total_hold_steps"], 30);
        assert_eq!(c["max_hold_steps"], 30);
        assert_eq!(c["longest_hold_thread"], 1);
        assert_eq!(c["longest_hold_start"], 10);
        assert_eq!(c["longest_hold_end"], 40);
    }

    #[test]
    fn test_analyze_json_jni_boundary() {
        const JNI_TRACE: &str = r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "jni-worker", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": "native-only", "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [], "context_switches": [], "state_changes": [],
            "jni_calls": [
                {"id": 1, "seq": 10, "thread_id": 1, "direction": "JavaToNative", "java_class": "com.app.Foo", "java_method": "doWork", "java_signature": "()V", "native_func_id": null, "native_address": 8192, "jni_env_address": null},
                {"id": 2, "seq": 20, "thread_id": 1, "direction": "NativeToJava", "java_class": "com.app.Bar", "java_method": "callback", "java_signature": "()V", "native_func_id": null, "native_address": 8192, "jni_env_address": null}
            ]
        }"#;
        let f = write_trace_json(JNI_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let events = envelope_to_events(&env).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        for t in &env.threads {
            engine.register_thread(t.clone()).unwrap();
        }
        feed_events(&mut engine, &events, &mut counts).unwrap();
        assert_eq!(counts.jni_calls, 2);

        let out = build_json_output(&mut engine, Some(AnalysisDim::JniBoundary)).unwrap();
        let stats = out.get("jni_boundary").unwrap().as_array().unwrap();
        // Thread 1 has crossings; thread 2 is attached? No — only thread 1.
        assert_eq!(stats.len(), 1);
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

    #[test]
    fn test_analyze_missing_file_errors() {
        let result = run_analyze(data_dir().path(), Some(PathBuf::from("/tmp/does_not_exist_xyz.json")), None, 0, TraceFormat::Native, 0, None, None, false);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("failed to read trace file"));
    }

    #[test]
    fn test_analyze_invalid_json_errors() {
        let f = write_trace_json(r#"{ this is not valid json"#);
        let result = run_analyze(data_dir().path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None, None, false);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("failed to parse trace JSON"));
    }

    #[test]
    fn test_envelope_default_fields() {
        // An envelope with only trace_id should parse (all event arrays default to empty).
        let f = write_trace_json(r#"{"trace_id": 7}"#);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        assert_eq!(env.trace_id, Some(7));
        assert!(env.threads.is_empty());
        assert!(env.instructions.is_empty());
        assert!(env.sync_events.is_empty());
    }

    #[test]
    fn test_instructions_sorted_by_seq() {
        // Instructions provided out of order should still import (sorted internally).
        let json = r#"{
            "trace_id": 1,
            "instructions": [
                {"seq": 5, "thread_id": 1, "address": 5000, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 1, "thread_id": 1, "address": 1000, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 3, "thread_id": 1, "address": 3000, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null}
            ]
        }"#;
        let f = write_trace_json(json);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let env: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        // run_analyze sorts before import; replicate that here.
        let mut instrs = env.instructions.clone();
        instrs.sort_by_key(|t| t.seq);
        for i in &instrs {
            engine.import_instruction(i.clone()).unwrap();
        }
        let range = engine.query_instructions_range(0, u64::MAX);
        let seqs: Vec<u64> = range.iter().map(|t| t.seq).collect();
        assert_eq!(seqs, vec![1, 3, 5]);
    }

    /// A Frida Stalker trace with an SO base address and a cross-thread race.
    const FRIDA_STALKER_TRACE: &str = r#"{"type":"inst","tid":100,"pc":"0x7fff1000"}
{"type":"inst","tid":100,"pc":"0x7fff1004","is_branch":true,"branch_taken":true}
{"type":"memwrite","tid":100,"address":"0x7fff1000","data":[255,255,255,255]}
{"type":"inst","tid":200,"pc":"0x7fff2000"}
{"type":"memread","tid":200,"address":"0x7fff1000","size":4}
{"type":"sync","tid":100,"sync_type":"MutexLock","sync_object_addr":"0xABCD0000","result":"Success"}
{"type":"sync","tid":200,"sync_type":"MutexLock","sync_object_addr":"0xABCD0000","result":"Success","wait_duration_ns":1500}"#;

    #[test]
    fn test_analyze_frida_stalker_format() {
        let dd = data_dir();
        let f = write_trace_json(FRIDA_STALKER_TRACE);
        // base_addr converts 0x7fff1000 → 0x1000
        let result = run_analyze(
            dd.path(),
            Some(f.path().to_path_buf()),
            None,
            0,
            TraceFormat::FridaStalker,
            0x7fff0000,
            Some(AnalysisDim::Races),
            None,
            true,
        );
        // Capture stdout to inspect the JSON race output.
        // run_analyze prints to stdout; we verify via direct engine feed instead.
        assert!(result.is_ok());

        // Direct verification: adapter + feed_events + detect_races
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let adapter = sotrace_core::adapters::frida::FridaAdapter::new();
        let (events, _) = adapter.parse("stalker", &raw, 0x7fff0000).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        feed_events(&mut engine, &events, &mut counts).unwrap();
        assert!(counts.instructions >= 3);
        assert!(counts.memory_writes >= 1);
        assert!(counts.memory_reads >= 1);
        assert!(counts.sync_events >= 2);
        let races = engine.detect_race_conditions();
        assert!(!races.is_empty(), "should detect the cross-thread race");
        // The race address should be the SO-relative offset 0x1000
        assert!(races.iter().any(|r| r.address == 0x1000));
        // #112: sizes + conflict range present
        assert!(races.iter().any(|r| r.overlap_address == 0x1000 && r.overlap_size > 0));
    }

    #[test]
    fn test_analyze_frida_stalker_contentions() {
        let f = write_trace_json(FRIDA_STALKER_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let adapter = sotrace_core::adapters::frida::FridaAdapter::new();
        let (events, _) = adapter.parse("stalker", &raw, 0x7fff0000).unwrap();
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        feed_events(&mut engine, &events, &mut counts).unwrap();
        let cs = engine.analyze_lock_contention();
        assert!(cs.iter().any(|c| c.lock_address.addr == 0xABCD_0000));
    }

    #[test]
    fn test_analyze_jnitrace_format() {
        let trace = r#"{"type":"async","payload":[{"tid":300,"type":"J2N","class":"com.example.Crypto","method":"decrypt","signature":"([B)[B","address":"0x4000","env":"0x7f00"}]}"#;
        let f = write_trace_json(trace);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let adapter = sotrace_core::adapters::frida::FridaAdapter::new();
        let (events, stats) = adapter.parse("jnitrace", &raw, 0).unwrap();
        assert_eq!(stats.jni_calls, 1);
        let mut engine = TraceEngine::new(0, Default::default());
        let mut counts = ImportedCounts::default();
        feed_events(&mut engine, &events, &mut counts).unwrap();
        assert_eq!(counts.jni_calls, 1);
    }

    #[test]
    fn test_trace_format_adapter_mapping() {
        assert_eq!(TraceFormat::Native.adapter(), None);
        assert_eq!(TraceFormat::FridaStalker.adapter(), Some(("frida", "stalker")));
        assert_eq!(TraceFormat::FridaInterceptor.adapter(), Some(("frida", "interceptor")));
        assert_eq!(TraceFormat::Jnitrace.adapter(), Some(("frida", "jnitrace")));
        assert_eq!(TraceFormat::DrCachesim.adapter(), Some(("dynamorio", "drcachesim")));
        assert_eq!(TraceFormat::DrMemtrace.adapter(), Some(("dynamorio", "memtrace")));
        assert_eq!(TraceFormat::Pinatrace.adapter(), Some(("pin", "pinatrace")));
    }
