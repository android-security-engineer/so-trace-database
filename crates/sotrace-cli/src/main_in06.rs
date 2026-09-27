
    #[test]
    fn test_hex_encoding() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00]), "00");
        assert_eq!(hex(&[0xff, 0x10, 0xab]), "ff10ab");
    }

    #[test]
    fn test_parse_addr_arg_decimal() {
        assert_eq!(parse_addr_arg("4096").unwrap(), 4096);
    }

    #[test]
    fn test_parse_addr_arg_hex() {
        assert_eq!(parse_addr_arg("0x7fff0000").unwrap(), 0x7fff0000);
        assert_eq!(parse_addr_arg("0XABCD").unwrap(), 0xABCD);
    }

    #[test]
    fn test_parse_addr_arg_invalid() {
        assert!(parse_addr_arg("not a number").is_err());
    }

    // --- query command tests ---

    /// load_engine + the engine query APIs that `run_query` wraps should
    /// surface the race trace's threads, sync events, and reconstructed memory.
    #[test]
    fn test_query_threads_and_sync() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        // Two threads registered.
        let mut ids = engine.all_thread_ids();
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
        // Each has stats.
        assert_eq!(engine.all_thread_stats().len(), 2);
        // #114: lock_release_count is present; the seed only has a MutexLock
        // acquire (no unlock), so thread 1 shows acquire=1, release=0.
        let t1_stats = engine.get_thread_stats(1).unwrap();
        assert_eq!(t1_stats.lock_acquire_count, 1);
        assert_eq!(t1_stats.lock_release_count, 0);
        // #118: max_lock_wait_ns is None — the seed acquire had no real wait.
        assert_eq!(t1_stats.max_lock_wait_ns, None);
        // Thread 1's sync events include the MutexLock at step 3.
        let sync = engine.query_thread_sync_events(1, 0, u64::MAX);
        assert_eq!(sync.len(), 1);
        assert_eq!(sync[0].step, 3);
        assert!(matches!(
            sync[0].sync_type,
            sotrace_core::models::thread::SyncEventType::MutexLock
        ));
    }

    /// The `jni-calls` subcommand exposes the AddressIndex that import has been
    /// maintaining: look up JNI boundary calls by native function address, with
    /// an optional step range. Previously the index existed but no query path
    /// surfaced it (the #95 pattern, JNI-side).
    #[test]
    fn test_query_jni_calls_by_address_subcommand() {
        let dd = data_dir();
        // Two JNI calls reach native_address 0x2000 (seq 10 and 20); a third
        // reaches 0x3000 at the SAME seq 10 as the first — must not leak into
        // the 0x2000 query.
        let f = write_trace_json(r#"{
            "trace_id": 1, "so_file_id": 0,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": null, "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true},
                {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": null, "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": true}
            ],
            "instructions": [], "memory_writes": [], "memory_reads": [],
            "sync_events": [], "context_switches": [], "state_changes": [],
            "jni_calls": [
                {"id": 1, "seq": 10, "thread_id": 1, "direction": "JavaToNative", "java_class": "com.app.Foo", "java_method": "doWork", "java_signature": "()V", "native_func_id": null, "native_address": 8192, "jni_env_address": null},
                {"id": 2, "seq": 10, "thread_id": 2, "direction": "JavaToNative", "java_class": "com.app.Bar", "java_method": "other", "java_signature": "()V", "native_func_id": null, "native_address": 12288, "jni_env_address": null},
                {"id": 3, "seq": 20, "thread_id": 1, "direction": "NativeToJava", "java_class": "com.app.Bar", "java_method": "callback", "java_signature": "()V", "native_func_id": null, "native_address": 8192, "jni_env_address": null}
            ]
        }"#);
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();

        // 0x2000 = 8192: two calls (seq 10 + 20), the 0x3000 sibling at seq 10
        // is filtered out despite sharing the step.
        let calls = engine.query_jni_calls_by_address(8192, 0, u64::MAX);
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|c| c.native_address == 8192));
        assert_eq!(calls[0].seq, 10);
        assert_eq!(calls[1].seq, 20);

        // Range [0,15] keeps only the seq-10 call.
        let early = engine.query_jni_calls_by_address(8192, 0, 15);
        assert_eq!(early.len(), 1);
        assert_eq!(early[0].java_method, "doWork");

        // The 0x3000 sibling is reachable via its own address.
        let other = engine.query_jni_calls_by_address(12288, 0, u64::MAX);
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].thread_id, 2);

        // The subcommand path also succeeds end to end.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::JniCalls { address: 8192, start: 0, end: u64::MAX },
        ).unwrap();
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::JniCalls { address: 8192, start: 0, end: 15 },
        ).unwrap();
    }

    /// `query_threads_at_address` returns (thread_id, step) pairs — the step at
    /// which each thread executed the address, NOT an access count. The
    /// `Address` subcommand renders these pairs; this test pins the (thread,
    /// step) contract so the CLI field name (`step`) stays honest. Two threads
    /// sharing one `seq` at the same address must both survive (regression for
    /// the field-mislabel fix — previously the step was emitted as `count`).
    #[test]
    fn test_query_threads_at_address_returns_step_not_count() {
        let dd = data_dir();
        // Two threads both execute address 0x1000 at seq 7 (shared seq), plus
        // thread 1 hits it again at seq 9.
        let f = write_trace_json(
            r#"{
                "threads": [
                    {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": null, "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
                    {"thread_id": 2, "pthread_id": null, "parent_thread_id": 0, "create_step": 0, "exit_step": null, "name": null, "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}
                ],
                "instructions": [
                    {"seq": 7, "thread_id": 1, "address": 4096, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
                    {"seq": 7, "thread_id": 2, "address": 4096, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null},
                    {"seq": 9, "thread_id": 1, "address": 4096, "timestamp": null, "is_branch": false, "branch_taken": false, "opcode": null}
                ]
            }"#,
        );
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        let accesses = engine.query_threads_at_address(4096);
        // Both threads at the shared seq survive, plus thread 1's later hit.
        assert_eq!(accesses.len(), 3);
        // Each entry carries the real step, not a count. Sort to make the
        // assertion order-independent (EventLog preserves insertion order
        // within a step, but we don't want the test coupled to thread write
        // order).
        let mut sorted = accesses.clone();
        sorted.sort();
        // Two (thread, step) pairs at seq 7 — threads 1 and 2 — plus thread 1
        // at seq 9. Tuple sort is lexicographic so (1,7) < (1,9) < (2,7). If
        // `step` were a count, seq-7 entries would read 2 instead of 7.
        assert_eq!(sorted, vec![(1, 7), (1, 9), (2, 7)]);
        // The subcommand renders successfully and (via the contract above) now
        // emits `step` rather than the old mislabeled `count`.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::Address { address: 4096 },
        ).unwrap();
    }

    /// query_memory_value reconstructs the written bytes at the write step.
    #[test]
    fn test_query_memory_reconstruction() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        // step 5 wrote [255,255,255,255] at address 4096.
        let res = engine.query_memory_value(4096, 4, 5).expect("value reconstructed");
        assert_eq!(res.value, vec![255, 255, 255, 255]);
        assert!(res.deltas_applied >= 1);
    }

    /// query_lock_contentions returns both lock acquisitions for the shared lock.
    #[test]
    fn test_query_lock_contentions() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        let events = engine.query_lock_contentions(2882338816, 0, u64::MAX);
        assert_eq!(events.len(), 2);
        let mut steps: Vec<u64> = events.iter().map(|e| e.step).collect();
        steps.sort();
        assert_eq!(steps, vec![3, 6]);
    }

    /// A native trace envelope carrying `register_deltas` feeds through
    /// `envelope_to_events` -> `TraceEvent::Register` -> engine, and the
    /// reconstructed value is queryable per register / per step.
    #[test]
    fn test_query_register_from_native_envelope() {
        let dd = data_dir();
        // x0 = 0x1000 at seq 5; then x0 = 0x2000 and x2 = 0x12345678 at seq 10.
        let f = write_trace_json(
            r#"{
                "register_deltas": [
                    {"seq": 5, "change_mask": 1, "values": [4096]},
                    {"seq": 10, "change_mask": 5, "values": [8192, 305419896]}
                ]
            }"#,
        );
        let (engine, imported, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        assert_eq!(imported.register_deltas, 2);
        // Before any delta the register is unknown.
        assert_eq!(engine.query_register(0, 3), None);
        // The first value holds until the next delta.
        assert_eq!(engine.query_register(0, 7), Some(0x1000));
        // The second delta updates x0 and sets x2 (bit-order value extraction).
        assert_eq!(engine.query_register(0, 12), Some(0x2000));
        assert_eq!(engine.query_register(2, 12), Some(0x12345678));

        // The full register file reconstructs the same values in one snapshot.
        let state = engine.reconstruct_register_state(12).expect("state reconstructed");
        assert_eq!(state.gp_regs[0], 0x2000);
        assert_eq!(state.gp_regs[2], 0x12345678);
        assert_eq!(state.gp_regs[1], 0); // never written

        // Both subcommand paths also succeed end to end.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::Register { register_id: 0, step: 7 },
        ).unwrap();
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::RegisterState { step: 12 },
        ).unwrap();
    }

    /// Two register deltas sharing the same `seq` must both survive ingestion
    /// through the native envelope path (`envelope_to_events` ->
    /// `TraceEvent::Register` -> `feed_events` -> engine) and resolve with
    /// last-writer-wins semantics — the same contract verified at the store
    /// layer in `register_store::tests`. This guards the end-to-end CLI path
    /// against a regression that would silently drop same-step deltas.
    #[test]
    fn test_query_register_same_seq_last_wins_native() {
        let dd = data_dir();
        let f = write_trace_json(
            r#"{
                "register_deltas": [
                    {"seq": 5, "change_mask": 1, "values": [170]},
                    {"seq": 5, "change_mask": 1, "values": [187]}
                ]
            }"#,
        );
        let (engine, imported, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        assert_eq!(imported.register_deltas, 2);
        // Both deltas landed; the second (0xBB) wins over the first (0xAA).
        assert_eq!(engine.query_register(0, 5), Some(0xBB));
        assert_eq!(engine.query_register(0, 6), Some(0xBB));
        // Before step 5 the register is still unknown.
        assert_eq!(engine.query_register(0, 4), None);

        // The full register file agrees with the point query.
        let state = engine.reconstruct_register_state(5).expect("state reconstructed");
        assert_eq!(state.gp_regs[0], 0xBB);

        // The `register` subcommand surfaces the same last-wins value.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::Register { register_id: 0, step: 5 },
        ).unwrap();
    }

    /// The `register-history` subcommand lists the steps at which a register
    /// changed. Exposes the per-register index that `register` uses for its
    /// single-point lookup — the list query was previously unreachable.
    #[test]
    fn test_query_register_history_subcommand() {
        let dd = data_dir();
        // x0 changes at seq 5 and 10; x2 only at seq 10.
        let f = write_trace_json(
            r#"{
                "register_deltas": [
                    {"seq": 5, "change_mask": 1, "values": [4096]},
                    {"seq": 10, "change_mask": 5, "values": [8192, 305419896]}
                ]
            }"#,
        );
        let (engine, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        // x0 changed at 5 and 10.
        assert_eq!(engine.query_register_history(0, 0, u64::MAX), vec![5, 10]);
        // x2 changed only at 10.
        assert_eq!(engine.query_register_history(2, 0, u64::MAX), vec![10]);
        // x1 never.
        assert!(engine.query_register_history(1, 0, u64::MAX).is_empty());
        // Range filter.
        assert_eq!(engine.query_register_history(0, 6, u64::MAX), vec![10]);
        // Out-of-range register_id → empty.
        assert!(engine.query_register_history(999, 0, u64::MAX).is_empty());

        // The subcommand path also succeeds end to end.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::RegisterHistory { register_id: 0, start: 0, end: u64::MAX },
        ).unwrap();
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::RegisterHistory { register_id: 0, start: 6, end: u64::MAX },
        ).unwrap();
    }

    /// A native envelope carrying `calls` feeds through `envelope_to_events`
    /// -> `TraceEvent::Call` -> engine, and the live call stack is
    /// reconstructable per thread / per step.
    #[test]
    fn test_callstack_from_native_envelope() {
        let dd = data_dir();
        // f(0x1000) calls g(0x2000); g returns at seq 3.
        let f = write_trace_json(
            r#"{
                "calls": [
                    {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 4080, "callee_address": 4096, "callee_func_id": 100, "seq": 1, "depth": 0, "return_seq": null},
                    {"id": 2, "thread_id": 1, "event_type": "Call", "caller_address": 4112, "callee_address": 8192, "callee_func_id": 200, "seq": 2, "depth": 1, "return_seq": null},
                    {"id": 3, "thread_id": 1, "event_type": "Return", "caller_address": 0, "callee_address": 0, "callee_func_id": null, "seq": 3, "depth": 1, "return_seq": null}
                ]
            }"#,
        );
        let (engine, imported, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, &None, true,
        ).unwrap();
        assert_eq!(imported.calls, 3);

        // At step 2 both frames are live, outermost first.
        let at2 = engine.rebuild_call_stack(1, 2);
        assert_eq!(at2.len(), 2);
        assert_eq!(at2[0].entry_address, 4096);
        assert_eq!(at2[1].entry_address, 8192);

        // After g returns (step 3) only f remains.
        let at3 = engine.rebuild_call_stack(1, 3);
        assert_eq!(at3.len(), 1);
        assert_eq!(at3[0].entry_address, 4096);

        // The `call-stack` subcommand path also succeeds end to end.
        run_query(
            dd.path(), Some(f.path().to_path_buf()), None, 0, TraceFormat::Native, 0, None,
            QueryCmd::CallStack { thread_id: 1, step: 2 },
        ).unwrap();
    }

    /// run_query for each subcommand should succeed (Ok) on the race trace.
    #[test]
    fn test_run_query_all_subcommands_succeed() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        let path = f.path().to_path_buf();
        let d = dd.path();
        // Threads
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Threads).unwrap();
        // Thread { id }
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Thread { thread_id: 1 }).unwrap();
        // Timeline
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Timeline {
            thread_id: 1, start: 0, end: 100,
        }).unwrap();
        // Instruction
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Instruction { step: 0 }).unwrap();
        // Instructions range
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Instructions {
            start: 0, end: 10,
        }).unwrap();
        // Address
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Address { address: 4096 }).unwrap();
        // Memory
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Memory {
            address: 4096, step: 5, size: 4,
        }).unwrap();
        // Sync
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Sync {
            thread_id: 1, start: 0, end: u64::MAX,
        }).unwrap();
        // Lock
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Lock {
            address: 2882338816, start: 0, end: u64::MAX,
        }).unwrap();
        // Switches
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Switches {
            start: 0, end: u64::MAX,
        }).unwrap();
        // Register (no register deltas in this trace — should still succeed with null)
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::Register {
            register_id: 0, step: 5,
        }).unwrap();
        // RegisterState (no register deltas — should still succeed with null state)
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::RegisterState {
            step: 5,
        }).unwrap();
        // RegisterHistory (no register deltas — should still succeed with empty)
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::RegisterHistory {
            register_id: 0, start: 0, end: u64::MAX,
        }).unwrap();
        // CallStack (no calls in this trace — should still succeed with empty stack)
        run_query(d, Some(path.clone()), None, 0, TraceFormat::Native, 0, None, QueryCmd::CallStack {
            thread_id: 1, step: 5,
        }).unwrap();
        // JniCalls (no jni_calls in this trace — should still succeed with empty)
        run_query(d, Some(path), None, 0, TraceFormat::Native, 0, None, QueryCmd::JniCalls {
            address: 4096, start: 0, end: u64::MAX,
        }).unwrap();
    }

    /// run_query surfaces a read error for a missing file.
    #[test]
    fn test_run_query_missing_file_errors() {
        let result = run_query(
            data_dir().path(),
            Some(PathBuf::from("/tmp/does_not_exist_xyz_query.json")),
            None, 0, TraceFormat::Native, 0, None, QueryCmd::Threads,
        );
        assert!(result.is_err());
    }

    // --- trace persistence CLI ---

    use sotrace_engine::persistence::{PersistedTrace, TraceRepository};

    /// Build a minimal PersistedTrace from RACE_TRACE's threads so load_engine
    /// can replay it. Uses the same event shape `envelope_to_events` produces.
    fn save_race_trace(data_dir: &Path) -> u64 {
        let f = write_trace_json(RACE_TRACE);
        let raw = std::fs::read_to_string(f.path()).unwrap();
        let envelope: TraceEnvelope = serde_json::from_str(&raw).unwrap();
        let events = envelope_to_events(&envelope).unwrap();
        let trace = PersistedTrace {
            trace_id: 0,
            so_file_id: 0,
            source: "native".into(),
            base_addr: 0,
            events,
            created_at: 1_700_000_000,
        };
        let repo = TraceRepository::open(data_dir).unwrap();
        repo.save(trace).unwrap()
    }
