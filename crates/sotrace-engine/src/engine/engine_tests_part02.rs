
    #[test]
    fn test_jni_boundary_backfills_native_function_names() {
        let mut engine = TraceEngine::new(1, make_config());

        // ELF functions: 0x4000 = decrypt, 0x5000 = Java_com_example_nativeMethod.
        // 0x6000 is intentionally unregistered (stripped / unknown).
        let functions = vec![
            sotrace_core::models::so_function::SOFunction {
                id: 0, so_file_id: 1, symbol_id: None,
                name: "decrypt".to_string(), offset: 0x4000, size: 100,
                is_jni: false, is_imported: false, is_exported: true, is_thunk: false,
            },
            sotrace_core::models::so_function::SOFunction {
                id: 1, so_file_id: 1, symbol_id: None,
                name: "Java_com_example_nativeMethod".to_string(), offset: 0x5000, size: 200,
                is_jni: true, is_imported: false, is_exported: true, is_thunk: false,
            },
        ];
        engine.register_so_functions(&functions);

        engine.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: true,
        }).unwrap();
        // Two JNI crossings reach 0x4000 and 0x6000 (the latter unknown).
        engine.import_jni_call(JNICall {
            id: 1, seq: 10, thread_id: 1,
            direction: sotrace_core::models::jni_call::JNICallDirection::JavaToNative,
            java_class: "com.app.Foo".to_string(), java_method: "doWork".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x4000, jni_env_address: None,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 2, seq: 20, thread_id: 1,
            direction: sotrace_core::models::jni_call::JNICallDirection::NativeToJava,
            java_class: "com.app.Bar".to_string(), java_method: "callback".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x6000, jni_env_address: None,
        }).unwrap();

        let stats = engine.analyze_jni_boundary();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        // native_addresses sorted ascending → [0x4000, 0x6000]
        assert_eq!(s.native_addresses, vec![0x4000, 0x6000]);
        // Parallel function names: 0x4000 resolved, 0x6000 None.
        assert_eq!(s.native_functions.len(), 2);
        assert_eq!(s.native_functions[0].as_deref(), Some("decrypt"));
        assert_eq!(s.native_functions[1], None);
    }

    /// A JNI call whose `native_address` lands *inside* a registered function
    /// (not at its entry) must still back-fill the containing function's name.
    /// `native_address` comes from the trace's PC at the JNI crossing, which is
    /// an arbitrary instruction — mid-function is the common case. The old
    /// exact-match `function_name` returned `None` for any non-entry PC, so the
    /// JNI report showed a bare offset; range resolution fixes it.
    #[test]
    fn test_jni_boundary_backfills_intra_function_native_address() {
        let mut engine = TraceEngine::new(1, make_config());
        // decrypt @ 0x4000, size 100 → covers [0x4000, 0x4064).
        let functions = vec![
            sotrace_core::models::so_function::SOFunction {
                id: 0, so_file_id: 1, symbol_id: None,
                name: "decrypt".to_string(), offset: 0x4000, size: 100,
                is_jni: false, is_imported: false, is_exported: true, is_thunk: false,
            },
        ];
        engine.register_so_functions(&functions);

        engine.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: true,
        }).unwrap();
        // JNI crossing lands at 0x4034 — inside decrypt, not at its entry.
        engine.import_jni_call(JNICall {
            id: 1, seq: 10, thread_id: 1,
            direction: sotrace_core::models::jni_call::JNICallDirection::JavaToNative,
            java_class: "com.app.Foo".to_string(), java_method: "doWork".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x4034, jni_env_address: None,
        }).unwrap();

        let stats = engine.analyze_jni_boundary();
        let s = &stats[0];
        assert_eq!(s.native_addresses, vec![0x4034]);
        // Mid-function PC resolves to the containing function, not None.
        assert_eq!(s.native_functions.len(), 1);
        assert_eq!(s.native_functions[0].as_deref(), Some("decrypt"));
    }

    /// `query_jni_calls_by_address` exposes the AddressIndex that
    /// `import_jni_call` has been maintaining all along. It must:
    ///  - return calls whose `native_address` matches, in step order;
    ///  - honor the `[start, end]` range;
    ///  - **filter by address again** after `get_at_step` expansion, because two
    ///    JNI calls sharing a `seq` can target different native addresses and
    ///    `find_by_address` only records the (address, step) pair once — without
    ///    the secondary filter, a same-step sibling call at a different address
    ///    would leak into the result (the #94 pattern, JNI-side).
    #[test]
    fn test_query_jni_calls_by_address_filters_sibling_at_same_step() {
        let mut engine = TraceEngine::new(1, make_config());
        engine.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: true,
        }).unwrap();
        engine.register_thread(ThreadInfo {
            thread_id: 2, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: true,
        }).unwrap();

        // Two threads share seq 10 but call DIFFERENT native addresses.
        // find_by_address(0x4000) records (0x4000, 10) once; get_at_step(10)
        // then yields BOTH calls — the 0x6000 sibling must be filtered out.
        engine.import_jni_call(JNICall {
            id: 1, seq: 10, thread_id: 1,
            direction: sotrace_core::models::jni_call::JNICallDirection::JavaToNative,
            java_class: "com.A".to_string(), java_method: "m".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x4000, jni_env_address: None,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 2, seq: 10, thread_id: 2,
            direction: sotrace_core::models::jni_call::JNICallDirection::JavaToNative,
            java_class: "com.B".to_string(), java_method: "m".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x6000, jni_env_address: None,
        }).unwrap();
        // A second hit on 0x4000 at a later step.
        engine.import_jni_call(JNICall {
            id: 3, seq: 30, thread_id: 1,
            direction: sotrace_core::models::jni_call::JNICallDirection::NativeToJava,
            java_class: "com.A".to_string(), java_method: "cb".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x4000, jni_env_address: None,
        }).unwrap();

        // Full range: both 0x4000 calls survive, the 0x6000 sibling is excluded.
        let all = engine.query_jni_calls_by_address(0x4000, 0, u64::MAX);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].seq, 10);
        assert_eq!(all[0].thread_id, 1);
        assert_eq!(all[1].seq, 30);
        assert!(all.iter().all(|c| c.native_address == 0x4000));

        // Range filter excludes the seq-30 call.
        let early = engine.query_jni_calls_by_address(0x4000, 0, 20);
        assert_eq!(early.len(), 1);
        assert_eq!(early[0].seq, 10);

        // The 0x6000 sibling is reachable via its own address.
        let other = engine.query_jni_calls_by_address(0x6000, 0, u64::MAX);
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].thread_id, 2);

        // An address nobody called returns empty, not a same-step leak.
        assert!(engine.query_jni_calls_by_address(0x9999, 0, u64::MAX).is_empty());
    }

    #[test]
    fn test_jni_boundary_backfill_in_full_analyze_threads() {
        // The full analyze_threads path must back-fill jni_boundary function
        // names too, not just thread_function_assocs / function_safety.
        let mut engine = TraceEngine::new(1, make_config());
        let functions = vec![
            sotrace_core::models::so_function::SOFunction {
                id: 0, so_file_id: 1, symbol_id: None,
                name: "decrypt".to_string(), offset: 0x4000, size: 100,
                is_jni: false, is_imported: false, is_exported: true, is_thunk: false,
            },
        ];
        engine.register_so_functions(&functions);
        engine.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: true,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 1, seq: 10, thread_id: 1,
            direction: sotrace_core::models::jni_call::JNICallDirection::JavaToNative,
            java_class: "com.app.Foo".to_string(), java_method: "doWork".to_string(),
            java_signature: "()V".to_string(), native_func_id: None,
            native_address: 0x4000, jni_env_address: None,
        }).unwrap();

        let result = engine.analyze_threads();
        let s = result.jni_boundary.iter().find(|s| s.thread_id == 1).unwrap();
        assert_eq!(s.native_addresses, vec![0x4000]);
        assert_eq!(s.native_functions[0].as_deref(), Some("decrypt"),
            "full analyze_threads must back-fill jni_boundary names");
    }

    #[test]
    fn test_rebuild_call_stack_through_engine() {
        use sotrace_core::models::call_trace::CallEventType;
        let mut engine = TraceEngine::new(1, make_config());

        let mk = |id: u64, seq: u64, et: CallEventType, callee: u64, depth: u16| CallTrace {
            id, thread_id: 1, event_type: et,
            caller_address: 0x4000, callee_address: callee,
            callee_func_id: None, seq, depth, return_seq: None,
        };
        engine.import_call_trace(mk(1, 1, CallEventType::Call, 0x1000, 0)).unwrap();
        engine.import_call_trace(mk(2, 2, CallEventType::Call, 0x2000, 1)).unwrap();
        engine.import_call_trace(mk(3, 3, CallEventType::Return, 0, 1)).unwrap();

        // At step 2 both frames are active; at step 3 the inner one returned.
        assert_eq!(engine.rebuild_call_stack(1, 2).len(), 2);
        let at3 = engine.rebuild_call_stack(1, 3);
        assert_eq!(at3.len(), 1);
        assert_eq!(at3[0].entry_address, 0x1000);
    }

    /// `feed_events` is the canonical ingestion path shared by CLI/MCP/HTTP.
    /// It must (a) sort by step before feeding — so order-sensitive live state
    /// like `thread_states` ends up stamped with the largest-step event — and
    /// (b) dispatch every `TraceEvent` variant to the right store. This test
    /// pins both: an out-of-order state_change stream and a multi-variant batch.
    #[test]
    fn test_feed_events_sorts_and_dispatches_all_variants() {
        use sotrace_core::adapters::TraceEvent;
        use sotrace_core::models::instruction_trace::InstructionTrace;
        use sotrace_core::models::thread::{ThreadInfo, ThreadState, ThreadStateChange};
        let mut engine = TraceEngine::new(1, make_config());

        let thread_info = ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };
        // Deliberately out of step order: Blocked@100 before Running@50.
        let events = vec![
            TraceEvent::StateChange(ThreadStateChange {
                step: 100, thread_id: 1, new_state: ThreadState::Blocked,
                prev_state: Some(ThreadState::Running), prev_running_thread: Some(1),
            }),
            TraceEvent::Thread(thread_info),
            TraceEvent::Instruction(InstructionTrace {
                seq: 5, thread_id: 1, address: 0x4000, timestamp: None,
                is_branch: false, branch_taken: false, opcode: None,
            }),
            TraceEvent::StateChange(ThreadStateChange {
                step: 50, thread_id: 1, new_state: ThreadState::Running,
                prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
            }),
        ];
        engine.feed_events(events).unwrap();

        // Sorted feed: step 50 (Running) applied before step 100 (Blocked),
        // so the live `thread_states` ends at Blocked — not stuck at Running.
        let states = engine.thread_store().all_thread_states();
        assert_eq!(*states.get(&1).unwrap(), ThreadState::Blocked,
            "feed_events must sort by step; largest-step state (Blocked) wins");

        // The instruction (step 5) was dispatched to the instruction store.
        assert_eq!(engine.instruction_store().total_count(), 1);
    }

    /// Cardinality, step-order state, and save/reload of the shipping
    /// `feed_events` path. The batch is deliberately out of step order.
    #[test]
    fn test_feed_events_cardinality_order_and_reload() {
        use crate::persistence::{PersistedTrace, TraceRepository};
        use sotrace_core::adapters::TraceEvent;
        use sotrace_core::models::instruction_trace::InstructionTrace;
        use sotrace_core::models::register_delta::RegisterDelta;
        use sotrace_core::models::thread::{ThreadState, ThreadStateChange};

        let events = vec![
            TraceEvent::StateChange(ThreadStateChange {
                step: 100,
                thread_id: 7,
                new_state: ThreadState::Blocked,
                prev_state: Some(ThreadState::Running),
                prev_running_thread: Some(7),
            }),
            TraceEvent::Instruction(InstructionTrace {
                seq: 5,
                thread_id: 7,
                address: 0x4000,
                timestamp: None,
                is_branch: false,
                branch_taken: false,
                opcode: None,
            }),
            TraceEvent::Register(RegisterDelta {
                seq: 6,
                change_mask: 0x1,
                values: vec![0x11],
            }),
            TraceEvent::MemoryWrite {
                step: 7,
                thread_id: 7,
                address: 0x2000,
                data: vec![0xAB, 0xCD],
            },
            TraceEvent::StateChange(ThreadStateChange {
                step: 50,
                thread_id: 7,
                new_state: ThreadState::Running,
                prev_state: Some(ThreadState::Runnable),
                prev_running_thread: None,
            }),
            TraceEvent::Instruction(InstructionTrace {
                seq: 80,
                thread_id: 7,
                address: 0x4010,
                timestamp: None,
                is_branch: true,
                branch_taken: true,
                opcode: Some(vec![0x01, 0x02]),
            }),
        ];
        let accepted = events.len() as u64;

        let mut engine = TraceEngine::new(1, make_config());
        engine.feed_events(events.clone()).unwrap();
        assert_eq!(queryable_event_count(&engine), accepted);
        assert_eq!(engine.instruction_store().total_count(), 2);
        // Step 50 is applied before step 100 even though Blocked was listed first.
        assert_eq!(
            engine.query_thread_state(7, 50).unwrap().new_state,
            ThreadState::Running
        );
        assert_eq!(
            engine.query_thread_state(7, 100).unwrap().new_state,
            ThreadState::Blocked
        );
        assert_eq!(
            *engine.thread_store().all_thread_states().get(&7).unwrap(),
            ThreadState::Blocked
        );
        // The earlier instruction is queryable, not dropped to go faster.
        assert_eq!(engine.query_instruction(5).unwrap().address, 0x4000);
        assert_eq!(engine.query_register(0, 6), Some(0x11));

        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let id = repo
            .save(PersistedTrace {
                trace_id: 0,
                so_file_id: 1,
                source: "feed_events".into(),
                base_addr: 0,
                events,
                created_at: 1,
            })
            .unwrap();
        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.events.len() as u64, accepted);

        let mut restored = TraceEngine::new(loaded.so_file_id, make_config());
        restored.feed_events(loaded.events).unwrap();
        assert_eq!(queryable_event_count(&restored), accepted);
        assert_eq!(
            restored.query_thread_state(7, 100).unwrap().new_state,
            ThreadState::Blocked
        );
        assert_eq!(restored.instruction_store().total_count(), 2);
    }

    fn queryable_event_count(engine: &TraceEngine) -> u64 {
        engine.instruction_store().total_count()
            + engine.register_store().record_count()
            + engine.memory_store().record_count()
            + engine.thread_store().all_state_changes().len() as u64
            + engine.thread_store().all_sync_events().len() as u64
            + engine.thread_store().all_context_switches().len() as u64
            + engine.call_store().all_calls().len() as u64
            + engine.jni_store().all_jni_calls().len() as u64
            + engine.thread_store().all_thread_infos().len() as u64
    }
