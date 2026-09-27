// TraceEngine tests. Module path remains `engine::tests`.
    use super::*;
    use sotrace_core::models::thread::{
        SyncEventType, SyncResult,
    };

    fn make_config() -> DeltaStoreConfig {
        DeltaStoreConfig::default()
    }

    #[test]
    fn test_engine_creation() {
        let engine = TraceEngine::new(1, make_config());
        assert_eq!(engine.so_file_id(), 1);
        assert_eq!(engine.current_step(), 0);
        assert_eq!(engine.thread_count(), 0);
    }

    #[test]
    fn test_import_instruction_and_query() {
        let mut engine = TraceEngine::new(1, make_config());

        let trace = InstructionTrace {
            seq: 1, thread_id: 1, address: 0x4000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        };
        engine.import_instruction(trace).unwrap();

        let result = engine.query_instruction(1);
        assert!(result.is_some());
        assert_eq!(result.unwrap().address, 0x4000);
    }

    /// Two instructions sharing a `seq` (a multi-threaded adapter assigning the
    /// same step to two threads) both survive in the EventLog. The public
    /// `query_instruction(step)` keeps its pre-EventLog contract — returns one
    /// instruction (the last) — while `query_threads_at_address` expands to
    /// both threads via `flat_map(get_at_step)`, so no thread is silently lost.
    #[test]
    fn test_same_seq_two_instructions_query_paths() {
        let mut engine = TraceEngine::new(1, make_config());
        // Same seq=5, two threads, same address 0x4000.
        engine.import_instruction(InstructionTrace {
            seq: 5, thread_id: 1, address: 0x4000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();
        engine.import_instruction(InstructionTrace {
            seq: 5, thread_id: 2, address: 0x4000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();

        // Public single-instruction query: returns one (the last, thread 2),
        // matching the old DeltaLog overwrite behavior — API stays compatible.
        let one = engine.query_instruction(5).unwrap();
        assert_eq!(one.thread_id, 2);

        // Cross-reference query: both threads appear, neither lost.
        let pairs = engine.query_threads_at_address(0x4000);
        let mut threads: Vec<u32> = pairs.iter().map(|(t, _)| *t).collect();
        threads.sort_unstable();
        assert_eq!(threads, vec![1, 2], "both same-seq threads visible");
    }

    /// An address index points to steps, not individual EventLog records.
    /// Same-step records at unrelated addresses must not leak into this
    /// address-specific cross-reference query.
    #[test]
    fn test_threads_at_address_excludes_other_addresses_at_same_step() {
        let mut engine = TraceEngine::new(1, make_config());
        engine.import_instruction(InstructionTrace {
            seq: 5, thread_id: 1, address: 0x4000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();
        engine.import_instruction(InstructionTrace {
            seq: 5, thread_id: 2, address: 0x5000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();

        assert_eq!(engine.query_threads_at_address(0x4000), vec![(1, 5)]);
        assert_eq!(engine.query_threads_at_address(0x5000), vec![(2, 5)]);
    }

    #[test]
    fn test_import_register_delta_and_query() {
        let mut engine = TraceEngine::new(1, make_config());

        // x0 = 0x1000 at seq 5; then x0 = 0x2000 and x2 = 0x12345678 at seq 10.
        engine
            .import_register_delta(RegisterDelta { seq: 5, change_mask: 1, values: vec![0x1000] })
            .unwrap();
        engine
            .import_register_delta(RegisterDelta {
                seq: 10,
                change_mask: (1 << 0) | (1 << 2),
                values: vec![0x2000, 0x12345678],
            })
            .unwrap();

        // Before any delta: no value known.
        assert_eq!(engine.query_register(0, 3), None);
        // Between the two deltas: first value holds.
        assert_eq!(engine.query_register(0, 7), Some(0x1000));
        // After the second delta: updated x0, and x2 extracted at the right bit offset.
        assert_eq!(engine.query_register(0, 12), Some(0x2000));
        assert_eq!(engine.query_register(2, 12), Some(0x12345678));
        // A register never written stays unknown.
        assert_eq!(engine.query_register(5, 12), None);
    }

    #[test]
    fn test_reconstruct_register_state_through_engine() {
        let mut engine = TraceEngine::new(1, make_config());

        engine
            .import_register_delta(RegisterDelta { seq: 5, change_mask: 1, values: vec![0x1000] })
            .unwrap();
        engine
            .import_register_delta(RegisterDelta {
                seq: 10,
                change_mask: (1 << 0) | (1 << 2),
                values: vec![0x2000, 0x12345678],
            })
            .unwrap();

        // Before any delta there is nothing to reconstruct.
        assert!(engine.reconstruct_register_state(3).is_none());

        // Between the deltas: only x0 known so far.
        let s7 = engine.reconstruct_register_state(7).unwrap();
        assert_eq!(s7.gp_regs[0], 0x1000);
        assert_eq!(s7.gp_regs[2], 0);

        // After both: the full file reflects the latest values.
        let s12 = engine.reconstruct_register_state(12).unwrap();
        assert_eq!(s12.seq, 12);
        assert_eq!(s12.gp_regs[0], 0x2000);
        assert_eq!(s12.gp_regs[2], 0x12345678);
        // Every reconstructed slot agrees with the point query.
        for reg in [0usize, 2] {
            assert_eq!(Some(s12.gp_regs[reg]), engine.query_register(reg, 12));
        }
    }

    /// `query_register_history` exposes the per-register index that
    /// `query_register` uses internally — the "when did register X change?"
    /// list query. Previously the index was maintained on every delta but only
    /// consumed for single-point lookup; the history list was unreachable.
    #[test]
    fn test_query_register_history_lists_change_steps() {
        let mut engine = TraceEngine::new(1, make_config());

        // x0 changes at seq 5 and 10; x2 only at seq 10; x1 never.
        engine
            .import_register_delta(RegisterDelta { seq: 5, change_mask: 1, values: vec![0x1000] })
            .unwrap();
        engine
            .import_register_delta(RegisterDelta {
                seq: 10,
                change_mask: (1 << 0) | (1 << 2),
                values: vec![0x2000, 0x12345678],
            })
            .unwrap();
        // Another x0 change later.
        engine
            .import_register_delta(RegisterDelta { seq: 20, change_mask: 1, values: vec![0x3000] })
            .unwrap();

        // x0 changed at 5, 10, 20.
        assert_eq!(engine.query_register_history(0, 0, u64::MAX), vec![5, 10, 20]);
        // x2 changed only at 10.
        assert_eq!(engine.query_register_history(2, 0, u64::MAX), vec![10]);
        // x1 never changed.
        assert!(engine.query_register_history(1, 0, u64::MAX).is_empty());

        // Range filter: x0 in [6, 15] → only 10.
        assert_eq!(engine.query_register_history(0, 6, 15), vec![10]);
        // Range [0, 10] inclusive → 5 and 10.
        assert_eq!(engine.query_register_history(0, 0, 10), vec![5, 10]);

        // Out-of-range register_id → empty (not panic).
        assert!(engine.query_register_history(999, 0, u64::MAX).is_empty());

        // Each listed step is consistent with the point query: query_register
        // at that step returns the value stamped there.
        for &step in &engine.query_register_history(0, 0, u64::MAX) {
            assert!(engine.query_register(0, step).is_some());
        }
    }

    #[test]
    fn test_thread_registration_and_analysis() {
        let mut engine = TraceEngine::new(1, make_config());

        // Register threads
        for tid in [1, 2] {
            let info = ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: None,
                stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
            };
            engine.register_thread(info).unwrap();
        }

        assert_eq!(engine.thread_count(), 2);

        // Feed sync events
        engine.record_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // Run analysis
        let result = engine.analyze_threads();
        // Lock contention should be computed
        assert!(result.lock_contentions.len() <= 1); // May or may not have contention
    }

    #[test]
    fn test_race_detection_via_engine() {
        let mut engine = TraceEngine::new(1, make_config());

        // Register threads
        for tid in [1, 2] {
            let info = ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: None,
                stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
            };
            engine.register_thread(info).unwrap();
        }

        // Thread 1 writes, Thread 2 reads same address (no sync = race)
        engine.import_memory_write(MemoryWrite {
            step: 100, thread_id: 1, address: 0x1000, data: vec![0xFF; 4],
        }).unwrap();
        engine.analyzer.feed_memory_read(200, 2, 0x1000, 4);

        let races = engine.detect_race_conditions();
        assert!(!races.is_empty());
        assert_eq!(races[0].address, 0x1000);
    }

    #[test]
    fn test_thread_function_assoc_via_engine() {
        let mut engine = TraceEngine::new(1, make_config());

        // Register thread
        let info = ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };
        engine.register_thread(info).unwrap();

        // Import call trace
        let call = CallTrace {
            id: 1, thread_id: 1,
            event_type: sotrace_core::models::call_trace::CallEventType::Call,
            caller_address: 0x3000, callee_address: 0x4000,
            callee_func_id: None, seq: 50, depth: 1, return_seq: None,
        };
        engine.import_call_trace(call).unwrap();

        // Run analysis
        let result = engine.analyze_threads();
        let assoc = result.thread_function_assocs.iter()
            .find(|a| a.thread_id == 1 && a.function_address == 0x4000);
        assert!(assoc.is_some());
        assert_eq!(assoc.unwrap().call_count, 1);
    }

    #[test]
    fn test_function_name_backfill_from_elf() {
        let mut engine = TraceEngine::new(1, make_config());

        // Register functions parsed from a (hypothetical) ELF: 0x4000 = decrypt,
        // 0x5000 = Java_com_example_nativeMethod.
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
        assert_eq!(engine.registered_function_count(), 2);
        assert_eq!(engine.function_name(0x4000), Some("decrypt"));
        assert_eq!(engine.function_name(0x5000), Some("Java_com_example_nativeMethod"));
        assert_eq!(engine.function_name(0x9999), None);

        // Register thread + import a call to 0x4000
        let info = ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };
        engine.register_thread(info).unwrap();
        let call = CallTrace {
            id: 1, thread_id: 1,
            event_type: sotrace_core::models::call_trace::CallEventType::Call,
            caller_address: 0x3000, callee_address: 0x4000,
            callee_func_id: None, seq: 50, depth: 1, return_seq: None,
        };
        engine.import_call_trace(call).unwrap();

        // Analysis should back-fill the function name.
        let result = engine.analyze_threads();
        let assoc = result.thread_function_assocs.iter()
            .find(|a| a.function_address == 0x4000).unwrap();
        assert_eq!(assoc.function_name.as_deref(), Some("decrypt"));

        let safety = result.function_safety.iter()
            .find(|f| f.function_address == 0x4000);
        // Function safety may or may not include 0x4000 depending on calling
        // thread count; if present, name must be back-filled.
        if let Some(f) = safety {
            assert_eq!(f.function_name.as_deref(), Some("decrypt"));
        }
    }

    /// `function_name` resolves any PC inside a function body, not just the
    /// entry address. JNI native addresses (and race locations) are often
    /// mid-function PCs; the old exact-match lookup returned `None` for them,
    /// leaving analysis reports full of bare offsets. Range resolution against
    /// `[offset, offset + size)` fixes that while keeping entry matches intact.
    #[test]
    fn test_function_name_resolves_intra_function_pc() {
        let mut engine = TraceEngine::new(1, make_config());
        // decrypt @ 0x4000, size 100 (0x64) → covers [0x4000, 0x4064).
        let functions = vec![
            sotrace_core::models::so_function::SOFunction {
                id: 0, so_file_id: 1, symbol_id: None,
                name: "decrypt".to_string(), offset: 0x4000, size: 100,
                is_jni: false, is_imported: false, is_exported: true, is_thunk: false,
            },
        ];
        engine.register_so_functions(&functions);
        // Entry and body both resolve.
        assert_eq!(engine.function_name(0x4000), Some("decrypt"));
        assert_eq!(engine.function_name(0x4034), Some("decrypt")); // mid-function PC
        assert_eq!(engine.function_name(0x4063), Some("decrypt")); // last covered byte
        // Just past the end → None (half-open interval).
        assert_eq!(engine.function_name(0x4064), None);
        // Well before the function → None.
        assert_eq!(engine.function_name(0x3FFF), None);
    }

    /// A `size == 0` function (stripped SO / dynsym-recovered symbol with no
    /// size) cannot claim an interval, so it matches by exact entry only. This
    /// preserves the pre-range-lookup behavior for stripped SOs, which would
    /// otherwise be left entirely unnamed.
    #[test]
    fn test_function_name_stripped_size_zero_exact_match_only() {
        let mut engine = TraceEngine::new(1, make_config());
        let functions = vec![
            sotrace_core::models::so_function::SOFunction {
                id: 0, so_file_id: 1, symbol_id: None,
                name: "decrypt".to_string(), offset: 0x5000, size: 0,
                is_jni: false, is_imported: false, is_exported: true, is_thunk: false,
            },
        ];
        engine.register_so_functions(&functions);
        // Exact entry → hit (old behavior preserved).
        assert_eq!(engine.function_name(0x5000), Some("decrypt"));
        // Mid-function PC → None (size unknown, cannot claim a body).
        assert_eq!(engine.function_name(0x5034), None);
        // Before the entry → None.
        assert_eq!(engine.function_name(0x4FFF), None);
    }

    #[test]
    fn test_coordinated_snapshot() {
        let mut engine = TraceEngine::new(1, make_config());

        // Import enough instructions to trigger snapshot interval
        for i in 0..10 {
            let trace = InstructionTrace {
                seq: i, thread_id: 1, address: 0x4000 + i * 4,
                timestamp: None, is_branch: false, branch_taken: false, opcode: None,
            };
            engine.import_instruction(trace).unwrap();
        }

        // Create a manual snapshot
        let snap_id = engine.create_coordinated_snapshot().unwrap();
        assert_eq!(snap_id, engine.current_step());
    }

    #[test]
    fn test_step_metadata_merge() {
        let mut engine = TraceEngine::new(1, make_config());

        // Step 1: instruction only
        engine.import_instruction(InstructionTrace {
            seq: 1, thread_id: 1, address: 0x4000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();

        // Step 2: instruction + memory write + sync event (all at same step)
        engine.import_instruction(InstructionTrace {
            seq: 2, thread_id: 1, address: 0x5000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();
        engine.import_memory_write(MemoryWrite {
            step: 2, thread_id: 1, address: 0x1000, data: vec![0xAB; 4],
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 2, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xDEAD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // Verify step 1 metadata: only instruction
        let meta1 = engine.get_step_metadata(1).unwrap();
        assert_eq!(meta1.thread_id, 1);
        assert_eq!(meta1.instruction_address, 0x4000);
        assert!(!meta1.has_memory_delta);
        assert!(!meta1.has_sync_event);
        assert!(!meta1.has_call_event);

        // Verify step 2 metadata: instruction + memory + sync (merged)
        let meta2 = engine.get_step_metadata(2).unwrap();
        assert_eq!(meta2.thread_id, 1);
        assert_eq!(meta2.instruction_address, 0x5000);
        assert!(meta2.has_memory_delta, "has_memory_delta should be true after memory write");
        assert!(meta2.has_sync_event, "has_sync_event should be true after sync event");
    }

    #[test]
    fn test_step_metadata_call_and_jni() {
        let mut engine = TraceEngine::new(1, make_config());

        // Step 10: instruction + call trace
        engine.import_instruction(InstructionTrace {
            seq: 10, thread_id: 1, address: 0x4000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();
        engine.import_call_trace(CallTrace {
            id: 1, thread_id: 1,
            event_type: sotrace_core::models::call_trace::CallEventType::Call,
            caller_address: 0x4000, callee_address: 0x5000,
            callee_func_id: None, seq: 10, depth: 1, return_seq: None,
        }).unwrap();

        // Step 20: instruction + JNI call
        engine.import_instruction(InstructionTrace {
            seq: 20, thread_id: 2, address: 0x6000,
            timestamp: None, is_branch: false, branch_taken: false, opcode: None,
        }).unwrap();
        engine.import_jni_call(JNICall {
            id: 1, seq: 20, thread_id: 2,
            direction: sotrace_core::models::jni_call::JNICallDirection::JavaToNative,
            java_class: "com/example/MyClass".to_string(),
            java_method: "nativeMethod".to_string(),
            java_signature: "()V".to_string(),
            native_func_id: None,
            native_address: 0x6000,
            jni_env_address: None,
        }).unwrap();

        // Verify step 10: has_call_event
        let meta10 = engine.get_step_metadata(10).unwrap();
        assert!(meta10.has_call_event, "has_call_event should be true after call trace import");

        // Verify step 20: has_jni_call
        let meta20 = engine.get_step_metadata(20).unwrap();
        assert!(meta20.has_jni_call, "has_jni_call should be true after JNI call import");
    }
