
#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta_store::types::DeltaStoreConfig;
    use crate::persistence::trace_codec::synthesize_mixed;
    use sotrace_core::models::instruction_trace::InstructionTrace;

    fn instr(seq: u64, addr: u64) -> TraceEvent {
        TraceEvent::Instruction(InstructionTrace {
            seq,
            thread_id: 1,
            address: addr,
            timestamp: None,
            is_branch: false,
            branch_taken: false,
            opcode: None,
        })
    }

    #[test]
    fn sync_ingest_is_immediately_queryable() {
        let engine = Arc::new(Mutex::new(TraceEngine::new(1, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::with_mode(Arc::clone(&engine), WriteMode::Sync);
        let events: Vec<_> = (0..50).map(|i| instr(i, 0x1000 + i * 4)).collect();
        let n = events.len() as u64;
        ingestor.ingest(events).unwrap();
        let st = ingestor.status();
        assert_eq!(st.accepted, n);
        assert_eq!(st.queryable, n);
        let eng = engine.lock().unwrap();
        let range = eng.query_instructions_range(0, u64::MAX);
        assert_eq!(range.len(), n as usize);
        let hits = eng.query_instructions_by_address(0x1000);
        assert_eq!(hits, &[0]);
    }

    #[test]
    fn async_ingest_status_then_drain_queryable() {
        let engine = Arc::new(Mutex::new(TraceEngine::new(1, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::new(Arc::clone(&engine)); // default async
        assert_eq!(ingestor.mode, WriteMode::Async);
        let events: Vec<_> = (0..200).map(|i| instr(i, 0x2000 + i * 4)).collect();
        let n = events.len() as u64;
        ingestor.ingest(events).unwrap();
        let st = ingestor.status();
        assert_eq!(st.accepted, n);
        assert!(st.queryable <= st.accepted);
        let drained = ingestor.drain().unwrap();
        assert_eq!(drained.queryable, n);
        assert_eq!(drained.accepted, n);
        let eng = engine.lock().unwrap();
        let range = eng.query_instructions_range(0, u64::MAX);
        assert_eq!(range.len(), n as usize);
    }

    #[test]
    fn second_append_leaves_first_batch_intact() {
        let engine = Arc::new(Mutex::new(TraceEngine::new(1, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::with_mode(Arc::clone(&engine), WriteMode::Sync);
        let first: Vec<_> = (0..10).map(|i| instr(i, 0x1000 + i * 4)).collect();
        let second: Vec<_> = (10..15).map(|i| instr(i, 0x2000 + (i - 10) * 4)).collect();
        ingestor.ingest(first).unwrap();
        ingestor.drain().unwrap();
        ingestor.ingest(second).unwrap();
        ingestor.drain().unwrap();
        let eng = engine.lock().unwrap();
        assert_eq!(eng.query_instructions_range(0, u64::MAX).len(), 15);
        assert_eq!(eng.query_instructions_by_address(0x1000), &[0]);
        assert_eq!(eng.query_instructions_by_address(0x2000), &[10]);
    }

    #[test]
    fn persist_append_is_durable_and_loadable() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let engine = Arc::new(Mutex::new(TraceEngine::new(0, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::with_mode(Arc::clone(&engine), WriteMode::Async);
        ingestor.enable_persist(
            repo,
            TraceStreamMetadata {
                trace_id: 0,
                so_file_id: 0,
                source: "ingest-test".into(),
                base_addr: 0,
                created_at: 1,
            },
        );
        let a = synthesize_mixed(64, 1);
        let b = synthesize_mixed(32, 1);
        let n = (a.len() + b.len()) as u64;
        ingestor.ingest(a.clone()).unwrap();
        ingestor.drain().unwrap();
        ingestor.ingest(b.clone()).unwrap();
        let st = ingestor.drain().unwrap();
        assert_eq!(st.queryable, n);
        assert_eq!(st.durable, n);
        let id = ingestor.persist_id().expect("persist id assigned");
        let loaded = TraceRepository::open(tmp.path()).unwrap().load(id).unwrap();
        let mut expected = a;
        expected.extend(b);
        assert_eq!(loaded.events, expected);
    }

    fn watermarks_ok(st: IngestStatus) {
        assert!(st.durable <= st.queryable, "{st:?}");
        assert!(st.queryable <= st.accepted, "{st:?}");
    }

    #[test]
    fn empty_ingest_is_noop() {
        let engine = Arc::new(Mutex::new(TraceEngine::new(1, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::new(Arc::clone(&engine));
        let before = ingestor.status();
        ingestor.ingest(Vec::new()).unwrap();
        let after = ingestor.status();
        assert_eq!(before, after);
        watermarks_ok(after);
        assert!(engine.lock().unwrap().query_instructions_range(0, u64::MAX).is_empty());
    }

    #[test]
    fn in_flight_query_sees_only_queryable_prefix() {
        let engine = Arc::new(Mutex::new(TraceEngine::new(1, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::new(Arc::clone(&engine));
        let first: Vec<_> = (0..10).map(|i| instr(i, 0x1000 + i * 4)).collect();
        ingestor.ingest(first).unwrap();
        ingestor.drain().unwrap();
        let pre = ingestor.status().queryable;

        let release = ingestor.stall_next_apply();
        let second: Vec<_> = (10..40).map(|i| instr(i, 0x2000 + (i - 10) * 4)).collect();
        ingestor.ingest(second).unwrap();
        let start = std::time::Instant::now();
        while !ingestor.status().in_flight {
            assert!(start.elapsed() < Duration::from_secs(2), "worker never in-flight");
            thread::sleep(Duration::from_micros(50));
        }
        watermarks_ok(ingestor.status());
        assert_eq!(ingestor.status().queryable, pre);
        let seen = engine.lock().unwrap().query_instructions_range(0, u64::MAX).len();
        assert_eq!(seen, pre as usize);
        release.send(()).unwrap();
        let st = ingestor.drain().unwrap();
        assert_eq!(st.queryable, st.accepted);
        assert_eq!(
            engine.lock().unwrap().query_instructions_range(0, u64::MAX).len(),
            40
        );
    }

    #[test]
    fn apply_error_unblocks_drain() {
        let engine = Arc::new(Mutex::new(TraceEngine::new(1, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::new(Arc::clone(&engine));
        ingestor.fail_next_apply();
        let events: Vec<_> = (0..8).map(|i| instr(i, 0x1000 + i * 4)).collect();
        ingestor.ingest(events).unwrap();
        let err = ingestor.drain().expect_err("drain must surface apply failure");
        assert!(err.to_string().contains("injected apply failure"));
        let st = ingestor.status();
        watermarks_ok(st);
        assert_eq!(st.queryable, 0);
        assert_eq!(st.accepted, 8);
        assert!(engine.lock().unwrap().query_instructions_range(0, u64::MAX).is_empty());
        assert!(ingestor.ingest(vec![instr(99, 0x1)]).is_err());
    }

    #[test]
    fn persist_fail_does_not_mark_durable() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let engine = Arc::new(Mutex::new(TraceEngine::new(0, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::new(Arc::clone(&engine));
        ingestor.enable_persist(
            repo,
            TraceStreamMetadata {
                trace_id: 0,
                so_file_id: 0,
                source: "fail-persist".into(),
                base_addr: 0,
                created_at: 1,
            },
        );
        ingestor.fail_next_persist();
        let events: Vec<_> = (0..12).map(|i| instr(i, 0x1000 + i * 4)).collect();
        ingestor.ingest(events).unwrap();
        let err = ingestor.drain().unwrap_err();
        assert!(err.to_string().contains("injected persist failure"));
        let st = ingestor.status();
        watermarks_ok(st);
        assert_eq!(st.queryable, 12);
        assert_eq!(st.accepted, 12);
        assert_eq!(st.durable, 0);
        assert_eq!(
            engine.lock().unwrap().query_instructions_range(0, u64::MAX).len(),
            12
        );
        assert!(ingestor.persist_id().is_none());
    }

    #[test]
    fn drop_applies_accepted_events() {
        let engine = Arc::new(Mutex::new(TraceEngine::new(1, DeltaStoreConfig::default())));
        let n;
        {
            let ingestor = TraceIngestor::new(Arc::clone(&engine));
            let events: Vec<_> = (0..80).map(|i| instr(i, 0x1000 + i * 4)).collect();
            n = events.len();
            ingestor.ingest(events).unwrap();
        }
        assert_eq!(
            engine.lock().unwrap().query_instructions_range(0, u64::MAX).len(),
            n
        );
    }

    /// Mixed batch through the durable ingest path, plus the sorting entry
    /// (`feed_events`) and the async/fault watermarks.
    #[test]
    fn mixed_batch_durable_roundtrip_sorted_feed_and_faults() {
        use sotrace_core::adapters::TraceEvent;
        use sotrace_core::models::call_trace::{CallEventType, CallTrace};
        use sotrace_core::models::register_delta::RegisterDelta;
        use sotrace_core::models::thread::{ThreadState, ThreadStateChange};

        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let engine = Arc::new(Mutex::new(TraceEngine::new(0, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::with_mode(Arc::clone(&engine), WriteMode::Async);
        ingestor.enable_persist(
            repo,
            TraceStreamMetadata {
                trace_id: 0,
                so_file_id: 0,
                source: "mixed-roundtrip".into(),
                base_addr: 0,
                created_at: 1,
            },
        );

        let planted_addr = 0xABC0u64;
        let mem_addr = 0x6000u64;
        let events = vec![
            instr(10, planted_addr),
            TraceEvent::MemoryWrite {
                step: 11,
                thread_id: 1,
                address: mem_addr,
                data: vec![0x11, 0x22, 0x33, 0x44],
            },
            TraceEvent::Register(RegisterDelta {
                seq: 12,
                change_mask: 0x1,
                values: vec![0xDEAD],
            }),
            TraceEvent::Call(CallTrace {
                id: 13,
                thread_id: 7,
                event_type: CallEventType::Call,
                caller_address: 0x1000,
                callee_address: 0x9000,
                callee_func_id: None,
                seq: 13,
                depth: 0,
                return_seq: None,
            }),
            TraceEvent::MemoryWrite {
                step: 14,
                thread_id: 1,
                address: mem_addr + 2,
                data: vec![0x99, 0x99],
            },
        ];
        let n = events.len() as u64;
        let expected_mem = vec![0x11, 0x22, 0x99, 0x99];

        // Async accept returns before this batch is queryable.
        let release = ingestor.stall_next_apply();
        assert_eq!(ingestor.ingest(events).unwrap(), n);
        let start = std::time::Instant::now();
        while !ingestor.status().in_flight {
            assert!(start.elapsed() < Duration::from_secs(2), "worker never in-flight");
            thread::sleep(Duration::from_micros(50));
        }
        let mid = ingestor.status();
        watermarks_ok(mid);
        assert_eq!(mid.accepted, n);
        assert_eq!(mid.queryable, 0, "async accept must not publish the batch");
        assert_eq!(mid.durable, 0);
        release.send(()).unwrap();

        let st = ingestor.drain().unwrap();
        assert_eq!(st.accepted, n);
        assert_eq!(st.queryable, n);
        assert_eq!(st.durable, n);
        watermarks_ok(st);

        {
            let eng = engine.lock().unwrap();
            assert_eq!(eng.query_instructions_by_address(planted_addr), &[10]);
            assert_eq!(
                eng.query_memory_value(mem_addr, 4, 14).unwrap().value,
                expected_mem
            );
            assert_eq!(eng.query_register(0, 12), Some(0xDEAD));
            let stack = eng.rebuild_call_stack(7, 13);
            assert_eq!(stack.len(), 1);
            assert_eq!(stack[0].entry_address, 0x9000);
        }

        let id = ingestor.persist_id().expect("persist id");
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let mut replayed = 0usize;
        let (replay_engine, replay) = repo
            .replay_sorted(
                id,
                |start| Ok(TraceEngine::new(start.so_file_id, DeltaStoreConfig::default())),
                |eng, event| {
                    replayed += 1;
                    eng.feed_event(event)?;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(replay.event_count, n as usize);
        assert_eq!(replayed, n as usize);
        assert_eq!(replay_engine.query_instructions_by_address(planted_addr), &[10]);
        assert_eq!(
            replay_engine.query_memory_value(mem_addr, 4, 14).unwrap().value,
            expected_mem
        );
        assert_eq!(replay_engine.query_register(0, 12), Some(0xDEAD));
        assert_eq!(replay_engine.rebuild_call_stack(7, 13)[0].entry_address, 0x9000);

        // Out-of-order batch through the sorting entry. The later step (Blocked
        // at 100) is the live stamp; the earlier step must not remain just
        // because it was last in the input.
        let mut sorted_engine = TraceEngine::new(1, DeltaStoreConfig::default());
        sorted_engine
            .feed_events([
                TraceEvent::StateChange(ThreadStateChange {
                    step: 100,
                    thread_id: 3,
                    new_state: ThreadState::Blocked,
                    prev_state: Some(ThreadState::Running),
                    prev_running_thread: Some(3),
                }),
                TraceEvent::StateChange(ThreadStateChange {
                    step: 40,
                    thread_id: 3,
                    new_state: ThreadState::Running,
                    prev_state: None,
                    prev_running_thread: None,
                }),
            ])
            .unwrap();
        assert_eq!(
            *sorted_engine.thread_store().all_thread_states().get(&3).unwrap(),
            ThreadState::Blocked
        );

        // Injected apply failure does not advance queryable.
        let engine = Arc::new(Mutex::new(TraceEngine::new(1, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::new(Arc::clone(&engine));
        ingestor.fail_next_apply();
        ingestor.ingest(vec![instr(1, 0x1000)]).unwrap();
        assert!(ingestor.drain().unwrap_err().to_string().contains("injected apply failure"));
        let st = ingestor.status();
        watermarks_ok(st);
        assert_eq!(st.queryable, 0);
        assert_eq!(st.accepted, 1);

        // Injected persist failure does not advance durable.
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let engine = Arc::new(Mutex::new(TraceEngine::new(0, DeltaStoreConfig::default())));
        let ingestor = TraceIngestor::new(Arc::clone(&engine));
        ingestor.enable_persist(
            repo,
            TraceStreamMetadata {
                trace_id: 0,
                so_file_id: 0,
                source: "fault".into(),
                base_addr: 0,
                created_at: 1,
            },
        );
        ingestor.fail_next_persist();
        ingestor.ingest(vec![instr(2, 0x2000)]).unwrap();
        assert!(ingestor.drain().unwrap_err().to_string().contains("injected persist failure"));
        let st = ingestor.status();
        watermarks_ok(st);
        assert_eq!(st.queryable, 1);
        assert_eq!(st.durable, 0);
        assert_eq!(st.accepted, 1);
    }
}
