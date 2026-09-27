// Persistence tests. Module path remains `persistence::tests`.
    use super::*;
    use sotrace_core::models::so_file::{Architecture, SOFile};
    use sotrace_core::models::so_function::SOFunction;
    use sotrace_core::models::so_segment::{SOSegment, SegmentType};
    use sotrace_core::models::so_symbol::{SOSymbol, SymbolType, SymbolBind};

    fn make_parsed(name: &str, build_id: Option<Vec<u8>>) -> ParsedSoFile {
        let so_file = SOFile {
            id: 0,
            path: name.to_string(),
            build_id,
            arch: Architecture::AArch64,
            file_size: 4096,
            md5: [1; 16],
            sha256: [2; 32],
            loaded_base_address: 0,
            created_at: 1_700_000_000,
        };
        let segments = vec![SOSegment {
            id: 0, so_file_id: 0, name: ".text".into(),
            seg_type: SegmentType::Load, offset: 0, vaddr: 0, size: 100, flags: 0,
        }];
        let symbols = vec![SOSymbol {
            id: 0, so_file_id: 0, name: "decrypt".into(), value: 0x1000, size: 64,
            sym_type: SymbolType::Func, bind: SymbolBind::Global,
            is_imported: false, is_exported: true,
        }];
        let functions = vec![SOFunction {
            id: 0, so_file_id: 0, symbol_id: Some(0), name: "decrypt".into(),
            offset: 0x1000, size: 64, is_jni: false, is_imported: false,
            is_exported: true, is_thunk: false,
        }];
        ParsedSoFile { so_file, segments, symbols, functions }
    }

    #[test]
    fn test_save_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = SoRepository::open(tmp.path()).unwrap();
        let parsed = make_parsed("/fake/libtest.so", Some(vec![0xab; 20]));
        let o = repo.save(&parsed).unwrap();
        // IDs start at 1 — 0 is the reserved "no SO" sentinel.
        assert_eq!(o.id, 1);
        assert!(!o.deduped);
        let id = o.id;

        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.so_file.path, "/fake/libtest.so");
        assert_eq!(loaded.functions.len(), 1);
        assert_eq!(loaded.functions[0].name, "decrypt");
        assert_eq!(loaded.so_file.build_id.as_ref().unwrap(), &(vec![0xab; 20]));
    }

    #[test]
    fn test_dedup_by_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = SoRepository::open(tmp.path()).unwrap();
        let parsed = make_parsed("/fake/a.so", None);
        let o1 = repo.save(&parsed).unwrap();
        assert!(!o1.deduped);
        // Same content, different path — should reuse id1, not write a new blob.
        let mut dup = parsed.clone();
        dup.so_file.path = "/fake/b.so".into();
        let o2 = repo.save(&dup).unwrap();
        // deduped is the authoritative signal straight from the index lookup —
        // no created_at second-grained heuristic involved.
        assert!(o2.deduped);
        assert_eq!(o2.id, o1.id);
        assert_eq!(repo.list().unwrap().len(), 1);
        // The loaded path is the original (first-write-wins).
        assert_eq!(repo.load(o1.id).unwrap().so_file.path, "/fake/a.so");
    }

    #[test]
    fn test_sequential_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = SoRepository::open(tmp.path()).unwrap();
        let mut p1 = make_parsed("/a.so", None);
        p1.so_file.sha256 = [1; 32];
        let mut p2 = make_parsed("/b.so", None);
        p2.so_file.sha256 = [2; 32];
        let id1 = repo.save(&p1).unwrap();
        let id2 = repo.save(&p2).unwrap();
        assert_eq!(id1.id, 1);
        assert_eq!(id2.id, 2);
        assert!(!id1.deduped && !id2.deduped);
        assert_eq!(repo.list().unwrap().len(), 2);
    }

    #[test]
    fn test_find_by_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = SoRepository::open(tmp.path()).unwrap();
        let parsed = make_parsed("/x.so", None);
        let id = repo.save(&parsed).unwrap().id;
        let sha = to_hex(&parsed.so_file.sha256);
        let found = repo.find_by_sha256(&sha).unwrap().expect("found");
        assert_eq!(found.0, id);
        assert_eq!(found.1.so_file.path, "/x.so");
        assert!(repo.find_by_sha256("deadbeef").unwrap().is_none());
    }

    #[test]
    fn test_list_and_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = SoRepository::open(tmp.path()).unwrap();
        let parsed = make_parsed("/y.so", Some(vec![0xcd; 20]));
        let id = repo.save(&parsed).unwrap().id;
        let list = repo.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].function_count, 1);
        assert_eq!(list[0].jni_function_count, 0);
        assert_eq!(list[0].build_id.as_ref().unwrap(), &"cd".repeat(20));
        let s = repo.summary(id).unwrap().expect("summary");
        assert_eq!(s.path, "/y.so");
        assert!(repo.summary(999).unwrap().is_none());
    }

    #[test]
    fn test_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = SoRepository::open(tmp.path()).unwrap();
        let parsed = make_parsed("/z.so", None);
        let id = repo.save(&parsed).unwrap().id;
        assert!(repo.delete(id).unwrap());
        assert!(!repo.delete(id).unwrap()); // already gone
        assert!(repo.load(id).is_err());
        assert!(repo.list().unwrap().is_empty());
        // next_id is not recycled. First save used id 1, so the next is 2.
        let mut p2 = make_parsed("/z2.so", None);
        p2.so_file.sha256 = [9; 32];
        assert_eq!(repo.save(&p2).unwrap().id, 2);
    }

    #[test]
    fn test_reopen_preserves_state() {
        let tmp = tempfile::tempdir().unwrap();
        let id = {
            let repo = SoRepository::open(tmp.path()).unwrap();
            repo.save(&make_parsed("/reopen.so", None)).unwrap().id
        };
        // Reopen from the same data dir — index should be loaded from disk.
        let repo = SoRepository::open(tmp.path()).unwrap();
        assert_eq!(repo.list().unwrap().len(), 1);
        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.so_file.path, "/reopen.so");
    }

    #[test]
    fn test_open_creates_so_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        let so_dir = tmp.path().join("so");
        assert!(!so_dir.exists());
        let _repo = SoRepository::open(tmp.path()).unwrap();
        assert!(so_dir.exists());
    }

    // --- Trace persistence ---

    use sotrace_core::adapters::TraceEvent;
    use sotrace_core::models::thread::ThreadInfo;

    fn sample_events() -> Vec<TraceEvent> {
        vec![
            TraceEvent::Thread(ThreadInfo {
                thread_id: 1,
                pthread_id: None,
                parent_thread_id: 0,
                create_step: 0,
                exit_step: None,
                name: Some("main".into()),
                stack_base: 0x7fff0000,
                stack_size: 8 * 1024 * 1024,
                tls_addr: 0,
                is_jni_attached: false,
            }),
            TraceEvent::MemoryWrite {
                step: 5,
                thread_id: 1,
                address: 0x1000,
                data: vec![0xff; 4],
            },
        ]
    }

    fn make_trace(id: u64, events: Vec<TraceEvent>) -> PersistedTrace {
        PersistedTrace {
            trace_id: id,
            so_file_id: 7,
            source: "native".into(),
            base_addr: 0x1000,
            events,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn test_trace_save_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let id = repo.save(make_trace(0, sample_events())).unwrap();

        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.trace_id, id);
        assert_eq!(loaded.so_file_id, 7);
        assert_eq!(loaded.source, "native");
        assert_eq!(loaded.base_addr, 0x1000);
        assert_eq!(loaded.events.len(), 2);
        // Events survive bincode round-trip with their step ordering intact.
        assert_eq!(loaded.events[0].step(), 0);
        assert_eq!(loaded.events[1].step(), 5);
    }

    #[test]
    fn test_trace_id_auto_assign() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let a = repo.save(make_trace(0, sample_events())).unwrap();
        let b = repo.save(make_trace(0, sample_events())).unwrap();
        // 0 is the input sentinel for automatic assignment; persisted ids
        // start at 1 just like SO ids.
        assert_eq!(a, 1);
        assert_eq!(b, 2);
        // An explicit id ahead of the counter bumps next_id past it.
        let c = repo.save(make_trace(42, sample_events())).unwrap();
        assert_eq!(c, 42);
        let d = repo.save(make_trace(0, sample_events())).unwrap();
        assert_eq!(d, 43);
    }

    #[test]
    fn test_trace_index_repairs_legacy_zero_counter() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let index_path = tmp.path().join("trace").join("index.json");
        std::fs::write(
            &index_path,
            serde_json::json!({ "next_id": 0, "summaries": [] }).to_string(),
        ).unwrap();

        assert_eq!(repo.save(make_trace(0, sample_events())).unwrap(), 1);
    }

    #[test]
    fn test_trace_list_and_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let id0 = repo.save(make_trace(0, sample_events())).unwrap();
        let id1 = repo.save(make_trace(0, sample_events())).unwrap();

        let list = repo.list().unwrap();
        assert_eq!(list.len(), 2);
        let sum0 = repo.summary(id0).unwrap().unwrap();
        assert_eq!(sum0.trace_id, id0);
        assert_eq!(sum0.so_file_id, 7);
        assert_eq!(sum0.event_count, 2);
        assert!(sum0.events_sorted);
        assert!(repo.summary(id1).unwrap().is_some());
        assert!(repo.summary(999).unwrap().is_none());
    }

    #[test]
    fn test_trace_save_sorts_events_stably() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let events = vec![
            TraceEvent::MemoryWrite {
                step: 9, thread_id: 1, address: 0x1000, data: vec![9],
            },
            TraceEvent::MemoryWrite {
                step: 3, thread_id: 1, address: 0x1001, data: vec![1],
            },
            TraceEvent::MemoryWrite {
                step: 3, thread_id: 1, address: 0x1002, data: vec![2],
            },
        ];
        let id = repo.save(make_trace(0, events)).unwrap();

        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.events.iter().map(TraceEvent::step).collect::<Vec<_>>(), vec![3, 3, 9]);
        let tied_data: Vec<u8> = loaded.events[..2].iter().map(|event| match event {
            TraceEvent::MemoryWrite { data, .. } => data[0],
            other => panic!("expected MemoryWrite, got {:?}", other),
        }).collect();
        assert_eq!(tied_data, vec![1, 2]);
        assert!(repo.summary(id).unwrap().unwrap().events_sorted);
    }

    #[test]
    fn test_trace_save_stream_roundtrip_and_layout_compatibility() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let events = vec![
            TraceEvent::MemoryWrite {
                step: 2, thread_id: 1, address: 0x1002, data: vec![2],
            },
            TraceEvent::MemoryWrite {
                step: 1, thread_id: 1, address: 0x1001, data: vec![1],
            },
        ];
        let mut expected_stats = ImportStats::default();
        for event in &events {
            expected_stats.record(event);
        }
        let expected_count = expected_stats.events;
        let producer_events = events.clone();
        let (id, stats) = repo.save_stream(
            TraceStreamMetadata {
                trace_id: 0,
                so_file_id: 7,
                source: "frida:stalker".into(),
                base_addr: 0x1000,
                created_at: 1_700_000_000,
            },
            expected_count,
            move |sink| {
                for event in producer_events {
                    sink(event)?;
                }
                Ok(expected_stats)
            },
        ).unwrap();

        assert_eq!(stats.events, expected_count);
        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.trace_id, id);
        assert_eq!(loaded.source, "frida:stalker");
        assert_eq!(loaded.events.iter().map(TraceEvent::step).collect::<Vec<_>>(), vec![2, 1]);
        assert!(!repo.summary(id).unwrap().unwrap().events_sorted);

        // The custom streaming serializer must remain byte-compatible with
        // the ordinary six-field PersistedTrace representation. In
        // particular, no stream-specific metadata may be added to the blob.
        let expected = PersistedTrace {
            trace_id: id,
            so_file_id: 7,
            source: "frida:stalker".into(),
            base_addr: 0x1000,
            events,
            created_at: 1_700_000_000,
        };
        assert_eq!(bincode::serialize(&loaded).unwrap(), bincode::serialize(&expected).unwrap());
    }

    #[test]
    fn test_trace_save_stream_rejects_event_count_without_publishing() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let event = TraceEvent::MemoryWrite {
            step: 1, thread_id: 1, address: 0x1000, data: vec![1],
        };
        let mut stats = ImportStats::default();
        stats.record(&event);
        let result = repo.save_stream(
            TraceStreamMetadata {
                trace_id: 0,
                so_file_id: 0,
                source: "test".into(),
                base_addr: 0,
                created_at: 1_700_000_000,
            },
            2,
            move |sink| {
                sink(event)?;
                Ok(stats)
            },
        );

        let error = result.unwrap_err();
        assert!(error.to_string().contains("stream event count mismatch"));
        assert!(repo.list().unwrap().is_empty());
        assert!(!tmp.path().join("trace").join("1.bincode.zst").exists());
        assert!(!tmp.path().join("trace").join("1.bincode.zst.tmp").exists());
    }

    #[test]
    fn test_trace_replay_sorted_streams_events() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let id = repo.save(make_trace(0, vec![
            TraceEvent::MemoryWrite {
                step: 8, thread_id: 1, address: 0x1008, data: vec![8],
            },
            TraceEvent::MemoryWrite {
                step: 2, thread_id: 1, address: 0x1002, data: vec![2],
            },
        ])).unwrap();
        let mut replayed_steps = Vec::new();

        let (start, result) = repo.replay_sorted(
            id,
            |start| Ok(start.clone()),
            |_, event| {
                replayed_steps.push(event.step());
                Ok(())
            },
        ).unwrap();

        assert_eq!(start.trace_id, id);
        assert_eq!(start.so_file_id, 7);
        assert_eq!(start.source, "native");
        assert_eq!(start.base_addr, 0x1000);
        assert_eq!(replayed_steps, vec![2, 8]);
        assert_eq!(result.event_count, 2);
        assert_eq!(result.created_at, 1_700_000_000);
        assert_eq!(result.start, start);
    }

    #[test]
    fn test_trace_replay_sorted_rejects_legacy_index() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let trace = make_trace(5, sample_events());
        std::fs::write(
            tmp.path().join("trace").join("5.bincode"),
            bincode::serialize(&trace).unwrap(),
        ).unwrap();
        let index = TraceIndex {
            next_id: 6,
            summaries: vec![TraceSummary {
                trace_id: 5,
                so_file_id: 7,
                source: "native".into(),
                base_addr: 0x1000,
                event_count: 2,
                events_sorted: false,
                created_at: 1_700_000_000,
            }],
        };
        std::fs::write(
            tmp.path().join("trace").join("index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        ).unwrap();

        let err = repo.replay_sorted(5, |start| Ok(start.clone()), |_, _| Ok(())).unwrap_err();
        assert!(err.to_string().contains("does not declare chronologically ordered events"));
    }

    #[test]
    fn test_trace_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let id = repo.save(make_trace(0, sample_events())).unwrap();
        assert!(repo.delete(id).unwrap());
        assert!(repo.load(id).is_err());
        // Deleting again is a no-op.
        assert!(!repo.delete(id).unwrap());
        assert!(repo.list().unwrap().is_empty());
    }

    #[test]
    fn test_trace_reopen_preserves_state() {
        let tmp = tempfile::tempdir().unwrap();
        let id = {
            let repo = TraceRepository::open(tmp.path()).unwrap();
            repo.save(make_trace(0, sample_events())).unwrap()
        };
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.events.len(), 2);
        assert_eq!(repo.list().unwrap().len(), 1);
    }
