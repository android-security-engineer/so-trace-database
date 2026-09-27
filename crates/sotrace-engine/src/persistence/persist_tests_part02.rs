
    #[test]
    fn test_trace_blob_is_compressed() {
        // A trace with a large, highly compressible memory payload should shrink
        // substantially under zstd — the on-disk blob must be smaller than the
        // raw bincode payload, proving the compression path is actually used.
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();

        let mut events = sample_events();
        events.push(TraceEvent::MemoryWrite {
            step: 10,
            thread_id: 1,
            address: 0x2000,
            data: vec![0xAA; 64 * 1024],
        });
        let trace = make_trace(0, events);

        let raw_len = bincode::serialize(&trace).unwrap().len();
        let id = repo.save(trace).unwrap();
        let blob_path = tmp.path().join("trace").join(format!("{}.bincode.zst", id));
        assert!(blob_path.exists(), "compressed blob file should exist");
        let blob_len = std::fs::metadata(&blob_path).unwrap().len() as usize;

        assert!(
            blob_len < raw_len,
            "compressed blob ({} B) should be smaller than raw bincode ({} B)",
            blob_len,
            raw_len
        );
        // Sanity: the load path still reconstructs the full payload.
        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.events.len(), 3);
        match &loaded.events[2] {
            TraceEvent::MemoryWrite { data, .. } => assert_eq!(data.len(), 64 * 1024),
            other => panic!("expected MemoryWrite, got {:?}", other),
        }
    }

    #[test]
    fn test_trace_load_legacy_uncompressed_blob() {
        // A blob written by an older version (plain bincode, no zstd) must still
        // load: the reader falls back to the `.bincode` path when `.bincode.zst`
        // is absent.
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();

        let trace = make_trace(5, sample_events());
        let raw = bincode::serialize(&trace).unwrap();
        let legacy_path = tmp.path().join("trace").join("5.bincode");
        std::fs::write(&legacy_path, &raw).unwrap();

        let loaded = repo.load(5).unwrap();
        assert_eq!(loaded.trace_id, 5);
        assert_eq!(loaded.events.len(), 2);
        assert_eq!(loaded.events[0].step(), 0);
    }

    #[test]
    fn test_trace_save_overwrites_legacy_blob() {
        // Saving a trace that previously existed as a legacy uncompressed blob
        // should write the compressed form and remove the stale legacy file, so
        // the next load reads only the fresh compressed bytes.
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();

        // Seed a legacy uncompressed blob + a matching index entry.
        let trace = make_trace(8, sample_events());
        let raw = bincode::serialize(&trace).unwrap();
        let legacy_path = tmp.path().join("trace").join("8.bincode");
        std::fs::write(&legacy_path, &raw).unwrap();
        let idx = TraceIndex {
            next_id: 9,
            summaries: vec![TraceSummary {
                trace_id: 8,
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
            serde_json::to_vec_pretty(&idx).unwrap(),
        )
        .unwrap();

        // Re-save id=8 — should produce the compressed blob and drop the legacy one.
        repo.save(make_trace(8, sample_events())).unwrap();
        let compressed = tmp.path().join("trace").join("8.bincode.zst");
        assert!(compressed.exists(), "compressed blob should be written");
        assert!(!legacy_path.exists(), "legacy blob should be removed");
        let loaded = repo.load(8).unwrap();
        assert_eq!(loaded.events.len(), 2);
    }

    #[test]
    fn test_sotc_save_is_smaller_than_m0_and_roundtrips() {
        use crate::persistence::trace_codec::{encode_m0, synthesize_mixed};
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let events = synthesize_mixed(4_096, 2);
        let m0 = encode_m0(&events).unwrap();
        let id = repo.save(make_trace(0, events.clone())).unwrap();
        let blob = std::fs::read(tmp.path().join("trace").join(format!("{}.bincode.zst", id))).unwrap();
        assert!(
            crate::persistence::trace_codec::is_sotc(&blob),
            "new persist must write SOTC"
        );
        assert!(
            blob.len() < m0.len(),
            "SOTC blob {} B must beat m0 {} B",
            blob.len(),
            m0.len()
        );
        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.events, events);
    }

    #[test]
    fn test_load_legacy_whole_blob_bincode_zstd() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let trace = make_trace(4, sample_events());
        let raw = bincode::serialize(&trace).unwrap();
        let zst = zstd::bulk::compress(&raw, TRACE_ZSTD_LEVEL).unwrap();
        std::fs::write(tmp.path().join("trace").join("4.bincode.zst"), &zst).unwrap();
        let loaded = repo.load(4).unwrap();
        assert_eq!(loaded.trace_id, 4);
        assert_eq!(loaded.events.len(), 2);
        assert_eq!(loaded.events[1].step(), 5);
    }

    #[test]
    fn test_append_events_does_not_clobber_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = TraceRepository::open(tmp.path()).unwrap();
        let first = vec![sample_events()[1].clone()];
        let id = repo
            .create_sotc(TraceStreamMetadata {
                trace_id: 0,
                so_file_id: 1,
                source: "append".into(),
                base_addr: 0,
                created_at: 1,
            })
            .unwrap();
        repo.append_events(id, &first).unwrap();
        let second = vec![TraceEvent::MemoryWrite {
            step: 9,
            thread_id: 1,
            address: 0x2000,
            data: vec![0x11],
        }];
        repo.append_events(id, &second).unwrap();
        let loaded = repo.load(id).unwrap();
        assert_eq!(loaded.events.len(), 2);
        assert_eq!(loaded.events[0].step(), 5);
        assert_eq!(loaded.events[1].step(), 9);
        assert_eq!(repo.summary(id).unwrap().unwrap().event_count, 2);
    }

    /// `TraceRepository::save` syncs before success: a new process (fresh
    /// `open`) sees the same event count. A directory that was never saved
    /// does not yield that batch.
    #[test]
    fn test_save_reopen_matches_event_count_and_unsaved_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let events = sample_events();
        let expected = events.len();
        let id = {
            let repo = TraceRepository::open(tmp.path()).unwrap();
            let id = repo.save(make_trace(0, events)).unwrap();
            drop(repo);
            id
        };
        let reopened = TraceRepository::open(tmp.path()).unwrap();
        let loaded = reopened.load(id).unwrap();
        assert_eq!(loaded.events.len(), expected);

        let empty = tempfile::tempdir().unwrap();
        let fresh = TraceRepository::open(empty.path()).unwrap();
        assert!(fresh.list().unwrap().is_empty());
        assert!(fresh.load(id).is_err());
    }
