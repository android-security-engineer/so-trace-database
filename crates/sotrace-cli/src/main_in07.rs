
    /// trace-save (via run_trace_save) persists the trace to disk.
    #[test]
    fn test_run_trace_save_persists() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);
        // quiet load inside run_trace_save; prints trace_id to stdout.
        let result = run_trace_save(
            dd.path(), f.path().to_path_buf(), 0, TraceFormat::Native, 0, None, 1_700_000_000,
        );
        assert!(result.is_ok(), "trace-save failed: {:?}", result.err());
        // Exactly one trace should now be persisted.
        let repo = TraceRepository::open(dd.path()).unwrap();
        let list = repo.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].source, "native");
        assert!(list[0].event_count > 0);
    }

    /// trace-list / trace-show / trace-delete run without error.
    #[test]
    fn test_run_trace_list_show_delete() {
        let dd = data_dir();
        let id = save_race_trace(dd.path());
        assert!(run_trace_list(dd.path()).is_ok());
        assert!(run_trace_show(dd.path(), id).is_ok());
        assert!(run_trace_delete(dd.path(), id).is_ok());
        // After delete, list is empty.
        let repo = TraceRepository::open(dd.path()).unwrap();
        assert!(repo.list().unwrap().is_empty());
    }

    /// Replaying a persisted trace via --trace-id yields the same thread set
    /// as parsing the source file directly.
    #[test]
    fn test_trace_id_replay_matches_file_parse() {
        let dd = data_dir();
        let f = write_trace_json(RACE_TRACE);

        // Direct file parse.
        let (engine_file, _, _) = load_engine(
            dd.path(), Some(&f.path().to_path_buf()), None, 0,
            TraceFormat::Native, 0, &None, true,
        ).unwrap();
        let mut from_file: Vec<u32> = engine_file.all_thread_ids();
        from_file.sort();

        // Persist then replay by id.
        let id = save_race_trace(dd.path());
        let (engine_replay, _, _) = load_engine(
            dd.path(), None, Some(id), 0,
            TraceFormat::Native, 0, &None, true,
        ).unwrap();
        let mut from_replay: Vec<u32> = engine_replay.all_thread_ids();
        from_replay.sort();

        assert_eq!(from_file, from_replay, "replayed trace must match file-parsed thread set");
        // Replay should also preserve sync events for the thread.
        assert!(engine_replay.query_thread_sync_events(from_replay[0], 0, u64::MAX).len()
            == engine_file.query_thread_sync_events(from_file[0], 0, u64::MAX).len());
    }

    /// trace_id pointing at a non-existent id errors.
    #[test]
    fn test_trace_id_missing_errors() {
        let dd = data_dir();
        let result = load_engine(
            dd.path(), None, Some(9999), 0,
            TraceFormat::Native, 0, &None, true,
        );
        assert!(result.is_err());
    }
