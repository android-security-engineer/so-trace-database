
    #[test]
    fn test_data_flow_analysis() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes to 0x3000
        analyzer.feed_memory_write(100, 1, 0x3000, 4);

        // Thread 2 reads from 0x3000
        analyzer.feed_memory_read(200, 2, 0x3000, 4);

        let flows = analyzer.analyze_data_flows();
        assert!(!flows.is_empty());

        let flow = flows.iter()
            .find(|f| f.from_thread == 1 && f.to_thread == 2 && f.address == 0x3000)
            .unwrap();
        assert!(!flow.is_synchronized);
        // #113: transfer sizes and precise transfer range are now reported
        assert_eq!(flow.write_size, 4);
        assert_eq!(flow.read_size, 4);
        assert_eq!(flow.overlap_address, 0x3000);
        assert_eq!(flow.overlap_size, 4);
    }

    /// #113: when the write and read only partially overlap, the transferred
    /// range must be the *intersection*. Thread 1 writes 8 bytes at 0x5000
    /// (0x5000-0x5007), thread 2 reads 8 bytes at 0x5004 (0x5004-0x500B) — the
    /// actual transfer is 0x5004-0x5007 (4 bytes).
    #[test]
    fn test_data_flow_partial_overlap_transfer_range() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));
        analyzer.feed_memory_write(100, 1, 0x5000, 8);
        analyzer.feed_memory_read(200, 2, 0x5004, 8);
        let flows = analyzer.analyze_data_flows();
        assert!(!flows.is_empty());
        let f = &flows[0];
        assert_eq!(f.write_size, 8);
        assert_eq!(f.read_size, 8);
        assert_eq!(f.overlap_address, 0x5004);
        assert_eq!(f.overlap_size, 4);
    }

    /// #113: accesses near `u64::MAX` must not overflow when computing the
    /// transfer range (saturating arithmetic, mirroring #112 race overlap).
    #[test]
    fn test_data_flow_overlap_no_overflow_near_u64_max() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));
        analyzer.feed_memory_write(100, 1, u64::MAX - 7, 8);
        analyzer.feed_memory_read(200, 2, u64::MAX - 3, 8);
        let flows = analyzer.analyze_data_flows();
        assert!(!flows.is_empty());
        let f = &flows[0];
        assert_eq!(f.overlap_address, u64::MAX - 3);
        // Saturating end clamps both ranges to MAX, so overlap is 3 bytes.
        assert_eq!(f.overlap_size, 3);
    }

    #[test]
    fn test_producer_consumer_detection() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));

        let mutex_addr = 0xABCD0000;

        // Produce-consume cycle 1
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 110, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 120, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_read(130, 2, 0x5000, 4);

        // Produce-consume cycle 2
        analyzer.feed_memory_write(200, 1, 0x5000, 4);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 210, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 220, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_read(230, 2, 0x5000, 4);

        let patterns = analyzer.detect_producer_consumer();
        assert!(!patterns.is_empty());

        let pc = patterns.iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert!(pc.cycle_count >= 2);
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: mutex_addr,
                kind: SyncPrimitiveKind::Mutex,
            })
        );
        // Both cycles reuse slot 0x5000, so the distinct shared-address set is a
        // single entry even though cycle_count is 2. Each slot carries its
        // access size and transferred range (#116).
        assert_eq!(
            pc.shared_addresses,
            vec![SharedAddress { address: 0x5000, access_size: 4, overlap_size: 4 }]
        );
        // #120: both cycles have equal latency (100→130, 200→230 = 30 each),
        // so max equals avg here. The distinct-latency case is covered by
        // test_producer_consumer_max_latency_distinct_from_avg.
        assert_eq!(pc.avg_latency_steps, 30);
        assert_eq!(pc.max_latency_steps, 30);
    }

    /// #120: max_latency_steps captures the slowest produce→consume cycle,
    /// distinct from avg when cycles have unequal latencies. Cycle 1: 30
    /// steps (100→130), cycle 2: 70 steps (200→270) → avg=50, max=70.
    #[test]
    fn test_producer_consumer_max_latency_distinct_from_avg() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));
        let mutex_addr = 0xABCD0000;

        // Cycle 1: latency 30 (write 100 → read 130)
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 110, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 120, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_read(130, 2, 0x5000, 4);

        // Cycle 2: latency 70 (write 200 → read 270)
        analyzer.feed_memory_write(200, 1, 0x5000, 4);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 210, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 220, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_read(270, 2, 0x5000, 4);

        let patterns = analyzer.detect_producer_consumer();
        let pc = patterns.iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert_eq!(pc.cycle_count, 2);
        assert_eq!(pc.avg_latency_steps, 50); // (30 + 70) / 2
        assert_eq!(pc.max_latency_steps, 70); // tail, not the avg
    }

    /// #116: shared_addresses reports access_size and overlap_size per slot,
    /// not just the bare address. A slot written 8B and read 8B with a 4B
    /// overlap (partial) reports access_size=8, overlap_size=4.
    #[test]
    fn test_producer_consumer_shared_address_carries_sizes() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));
        let mutex_addr = 0xABCD0000;
        // Two cycles on slot 0x5000: write 8B, read 8B at +4 (4B overlap).
        for &(ws, rs) in &[(100u64, 200u64), (300, 400)] {
            analyzer.feed_memory_write(ws, 1, 0x5000, 8);
            analyzer.feed_sync_event(ThreadSyncEvent {
                step: ws + 10, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
                sync_object_addr: mutex_addr, result: SyncResult::Success, wait_duration_ns: None,
            });
            analyzer.feed_sync_event(ThreadSyncEvent {
                step: rs - 10, thread_id: 2, sync_type: SyncEventType::MutexLock,
                sync_object_addr: mutex_addr, result: SyncResult::Success, wait_duration_ns: Some(1000),
            });
            analyzer.feed_memory_read(rs, 2, 0x5004, 8);
        }
        let pcs = analyzer.detect_producer_consumer();
        assert_eq!(pcs.len(), 1);
        let pc = &pcs[0];
        assert_eq!(pc.shared_addresses.len(), 1);
        let slot = &pc.shared_addresses[0];
        assert_eq!(slot.address, 0x5000);
        assert_eq!(slot.access_size, 8);
        assert_eq!(slot.overlap_size, 4);
    }

    /// When two locks are used the same number of times by the thread pair,
    /// `find_sync_mechanism` must pick the LOWEST address — both for
    /// deterministic output and to match its doc comment. A prior version used
    /// `b.0.cmp(&a.0)` under `max_by`, which silently selected the HIGHEST
    /// address, contradicting the comment.
    #[test]
    fn test_find_sync_mechanism_tie_breaks_lowest_address() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));

        let low = 0x1000_0000u64;
        let high = 0x2000_0000u64;

        // Both threads touch BOTH locks the same number of times (2 each),
        // so the tie-break decides which address is reported.
        for &addr in &[low, high] {
            for &tid in &[1u32, 2u32] {
                analyzer.feed_sync_event(ThreadSyncEvent {
                    step: 10, thread_id: tid,
                    sync_type: SyncEventType::MutexLock,
                    sync_object_addr: addr,
                    result: SyncResult::Success,
                    wait_duration_ns: None,
                });
                analyzer.feed_sync_event(ThreadSyncEvent {
                    step: 20, thread_id: tid,
                    sync_type: SyncEventType::MutexUnlock,
                    sync_object_addr: addr,
                    result: SyncResult::Success,
                    wait_duration_ns: None,
                });
            }
        }

        analyzer.build_indexes();
        assert_eq!(
            analyzer.find_sync_mechanism(1, 2),
            Some(SyncMechanism {
                addr: low,
                kind: SyncPrimitiveKind::Mutex,
            })
        );
    }

    /// `find_sync_mechanism` reports the sync object two threads rendezvous on.
    /// #109 shrank `is_acquire()` to holdable-only (dropping CondvarWait/
    /// BarrierWait). `CondvarWait` is in neither `is_acquire()` nor
    /// `is_release()` after the shrink — only `is_sync_signal()` covers it — so
    /// `sync_locks_by_thread` (which `find_sync_mechanism` reads) must tally it
    /// via `is_sync_signal()`; otherwise two threads that BOTH only wait on a
    /// condvar (the pure-sync-signal case, no signal/broadcast to ride through
    /// `is_release()`) would lose their sync mechanism and report `None`.
    #[test]
    fn test_find_sync_mechanism_recognizes_condvar_signal_wait() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));

        let cv = 0xCD00_0000u64;
        // Both threads ONLY CondvarWait on the same condvar — neither emits a
        // signal/broadcast, so neither event is an `is_release()`; only
        // `is_sync_signal()` can carry them into `sync_locks_by_thread`.
        analyzer.feed_sync_event(hold_ev(10, 1, cv, SyncEventType::CondvarWait));
        analyzer.feed_sync_event(hold_ev(20, 2, cv, SyncEventType::CondvarWait));

        analyzer.build_indexes();
        assert_eq!(
            analyzer.find_sync_mechanism(1, 2),
            Some(SyncMechanism {
                addr: cv,
                kind: SyncPrimitiveKind::Condvar,
            }),
            "condvar wait-only rendezvous must be recognized as a condvar sync mechanism"
        );
    }

    /// `sync_mechanism` must report the *primitive kind*, not just the address.
    /// A futex-only producer-consumer rendezvous must yield `kind: Futex`,
    /// proving the address→kind annotation flows through `find_sync_mechanism`.
    #[test]
    fn test_producer_consumer_sync_mechanism_kind_is_futex() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));

        let futex_word = 0xF071_0000u64;
        // Producer wakes (FutexWake), consumer waits (FutexWait) on the same word.
        analyzer.feed_sync_event(hold_ev(110, 1, futex_word, SyncEventType::FutexWake));
        analyzer.feed_sync_event(hold_ev(120, 2, futex_word, SyncEventType::FutexWait));
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_memory_read(130, 2, 0x5000, 4);
        // Second cycle so detect_producer_consumer (needs >=2 cycles) reports it.
        analyzer.feed_sync_event(hold_ev(210, 1, futex_word, SyncEventType::FutexWake));
        analyzer.feed_sync_event(hold_ev(220, 2, futex_word, SyncEventType::FutexWait));
        analyzer.feed_memory_write(200, 1, 0x6000, 4);
        analyzer.feed_memory_read(230, 2, 0x6000, 4);

        let patterns = analyzer.detect_producer_consumer();
        let pc = patterns
            .iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: futex_word,
                kind: SyncPrimitiveKind::Futex,
            })
        );
    }

    /// A semaphore rendezvous must yield `kind: Semaphore`, covering the #109
    /// holdable-acquire family that was previously mis-tallied.
    #[test]
    fn test_producer_consumer_sync_mechanism_kind_is_semaphore() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));

        let sem = 0x5E80_0000u64;
        analyzer.feed_sync_event(hold_ev(110, 1, sem, SyncEventType::SemPost));
        analyzer.feed_sync_event(hold_ev(120, 2, sem, SyncEventType::SemWait));
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_memory_read(130, 2, 0x5000, 4);
        // Second cycle.
        analyzer.feed_sync_event(hold_ev(210, 1, sem, SyncEventType::SemPost));
        analyzer.feed_sync_event(hold_ev(220, 2, sem, SyncEventType::SemWait));
        analyzer.feed_memory_write(200, 1, 0x6000, 4);
        analyzer.feed_memory_read(230, 2, 0x6000, 4);

        let patterns = analyzer.detect_producer_consumer();
        let pc = patterns
            .iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: sem,
                kind: SyncPrimitiveKind::Semaphore,
            })
        );
    }

    #[test]
    fn test_full_analysis() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Add some data
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);
        analyzer.feed_call_event(50, 1, 0x4000);
        analyzer.feed_call_event(150, 2, 0x4000);

        let result = analyzer.analyze_all();

        // Should have results in all categories
        assert!(!result.race_conditions.is_empty());
        assert!(!result.thread_function_assocs.is_empty());
        assert!(!result.function_safety.is_empty());
        assert!(!result.data_flows.is_empty());
    }

    /// A read whose start address lives in a different 4 KiB page than the
    /// write, but whose byte range overlaps the write, must still be detected.
    /// This is the page-index's trickiest case — a naive per-page exact match
    /// would miss it; the page-covering expansion is what catches it.
    #[test]
    fn test_race_cross_page_overlap() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Write spans the page boundary at 0x2000: [0x1FFE, 0x2022)
        analyzer.feed_memory_write(100, 1, 0x1FFE, 0x24);
        // Read starts in the *next* page (0x2010) but overlaps the write range.
        analyzer.feed_memory_read(200, 2, 0x2010, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.iter().any(|r| r.address == 0x1FFE && r.first_thread == 1 && r.second_thread == 2),
            "cross-page overlapping read must be detected as a race: {:?}", races);

        let flows = analyzer.analyze_data_flows();
        assert!(flows.iter().any(|f| f.from_thread == 1 && f.to_thread == 2),
            "cross-page overlapping read must be detected as a data flow: {:?}", flows);
    }

    /// A large read spanning multiple pages must be found by a write touching
    /// any one of those pages (here the write sits in the middle page).
    #[test]
    fn test_race_multi_page_read() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Read spans three 4 KiB pages: [0x0FFC, 0x3004)
        analyzer.feed_memory_read(200, 2, 0x0FFC, 0x2008);
        // Write lands in the middle page at 0x2000.
        analyzer.feed_memory_write(100, 1, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.iter().any(|r| r.address == 0x2000),
            "write in a middle page of a multi-page read must be detected: {:?}", races);
    }
