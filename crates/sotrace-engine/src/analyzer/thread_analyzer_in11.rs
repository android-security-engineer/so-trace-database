
    /// #111: contention and critical-section reports must type the lock with its
    /// primitive kind, not a bare address. A futex-backed lock yields kind: Futex
    /// in both `LockContentionInfo.lock_address` and `CriticalSectionStats.lock_address`.
    #[test]
    fn test_contention_and_critical_section_kind_is_futex() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        let futex_word = 0xF071_0000u64;
        // Acquire then release a futex word once → one hold interval + one acquire.
        analyzer.feed_sync_event(hold_ev(10, 1, futex_word, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(50, 1, futex_word, SyncEventType::FutexWake));

        let contentions = analyzer.analyze_lock_contention();
        let ct = contentions.iter().find(|c| c.lock_address.addr == futex_word).unwrap();
        assert_eq!(ct.lock_address.kind, SyncPrimitiveKind::Futex);

        let cs = analyzer.analyze_critical_sections();
        let cs_lock = cs.iter().find(|c| c.lock_address.addr == futex_word).unwrap();
        assert_eq!(cs_lock.lock_address.kind, SyncPrimitiveKind::Futex);
    }

    /// A single acquire→release pair yields one hold interval spanning the two
    /// steps, with the span attributed to the holding thread.
    #[test]
    fn test_critical_section_basic_hold() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xABCD_0000u64;

        analyzer.feed_sync_event(hold_ev(100, 1, lock, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(130, 1, lock, SyncEventType::MutexUnlock));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c.lock_address.addr, lock);
        assert_eq!(c.hold_count, 1);
        assert_eq!(c.total_hold_steps, 30);
        assert_eq!(c.avg_hold_steps, 30);
        assert_eq!(c.max_hold_steps, 30);
        assert_eq!(c.longest_hold_thread, 1);
        assert_eq!(c.longest_hold_start, 100);
        assert_eq!(c.longest_hold_end, 130);
        assert_eq!(c.holder_threads, vec![1]);
    }

    /// A recursively-acquired lock (nested acquire before the matching unlocks)
    /// is ONE hold interval spanning the outermost acquire to the outermost
    /// release — not two. A bool-based "held" flag would close the interval on
    /// the first unlock and under-report the true critical-section length.
    #[test]
    fn test_critical_section_recursive_is_single_interval() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x1111_0000u64;

        analyzer.feed_sync_event(hold_ev(100, 1, lock, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(110, 1, lock, SyncEventType::MutexLock)); // nested
        analyzer.feed_sync_event(hold_ev(120, 1, lock, SyncEventType::MutexUnlock)); // inner
        analyzer.feed_sync_event(hold_ev(140, 1, lock, SyncEventType::MutexUnlock)); // outer

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c.hold_count, 1, "nested re-acquire must not open a second interval");
        assert_eq!(c.total_hold_steps, 40, "held from outermost acquire (100) to outermost release (140)");
        assert_eq!(c.max_hold_steps, 40);
        assert_eq!(c.longest_hold_start, 100);
        assert_eq!(c.longest_hold_end, 140);
    }

    /// An acquire never matched by a release is an unbounded hold — it invents no
    /// duration and produces no row (mirrors trailing-state handling in #65).
    #[test]
    fn test_critical_section_unreleased_contributes_nothing() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x2222_0000u64;

        analyzer.feed_sync_event(hold_ev(100, 1, lock, SyncEventType::MutexLock));
        // no unlock

        let cs = analyzer.analyze_critical_sections();
        assert!(cs.is_empty(), "an unreleased lock has no completed hold: {:?}", cs);
    }

    /// A failed acquire (trylock WouldBlock) never held the lock, so a following
    /// stray unlock must not fabricate a hold interval or underflow the depth.
    #[test]
    fn test_critical_section_failed_acquire_not_held() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x3333_0000u64;

        let mut fail = hold_ev(100, 1, lock, SyncEventType::MutexTryLock);
        fail.result = SyncResult::WouldBlock;
        analyzer.feed_sync_event(fail);
        analyzer.feed_sync_event(hold_ev(110, 1, lock, SyncEventType::MutexUnlock)); // stray

        let cs = analyzer.analyze_critical_sections();
        assert!(cs.is_empty(), "a WouldBlock acquire never held the lock: {:?}", cs);
    }

    /// Two locks, each held once, must sort by aggregate hold time (longest-held
    /// first), tie-broken by address; a lock held by several threads lists them
    /// sorted regardless of feed order.
    #[test]
    fn test_critical_section_sort_and_multi_thread() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        let lock_short = 0x1000_0000u64; // low address, short hold
        let lock_long = 0x9000_0000u64;  // high address, long hold

        // lock_short: thread 2 holds 10 steps, then thread 1 holds 10 steps.
        analyzer.feed_sync_event(hold_ev(10, 2, lock_short, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(20, 2, lock_short, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(hold_ev(30, 1, lock_short, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(40, 1, lock_short, SyncEventType::MutexUnlock));
        // lock_long: thread 1 holds 100 steps.
        analyzer.feed_sync_event(hold_ev(0, 1, lock_long, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(100, 1, lock_long, SyncEventType::MutexUnlock));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 2);
        // Longest aggregate hold first: lock_long (100) before lock_short (20).
        assert_eq!(cs[0].lock_address.addr, lock_long);
        assert_eq!(cs[0].total_hold_steps, 100);
        assert_eq!(cs[1].lock_address.addr, lock_short);
        assert_eq!(cs[1].hold_count, 2);
        assert_eq!(cs[1].total_hold_steps, 20);
        assert_eq!(cs[1].avg_hold_steps, 10);
        // Both threads completed a hold; listed sorted despite thread 2 first.
        assert_eq!(cs[1].holder_threads, vec![1, 2]);
    }

    /// Acquire and release at the SAME step (steps come from `trace.seq` and are
    /// not unique) is still a completed hold — counted with a zero-step span,
    /// not dropped.
    #[test]
    fn test_critical_section_same_step_hold_counts() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x4444_0000u64;

        analyzer.feed_sync_event(hold_ev(50, 1, lock, SyncEventType::MutexLock));
        analyzer.feed_sync_event(hold_ev(50, 1, lock, SyncEventType::MutexUnlock));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].hold_count, 1, "same-step acquire/release is a real completed hold");
        assert_eq!(cs[0].total_hold_steps, 0);
    }

    /// A single acquisition that both waited AND timed out is one contended
    /// attempt, not two. It must count once so `contention_count` never exceeds
    /// `acquire_count` and the ratio stays within [0, 1].
    #[test]
    fn test_contention_waited_and_timeout_counts_once() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));

        let lock = 0xCAFE_0000u64;
        // One timed lock: it waited 3ms then timed out (both contention signals).
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock,
            result: SyncResult::Timeout,
            wait_duration_ns: Some(3_000_000),
        });

        let contentions = analyzer.analyze_lock_contention();
        let info = contentions.iter().find(|c| c.lock_address.addr == lock).unwrap();
        assert_eq!(info.acquire_count, 1);
        assert_eq!(info.contention_count, 1, "waited+timeout must count once, not twice");
        assert!(info.contention_ratio <= 1.0, "ratio must stay within [0,1]: {}", info.contention_ratio);
        assert_eq!(info.max_wait_ns, 3_000_000);
        assert_eq!(info.avg_wait_ns, 3_000_000);
    }

    /// Two sync events at the SAME step (different threads/locks) must both be
    /// retained. The old `BTreeMap<step, event>` silently overwrote one, so the
    /// lock whose event was dropped got another lock's wait/result attributed
    /// to it. With the multimap each acquisition matches its own event.
    #[test]
    fn test_sync_events_same_step_not_overwritten() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let lock_a = 0xAAAA_0000u64;
        let lock_b = 0xBBBB_0000u64;
        // Both acquisitions happen at step 100. Thread 1 waited on lock_a
        // (contended); thread 2 took lock_b with no wait (uncontended). Feed the
        // uncontended one LAST so the old map would have kept it and dropped the
        // contended one — mis-reporting lock_a as uncontended.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_a,
            result: SyncResult::Success,
            wait_duration_ns: Some(5_000_000),
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_b,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        let contentions = analyzer.analyze_lock_contention();
        let a = contentions.iter().find(|c| c.lock_address.addr == lock_a).unwrap();
        let b = contentions.iter().find(|c| c.lock_address.addr == lock_b).unwrap();
        // lock_a keeps its own 5ms wait → contended; lock_b stays uncontended.
        assert_eq!(a.acquire_count, 1);
        assert_eq!(a.contention_count, 1, "lock_a's own wait must not be lost to a same-step event");
        assert_eq!(a.max_wait_ns, 5_000_000);
        assert_eq!(b.acquire_count, 1);
        assert_eq!(b.contention_count, 0, "lock_b was never contended");
    }

    #[test]
    fn test_thread_function_association() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 calls function at 0x4000 three times
        analyzer.feed_call_event(100, 1, 0x4000);
        analyzer.feed_call_event(200, 1, 0x4000);
        analyzer.feed_call_event(300, 1, 0x4000);

        // Thread 2 calls function at 0x4000 once
        analyzer.feed_call_event(150, 2, 0x4000);

        // Thread 2 calls function at 0x5000 twice
        analyzer.feed_call_event(250, 2, 0x5000);
        analyzer.feed_call_event(350, 2, 0x5000);

        let assocs = analyzer.analyze_thread_function_assoc();

        // Thread 1 → 0x4000: 3 calls
        let assoc_1_4000 = assocs.iter()
            .find(|a| a.thread_id == 1 && a.function_address == 0x4000)
            .unwrap();
        assert_eq!(assoc_1_4000.call_count, 3);

        // Thread 2 → 0x4000: 1 call
        let assoc_2_4000 = assocs.iter()
            .find(|a| a.thread_id == 2 && a.function_address == 0x4000)
            .unwrap();
        assert_eq!(assoc_2_4000.call_count, 1);

        // Thread 2 → 0x5000: 2 calls
        let assoc_2_5000 = assocs.iter()
            .find(|a| a.thread_id == 2 && a.function_address == 0x5000)
            .unwrap();
        assert_eq!(assoc_2_5000.call_count, 2);

        // First/last call steps come from the range index
        assert_eq!(assoc_1_4000.first_call_step, 100);
        assert_eq!(assoc_1_4000.last_call_step, 300);
        assert_eq!(assoc_2_5000.first_call_step, 250);
        assert_eq!(assoc_2_5000.last_call_step, 350);
    }

    /// Thread-function rows with equal call counts must be ordered
    /// deterministically by (thread_id, function_address), not by
    /// `thread_functions` HashMap iteration order.
    #[test]
    fn test_thread_function_assoc_deterministic_order() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));

        // Two functions, each called exactly twice by thread 1 (equal counts).
        analyzer.feed_call_event(100, 1, 0x5000);
        analyzer.feed_call_event(200, 1, 0x5000);
        analyzer.feed_call_event(300, 1, 0x4000);
        analyzer.feed_call_event(400, 1, 0x4000);

        let assocs = analyzer.analyze_thread_function_assoc();
        // Both have call_count 2 → ascending (thread, address): 0x4000 then 0x5000.
        let addrs: Vec<u64> = assocs.iter().map(|a| a.function_address).collect();
        assert_eq!(addrs, vec![0x4000, 0x5000]);
    }

    /// `calling_threads` on a thread-safety row must be sorted regardless of the
    /// order the calls were fed.
    #[test]
    fn test_function_safety_calling_threads_sorted() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_thread_info(make_thread_info(3, "thread-3"));

        // Function 0x4000 called by threads 3, 1, 2 in that (unsorted) feed order.
        analyzer.feed_call_event(100, 3, 0x4000);
        analyzer.feed_call_event(200, 1, 0x4000);
        analyzer.feed_call_event(300, 2, 0x4000);

        let safety = analyzer.classify_function_thread_safety();
        let func = safety.iter().find(|f| f.function_address == 0x4000).unwrap();
        assert_eq!(func.calling_threads, vec![1, 2, 3], "calling threads must be sorted");
    }

    #[test]
    fn test_function_assoc_first_last_step_out_of_order() {
        // Call events fed out of step order: the range index must report the
        // true min/max step, not the first/last insertion order.
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));

        analyzer.feed_call_event(300, 1, 0x4000);
        analyzer.feed_call_event(100, 1, 0x4000);
        analyzer.feed_call_event(500, 1, 0x4000);
        analyzer.feed_call_event(200, 1, 0x4000);

        let assocs = analyzer.analyze_thread_function_assoc();
        let a = assocs.iter()
            .find(|a| a.thread_id == 1 && a.function_address == 0x4000)
            .unwrap();
        assert_eq!(a.call_count, 4);
        assert_eq!(a.first_call_step, 100, "first must be min step, not first fed");
        assert_eq!(a.last_call_step, 500, "last must be max step, not last fed");
    }

    #[test]
    fn test_function_assoc_stable_across_repeated_calls() {
        // Repeated analysis must be idempotent (index guarded by indexes_built).
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(7, "worker"));
        analyzer.feed_call_event(10, 7, 0xA000);
        analyzer.feed_call_event(40, 7, 0xA000);

        let first = analyzer.analyze_thread_function_assoc();
        let second = analyzer.analyze_thread_function_assoc();
        assert_eq!(first.len(), second.len());
        let f = first.iter().find(|a| a.function_address == 0xA000).unwrap();
        let s = second.iter().find(|a| a.function_address == 0xA000).unwrap();
        assert_eq!(f.call_count, s.call_count);
        assert_eq!((f.first_call_step, f.last_call_step), (s.first_call_step, s.last_call_step));
        assert_eq!((f.first_call_step, f.last_call_step), (10, 40));
    }

    #[test]
    fn test_active_function_attribution_out_of_order() {
        // A sync event must be attributed to the function active at its step,
        // determined by the highest call step <= the sync step — NOT by call
        // insertion order. Both funcs are called at steps below the sync step,
        // so binary search (not `.last()` on insertion order) is required.
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1: 0x2000 @ 80 is the active one at step 100, but it is fed
        // BEFORE 0x1000 @ 50 so insertion order would mis-pick 0x1000.
        analyzer.feed_call_event(80, 1, 0x2000);
        analyzer.feed_call_event(50, 1, 0x1000);
        // Thread 2: same two functions so both are called by 2 threads.
        analyzer.feed_call_event(80, 2, 0x2000);
        analyzer.feed_call_event(50, 2, 0x1000);

        // Sync events at step 100 on each thread → active function is 0x2000.
        for tid in [1u32, 2u32] {
            analyzer.feed_sync_event(ThreadSyncEvent {
                step: 100, thread_id: tid,
                sync_type: SyncEventType::MutexLock,
                sync_object_addr: 0xCAFE0000,
                result: SyncResult::Success,
                wait_duration_ns: None,
            });
        }

        let safety = analyzer.classify_function_thread_safety();
        let s2000 = safety.iter().find(|s| s.function_address == 0x2000).unwrap();
        let s1000 = safety.iter().find(|s| s.function_address == 0x1000).unwrap();
        // Sync attributed to 0x2000 → thread-safe; 0x1000 saw no sync.
        assert_eq!(s2000.safety, ThreadSafety::ThreadSafe,
            "sync must attribute to 0x2000 (active at step 100)");
        assert_eq!(s1000.safety, ThreadSafety::PotentiallyUnsafe,
            "0x1000 was not active at the sync step");
    }

    #[test]
    fn test_function_thread_safety_classification() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Function 0x4000 called by both threads (potentially unsafe)
        analyzer.feed_call_event(100, 1, 0x4000);
        analyzer.feed_call_event(200, 2, 0x4000);

        // Function 0x5000 called by both threads WITH sync (thread-safe)
        analyzer.feed_call_event(100, 1, 0x5000);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 110, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_call_event(200, 2, 0x5000);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 210, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Function 0x6000 called by only thread 1 (unknown)
        analyzer.feed_call_event(100, 1, 0x6000);

        let safety = analyzer.classify_function_thread_safety();

        let func_4000 = safety.iter().find(|f| f.function_address == 0x4000).unwrap();
        assert_eq!(func_4000.safety, ThreadSafety::PotentiallyUnsafe);

        let func_5000 = safety.iter().find(|f| f.function_address == 0x5000).unwrap();
        assert_eq!(func_5000.safety, ThreadSafety::ThreadSafe);

        let func_6000 = safety.iter().find(|f| f.function_address == 0x6000).unwrap();
        assert_eq!(func_6000.safety, ThreadSafety::Unknown);
    }
