    use super::*;
    use sotrace_core::models::thread::{ThreadInfo, SyncResult};

    fn make_thread_info(thread_id: u32, name: &str) -> ThreadInfo {
        ThreadInfo {
            thread_id,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: Some(name.to_string()),
            stack_base: 0x7F000000,
            stack_size: 8 * 1024 * 1024,
            tls_addr: 0,
            is_jni_attached: false,
        }
    }

    #[test]
    fn test_race_condition_detection() {
        let mut analyzer = ThreadAnalyzer::new();

        // Register threads
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes to address 0x1000 at step 100
        analyzer.feed_memory_write(100, 1, 0x1000, 4);

        // Thread 2 reads from address 0x1000 at step 200 (NO sync!)
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        assert_eq!(races[0].first_thread, 1);
        assert_eq!(races[0].second_thread, 2);
        assert_eq!(races[0].address, 0x1000);
        assert!(races[0].first_is_write);
        assert!(!races[0].second_is_write);
        // #112: access sizes and precise conflict range are now reported
        assert_eq!(races[0].first_access_size, 4);
        assert_eq!(races[0].second_access_size, 4);
        assert_eq!(races[0].overlap_address, 0x1000);
        assert_eq!(races[0].overlap_size, 4);
    }

    /// #112: when two accesses only partially overlap, the conflict range must
    /// be the *intersection*, not either access's full span. Thread 1 writes 8
    /// bytes at 0x5000 (0x5000-0x5007), thread 2 reads 8 bytes at 0x5004
    /// (0x5004-0x500B) — the real conflict is 0x5004-0x5007 (4 bytes).
    #[test]
    fn test_race_partial_overlap_conflict_range() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, 0x5000, 8);
        analyzer.feed_memory_read(200, 2, 0x5004, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert_eq!(r.first_access_size, 8);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x5004);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: write-write race also reports per-access sizes and the overlap.
    #[test]
    fn test_write_write_race_reports_access_sizes() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, 0x6000, 4);
        analyzer.feed_memory_write(200, 2, 0x6000, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert!(r.first_is_write && r.second_is_write);
        assert_eq!(r.first_access_size, 4);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x6000);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: read-then-write race reports the read's real address as first
    /// access size source, not the write's page-aligned address.
    #[test]
    fn test_read_then_write_race_reports_access_sizes() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_read(100, 1, 0x7004, 8);
        analyzer.feed_memory_write(200, 2, 0x7000, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert!(!r.first_is_write && r.second_is_write);
        assert_eq!(r.first_access_size, 8);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x7004);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: accesses near `u64::MAX` must not overflow when computing the
    /// overlap range (saturating arithmetic, mirroring `reads_overlapping`).
    /// With saturating end-points, an 8-byte write at `MAX-7` and an 8-byte
    /// read at `MAX-3` both have their end clamped to `MAX`, so the contended
    /// region is `[MAX-3, MAX)` = 3 bytes. The point of this test is that the
    /// computation does not panic/overflow, not the exact count.
    #[test]
    fn test_race_overlap_no_overflow_near_u64_max() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, u64::MAX - 7, 8);
        analyzer.feed_memory_read(200, 2, u64::MAX - 3, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert_eq!(r.overlap_address, u64::MAX - 3);
        // Saturating end clamps both ranges to MAX, so overlap is 3 bytes.
        assert_eq!(r.overlap_size, 3);
    }

    #[test]
    fn test_no_race_with_sync() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes to address 0x2000 at step 100
        analyzer.feed_memory_write(100, 1, 0x2000, 4);

        // Thread 1 releases mutex at step 150
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Thread 2 acquires same mutex at step 160
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 160, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });

        // Thread 2 reads from address 0x2000 at step 200
        analyzer.feed_memory_read(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        // Should detect no race because there is synchronization
        // (both threads touched the same mutex between write and read)
        assert!(races.is_empty() || races.iter().all(|r| r.address != 0x2000));
    }

    /// A `MutexLocked` event (frida emits it for a *successful* acquire, as
    /// opposed to `MutexLock` which is the attempt) is just as strong a sync
    /// signal as `MutexLock` — it proves the thread holds the lock. `has_sync_between`
    /// only recognizes a sync pair when at least one side is `is_acquire() ||
    /// is_release()`; `MutexLocked` is neither, so two threads that BOTH record
    /// only `MutexLocked` (no unlock, no attempt) on the same lock are treated as
    /// unsynchronized — a false race. This covers the frida path that stamps
    /// successful acquires as `MutexLocked` and nothing else.
    #[test]
    fn test_no_race_when_both_threads_only_emit_mutex_locked() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes to address 0x2000 at step 100.
        analyzer.feed_memory_write(100, 1, 0x2000, 4);

        // Thread 1 holds the mutex (MutexLocked) at step 150.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexLocked,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Thread 2 also acquires the SAME mutex (MutexLocked) at 160 — serialized.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 160, thread_id: 2,
            sync_type: SyncEventType::MutexLocked,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });

        // Thread 2 reads from address 0x2000 at step 200.
        analyzer.feed_memory_read(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(
            races.iter().all(|r| r.address != 0x2000),
            "MutexLocked is a real acquire — the write/read pair is serialized; got race: {races:?}"
        );
    }

    /// Two INDEPENDENT races between the same pair of threads on the same
    /// address — at different steps — must both be reported. The dedup key
    /// used to be `(address, first_thread, second_thread)`, which collapsed the
    /// second race onto the first and silently dropped it. For reverse
    /// engineering, repeated races on one address (e.g. a racy loop) are a
    /// strong signal, so losing the repetition loses real information.
    #[test]
    fn test_repeated_race_same_threads_address_not_deduped() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // First race: T1 writes 0x1000 @ step 100, T2 reads @ step 200.
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        // Second independent race, much later, same address + thread pair,
        // no synchronization in between.
        analyzer.feed_memory_write(500, 1, 0x1000, 4);
        analyzer.feed_memory_read(530, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        // Both (first_step, second_step) pairs must survive dedup.
        let pairs: Vec<(u64, u64)> = races
            .iter()
            .map(|r| (r.first_step, r.second_step))
            .collect();
        assert!(
            pairs.contains(&(100, 200)),
            "first race (100, 200) must be reported, got {pairs:?}"
        );
        assert!(
            pairs.contains(&(500, 530)),
            "second race (500, 530) must be reported, got {pairs:?}"
        );
    }

    #[test]
    fn test_deadlock_detection() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let lock_m1 = 0xABCD0000;
        let lock_m2 = 0xEF010000;

        // Thread 1: lock(M1) → lock(M2) (order: M1 → M2)
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_m1,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 200, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_m2,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Thread 2: lock(M2) → lock(M1) (order: M2 → M1) — VIOLATION!
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_m2,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 250, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock_m1,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        let deadlocks = analyzer.detect_deadlocks();
        // Should detect a cycle in the lock graph
        assert!(!deadlocks.is_empty());
    }

    /// Deadlock detection must be invariant to the order sync events are fed.
    /// `lock_order` (per-thread acquisition sequence) and `lock_events` (folded
    /// by `is_lock_held_at`) are step-sorted in `build_indexes`, so a scrambled
    /// feed of the same A→B / B→A deadlock is still detected.
    #[test]
    fn test_deadlock_detection_out_of_order_feed() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // Intended step order: T1 A@10 then B@20; T2 B@15 then A@25 (A→B / B→A
        // cycle). Feed them badly scrambled — later steps first, threads mixed.
        analyzer.feed_sync_event(lock(25, 2, a));
        analyzer.feed_sync_event(lock(20, 1, b));
        analyzer.feed_sync_event(lock(15, 2, b));
        analyzer.feed_sync_event(lock(10, 1, a));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(!deadlocks.is_empty(), "scrambled feed of a real deadlock must still be detected");
    }

    /// A `MutexLocked` event (frida's "successful acquire") must count as holding
    /// the lock just like `MutexLock`. The acquire match in `lock_order`,
    /// `is_lock_held_at`, and `analyze_critical_sections` used to list only
    /// `MutexLock | MutexTryLock | RwLockRead | RwLockWrite`, so a trace that
    /// stamps successful acquires as `MutexLocked` (and nothing else) built no
    /// lock-hold state — the ABBA cycle below was MISSED. This mirrors the frida
    /// adapter path that maps `"mutexlocked"` to `SyncEventType::MutexLocked`.
    #[test]
    fn test_deadlock_detected_with_mutex_locked_acquires() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLocked,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // T1: hold A@10, then acquire B@20 while still holding A → A→B edge.
        analyzer.feed_sync_event(lock(10, 1, a));
        analyzer.feed_sync_event(lock(20, 1, b));
        // T2: hold B@15, then acquire A@25 while still holding B → B→A edge.
        analyzer.feed_sync_event(lock(15, 2, b));
        analyzer.feed_sync_event(lock(25, 2, a));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            !deadlocks.is_empty(),
            "MutexLocked acquires form a real ABBA cycle; got deadlocks: {deadlocks:?}"
        );
    }

    /// A thread that releases a lock before taking the next one has no nested
    /// hold, so no deadlock edge — even when the release is fed BEFORE the
    /// acquire it follows in step time. Guards against `is_lock_held_at` folding
    /// events in feed order (which would report the lock still held).
    #[test]
    fn test_no_false_deadlock_when_lock_released_out_of_order() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: lock A@10, UNLOCK A@15, lock B@20  → A not held when B taken.
        // T2: lock B@12, UNLOCK B@18, lock A@25  → B not held when A taken.
        // No nested holds → no cycle. Feed each thread's unlock BEFORE its lock.
        analyzer.feed_sync_event(ev(15, 1, a, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(18, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(12, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(25, 2, a, SyncEventType::MutexLock));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(deadlocks.is_empty(), "released locks must not fabricate a deadlock: {:?}", deadlocks);
    }

    /// A *failed* re-acquire must not count as holding the lock. T2 releases B,
    /// then a later trylock-B returns WouldBlock (it did NOT take B) before it
    /// acquires A. If `is_lock_held_at` treated that failed trylock as "held",
    /// it would fabricate a B→A edge and, with T1's A→B, a phantom ABBA cycle.
    #[test]
    fn test_no_false_deadlock_from_failed_reacquire() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType, res: SyncResult| {
            ThreadSyncEvent {
                step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
                result: res, wait_duration_ns: None,
            }
        };
        // T1: lock A@10, lock B@20 (holds both → real A→B edge).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock, SyncResult::Success));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock, SyncResult::Success));
        // T2: lock B@30 (success), UNLOCK B@35, trylock B@40 WouldBlock (FAILED —
        // does not hold B), then lock A@50. B is not held when A is taken, so
        // there must be NO B→A edge and NO cycle.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock, SyncResult::Success));
        analyzer.feed_sync_event(ev(35, 2, b, SyncEventType::MutexUnlock, SyncResult::Success));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexTryLock, SyncResult::WouldBlock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock, SyncResult::Success));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(deadlocks.is_empty(), "a failed trylock must not be treated as held: {:?}", deadlocks);
    }
