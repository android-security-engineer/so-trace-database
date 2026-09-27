
    /// ABBA with SemWait acquires: T1 holds A then takes B, T2 holds B then
    /// takes A. Before #109 `is_lock_held_at` did not recognize SemWait, so
    /// `a_still_held` was false and the deadlock edge was dropped (missed
    /// deadlock). Now it must be reported.
    #[test]
    fn test_deadlock_detected_with_sem_wait_acquires() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        // T1: SemWait A@10, SemWait B@20 (real A→B).
        analyzer.feed_sync_event(hold_ev(10, 1, a, SyncEventType::SemWait));
        analyzer.feed_sync_event(hold_ev(20, 1, b, SyncEventType::SemWait));
        // T2: SemWait B@15, SemWait A@25 (real B→A).
        analyzer.feed_sync_event(hold_ev(15, 2, b, SyncEventType::SemWait));
        analyzer.feed_sync_event(hold_ev(25, 2, a, SyncEventType::SemWait));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            deadlocks.iter().any(|d| d.lock_cycle.iter().any(|m| m.addr == a) && d.lock_cycle.iter().any(|m| m.addr == b)),
            "semaphore-backed ABBA must be detected: {:?}",
            deadlocks
        );
        // #111: the cycle's locks are typed — a semaphore-backed deadlock must
        // report kind: Semaphore on every cycle entry, not bare addresses.
        let sem_cycle = deadlocks.iter()
            .find(|d| d.lock_cycle.iter().any(|m| m.addr == a) && d.lock_cycle.iter().any(|m| m.addr == b))
            .unwrap();
        assert!(sem_cycle.lock_cycle.iter().all(|m| m.kind == SyncPrimitiveKind::Semaphore));
    }

    /// Same ABBA as above but using FutexWait — bionic pthread_mutex/condvar
    /// and Java monitors are futex-backed, so this is the common path. Before
    /// #109 the deadlock was missed (FutexWait not in the acquire arm).
    #[test]
    fn test_deadlock_detected_with_futex_wait_acquires() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        analyzer.feed_sync_event(hold_ev(10, 1, a, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(20, 1, b, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(15, 2, b, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(25, 2, a, SyncEventType::FutexWait));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            deadlocks.iter().any(|d| d.lock_cycle.iter().any(|m| m.addr == a) && d.lock_cycle.iter().any(|m| m.addr == b)),
            "futex-backed ABBA must be detected: {:?}",
            deadlocks
        );
        // #111: the cycle's locks are typed — a futex-backed deadlock must
        // report kind: Futex on every cycle entry.
        let futex_cycle = deadlocks.iter()
            .find(|d| d.lock_cycle.iter().any(|m| m.addr == a) && d.lock_cycle.iter().any(|m| m.addr == b))
            .unwrap();
        assert!(futex_cycle.lock_cycle.iter().all(|m| m.kind == SyncPrimitiveKind::Futex));
    }

    /// A semaphore acquire followed by its post must drop the hold depth back
    /// to zero. Before #109 SemPost was not in the release arm, so depth only
    /// ever increased (permanent hold → false deadlocks downstream).
    #[test]
    fn test_semaphore_held_depth_decrements_on_sem_post() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x5E80_0000u64;

        analyzer.feed_sync_event(hold_ev(10, 1, lock, SyncEventType::SemWait));
        analyzer.feed_sync_event(hold_ev(20, 1, lock, SyncEventType::SemPost));

        analyzer.build_indexes();
        assert!(
            !analyzer.is_lock_held_at(1, lock, 20),
            "SemPost must release the hold acquired by SemWait"
        );
    }

    /// Same depth-decrement contract for futex: FutexWake (single-waiter wake)
    /// must drop the depth taken by FutexWait.
    #[test]
    fn test_futex_held_depth_decrements_on_futex_wake() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xF071_0000u64;

        analyzer.feed_sync_event(hold_ev(10, 1, lock, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(20, 1, lock, SyncEventType::FutexWake));

        analyzer.build_indexes();
        assert!(
            !analyzer.is_lock_held_at(1, lock, 20),
            "FutexWake must release the hold acquired by FutexWait"
        );
    }

    /// Critical-section stats must reflect a semaphore hold: one interval from
    /// SemWait to SemPost, span = 40 steps. Before #109 SemWait/SemPost were
    /// absent from both arms → no interval recorded.
    #[test]
    fn test_critical_sections_counts_semaphore_hold() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0x5E80_0000u64;

        analyzer.feed_sync_event(hold_ev(10, 1, lock, SyncEventType::SemWait));
        analyzer.feed_sync_event(hold_ev(50, 1, lock, SyncEventType::SemPost));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c.lock_address.addr, lock);
        assert_eq!(c.hold_count, 1);
        assert_eq!(c.max_hold_steps, 40);
        assert_eq!(c.longest_hold_start, 10);
        assert_eq!(c.longest_hold_end, 50);
        assert_eq!(c.holder_threads, vec![1]);
    }

    /// Same critical-section contract for a futex-backed hold.
    #[test]
    fn test_critical_sections_counts_futex_hold() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xF071_0000u64;

        analyzer.feed_sync_event(hold_ev(10, 1, lock, SyncEventType::FutexWait));
        analyzer.feed_sync_event(hold_ev(50, 1, lock, SyncEventType::FutexWake));

        let cs = analyzer.analyze_critical_sections();
        assert_eq!(cs.len(), 1);
        let c = &cs[0];
        assert_eq!(c.lock_address.addr, lock);
        assert_eq!(c.hold_count, 1);
        assert_eq!(c.max_hold_steps, 40);
        assert_eq!(c.holder_threads, vec![1]);
    }

    /// A contended futex acquire (Success with a non-zero wait) must be counted
    /// as both an acquire and a contention. Before #109 FutexWait was not in
    /// the contention acquire arm → acquire_count == 0 (missed contention).
    #[test]
    fn test_contention_counts_futex_wait() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xF071_0000u64;

        // FutexWait that succeeded after waiting 5µs.
        analyzer.feed_sync_event(sync_ev(
            10, 1, lock, SyncEventType::FutexWait, SyncResult::Success, Some(5_000),
        ));

        let contention = analyzer.analyze_lock_contention();
        assert_eq!(contention.len(), 1);
        let ci = &contention[0];
        assert_eq!(ci.lock_address.addr, lock);
        assert_eq!(ci.acquire_count, 1);
        assert_eq!(ci.contention_count, 1);
    }

    /// Two threads meeting at a barrier in opposite order must NOT be reported
    /// as a lock-ordering deadlock. A barrier is a rendezvous, not a held lock:
    /// there is no per-thread hold and no paired release. Direction A (treat
    /// BarrierWait as a holdable acquire) would fabricate ever-increasing depth
    /// and report a false ABBA cycle here — this test guards against that
    /// regression.
    #[test]
    fn test_no_false_deadlock_from_barrier_wait() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let b1 = 0xBA11_0000u64;
        let b2 = 0xBA22_0000u64;
        // T1 "acquires" b1 then b2 (both BarrierWait).
        analyzer.feed_sync_event(hold_ev(10, 1, b1, SyncEventType::BarrierWait));
        analyzer.feed_sync_event(hold_ev(20, 1, b2, SyncEventType::BarrierWait));
        // T2 "acquires" b2 then b1 — opposite order.
        analyzer.feed_sync_event(hold_ev(15, 2, b2, SyncEventType::BarrierWait));
        analyzer.feed_sync_event(hold_ev(25, 2, b1, SyncEventType::BarrierWait));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            deadlocks.is_empty(),
            "barrier rendezvous must not fabricate a deadlock: {:?}",
            deadlocks
        );
    }

    /// Two threads crossing on a condvar must NOT be reported as a deadlock.
    /// CondvarWait releases its associated mutex before waiting — it is a sync
    /// signal, not a holdable acquire.
    #[test]
    fn test_no_false_deadlock_from_condvar_wait() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let c1 = 0xCD11_0000u64;
        let c2 = 0xCD22_0000u64;
        analyzer.feed_sync_event(hold_ev(10, 1, c1, SyncEventType::CondvarWait));
        analyzer.feed_sync_event(hold_ev(20, 1, c2, SyncEventType::CondvarWait));
        analyzer.feed_sync_event(hold_ev(15, 2, c2, SyncEventType::CondvarWait));
        analyzer.feed_sync_event(hold_ev(25, 2, c1, SyncEventType::CondvarWait));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(
            deadlocks.is_empty(),
            "condvar wait must not fabricate a deadlock: {:?}",
            deadlocks
        );
    }

    /// CondvarSignal on the writing thread plus CondvarWait on the reading
    /// thread establishes a happens-before edge: the read after the wait must
    /// NOT race with the write before the signal. `has_sync_between` recognizes
    /// the pair via `is_sync_signal()` (CondvarSignal/CondvarWait) — this is
    /// the race-suppression side of the three-way split.
    #[test]
    fn test_condvar_signal_suppresses_race() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let cv = 0xCD00_0000u64;
        // T1 writes, then signals the condvar.
        analyzer.feed_memory_write(100, 1, 0x2000, 4);
        analyzer.feed_sync_event(hold_ev(150, 1, cv, SyncEventType::CondvarSignal));
        // T2 waits on the condvar (released by the signal), then reads.
        analyzer.feed_sync_event(hold_ev(160, 2, cv, SyncEventType::CondvarWait));
        analyzer.feed_memory_read(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(
            races.is_empty() || races.iter().all(|r| r.address != 0x2000),
            "condvar signal→wait must suppress the write/read race: {:?}",
            races
        );
    }

    /// A futex wait that timed out never held the lock — the `result` guard in
    /// `is_lock_held_at` must keep depth at zero for a Timeout result.
    #[test]
    fn test_futex_wait_timeout_not_held() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        let lock = 0xF071_0000u64;

        analyzer.feed_sync_event(sync_ev(
            10, 1, lock, SyncEventType::FutexWait, SyncResult::Timeout, Some(1_000_000),
        ));

        analyzer.build_indexes();
        assert!(
            !analyzer.is_lock_held_at(1, lock, 10),
            "a timed-out FutexWait must not be treated as a held lock"
        );
    }
