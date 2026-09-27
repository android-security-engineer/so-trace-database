
    /// #117: core_residency accumulates per-core step spans. A thread run-in
    /// on core 0 closed after 20 steps, then run-in on core 1 closed after 60
    /// steps — the residency map carries both cores with their sums.
    #[test]
    fn test_scheduling_core_residency_accumulates_per_core() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));
        // @10: T1 preempted off (no prior run-in to close), T2 on core 0.
        analyzer.feed_context_switch(make_switch(10, 1, 2, SwitchReason::Preemption, Some(0)));
        // @30: T2 preempted off -> closes T2's core-0 run-in (20 steps), T1 on core 1.
        analyzer.feed_context_switch(make_switch(30, 2, 1, SwitchReason::Preemption, Some(1)));
        // @100: T1 preempted off -> closes T1's core-1 run-in (70 steps), T2 on core 0.
        analyzer.feed_context_switch(make_switch(100, 1, 2, SwitchReason::Preemption, Some(0)));

        let stats = analyzer.analyze_scheduling();
        let t1 = stats.iter().find(|s| s.thread_id == 1).unwrap();
        let t2 = stats.iter().find(|s| s.thread_id == 2).unwrap();
        // T1: core-1 run-in @30..100 = 70 steps. (Its tail on core 0 after @100
        // is unbounded — no following switch — and contributes 0.)
        assert_eq!(t1.core_residency, vec![(1, 70)], "T1 ran 70 steps on core 1");
        // T2: core-0 run-in @10..30 = 20 steps. (Its tail on core 0 after @100 is
        // unbounded and contributes 0.)
        assert_eq!(t2.core_residency, vec![(0, 20)], "T2 ran 20 steps on core 0");
    }

    /// #117: a switch with `cpu_core == None` must not fabricate residency and
    /// must clear any stale run-in so a later close doesn't attribute span to
    /// the wrong core.
    #[test]
    fn test_scheduling_unknown_core_does_not_fabricate_residency() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));
        analyzer.feed_thread_info(make_thread_info(3, "t3"));
        // @10: T1 off, T2 on core 0.
        analyzer.feed_context_switch(make_switch(10, 1, 2, SwitchReason::Preemption, Some(0)));
        // @25: T2 off (no core info on the *incoming* T3) — T2's core-0 run-in
        // closes at 25 (15 steps). T3's run-in has no core -> not tracked.
        analyzer.feed_context_switch(make_switch(25, 2, 3, SwitchReason::Preemption, None));
        // @50: T3 off, T1 on core 1 — T3 had no tracked run-in, so nothing is
        // attributed to it. T1's tail on core 1 is unbounded.
        analyzer.feed_context_switch(make_switch(50, 3, 1, SwitchReason::Preemption, Some(1)));

        let stats = analyzer.analyze_scheduling();
        let t2 = stats.iter().find(|s| s.thread_id == 2).unwrap();
        let t3 = stats.iter().find(|s| s.thread_id == 3).unwrap();
        // T2's core-0 interval @10..25 = 15 steps survived the None-core switch.
        assert_eq!(t2.core_residency, vec![(0, 15)]);
        // T3 was scheduled in with an unknown core and out again with no
        // tracked run-in: no residency fabricated.
        assert!(t3.core_residency.is_empty(),
            "unknown-core run-in must not fabricate residency, got {:?}", t3.core_residency);
    }

    /// Build a thread info with an explicit parent and lifespan for lifecycle tests.
    fn make_lifecycle_info(
        thread_id: u32,
        parent: u32,
        create_step: u64,
        exit_step: Option<u64>,
    ) -> ThreadInfo {
        ThreadInfo {
            thread_id,
            pthread_id: None,
            parent_thread_id: parent,
            create_step,
            exit_step,
            name: Some(format!("t{thread_id}")),
            stack_base: 0x7F000000,
            stack_size: 8 * 1024 * 1024,
            tls_addr: 0,
            is_jni_attached: false,
        }
    }

    /// The spawn tree is reconstructed from `parent_thread_id`: each parent lists
    /// its children (sorted), and a child records its parent.
    #[test]
    fn test_lifecycle_spawn_tree_children() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, None)); // root
        analyzer.feed_thread_info(make_lifecycle_info(3, 1, 10, None)); // child of 1
        analyzer.feed_thread_info(make_lifecycle_info(2, 1, 5, None)); // child of 1

        let life = analyzer.analyze_thread_lifecycle();
        // Sorted by thread_id regardless of feed order.
        let ids: Vec<u32> = life.iter().map(|l| l.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);

        let root = &life[0];
        assert_eq!(root.thread_id, 1);
        assert_eq!(root.parent_thread_id, 0);
        // Children are sorted ascending.
        assert_eq!(root.child_thread_ids, vec![2, 3]);
        assert_eq!(root.tree_depth, 0);

        // Each child points back at parent 1 and has no children of its own.
        assert_eq!(life[1].parent_thread_id, 1);
        assert!(life[1].child_thread_ids.is_empty());
        assert_eq!(life[1].tree_depth, 1);
        assert_eq!(life[2].parent_thread_id, 1);
    }

    /// Lifespan and liveness derive from create/exit steps: an exited thread has
    /// `Some(exit - create)` and is not alive; a running thread has `None` and is
    /// alive.
    #[test]
    fn test_lifecycle_lifespan_and_liveness() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 100, Some(400))); // exited
        analyzer.feed_thread_info(make_lifecycle_info(2, 0, 50, None)); // still alive

        let life = analyzer.analyze_thread_lifecycle();
        let exited = life.iter().find(|l| l.thread_id == 1).unwrap();
        assert_eq!(exited.lifespan, Some(300));
        assert!(!exited.is_alive);
        assert_eq!(exited.exit_step, Some(400));

        let alive = life.iter().find(|l| l.thread_id == 2).unwrap();
        assert_eq!(alive.lifespan, None);
        assert!(alive.is_alive);
        assert_eq!(alive.exit_step, None);
    }

    /// Tree depth counts present ancestors: a three-level chain 1 → 2 → 3 yields
    /// depths 0, 1, 2.
    #[test]
    fn test_lifecycle_tree_depth_multilevel() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, None));
        analyzer.feed_thread_info(make_lifecycle_info(2, 1, 1, None));
        analyzer.feed_thread_info(make_lifecycle_info(3, 2, 2, None));

        let life = analyzer.analyze_thread_lifecycle();
        assert_eq!(life[0].tree_depth, 0); // thread 1, root
        assert_eq!(life[1].tree_depth, 1); // thread 2
        assert_eq!(life[2].tree_depth, 2); // thread 3
    }

    /// An orphan whose parent was never recorded is treated as a root (depth 0),
    /// and it is not attributed as anyone's child.
    #[test]
    fn test_lifecycle_unknown_parent_is_root() {
        let mut analyzer = ThreadAnalyzer::new();
        // Parent 99 is never fed.
        analyzer.feed_thread_info(make_lifecycle_info(5, 99, 0, None));

        let life = analyzer.analyze_thread_lifecycle();
        assert_eq!(life.len(), 1);
        assert_eq!(life[0].thread_id, 5);
        assert_eq!(life[0].parent_thread_id, 99); // recorded as-is
        assert_eq!(life[0].tree_depth, 0); // but treated as a root
        assert!(life[0].child_thread_ids.is_empty());
    }

    /// A malformed exit step before creation yields `None` lifespan (no underflow)
    /// rather than a wrapped huge span.
    #[test]
    fn test_lifecycle_malformed_exit_before_create() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 500, Some(200))); // exit < create

        let life = analyzer.analyze_thread_lifecycle();
        assert_eq!(life[0].lifespan, None);
        // Still marked not-alive because an exit step is present.
        assert!(!life[0].is_alive);
    }

    /// A parent cycle (1 → 2 → 1) does not hang: the `seen` guard terminates the
    /// depth walk.
    #[test]
    fn test_lifecycle_parent_cycle_guard() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 2, 0, None));
        analyzer.feed_thread_info(make_lifecycle_info(2, 1, 0, None));

        // Must terminate; depth is bounded by the number of threads.
        let life = analyzer.analyze_thread_lifecycle();
        assert_eq!(life.len(), 2);
        for l in &life {
            assert!(l.tree_depth <= 2);
        }
    }

    fn make_state_change(step: u64, thread_id: u32, new_state: ThreadState) -> ThreadStateChange {
        ThreadStateChange {
            step,
            thread_id,
            new_state,
            prev_state: None,
            prev_running_thread: None,
        }
    }

    /// State residency accumulates the interval between consecutive changes,
    /// attributing it to the earlier state; the final open interval is bounded by
    /// the thread's exit step.
    #[test]
    fn test_state_residency_across_transitions() {
        let mut analyzer = ThreadAnalyzer::new();
        // Thread 1 exits at step 100 so the final Running interval is bounded.
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, Some(100)));
        analyzer.feed_state_change(make_state_change(0, 1, ThreadState::Running));
        analyzer.feed_state_change(make_state_change(30, 1, ThreadState::WaitingForLock));
        analyzer.feed_state_change(make_state_change(50, 1, ThreadState::Running));

        let stats = analyzer.analyze_thread_states();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert_eq!(s.thread_id, 1);
        assert_eq!(s.transition_count, 3);
        // Running: 0→30 (30) + 50→100 (50) = 80; WaitingForLock: 30→50 (20).
        assert_eq!(s.running_steps, 80);
        assert_eq!(s.waiting_steps, 20);
        assert_eq!(s.total_measured_steps, 100);
        assert!((s.blocked_ratio - 0.2).abs() < 1e-9);
        assert_eq!(s.final_state, "Running");
        // time_in_state is sorted by state name.
        assert_eq!(
            s.time_in_state,
            vec![
                ("Running".to_string(), 80),
                ("WaitingForLock".to_string(), 20),
            ]
        );
    }

    /// Two threads changing state at the same step are both tracked (step is not
    /// unique — the per-step `Vec` must not overwrite).
    #[test]
    fn test_state_same_step_multi_thread() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, Some(20)));
        analyzer.feed_thread_info(make_lifecycle_info(2, 0, 0, Some(20)));
        // Both threads change at step 0 and again at step 10.
        analyzer.feed_state_change(make_state_change(0, 1, ThreadState::Running));
        analyzer.feed_state_change(make_state_change(0, 2, ThreadState::WaitingForIO));
        analyzer.feed_state_change(make_state_change(10, 1, ThreadState::Sleeping));
        analyzer.feed_state_change(make_state_change(10, 2, ThreadState::Running));

        let stats = analyzer.analyze_thread_states();
        assert_eq!(stats.len(), 2);
        // Thread 1: Running 0→10 (10), Sleeping 10→20 (10).
        let t1 = stats.iter().find(|s| s.thread_id == 1).unwrap();
        assert_eq!(t1.running_steps, 10);
        assert_eq!(t1.waiting_steps, 0);
        assert_eq!(t1.total_measured_steps, 20);
        // Thread 2: WaitingForIO 0→10 (10, waiting), Running 10→20 (10).
        let t2 = stats.iter().find(|s| s.thread_id == 2).unwrap();
        assert_eq!(t2.running_steps, 10);
        assert_eq!(t2.waiting_steps, 10);
        assert!((t2.blocked_ratio - 0.5).abs() < 1e-9);
    }

    /// A trailing state with no following change and no known exit step is
    /// unbounded, so it contributes zero measured time (we never invent duration).
    #[test]
    fn test_state_unbounded_trailing_contributes_nothing() {
        let mut analyzer = ThreadAnalyzer::new();
        // No exit step → the final interval is unbounded.
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, None));
        analyzer.feed_state_change(make_state_change(0, 1, ThreadState::Running));
        analyzer.feed_state_change(make_state_change(40, 1, ThreadState::WaitingForFutex));

        let stats = analyzer.analyze_thread_states();
        let s = &stats[0];
        // Only the bounded first interval (0→40) counts; the trailing wait is open.
        assert_eq!(s.running_steps, 40);
        assert_eq!(s.waiting_steps, 0);
        assert_eq!(s.total_measured_steps, 40);
        assert_eq!(s.transition_count, 2);
        assert_eq!(s.final_state, "WaitingForFutex");
    }

    /// A single state change yields zero measured steps (no interval to bound
    /// against) but still records the transition and final state.
    #[test]
    fn test_state_single_change_yields_zero_measured() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_lifecycle_info(1, 0, 0, None));
        analyzer.feed_state_change(make_state_change(5, 1, ThreadState::Blocked));

        let stats = analyzer.analyze_thread_states();
        let s = &stats[0];
        assert_eq!(s.transition_count, 1);
        assert_eq!(s.total_measured_steps, 0);
        assert_eq!(s.blocked_ratio, 0.0);
        assert!(s.time_in_state.is_empty());
        assert_eq!(s.final_state, "Blocked");
    }

    /// Output is sorted by thread_id regardless of feed order (determinism).
    #[test]
    fn test_state_stats_sorted_by_thread_id() {
        let mut analyzer = ThreadAnalyzer::new();
        for tid in [3u32, 1, 2] {
            analyzer.feed_thread_info(make_lifecycle_info(tid, 0, 0, Some(10)));
            analyzer.feed_state_change(make_state_change(0, tid, ThreadState::Running));
            analyzer.feed_state_change(make_state_change(10, tid, ThreadState::Terminated));
        }
        let stats = analyzer.analyze_thread_states();
        let ids: Vec<u32> = stats.iter().map(|s| s.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    /// `canonicalize_cycle` rotates any entry rotation of a directed cycle to
    /// start at its minimum element while preserving edge order.
    #[test]
    fn test_canonicalize_cycle_rotation() {
        assert_eq!(canonicalize_cycle(&[3, 1, 2]), vec![1, 2, 3]);
        assert_eq!(canonicalize_cycle(&[2, 3, 1]), vec![1, 2, 3]);
        assert_eq!(canonicalize_cycle(&[1, 2, 3]), vec![1, 2, 3]);
        // Edge order is preserved, not sorted: 1→3→2→1 stays 1,3,2.
        assert_eq!(canonicalize_cycle(&[3, 2, 1]), vec![1, 3, 2]);
        assert_eq!(canonicalize_cycle(&[5]), vec![5]);
        assert_eq!(canonicalize_cycle(&[]), Vec::<u64>::new());
    }

    #[test]
    fn test_lock_contention_analysis() {
        let mut analyzer = ThreadAnalyzer::new();

        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let mutex_addr = 0xABCD0000;

        // Thread 1 acquires mutex (no contention)
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        });

        // Thread 2 acquires same mutex (contended, 5ms wait)
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 200, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(5_000_000), // 5ms
        });

        let contentions = analyzer.analyze_lock_contention();
        assert!(!contentions.is_empty());

        let mutex_contention = contentions.iter()
            .find(|c| c.lock_address.addr == mutex_addr)
            .unwrap();
        assert_eq!(mutex_contention.acquire_count, 2);
        assert!(mutex_contention.contention_count >= 1);
    }

    /// `analyze_critical_sections` and `analyze_lock_contention` must count a
    /// `MutexLocked` (frida's successful acquire) the same as a `MutexLock`:
    /// the acquire match used to list only `MutexLock | MutexTryLock |
    /// RwLockRead | RwLockWrite`, so a `MutexLocked`+`MutexUnlock` pair opened
    /// no hold interval (critical-section stats missed it) and was not tallied
    /// as an acquisition (contention stats missed it).
    #[test]
    fn test_critical_section_and_contention_count_mutex_locked() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));

        let lock_addr = 0xDEAD0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1 acquires (MutexLocked) @10, releases @20 — a 10-step hold.
        analyzer.feed_sync_event(ev(10, 1, lock_addr, SyncEventType::MutexLocked));
        analyzer.feed_sync_event(ev(20, 1, lock_addr, SyncEventType::MutexUnlock));

        let cs = analyzer.analyze_critical_sections();
        let cs_lock = cs.iter().find(|c| c.lock_address.addr == lock_addr).unwrap();
        assert_eq!(cs_lock.hold_count, 1, "MutexLocked+Unlock is one hold interval");
        assert_eq!(cs_lock.max_hold_steps, 10);
        assert_eq!(cs_lock.holder_threads, vec![1]);

        let ct = analyzer.analyze_lock_contention();
        let ct_lock = ct.iter().find(|c| c.lock_address.addr == lock_addr).unwrap();
        assert_eq!(ct_lock.acquire_count, 1, "MutexLocked counts as an acquisition");
    }

    /// Locks with equal contention ratio must be ordered deterministically by
    /// address (not `lock_events` HashMap order), and each lock's
    /// `contending_threads` must be sorted regardless of the feed order.
    #[test]
    fn test_lock_contention_is_deterministic() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let lock_hi = 0xBBBB_0000u64;
        let lock_lo = 0x1111_0000u64;
        let contended = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: Some(1_000_000), // non-zero wait → contended
        };
        // Feed the high-address lock first so HashMap order would tend to place
        // it first; both locks end at contention_ratio == 1.0 (every acquire
        // contended). lock_lo is contended by thread 2 then thread 1.
        analyzer.feed_sync_event(contended(10, 1, lock_hi));
        analyzer.feed_sync_event(contended(20, 2, lock_lo));
        analyzer.feed_sync_event(contended(30, 1, lock_lo));

        let contentions = analyzer.analyze_lock_contention();
        assert_eq!(contentions.len(), 2);
        // Equal ratio (1.0 each) → ascending address order: lock_lo before lock_hi.
        assert_eq!(contentions[0].lock_address.addr, lock_lo);
        assert_eq!(contentions[1].lock_address.addr, lock_hi);
        // Threads that contended on lock_lo are sorted despite reverse feed.
        assert_eq!(contentions[0].contending_threads, vec![1, 2]);
    }

    // ------------------------------------------------------------------------
    // Critical-section / lock hold-time analysis (#66)
    // ------------------------------------------------------------------------

    /// Build a sync event for the hold-time tests. Successful by default; the
    /// hold-time analyzer only cares about type/step/thread/result.
    fn hold_ev(step: u64, tid: u32, addr: u64, ty: SyncEventType) -> ThreadSyncEvent {
        ThreadSyncEvent {
            step,
            thread_id: tid,
            sync_type: ty,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }
    }
