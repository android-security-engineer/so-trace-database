
    /// Control for the test above: with the SAME failed-trylock noise present,
    /// if T2 additionally holds B (successfully) while taking A, the B→A edge is
    /// real and the ABBA cycle must still be reported — the `result` guard must
    /// suppress only the failed acquire, not the genuine hold beside it.
    #[test]
    fn test_deadlock_detected_despite_failed_reacquire_noise() {
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
        // T1: lock A@10, lock B@20 (real A→B).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock, SyncResult::Success));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock, SyncResult::Success));
        // T2: lock B@30 (success, and NEVER released), a failed trylock-B@40
        // WouldBlock (noise — already holds B), then lock A@50. B is genuinely
        // held across A's acquire → real B→A edge → cycle. The failed trylock
        // neither adds nor removes the hold.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock, SyncResult::Success));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexTryLock, SyncResult::WouldBlock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock, SyncResult::Success));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "a genuine hold beside failed-trylock noise keeps the deadlock real: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
    }

    /// A thread that sequentially re-acquires the SAME lock (lock B, unlock B,
    /// lock B again) must NOT produce a single-lock self-loop "cycle". Lock
    /// ordering is only meaningful between distinct locks; the re-acquire's own
    /// event would otherwise make `is_lock_held_at` report B held at its own
    /// step, fabricating a B→B edge. Here T1 forms a real A→B edge and T2
    /// re-locks B around it — only the genuine [a, b] cycle may be reported, and
    /// no bogus [b] self-cycle alongside it.
    #[test]
    fn test_no_self_loop_cycle_from_lock_reacquire() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: lock A@10, lock B@20 (real A→B edge).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock));
        // T2: lock B@30, unlock B@35, lock B@40 (sequential re-acquire — a (B,B)
        // pair that must be dropped), then lock A@50 while holding B → real B→A.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(35, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock));

        let deadlocks = analyzer.detect_deadlocks();
        // Exactly the genuine two-lock cycle, no single-lock self-loop.
        assert_eq!(deadlocks.len(), 1, "self-loop must not be reported alongside the real cycle: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
        assert!(
            deadlocks.iter().all(|d| d.lock_cycle.len() >= 2),
            "no single-lock self-cycle may appear: {:?}",
            deadlocks
        );
    }

    /// A recursively-held lock is still held after a SINGLE unlock. T2 locks B
    /// twice (recursive nesting, depth 2), unlocks B ONCE (back to depth 1 —
    /// still held), then acquires A while T1 holds the A→B order. B is genuinely
    /// held across A's acquire → real B→A edge → ABBA cycle. A bool-based
    /// `is_lock_held_at` would clear on the first unlock and MISS this deadlock
    /// (false negative); the depth counter tracks the nesting and reports it.
    #[test]
    fn test_deadlock_detected_with_recursive_lock_partial_unlock() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: lock A@10, lock B@20 (real A→B edge).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock));
        // T2: lock B@30, lock B@40 (recursive → depth 2), UNLOCK B@45 (depth 1,
        // STILL held), then lock A@50 while B is still held → real B→A edge.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(45, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "recursive lock still held after one unlock must keep the deadlock: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
    }

    /// Control for the recursive case: once BOTH nesting levels are released, the
    /// lock is free. T2 locks B twice (depth 2), unlocks B TWICE (depth 0 — no
    /// longer held), then acquires A. B is NOT held when A is taken → no B→A edge
    /// → no cycle. Guards the saturating counter against reporting a phantom
    /// hold when the unlocks fully balance the acquires.
    #[test]
    fn test_no_deadlock_when_recursive_lock_fully_unlocked() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: lock A@10, lock B@20 (real A→B edge).
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::MutexLock));
        // T2: lock B@30, lock B@40 (depth 2), UNLOCK B@45, UNLOCK B@48 (depth 0 —
        // fully released), then lock A@50. B not held when A taken → no cycle.
        analyzer.feed_sync_event(ev(30, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(40, 2, b, SyncEventType::MutexLock));
        analyzer.feed_sync_event(ev(45, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(48, 2, b, SyncEventType::MutexUnlock));
        analyzer.feed_sync_event(ev(50, 2, a, SyncEventType::MutexLock));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(deadlocks.is_empty(), "fully-released recursive lock must not fabricate a deadlock: {:?}", deadlocks);
    }

    /// Two threads read-locking the same pair of rwlocks in opposite order is
    /// NOT a deadlock: readers are mutually compatible, so neither acquire ever
    /// blocks. The analyzer must not fabricate a read-read ordering deadlock.
    #[test]
    fn test_no_false_deadlock_for_read_read_rwlock() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0xAAAA0000;
        let b = 0xBBBB0000;
        let rd = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::RwLockRead,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // T1: read-A@10, read-B@20 (A→B). T2: read-B@15, read-A@25 (B→A).
        // Shaped exactly like the mutex ABBA deadlock, but all read locks.
        analyzer.feed_sync_event(rd(10, 1, a));
        analyzer.feed_sync_event(rd(20, 1, b));
        analyzer.feed_sync_event(rd(15, 2, b));
        analyzer.feed_sync_event(rd(25, 2, a));

        let deadlocks = analyzer.detect_deadlocks();
        assert!(deadlocks.is_empty(), "read-read opposite ordering is not a deadlock: {:?}", deadlocks);
    }

    /// When one of the two locks in an ABBA ordering is genuinely written
    /// (exclusive) by a thread, the acquire can block, so the deadlock is real
    /// and must still be reported — the read-lock exemption must not swallow it.
    #[test]
    fn test_deadlock_still_detected_when_one_lock_is_written() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0x1000u64;
        let b = 0x2000u64;
        let ev = |step: u64, tid: u32, addr: u64, ty: SyncEventType| ThreadSyncEvent {
            step, thread_id: tid, sync_type: ty, sync_object_addr: addr,
            result: SyncResult::Success, wait_duration_ns: None,
        };
        // T1: write-A@10, write-B@20 (A→B, both exclusive).
        // T2: read-B@15, write-A@25 (B→A). B is written by T1, so B is
        // exclusive-capable: T2's read-B can block behind T1's write. Cycle real.
        analyzer.feed_sync_event(ev(10, 1, a, SyncEventType::RwLockWrite));
        analyzer.feed_sync_event(ev(20, 1, b, SyncEventType::RwLockWrite));
        analyzer.feed_sync_event(ev(15, 2, b, SyncEventType::RwLockRead));
        analyzer.feed_sync_event(ev(25, 2, a, SyncEventType::RwLockWrite));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "an exclusive-capable lock in the cycle keeps the deadlock real: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
    }

    /// A single A↔B lock-order cycle must be reported exactly once, with a
    /// canonical (min-address-first) `lock_cycle` and sorted `threads` —
    /// regardless of HashMap/HashSet iteration order. Before the canonical
    /// dedup the same cycle surfaced as either `[a, b]` or `[b, a]` depending
    /// on which lock the DFS happened to root at.
    #[test]
    fn test_deadlock_cycle_is_canonical_and_unique() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0x1000u64; // smaller address → canonical cycle starts here
        let b = 0x2000u64;
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // T1: A then B (edge A→B). T2: B then A (edge B→A). Cycle A↔B.
        analyzer.feed_sync_event(lock(10, 1, a));
        analyzer.feed_sync_event(lock(20, 1, b));
        analyzer.feed_sync_event(lock(15, 2, b));
        analyzer.feed_sync_event(lock(25, 2, a));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "one cycle must be reported once, got {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].lock_cycle.iter().map(|m| m.addr).collect::<Vec<_>>(),
            vec![a, b],
            "cycle must be min-address-first"
        );
        assert_eq!(deadlocks[0].threads, vec![1, 2], "threads must be sorted and deduped");

        // Deterministic: re-running yields byte-identical output.
        let again = analyzer.detect_deadlocks();
        assert_eq!(deadlocks[0].lock_cycle, again[0].lock_cycle);
        assert_eq!(deadlocks[0].threads, again[0].threads);
    }

    /// Two DISTINCT lock-order cycles that share a node must BOTH be reported.
    /// Graph: A→B, A→C, B→D, C→D, D→A → cycles A→B→D→A and A→C→D→A share
    /// node D and edge D→A. A DFS with a permanent `visited` black-set marks D
    /// visited on the B-branch, then returns early when the C-branch reaches D,
    /// silently dropping the second deadlock. For a deadlock *detector*, a missed
    /// cycle is a false negative — the costly kind. Both must surface.
    #[test]
    fn test_two_cycles_sharing_a_node_both_reported() {
        let mut analyzer = ThreadAnalyzer::new();
        for tid in 1..=5 {
            analyzer.feed_thread_info(make_thread_info(tid, "t"));
        }
        let (a, b, c, d) = (0x1000u64, 0x2000u64, 0x3000u64, 0x4000u64);
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // Each thread acquires exactly two locks in order → exactly one edge,
        // so the graph is precisely {A→B, A→C, B→D, C→D, D→A} and nothing else.
        analyzer.feed_sync_event(lock(10, 1, a)); // T1: A→B
        analyzer.feed_sync_event(lock(11, 1, b));
        analyzer.feed_sync_event(lock(20, 2, a)); // T2: A→C
        analyzer.feed_sync_event(lock(21, 2, c));
        analyzer.feed_sync_event(lock(30, 3, b)); // T3: B→D
        analyzer.feed_sync_event(lock(31, 3, d));
        analyzer.feed_sync_event(lock(40, 4, c)); // T4: C→D
        analyzer.feed_sync_event(lock(41, 4, d));
        analyzer.feed_sync_event(lock(50, 5, d)); // T5: D→A
        analyzer.feed_sync_event(lock(51, 5, a));

        let mut cycles: Vec<Vec<u64>> =
            analyzer.detect_deadlocks().into_iter()
                .map(|d| d.lock_cycle.into_iter().map(|m| m.addr).collect())
                .collect();
        cycles.sort();
        assert_eq!(
            cycles,
            vec![vec![a, b, d], vec![a, c, d]],
            "both node-sharing cycles must be reported, got {:?}",
            cycles
        );
    }

    /// `violation_steps` must point at the precise events that form the cycle —
    /// the involved threads' acquisitions of the *cycle's* locks — not every
    /// lock a thread ever touched. A cycle thread that also grabs an unrelated
    /// lock must not have that unrelated acquisition leak into the report.
    #[test]
    fn test_violation_steps_are_scoped_to_cycle_locks() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        let a = 0x1000u64;
        let b = 0x2000u64;
        let unrelated = 0x9000u64; // not part of the A↔B cycle
        let lock = |step: u64, tid: u32, addr: u64| ThreadSyncEvent {
            step, thread_id: tid,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        };
        // T1: A@10, B@20 (A→B). T2: B@30, A@40 (B→A). Cycle A↔B, steps 10/20/30/40.
        analyzer.feed_sync_event(lock(10, 1, a));
        analyzer.feed_sync_event(lock(20, 1, b));
        analyzer.feed_sync_event(lock(30, 2, b));
        analyzer.feed_sync_event(lock(40, 2, a));
        // T1 also grabs an unrelated lock at step 99 — must NOT appear in the report.
        analyzer.feed_sync_event(lock(99, 1, unrelated));

        let deadlocks = analyzer.detect_deadlocks();
        assert_eq!(deadlocks.len(), 1, "one A↔B cycle expected: {:?}", deadlocks);
        assert_eq!(
            deadlocks[0].violation_steps,
            vec![10, 20, 30, 40],
            "only cycle-lock acquisitions belong in violation_steps (step 99 is unrelated)"
        );
    }

    fn make_switch(
        step: u64,
        from: u32,
        to: u32,
        reason: SwitchReason,
        core: Option<u32>,
    ) -> ContextSwitch {
        ContextSwitch { step, from_thread: from, to_thread: to, switch_reason: reason, cpu_core: core }
    }

    /// `analyze_scheduling` must classify each switch-out as voluntary
    /// (Yield/Blocking) or involuntary (Preemption/TimeSliceExpired/Interrupt),
    /// count migrations onto a core, and collect the distinct cores a thread ran
    /// on — all deterministically ordered by thread id.
    #[test]
    fn test_scheduling_classifies_switch_reasons() {
        let mut analyzer = ThreadAnalyzer::new();
        for tid in 1..=3 {
            analyzer.feed_thread_info(make_thread_info(tid, "t"));
        }
        // T1 preempted off → T2 on core 0
        analyzer.feed_context_switch(make_switch(10, 1, 2, SwitchReason::Preemption, Some(0)));
        // T2 yields off → T1 on core 0
        analyzer.feed_context_switch(make_switch(20, 2, 1, SwitchReason::Yield, Some(0)));
        // T1 blocks off → T3 on core 1
        analyzer.feed_context_switch(make_switch(30, 1, 3, SwitchReason::Blocking, Some(1)));
        // T3 off → T1 migrated onto core 2
        analyzer.feed_context_switch(make_switch(40, 3, 1, SwitchReason::Migration, Some(2)));

        let stats = analyzer.analyze_scheduling();
        // Sorted by thread_id: T1, T2, T3.
        let ids: Vec<u32> = stats.iter().map(|s| s.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3], "output must be ordered by thread id");

        let t1 = &stats[0];
        assert_eq!(t1.scheduled_in_count, 2); // steps 20, 40
        assert_eq!(t1.scheduled_out_count, 2); // steps 10, 30
        assert_eq!(t1.voluntary_switches, 1); // Blocking@30
        assert_eq!(t1.involuntary_switches, 1); // Preemption@10
        assert_eq!(t1.migration_count, 1); // Migration@40 landed on T1
        assert_eq!(t1.cpu_cores, vec![0, 2]); // ran on core 0 (@20) and 2 (@40)

        let t2 = &stats[1];
        assert_eq!(t2.scheduled_in_count, 1);
        assert_eq!(t2.scheduled_out_count, 1);
        assert_eq!(t2.voluntary_switches, 1); // Yield@20
        assert_eq!(t2.involuntary_switches, 0);
        assert_eq!(t2.migration_count, 0);
        assert_eq!(t2.cpu_cores, vec![0]);

        let t3 = &stats[2];
        assert_eq!(t3.scheduled_in_count, 1);
        assert_eq!(t3.scheduled_out_count, 1);
        // Migration as a switch-*out* reason is neither voluntary nor forced.
        assert_eq!(t3.voluntary_switches, 0);
        assert_eq!(t3.involuntary_switches, 0);
        assert_eq!(t3.migration_count, 0); // it was migrated *off*, not onto a core
        assert_eq!(t3.cpu_cores, vec![1]);

        // #117: per-core residency in steps. Each thread ran 10 steps on its
        // run-in core before being switched out. T1's tail run-in on core 2
        // (@40) is unbounded (no following switch) and contributes 0, so T1
        // only carries the core-0 interval @20..30 = 10 steps.
        assert_eq!(t1.core_residency, vec![(0, 10)]);
        assert_eq!(t2.core_residency, vec![(0, 10)]);
        assert_eq!(t3.core_residency, vec![(1, 10)]);
    }

    /// Two context switches at the SAME step (two cores switching at once) must
    /// both be counted. A step is not unique, so a keyed insert would drop one —
    /// this pins the `Vec`-per-step retention (same bug class as #49/#52).
    #[test]
    fn test_scheduling_same_step_switches_both_counted() {
        let mut analyzer = ThreadAnalyzer::new();
        for tid in 1..=4 {
            analyzer.feed_thread_info(make_thread_info(tid, "t"));
        }
        // Both at step 100 — an old BTreeMap<step, ContextSwitch> would keep only
        // the second, losing T1/T2 entirely.
        analyzer.feed_context_switch(make_switch(100, 1, 2, SwitchReason::Preemption, Some(0)));
        analyzer.feed_context_switch(make_switch(100, 3, 4, SwitchReason::Preemption, Some(1)));

        let stats = analyzer.analyze_scheduling();
        let ids: Vec<u32> = stats.iter().map(|s| s.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4], "all four threads from both same-step switches survive");
        assert_eq!(stats[0].scheduled_out_count, 1); // T1 switched out
        assert_eq!(stats[1].scheduled_in_count, 1); // T2 switched in
        assert_eq!(stats[2].scheduled_out_count, 1); // T3 switched out
        assert_eq!(stats[3].scheduled_in_count, 1); // T4 switched in

        // #117: both run-ins (@100) are unbounded (no following switch), so
        // no residency is fabricated for T2/T4; T1/T3 had no prior run-in to
        // close. All four have empty residency — the field exists but no
        // span is invented.
        for s in &stats {
            assert!(s.core_residency.is_empty(),
                "unbounded run-ins contribute no residency, got {:?}", s.core_residency);
        }
    }
