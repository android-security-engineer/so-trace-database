
    #[test]
    fn test_jni_attached_thread() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Java thread attaching to JNI
        let jni_info = ThreadInfo {
            thread_id: 100,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 500,
            exit_step: None,
            name: Some("Java-AsyncTask-1".to_string()),
            stack_base: 0,
            stack_size: 0,
            tls_addr: 0,
            is_jni_attached: true, // JNI attached!
        };
        store.register_thread(jni_info).unwrap();

        let info = store.get_thread_info(100).unwrap();
        assert_eq!(info.is_jni_attached, true);
        assert_eq!(info.name, Some("Java-AsyncTask-1".to_string()));
    }

    #[test]
    fn test_thread_state_helpers() {
        assert!(ThreadState::WaitingForLock.is_waiting());
        assert!(ThreadState::WaitingForFutex.is_waiting());
        assert!(ThreadState::WaitingForCondvar.is_waiting());
        assert!(!ThreadState::Running.is_waiting());
        assert!(!ThreadState::Runnable.is_waiting());

        assert!(ThreadState::Running.is_alive());
        assert!(ThreadState::WaitingForLock.is_alive());
        assert!(!ThreadState::Terminated.is_alive());

        assert!(SyncEventType::MutexLock.is_acquire());
        assert!(!SyncEventType::MutexLock.is_release());
        assert!(SyncEventType::MutexUnlock.is_release());
        assert!(!SyncEventType::MutexUnlock.is_acquire());
        // `MutexLocked` (frida's successful acquire) is an acquire, not a release.
        // Omitting it from `is_acquire` made `has_sync_between` miss synchronization
        // and `exclusive_locks` drop deadlock edges on MutexLocked-only traces.
        assert!(SyncEventType::MutexLocked.is_acquire());
        assert!(!SyncEventType::MutexLocked.is_release());

        // #109: three-way classification. CondvarWait/BarrierWait are NOT
        // holdable acquires (condvar wait releases its mutex; a barrier is a
        // rendezvous) — counting them as acquires fabricated monotonically-
        // increasing depth with no paired release, producing false deadlocks.
        // They remain synchronization signals for race suppression.
        assert!(SyncEventType::CondvarWait.is_sync_signal());
        assert!(!SyncEventType::CondvarWait.is_acquire());
        assert!(SyncEventType::BarrierWait.is_sync_signal());
        assert!(!SyncEventType::BarrierWait.is_acquire());
        // SemWait/FutexWait ARE holdable acquires (paired with SemPost/FutexWake).
        assert!(SyncEventType::SemWait.is_holdable_acquire());
        assert!(SyncEventType::SemPost.is_holdable_release());
        assert!(SyncEventType::FutexWait.is_holdable_acquire());
        assert!(SyncEventType::FutexWake.is_holdable_release());
        // FutexWakeCount is a sync signal, NOT a holdable release (waker-emitted,
        // no per-waiter identity → cannot account per-thread depth).
        assert!(SyncEventType::FutexWakeCount.is_sync_signal());
        assert!(!SyncEventType::FutexWakeCount.is_holdable_release());
        // CondvarSignal/Broadcast are sync signals; they stay in is_release() as
        // a broad superset for has_sync_between, but are not holdable releases.
        assert!(SyncEventType::CondvarSignal.is_sync_signal());
        assert!(!SyncEventType::CondvarSignal.is_holdable_release());
    }

    /// `primitive_kind()` classifies each of the 16 `SyncEventType` variants into
    /// its primitive class — all variants operating on the same primitive
    /// collapse together (every mutex op → `Mutex`, every condvar op →
    /// `Condvar`, etc.). Used to type the producer-consumer `sync_mechanism`
    /// field so the reported mechanism is a typed primitive, not a bare addr.
    #[test]
    fn test_primitive_kind_classifies_all_variants() {
        use sotrace_core::models::thread::SyncPrimitiveKind as K;
        use sotrace_core::models::thread::SyncEventType as T;

        // Mutex family — all four operations collapse to Mutex.
        assert_eq!(T::MutexLock.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexLocked.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexTryLock.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexUnlock.primitive_kind(), K::Mutex);

        // RwLock family.
        assert_eq!(T::RwLockRead.primitive_kind(), K::RwLock);
        assert_eq!(T::RwLockWrite.primitive_kind(), K::RwLock);
        assert_eq!(T::RwLockUnlock.primitive_kind(), K::RwLock);

        // Semaphore family.
        assert_eq!(T::SemWait.primitive_kind(), K::Semaphore);
        assert_eq!(T::SemPost.primitive_kind(), K::Semaphore);

        // Futex family — including the #109 sync-signal FutexWakeCount.
        assert_eq!(T::FutexWait.primitive_kind(), K::Futex);
        assert_eq!(T::FutexWake.primitive_kind(), K::Futex);
        assert_eq!(T::FutexWakeCount.primitive_kind(), K::Futex);

        // Condvar family.
        assert_eq!(T::CondvarWait.primitive_kind(), K::Condvar);
        assert_eq!(T::CondvarSignal.primitive_kind(), K::Condvar);
        assert_eq!(T::CondvarBroadcast.primitive_kind(), K::Condvar);

        // Barrier.
        assert_eq!(T::BarrierWait.primitive_kind(), K::Barrier);
    }

    // ------------------------------------------------------------------------
    // #52: EventLog same-step retention. `step`/`seq` comes from the adapter
    // (`trace.seq`) and is NOT unique, so two threads can emit an event at the
    // same step. The old `DeltaLog` keyed insert clobbered all but the last;
    // `EventLog` keeps every same-step record. These tests drive each of the
    // three event logs (sync / state / switch) with a colliding step and assert
    // both records survive on every read path (indexed query + `all_*`).
    // ------------------------------------------------------------------------

    /// Two sync events on different locks/threads at the SAME step both survive,
    /// and each read path attributes them to the right lock/thread.
    #[test]
    fn test_sync_events_same_step_both_retained() {
        let mut store = ThreadStore::new(make_config());

        // thread 1 waits on lock 0xA at step 100; thread 2 acquires lock 0xB at
        // the same step 100. A keyed-insert log would keep only the second.
        store.write_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000,
            result: SyncResult::Success,
            wait_duration_ns: Some(5_000_000),
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xB000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // all_sync_events keeps both.
        assert_eq!(store.all_sync_events().len(), 2);

        // Per-thread query returns exactly that thread's event.
        let t1 = store.query_sync_events(1, 0, u64::MAX);
        assert_eq!(t1.len(), 1);
        assert_eq!(t1[0].sync_object_addr, 0xA000);
        assert_eq!(t1[0].wait_duration_ns, Some(5_000_000));

        let t2 = store.query_sync_events(2, 0, u64::MAX);
        assert_eq!(t2.len(), 1);
        assert_eq!(t2[0].sync_object_addr, 0xB000);

        // Per-lock query returns exactly that lock's event.
        let lock_a = store.query_lock_contentions(0xA000, 0, u64::MAX);
        assert_eq!(lock_a.len(), 1);
        assert_eq!(lock_a[0].thread_id, 1);
        let lock_b = store.query_lock_contentions(0xB000, 0, u64::MAX);
        assert_eq!(lock_b.len(), 1);
        assert_eq!(lock_b[0].thread_id, 2);
    }

    /// Two state changes for different threads at the SAME step both survive;
    /// `query_thread_state` and `query_thread_timeline` each pick the right one.
    #[test]
    fn test_state_changes_same_step_both_retained() {
        let mut store = ThreadStore::new(make_config());
        for tid in [1u32, 2] {
            store.register_thread(ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: None,
                stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
            }).unwrap();
        }

        // A context switch: thread 1 blocks and thread 2 runs, both stamped at
        // step 200 (one seq, two state deltas).
        store.write(ThreadStateChange {
            step: 200, thread_id: 1,
            new_state: ThreadState::WaitingForLock,
            prev_state: Some(ThreadState::Running),
            prev_running_thread: Some(1),
        }).unwrap();
        store.write(ThreadStateChange {
            step: 200, thread_id: 2,
            new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable),
            prev_running_thread: Some(1),
        }).unwrap();

        // Both retained in the raw dump.
        assert_eq!(store.all_state_changes().len(), 2);

        // query_thread_state resolves per thread at that step.
        assert_eq!(
            store.query_thread_state(1, 200).unwrap().new_state,
            ThreadState::WaitingForLock
        );
        assert_eq!(
            store.query_thread_state(2, 200).unwrap().new_state,
            ThreadState::Running
        );

        // The timeline for each thread contains only its own change.
        let tl1 = store.query_thread_timeline(1, 0, u64::MAX);
        assert_eq!(tl1.state_changes.len(), 1);
        assert_eq!(tl1.state_changes[0].new_state, ThreadState::WaitingForLock);
        let tl2 = store.query_thread_timeline(2, 0, u64::MAX);
        assert_eq!(tl2.state_changes.len(), 1);
        assert_eq!(tl2.state_changes[0].new_state, ThreadState::Running);
    }

    /// A lock that waits then times out (or is interrupted) must still count its
    /// wait time toward the thread's `avg_lock_wait_ns`, and an interrupted wait
    /// must count as a contention. #53: the old stats only accumulated wait on
    /// `Success`, dropping the wait of every non-Success acquire.
    #[test]
    fn test_stats_wait_time_counted_for_nonsuccess_results() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();

        // Acquire A: waited 3ms then TIMED OUT. Old code: contention counted but
        // wait dropped → avg would be 0. New: wait accounted.
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0x1000,
            result: SyncResult::Timeout,
            wait_duration_ns: Some(3_000_000),
        }).unwrap();

        // Acquire B: waited 5ms then INTERRUPTED. Old code: neither branch fired
        // → not even counted as a contention, wait dropped entirely.
        store.write_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1,
            sync_type: SyncEventType::FutexWait,
            sync_object_addr: 0x2000,
            result: SyncResult::Interrupted,
            wait_duration_ns: Some(5_000_000),
        }).unwrap();

        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 2);
        // Both waited → both are contentions (each counted once).
        assert_eq!(stats.lock_contention_count, 2);
        // avg = (3ms + 5ms) / 2 contentions = 4ms. Old code would report 0.
        assert_eq!(stats.avg_lock_wait_ns, Some(4_000_000));
        // #118: the longest single wait (5ms Interrupted) is the long tail.
        assert_eq!(stats.max_lock_wait_ns, Some(5_000_000));
    }

    /// A trylock that WouldBlock with zero wait is a contention but contributes
    /// no wait time — so it must not deflate a real average via a phantom sample.
    #[test]
    fn test_stats_wouldblock_zero_wait_is_contention_without_wait() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();

        // A real wait of 6ms (succeeded).
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0x1000,
            result: SyncResult::Success,
            wait_duration_ns: Some(6_000_000),
        }).unwrap();
        // A trylock that would block, no measurable wait.
        store.write_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1,
            sync_type: SyncEventType::MutexTryLock,
            sync_object_addr: 0x2000,
            result: SyncResult::WouldBlock,
            wait_duration_ns: None,
        }).unwrap();

        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 2);
        assert_eq!(stats.lock_contention_count, 2);
        // total wait 6ms over 2 contentions = 3ms average.
        assert_eq!(stats.avg_lock_wait_ns, Some(3_000_000));
        // #118: only the 6ms acquire actually waited; WouldBlock trylock has
        // no wait, so max is the single real wait, not deflated by zero.
        assert_eq!(stats.max_lock_wait_ns, Some(6_000_000));
    }

    /// #118: max_lock_wait_ns tracks the longest single wait, not just the
    /// running average. A thread that waits 3ms then 5ms then 1ms must report
    /// max=5ms even though avg=3ms — the long tail avg hides.
    #[test]
    fn test_stats_max_lock_wait_tracks_longest() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        let mk = |step, wait_ns| ThreadSyncEvent {
            step, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000,
            result: SyncResult::Success,
            wait_duration_ns: Some(wait_ns),
        };
        store.write_sync_event(mk(10, 3_000_000)).unwrap();
        store.write_sync_event(mk(20, 5_000_000)).unwrap();
        store.write_sync_event(mk(30, 1_000_000)).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_contention_count, 3);
        assert_eq!(stats.avg_lock_wait_ns, Some(3_000_000)); // (3+5+1)/3 = 3ms
        assert_eq!(stats.max_lock_wait_ns, Some(5_000_000)); // long tail
    }

    /// #118: max_lock_wait_ns is None when the thread never waited (no
    /// contention with a real wait), mirroring avg_lock_wait_ns.
    #[test]
    fn test_stats_max_lock_wait_none_when_no_wait() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        // A successful acquire with zero wait is not a contention.
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_contention_count, 0);
        assert_eq!(stats.avg_lock_wait_ns, None);
        assert_eq!(stats.max_lock_wait_ns, None);
    }

    /// Two context switches at the SAME step both survive on every read path.
    #[test]
    fn test_context_switches_same_step_both_retained() {
        let mut store = ThreadStore::new(make_config());

        store.write_context_switch(ContextSwitch {
            step: 300, from_thread: 1, to_thread: 2,
            switch_reason: SwitchReason::Blocking, cpu_core: Some(0),
        }).unwrap();
        store.write_context_switch(ContextSwitch {
            step: 300, from_thread: 3, to_thread: 4,
            switch_reason: SwitchReason::Preemption, cpu_core: Some(1),
        }).unwrap();

        assert_eq!(store.all_context_switches().len(), 2);
        assert_eq!(store.total_switches(), 2);

        // Range query flattens both same-step switches.
        let switches = store.query_context_switches(0, u64::MAX);
        assert_eq!(switches.len(), 2);

        // The per-thread timeline filter still isolates the switch involving it.
        let mut cores: Vec<u32> = switches.iter().filter_map(|s| s.cpu_core).collect();
        cores.sort_unstable();
        assert_eq!(cores, vec![0, 1]);
    }

    /// Re-registering an existing thread must NOT reset its accumulated state
    /// or statistics. An adapter can re-report a thread (e.g. its name resolved
    /// later, or a duplicate event) — the metadata should refresh, but the
    /// thread's `thread_states` (could be Running/Terminated) and `thread_stats`
    /// (steps/sync/lock counts already accrued) must survive. Before the fix
    /// both were unconditional `insert`, silently zeroing stats and flipping a
    /// Terminated thread back to Runnable.
    #[test]
    fn test_reregister_thread_preserves_stats_and_state() {
        let mut store = ThreadStore::new(make_config());

        let info = |tid: u32, name: &str| ThreadInfo {
            thread_id: tid, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some(name.to_string()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };

        // Register thread 1, accrue a sync event + a state-change step.
        store.register_thread(info(1, "initial")).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();
        // A state change records a step executed and moves the thread to Running.
        store.write(ThreadStateChange {
            step: 110, thread_id: 1, new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
        }).unwrap();

        let before = store.get_thread_stats(1).unwrap();
        assert_eq!(before.sync_event_count, 1, "setup: one sync event counted");
        assert_eq!(before.steps_executed, 1, "setup: one state-change step counted");

        // Re-register thread 1 with refreshed metadata (name change).
        store.register_thread(info(1, "refreshed")).unwrap();

        // Metadata refreshed...
        assert_eq!(store.get_thread_info(1).unwrap().name.as_deref(), Some("refreshed"));

        // ...but stats preserved, NOT reset to zero.
        let after = store.get_thread_stats(1).unwrap();
        assert_eq!(after.sync_event_count, 1, "sync_event_count must survive re-register");
        assert_eq!(after.steps_executed, 1, "steps_executed must survive re-register");

        // And state not flipped back to Runnable — it was Running (and stays so).
        assert_eq!(*store.all_thread_states().get(&1).unwrap(), ThreadState::Running,
            "thread_states must not reset to Runnable on re-register");
    }
