    use super::*;

    fn make_config() -> DeltaStoreConfig {
        DeltaStoreConfig::default()
    }

    #[test]
    fn test_thread_registration_and_info() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register main thread (thread_id=1, no parent)
        let main_info = ThreadInfo {
            thread_id: 1,
            pthread_id: Some(100),
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: Some("main".to_string()),
            stack_base: 0x7F000000,
            stack_size: 8 * 1024 * 1024, // 8MB
            tls_addr: 0x7F008000,
            is_jni_attached: false,
        };
        store.register_thread(main_info).unwrap();

        // Register worker thread created by main
        let worker_info = ThreadInfo {
            thread_id: 2,
            pthread_id: Some(101),
            parent_thread_id: 1, // Created by main thread
            create_step: 100,
            exit_step: None,
            name: Some("worker-1".to_string()),
            stack_base: 0x7E000000,
            stack_size: 4 * 1024 * 1024, // 4MB
            tls_addr: 0x7E040000,
            is_jni_attached: false,
        };
        store.register_thread(worker_info).unwrap();

        // Query thread info
        let main = store.get_thread_info(1).unwrap();
        assert_eq!(main.name, Some("main".to_string()));
        assert_eq!(main.parent_thread_id, 0);
        assert_eq!(main.stack_size, 8 * 1024 * 1024);

        let worker = store.get_thread_info(2).unwrap();
        assert_eq!(worker.parent_thread_id, 1);
        assert_eq!(worker.name, Some("worker-1".to_string()));

        // Check thread count
        assert_eq!(store.thread_count(), 2);
        let mut tids = store.all_thread_ids();
        tids.sort();
        assert_eq!(tids, vec![1, 2]);
    }

    #[test]
    fn test_thread_state_changes() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register thread
        let info = ThreadInfo {
            thread_id: 1,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: None,
            stack_base: 0,
            stack_size: 0,
            tls_addr: 0,
            is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // State changes: Runnable → Running → WaitingForLock → Running
        store.write(ThreadStateChange {
            step: 10, thread_id: 1,
            new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable),
            prev_running_thread: None,
        }).unwrap();

        store.write(ThreadStateChange {
            step: 500, thread_id: 1,
            new_state: ThreadState::WaitingForLock,
            prev_state: Some(ThreadState::Running),
            prev_running_thread: Some(1),
        }).unwrap();

        store.write(ThreadStateChange {
            step: 600, thread_id: 1,
            new_state: ThreadState::Running,
            prev_state: Some(ThreadState::WaitingForLock),
            prev_running_thread: Some(2),
        }).unwrap();

        // Query state at different steps
        let state_at_100 = store.query_thread_state(1, 100).unwrap();
        assert_eq!(state_at_100.new_state, ThreadState::Running);

        let state_at_550 = store.query_thread_state(1, 550).unwrap();
        assert_eq!(state_at_550.new_state, ThreadState::WaitingForLock);

        let state_at_700 = store.query_thread_state(1, 700).unwrap();
        assert_eq!(state_at_700.new_state, ThreadState::Running);

        // Check current running thread
        assert_eq!(store.current_thread(), Some(1));
    }

    #[test]
    fn test_sync_events_and_lock_contentions() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register two threads
        for tid in [1, 2] {
            let info = ThreadInfo {
                thread_id: tid,
                pthread_id: None,
                parent_thread_id: 0,
                create_step: 0,
                exit_step: None,
                name: None,
                stack_base: 0,
                stack_size: 0,
                tls_addr: 0,
                is_jni_attached: false,
            };
            store.register_thread(info).unwrap();
        }

        let mutex_addr = 0xABCD0000;

        // Thread 1 acquires mutex
        store.write_sync_event(ThreadSyncEvent {
            step: 100, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // Thread 2 tries to acquire same mutex — contends
        store.write_sync_event(ThreadSyncEvent {
            step: 200, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success, // Eventually acquired
            wait_duration_ns: Some(5000000), // 5ms wait
        }).unwrap();

        // Thread 1 releases mutex
        store.write_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // Query: all events for this mutex
        let mutex_events = store.query_lock_contentions(mutex_addr, 0, 300);
        assert_eq!(mutex_events.len(), 3);

        // Query: all sync events for thread 1
        let thread1_events = store.query_sync_events(1, 0, 300);
        assert_eq!(thread1_events.len(), 2); // Lock + Unlock

        // Sub-range query must binary-search the (out-of-order-fed) sorted
        // index and return only events inside [120, 180] — i.e. the step-150
        // unlock, not the step-100 or step-200 locks.
        let mid = store.query_lock_contentions(mutex_addr, 120, 180);
        assert_eq!(mid.len(), 1);
        assert_eq!(mid[0].step, 150);
        // Per-thread sub-range: thread 1 only has the unlock at 150 in [120, 300].
        let t1_mid = store.query_sync_events(1, 120, 300);
        assert_eq!(t1_mid.len(), 1);
        assert_eq!(t1_mid[0].step, 150);

        // Query: last sync access before step 180
        let last = store.find_last_sync_access(mutex_addr, 180);
        assert_eq!(last, Some(150)); // Thread 1's unlock at step 150

        // Check stats
        let stats1 = store.get_thread_stats(1).unwrap();
        assert_eq!(stats1.lock_acquire_count, 1);
        assert_eq!(stats1.lock_release_count, 1); // thread 1 unlocked at step 150
        let stats2 = store.get_thread_stats(2).unwrap();
        assert_eq!(stats2.lock_acquire_count, 1);
        assert_eq!(stats2.lock_contention_count, 1);
    }

    /// #114: a MutexUnlock increments lock_release_count symmetric to acquire.
    #[test]
    fn test_lock_release_count_tracks_unlocks() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 1);
        assert_eq!(stats.lock_release_count, 1);
    }

    /// #114: CondvarSignal counts as a release (wake-the-waiter semantics,
    /// per #109's is_release superset).
    #[test]
    fn test_lock_release_count_includes_condvar_signal() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::CondvarSignal,
            sync_object_addr: 0xB000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 0);
        assert_eq!(stats.lock_release_count, 1);
    }

    /// #114: acquire without release is detectable (acquire > release → leak).
    #[test]
    fn test_lock_release_count_detects_leak() {
        let mut store = ThreadStore::new(make_config());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        // Two acquires, one release → leak (acquire=2, release=1)
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA001, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.write_sync_event(ThreadSyncEvent {
            step: 30, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 2);
        assert_eq!(stats.lock_release_count, 1);
        assert!(stats.lock_acquire_count > stats.lock_release_count);
    }

    #[test]
    fn test_context_switches() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register two threads
        for tid in [1, 2] {
            let info = ThreadInfo {
                thread_id: tid,
                pthread_id: None,
                parent_thread_id: 0,
                create_step: 0,
                exit_step: None,
                name: None,
                stack_base: 0,
                stack_size: 0,
                tls_addr: 0,
                is_jni_attached: false,
            };
            store.register_thread(info).unwrap();
        }

        // Context switch: thread 1 → thread 2
        store.write_context_switch(ContextSwitch {
            step: 1000,
            from_thread: 1,
            to_thread: 2,
            switch_reason: SwitchReason::Preemption,
            cpu_core: Some(0),
        }).unwrap();

        // Context switch: thread 2 → thread 1
        store.write_context_switch(ContextSwitch {
            step: 2000,
            from_thread: 2,
            to_thread: 1,
            switch_reason: SwitchReason::Blocking,
            cpu_core: Some(0),
        }).unwrap();

        // Query context switches in range
        let switches = store.query_context_switches(0, 3000);
        assert_eq!(switches.len(), 2);
        assert_eq!(switches[0].from_thread, 1);
        assert_eq!(switches[0].to_thread, 2);
        assert_eq!(switches[0].switch_reason, SwitchReason::Preemption);

        // Check total switches
        assert_eq!(store.total_switches(), 2);

        // Check stats
        let stats1 = store.get_thread_stats(1).unwrap();
        assert_eq!(stats1.context_switch_count, 2); // Involved in both switches
    }

    #[test]
    fn test_thread_timeline_query() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        // Register thread
        let info = ThreadInfo {
            thread_id: 1,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: Some("main".to_string()),
            stack_base: 0x7F000000,
            stack_size: 8 * 1024 * 1024,
            tls_addr: 0,
            is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // State change
        store.write(ThreadStateChange {
            step: 10, thread_id: 1,
            new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable),
            prev_running_thread: None,
        }).unwrap();

        // Sync event
        store.write_sync_event(ThreadSyncEvent {
            step: 50, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();

        // Context switch
        store.write_context_switch(ContextSwitch {
            step: 100, from_thread: 1, to_thread: 2,
            switch_reason: SwitchReason::Blocking,
            cpu_core: None,
        }).unwrap();

        // Query timeline
        let timeline = store.query_thread_timeline(1, 0, 200);
        assert_eq!(timeline.thread_id, 1);
        assert_eq!(timeline.state_changes.len(), 1);
        assert_eq!(timeline.sync_events.len(), 1);
        assert_eq!(timeline.context_switches.len(), 1);
    }

    #[test]
    fn test_thread_exit() {
        let config = make_config();
        let mut store = ThreadStore::new(config);

        let info = ThreadInfo {
            thread_id: 1,
            pthread_id: None,
            parent_thread_id: 0,
            create_step: 0,
            exit_step: None,
            name: None,
            stack_base: 0,
            stack_size: 0,
            tls_addr: 0,
            is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // Record exit
        store.record_thread_exit(1, 10000).unwrap();

        // Check exit_step
        let info = store.get_thread_info(1).unwrap();
        assert_eq!(info.exit_step, Some(10000));

        // Check state
        let state = store.all_thread_states().get(&1).unwrap();
        assert_eq!(*state, ThreadState::Terminated);
    }

    /// `record_thread_exit` must stamp the thread's ACTUAL prior state in the
    /// generated `ThreadStateChange.prev_state`, not a hardcoded Running. A
    /// thread can exit from Blocked/Waiting (e.g. cancelled mid-wait); the
    /// transition record should reflect that. Before the fix `prev_state` was
    /// always `Some(Running)` regardless of the real state.
    #[test]
    fn test_thread_exit_records_actual_prev_state() {
        let mut store = ThreadStore::new(make_config());

        let info = ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // Move the thread into Blocked (not Running) before it exits.
        store.write(ThreadStateChange {
            step: 50, thread_id: 1, new_state: ThreadState::Blocked,
            prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
        }).unwrap();
        assert_eq!(*store.all_thread_states().get(&1).unwrap(), ThreadState::Blocked);

        // Now exit. The recorded transition must be Blocked → Terminated.
        store.record_thread_exit(1, 10000).unwrap();

        let change = store.query_thread_state(1, 10000).unwrap();
        assert_eq!(change.new_state, ThreadState::Terminated);
        assert_eq!(change.prev_state, Some(ThreadState::Blocked),
            "prev_state must be the real prior state (Blocked), not hardcoded Running");
    }

    /// A thread leaving Running must clear `current_thread` — otherwise the
    /// store keeps reporting a runner that is no longer executing, and any
    /// later `prev_running_thread` (e.g. in `record_thread_exit`) is recorded
    /// wrong. Before the fix, only the *entering* branch updated
    /// `current_thread`; the *leaving* branch was missing.
    #[test]
    fn test_leaving_running_clears_current_thread() {
        let mut store = ThreadStore::new(make_config());

        let info = ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: None,
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        };
        store.register_thread(info).unwrap();

        // Runnable → Running: now thread 1 is the runner.
        store.write(ThreadStateChange {
            step: 10, thread_id: 1, new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
        }).unwrap();
        assert_eq!(store.current_thread(), Some(1));

        // Running → Blocked: thread 1 is no longer executing.
        store.write(ThreadStateChange {
            step: 20, thread_id: 1, new_state: ThreadState::Blocked,
            prev_state: Some(ThreadState::Running), prev_running_thread: Some(1),
        }).unwrap();
        assert_eq!(store.current_thread(), None,
            "leaving Running must clear current_thread — the thread is not running");

        // A different thread entering Running must still register as the runner.
        store.write(ThreadStateChange {
            step: 30, thread_id: 2, new_state: ThreadState::Running,
            prev_state: Some(ThreadState::Runnable), prev_running_thread: None,
        }).unwrap();
        assert_eq!(store.current_thread(), Some(2));
    }
