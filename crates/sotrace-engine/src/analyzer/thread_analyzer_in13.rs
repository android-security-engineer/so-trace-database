
    /// Repeated analysis calls must not duplicate or drop results — the cached
    /// sorted/indexed structures are stable across calls.
    #[test]
    fn test_repeated_analysis_is_stable() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        let first_races = analyzer.detect_race_conditions();
        let first_flows = analyzer.analyze_data_flows();
        let second_races = analyzer.detect_race_conditions();
        let second_flows = analyzer.analyze_data_flows();

        assert_eq!(first_races.len(), second_races.len());
        assert_eq!(first_flows.len(), second_flows.len());
    }

    /// The page-granular read index must keep race detection fast even when
    /// many unrelated reads exist on different pages. With the index, the N
    /// unrelated reads are never scanned for the one write at 0x1000; a full
    /// O(W·R) scan would visit all of them. We assert the write at 0x1000 is
    /// still found (correctness) and the call returns promptly (the build runs
    /// in debug here; the point is it terminates without scanning everything).
    #[test]
    fn test_race_detection_ignores_unrelated_reads() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // One contended write + read on page 0x1000.
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        // Many unrelated reads scattered across other pages — these must NOT
        // produce false races (different addresses) nor slow down detection.
        for i in 0..2000u64 {
            let addr = 0x1_0000 + i * 0x100; // each on its own page region
            analyzer.feed_memory_read(150 + i, 2, addr, 4);
        }

        let races = analyzer.detect_race_conditions();
        // Exactly one race: the 0x1000 pair. Unrelated reads share no page with
        // the 0x1000 write, so the index prunes them before the overlap check.
        let races_on_1000 = races.iter().filter(|r| r.address == 0x1000).count();
        assert_eq!(races_on_1000, 1);
        // No race reported at any unrelated address.
        assert!(races.iter().all(|r| r.address == 0x1000),
            "unrelated reads on other pages must not surface as races: {:?}", races);
    }

    /// Write-write races (two threads writing the same address without sync)
    /// must be detected and flagged `second_is_write: true`. This covers the
    /// writes_by_page index path symmetric to the read path.
    #[test]
    fn test_write_write_race_detection() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        // Thread 1 writes 0x1000 at step 100; thread 2 writes 0x1000 at step 200.
        analyzer.feed_memory_write(100, 1, 0x1000, 4);
        analyzer.feed_memory_write(200, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        let ww = races.iter().find(|r| r.address == 0x1000 && r.first_thread == 1 && r.second_thread == 2);
        assert!(ww.is_some(), "write-write race should be detected: {:?}", races);
        let ww = ww.unwrap();
        assert!(ww.first_is_write && ww.second_is_write, "both sides should be writes");
    }

    /// Write-write race must NOT be reported when the two writes are
    /// synchronized via a shared mutex — mirrors the read-path sync test.
    #[test]
    fn test_no_write_write_race_with_sync() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));

        analyzer.feed_memory_write(100, 1, 0x2000, 4);
        // Both threads touch the same mutex between the writes.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success, wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 160, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success, wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_write(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.is_empty() || races.iter().all(|r| r.address != 0x2000),
            "synchronized write-write should not be a race: {:?}", races);
    }

    /// Read-then-write race: thread A reads an address, then thread B writes it
    /// without synchronization. The reader may act on a value the writer is
    /// about to change. The old detector only looked forward from a write and
    /// missed this ordering entirely; it must now be flagged with the read as
    /// the first (non-write) event and the write as the second.
    #[test]
    fn test_read_then_write_race_detection() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "reader"));
        analyzer.feed_thread_info(make_thread_info(2, "writer"));

        // Thread 1 reads 0x1000 at step 100; thread 2 writes 0x1000 at step 200.
        analyzer.feed_memory_read(100, 1, 0x1000, 4);
        analyzer.feed_memory_write(200, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        let rw = races
            .iter()
            .find(|r| r.address == 0x1000 && r.first_thread == 1 && r.second_thread == 2)
            .expect(&format!("read-then-write race should be detected: {:?}", races));
        assert!(!rw.first_is_write, "the earlier read must be the first, non-write event");
        assert!(rw.second_is_write, "the later write must be the second event");
        assert_eq!(rw.first_step, 100);
        assert_eq!(rw.second_step, 200);
    }

    /// A read-then-write pair separated by a shared mutex is NOT a race —
    /// mirrors the write-path sync tests for the new read-first ordering.
    #[test]
    fn test_no_read_then_write_race_with_sync() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "reader"));
        analyzer.feed_thread_info(make_thread_info(2, "writer"));

        analyzer.feed_memory_read(100, 1, 0x2000, 4);
        // Both threads touch the same mutex between the read and the write.
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 150, thread_id: 1,
            sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success, wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 160, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success, wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_write(200, 2, 0x2000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.is_empty() || races.iter().all(|r| r.address != 0x2000),
            "synchronized read-then-write should not be a race: {:?}", races);
    }

    /// Two reads by different threads are never a race (no write involved),
    /// even though the read-first loop now scans reads around every write.
    #[test]
    fn test_read_read_is_not_a_race() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "reader-a"));
        analyzer.feed_thread_info(make_thread_info(2, "reader-b"));

        analyzer.feed_memory_read(100, 1, 0x1000, 4);
        analyzer.feed_memory_read(200, 2, 0x1000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.is_empty(), "read-read must not be flagged: {:?}", races);
    }

    /// An access whose `addr + size` would overflow `u64` must not panic or
    /// wrap to a tiny `end` (which would mis-classify overlaps). Saturating
    /// arithmetic clamps the range end to `u64::MAX`, so a write near the top
    /// of the address space still correctly races with a same-address read on
    /// another thread. Regression guard for #83.
    #[test]
    fn test_race_detection_near_u64_max_no_overflow() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "w"));
        analyzer.feed_thread_info(make_thread_info(2, "r"));

        // addr = u64::MAX - 7, size = 16 → addr+size overflows u64.
        let addr = u64::MAX - 7;
        analyzer.feed_memory_write(100, 1, addr, 16);
        analyzer.feed_memory_read(200, 2, addr, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.iter().any(|r| r.address == addr),
            "expected a race at {addr:#x}: {:?}", races);
    }

    /// A write and a read to the same address at the SAME step, on two threads,
    /// is the strongest possible race — fully concurrent, no ordering at all.
    /// Steps come from `trace.seq` and are not unique, so this must be reported
    /// (labelled write-first), not silently dropped by a `<=`/`>=` guard.
    #[test]
    fn test_same_step_write_read_is_a_race() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "writer"));
        analyzer.feed_thread_info(make_thread_info(2, "reader"));

        analyzer.feed_memory_write(100, 1, 0x3000, 4);
        analyzer.feed_memory_read(100, 2, 0x3000, 4);

        let races = analyzer.detect_race_conditions();
        let r = races
            .iter()
            .find(|r| r.address == 0x3000)
            .unwrap_or_else(|| panic!("same-step write/read must be a race: {:?}", races));
        assert_eq!(r.first_step, 100);
        assert_eq!(r.second_step, 100);
        assert!(r.first_is_write, "write is labelled first: {:?}", r);
        assert!(!r.second_is_write, "read is labelled second: {:?}", r);
        assert_eq!(r.first_thread, 1);
        assert_eq!(r.second_thread, 2);
        // Concurrent (zero step distance) → top confidence bucket.
        assert!(r.confidence >= 0.8, "same-step race should be high confidence: {:?}", r);
    }

    /// Two writes to the same address at the SAME step on two threads is a
    /// concurrent write-write race. It must be reported EXACTLY once (not twice
    /// from each side), with the lower-tid thread canonically first.
    #[test]
    fn test_same_step_write_write_reported_once() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "writer-a"));
        analyzer.feed_thread_info(make_thread_info(2, "writer-b"));

        // Feed higher tid first to prove ordering is by tid, not feed order.
        analyzer.feed_memory_write(100, 2, 0x4000, 4);
        analyzer.feed_memory_write(100, 1, 0x4000, 4);

        let races: Vec<_> = analyzer
            .detect_race_conditions()
            .into_iter()
            .filter(|r| r.address == 0x4000)
            .collect();
        assert_eq!(races.len(), 1, "same-step write-write must be reported once: {:?}", races);
        assert!(races[0].first_is_write && races[0].second_is_write);
        assert_eq!(races[0].first_thread, 1, "lower tid is canonically first");
        assert_eq!(races[0].second_thread, 2);
    }

    /// Same-step access on the SAME thread is not a race (a thread cannot race
    /// with itself), and must not be fabricated by the relaxed guards.
    #[test]
    fn test_same_step_same_thread_is_not_a_race() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "solo"));

        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_memory_read(100, 1, 0x5000, 4);
        analyzer.feed_memory_write(100, 1, 0x5000, 4);

        let races = analyzer.detect_race_conditions();
        assert!(races.is_empty(), "one thread cannot race with itself: {:?}", races);
    }

    // ========================================================================
    // JNI boundary analysis (#67)
    // ========================================================================

    /// Build a `JNICall` fixture. `seq` is the trace step (may collide across
    /// calls — the store keeps a Vec per step).
    fn make_jni_call(
        seq: u64,
        thread_id: u32,
        direction: JNICallDirection,
        java_class: &str,
        java_method: &str,
        native_address: u64,
    ) -> JNICall {
        JNICall {
            id: seq,
            seq,
            thread_id,
            direction,
            java_class: java_class.to_string(),
            java_method: java_method.to_string(),
            java_signature: "()V".to_string(),
            native_func_id: None,
            native_address,
            jni_env_address: None,
        }
    }

    /// Basic split: crossings on one thread are counted and bucketed by
    /// direction, and distinct native addresses / java methods are collected.
    #[test]
    fn test_jni_boundary_basic_split() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "worker"));

        analyzer.feed_jni_call(make_jni_call(10, 1, JNICallDirection::JavaToNative, "com.app.Foo", "doWork", 0x2000));
        analyzer.feed_jni_call(make_jni_call(20, 1, JNICallDirection::JavaToNative, "com.app.Foo", "init", 0x3000));
        analyzer.feed_jni_call(make_jni_call(30, 1, JNICallDirection::NativeToJava, "com.app.Bar", "callback", 0x2000));

        let stats = analyzer.analyze_jni_boundary();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert_eq!(s.thread_id, 1);
        assert_eq!(s.total_crossings, 3);
        assert_eq!(s.java_to_native_count, 2);
        assert_eq!(s.native_to_java_count, 1);
        // 0x2000 appears twice → distinct set keeps it once.
        assert_eq!(s.native_addresses, vec![0x2000, 0x3000]);
        assert_eq!(s.java_methods, vec!["com.app.Bar.callback", "com.app.Foo.doWork", "com.app.Foo.init"]);
        // #119: first/last crossing step locate the JNI activity window.
        assert_eq!(s.first_crossing_step, Some(10));
        assert_eq!(s.last_crossing_step, Some(30));
    }

    /// A thread the runtime marked JNI-attached but with no captured crossings
    /// must still appear (attached-but-idle surfacing), with zero counts.
    #[test]
    fn test_jni_boundary_attached_but_idle_appears() {
        let mut analyzer = ThreadAnalyzer::new();
        let mut idle = make_thread_info(7, "attached-idle");
        idle.is_jni_attached = true;
        analyzer.feed_thread_info(idle);

        let stats = analyzer.analyze_jni_boundary();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].thread_id, 7);
        assert!(stats[0].is_jni_attached);
        assert_eq!(stats[0].total_crossings, 0);
        assert!(stats[0].native_addresses.is_empty());
        assert!(stats[0].java_methods.is_empty());
        // #119: no crossings → no first/last step.
        assert_eq!(stats[0].first_crossing_step, None);
        assert_eq!(stats[0].last_crossing_step, None);
    }

    /// #119: first/last_crossing_step locate the JNI activity window. A thread
    /// with crossings at seq 50, 120, 300 reports first=50, last=300.
    #[test]
    fn test_jni_boundary_first_last_crossing_step() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "jni-worker"));
        analyzer.feed_jni_call(make_jni_call(50, 1, JNICallDirection::JavaToNative, "C", "m", 0x2000));
        analyzer.feed_jni_call(make_jni_call(120, 1, JNICallDirection::NativeToJava, "C", "cb", 0x0));
        analyzer.feed_jni_call(make_jni_call(300, 1, JNICallDirection::JavaToNative, "C", "m2", 0x3000));
        let stats = analyzer.analyze_jni_boundary();
        let s = &stats[0];
        assert_eq!(s.thread_id, 1);
        assert_eq!(s.total_crossings, 3);
        assert_eq!(s.first_crossing_step, Some(50));
        assert_eq!(s.last_crossing_step, Some(300));
    }

    /// #119: when crossings are fed out of seq order, first/last still reflect
    /// the globally-earliest/latest seq (jni_calls is BTreeMap-keyed by seq).
    #[test]
    fn test_jni_boundary_first_last_resilient_to_feed_order() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "jni-worker"));
        // Feed latest-first; the BTreeMap must still surface first=10, last=300.
        analyzer.feed_jni_call(make_jni_call(300, 1, JNICallDirection::JavaToNative, "C", "m3", 0x4000));
        analyzer.feed_jni_call(make_jni_call(10, 1, JNICallDirection::JavaToNative, "C", "m1", 0x2000));
        analyzer.feed_jni_call(make_jni_call(120, 1, JNICallDirection::NativeToJava, "C", "cb", 0x0));
        let s = &analyzer.analyze_jni_boundary()[0];
        assert_eq!(s.first_crossing_step, Some(10));
        assert_eq!(s.last_crossing_step, Some(300));
    }

    /// Two JNI calls at the SAME seq on different threads must both be retained
    /// (Vec-per-step), not overwritten.
    #[test]
    fn test_jni_boundary_same_step_multi_thread() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));

        analyzer.feed_jni_call(make_jni_call(100, 1, JNICallDirection::JavaToNative, "A", "m", 0x1000));
        analyzer.feed_jni_call(make_jni_call(100, 2, JNICallDirection::JavaToNative, "B", "m", 0x1000));

        let stats = analyzer.analyze_jni_boundary();
        assert_eq!(stats.len(), 2, "same-seq calls on two threads must both count");
        assert_eq!(stats[0].total_crossings, 1);
        assert_eq!(stats[1].total_crossings, 1);
    }

    /// Output is deterministic: sorted by thread_id regardless of feed order.
    #[test]
    fn test_jni_boundary_sorted_by_thread_id() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(3, "t3"));
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));

        // Feed out of order.
        analyzer.feed_jni_call(make_jni_call(1, 3, JNICallDirection::JavaToNative, "C", "m", 0x30));
        analyzer.feed_jni_call(make_jni_call(2, 1, JNICallDirection::JavaToNative, "A", "m", 0x10));
        analyzer.feed_jni_call(make_jni_call(3, 2, JNICallDirection::NativeToJava, "B", "m", 0x20));

        let ids: Vec<u32> = analyzer.analyze_jni_boundary().iter().map(|s| s.thread_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    /// A thread with crossings but no registered `ThreadInfo` still appears
    /// (default `is_jni_attached = false`), so JNI activity is never dropped
    /// just because thread metadata was missing.
    #[test]
    fn test_jni_boundary_unknown_thread_defaults_unattached() {
        let mut analyzer = ThreadAnalyzer::new();
        // No feed_thread_info for thread 9.
        analyzer.feed_jni_call(make_jni_call(5, 9, JNICallDirection::JavaToNative, "X", "y", 0x99));

        let stats = analyzer.analyze_jni_boundary();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].thread_id, 9);
        assert!(!stats[0].is_jni_attached);
        assert_eq!(stats[0].total_crossings, 1);
    }

    // ------------------------------------------------------------------------
    // #109: SyncEventType three-way classification — semaphore / futex /
    // condvar / barrier coverage. Before #109 the four inline match arms
    // (lock_order, is_lock_held_at, analyze_lock_contention,
    // analyze_critical_sections) only listed Mutex*/RwLock* (and BarrierWait
    // erroneously in lock_order). Semaphore acquire was counted without a
    // paired release, futex-backed locks were entirely missed, and BarrierWait
    // leaked into exclusive_locks while is_lock_held_at never recognized it —
    // a self-contradiction. These tests pin the corrected behavior and guard
    // against the direction-A regression (treating BarrierWait/CondvarWait as
    // holdable acquires, which fabricates ever-increasing depth → false
    // deadlocks).
    // ------------------------------------------------------------------------

    /// Helper mirroring `hold_ev` but allowing a non-Success result and a wait
    /// duration, needed for the futex-timeout and contention tests below.
    fn sync_ev(
        step: u64,
        tid: u32,
        addr: u64,
        ty: SyncEventType,
        res: SyncResult,
        wait_ns: Option<u64>,
    ) -> ThreadSyncEvent {
        ThreadSyncEvent {
            step,
            thread_id: tid,
            sync_type: ty,
            sync_object_addr: addr,
            result: res,
            wait_duration_ns: wait_ns,
        }
    }
