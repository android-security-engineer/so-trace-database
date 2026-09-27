
fn sync_type_from_str(s: &str) -> Option<SyncEventType> {
    match s.to_ascii_lowercase().as_str() {
        "mutexlock" | "mutex_lock" | "lock" => Some(SyncEventType::MutexLock),
        "mutexlocked" | "mutex_locked" => Some(SyncEventType::MutexLocked),
        "mutexunlock" | "mutex_unlock" | "unlock" => Some(SyncEventType::MutexUnlock),
        "mutextrylock" | "mutex_trylock" | "trylock" => Some(SyncEventType::MutexTryLock),
        "futexwait" | "futex_wait" => Some(SyncEventType::FutexWait),
        "futexwake" | "futex_wake" => Some(SyncEventType::FutexWake),
        "futexwakecount" | "futex_wake_count" | "futexwake_count" => {
            Some(SyncEventType::FutexWakeCount)
        }
        "condvarwait" | "cond_wait" | "condwait" => Some(SyncEventType::CondvarWait),
        "condvarsignal" | "cond_signal" | "condsignal" => Some(SyncEventType::CondvarSignal),
        "condvarbroadcast" | "cond_broadcast" | "condbroadcast" => {
            Some(SyncEventType::CondvarBroadcast)
        }
        "rwlockread" | "rwlock_read" | "rdlock" => Some(SyncEventType::RwLockRead),
        "rwlockwrite" | "rwlock_write" | "wrlock" => Some(SyncEventType::RwLockWrite),
        "rwlockunlock" | "rwlock_unlock" => Some(SyncEventType::RwLockUnlock),
        "barrierwait" | "barrier_wait" => Some(SyncEventType::BarrierWait),
        "semwait" | "sem_wait" => Some(SyncEventType::SemWait),
        "sempost" | "sem_post" => Some(SyncEventType::SemPost),
        _ => None,
    }
}

fn sync_result_from_str(s: &str) -> Option<SyncResult> {
    match s.to_ascii_lowercase().as_str() {
        "success" | "ok" => Some(SyncResult::Success),
        "timeout" => Some(SyncResult::Timeout),
        "wouldblock" | "would_block" | "busy" => Some(SyncResult::WouldBlock),
        "error" | "failed" => Some(SyncResult::Error),
        "interrupted" => Some(SyncResult::Interrupted),
        _ => None,
    }
}

fn switch_reason_from_str(s: &str) -> Option<crate::models::thread::SwitchReason> {
    use crate::models::thread::SwitchReason;
    match s.to_ascii_lowercase().as_str() {
        "yield" => Some(SwitchReason::Yield),
        "preemption" | "preempt" => Some(SwitchReason::Preemption),
        "blocking" | "block" => Some(SwitchReason::Blocking),
        "interrupt" => Some(SwitchReason::Interrupt),
        "timeslice" | "time_slice" | "timesliceexpired" => Some(SwitchReason::TimeSliceExpired),
        "migration" | "migrate" => Some(SwitchReason::Migration),
        "other" | "unknown" => Some(SwitchReason::Other),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::TraceAdapter;
    use std::io::{self, BufRead, Cursor, Read};

    #[test]
    fn test_parse_stalker_instructions() {
        let input = r#"{"type":"inst","tid":100,"pc":"0x7fff1000"}
{"type":"inst","tid":100,"pc":"0x7fff1004","is_branch":true,"branch_taken":true}
{"type":"send","payload":{"type":"inst","tid":101,"pc":"0x7fff2000"}}"#;
        let (events, stats) = FridaAdapter.parse("stalker", input, 0x7fff0000).unwrap();
        // 3 instructions + 2 thread announcements (tid 100, 101)
        assert_eq!(stats.instructions, 3);
        assert_eq!(stats.threads, 2);
        assert!(stats.skipped == 0);
        // Addresses converted to SO-relative offsets
        let instrs: Vec<&InstructionTrace> = events.iter().filter_map(|e| match e {
            TraceEvent::Instruction(i) => Some(i),
            _ => None,
        }).collect();
        assert_eq!(instrs[0].address, 0x1000);
        assert_eq!(instrs[1].address, 0x1004);
        assert_eq!(instrs[1].is_branch, true);
        assert_eq!(instrs[2].address, 0x2000);
        assert_eq!(instrs[2].thread_id, 101);
    }

    #[test]
    fn test_parse_interceptor_calls() {
        let input = r#"{"type":"call","tid":1,"caller":"0x100","callee":"0x200","depth":0}
{"type":"return","tid":1,"caller":"0x200","callee":"0x104","depth":1}"#;
        let (events, stats) = FridaAdapter.parse("interceptor", input, 0).unwrap();
        assert_eq!(stats.calls, 2);
        let calls: Vec<_> = events.iter().filter_map(|e| match e {
            TraceEvent::Call(c) => Some(c.clone()),
            _ => None,
        }).collect();
        assert_eq!(calls.len(), 2);
        assert!(matches!(calls[0].event_type, crate::models::call_trace::CallEventType::Call));
        assert!(matches!(calls[1].event_type, crate::models::call_trace::CallEventType::Return));
        assert_eq!(calls[0].callee_address, 0x200);
    }

    #[test]
    fn test_parse_jnitrace_records() {
        let input = r#"{"type":"async","payload":[{"tid":200,"type":"J2N","class":"com.example.App","method":"nativeFunc","signature":"()V","address":"0x3000","env":"0x7f00"}]}"#;
        let (events, stats) = FridaAdapter.parse("jnitrace", input, 0).unwrap();
        assert_eq!(stats.jni_calls, 1);
        let jni: Vec<_> = events.iter().filter_map(|e| match e {
            TraceEvent::JniCall(j) => Some(j.clone()),
            _ => None,
        }).collect();
        assert_eq!(jni.len(), 1);
        assert_eq!(jni[0].java_class, "com.example.App");
        assert_eq!(jni[0].java_method, "nativeFunc");
        assert!(matches!(jni[0].direction, JNICallDirection::JavaToNative));
        assert_eq!(jni[0].native_address, 0x3000);
        // jnitrace threads are marked JNI-attached
        let thread_ev = events.iter().find(|e| matches!(e, TraceEvent::Thread(_)));
        assert!(matches!(thread_ev, Some(TraceEvent::Thread(t)) if t.is_jni_attached));
    }

    #[test]
    fn test_parse_jnitrace_multi_record_payload() {
        // A single jnitrace async line whose payload array carries THREE
        // records (jnitrace emits one JSON object per line, but a payload
        // array can batch several records). The old parser took only
        // payload[0] and dropped the rest.
        let input = r#"{"type":"async","payload":[{"tid":200,"type":"J2N","class":"com.example.App","method":"a","signature":"()V","address":"0x3000","env":"0x7f00"},{"tid":201,"type":"N2J","class":"com.example.Bar","method":"b","signature":"()I","address":"0x4000","env":"0x7f01"},{"tid":200,"type":"J2N","class":"com.example.App","method":"c","signature":"()V","address":"0x5000","env":"0x7f00"}]}"#;
        let (events, stats) = FridaAdapter.parse("jnitrace", input, 0).unwrap();
        assert_eq!(stats.jni_calls, 3, "all three payload records must be emitted");
        let jni: Vec<_> = events.iter().filter_map(|e| match e {
            TraceEvent::JniCall(j) => Some(j.clone()),
            _ => None,
        }).collect();
        assert_eq!(jni.len(), 3);
        // Records preserved in payload order.
        assert_eq!(jni[0].java_method, "a");
        assert_eq!(jni[1].java_method, "b");
        assert_eq!(jni[2].java_method, "c");
        // Distinct native addresses all survive (relevant for #67 jni-boundary).
        let addrs: std::collections::HashSet<u64> = jni.iter().map(|j| j.native_address).collect();
        assert_eq!(addrs.len(), 3);
    }

    #[test]
    fn test_parse_memory_events() {
        let input = r#"{"type":"memwrite","tid":1,"address":"0x1000","data":[255,255,255,255]}
{"type":"memread","tid":2,"address":"0x1000","size":4}"#;
        let (events, stats) = FridaAdapter.parse("stalker", input, 0).unwrap();
        assert_eq!(stats.memory_writes, 1);
        assert_eq!(stats.memory_reads, 1);
        let mw = events.iter().find_map(|e| match e {
            TraceEvent::MemoryWrite { address, data, .. } => Some((*address, data.clone())),
            _ => None,
        }).unwrap();
        assert_eq!(mw.0, 0x1000);
        assert_eq!(mw.1, vec![255, 255, 255, 255]);
    }

    #[test]
    fn test_parse_sync_events() {
        let input = r#"{"type":"sync","tid":1,"sync_type":"MutexLock","sync_object_addr":"0xABCD0000","result":"Success"}
{"type":"sync","tid":2,"sync_type":"MutexLock","sync_object_addr":"0xABCD0000","result":"Success","wait_duration_ns":1500}"#;
        let (events, stats) = FridaAdapter.parse("stalker", input, 0).unwrap();
        assert_eq!(stats.sync_events, 2);
        let syncs: Vec<_> = events.iter().filter_map(|e| match e {
            TraceEvent::Sync(s) => Some(s.clone()),
            _ => None,
        }).collect();
        assert_eq!(syncs.len(), 2);
        assert!(matches!(syncs[0].sync_type, SyncEventType::MutexLock));
        assert_eq!(syncs[1].wait_duration_ns, Some(1500));
    }

    /// Every `SyncEventType` variant must be reachable from at least one
    /// spelling in `sync_type_from_str` — a frida script that emits an
    /// unmapped spelling silently drops the sync event (the `_ => None` arm),
    /// which for futex/sem/condvar/barrier would undo the analyzer's
    /// three-way-classification coverage (#109). This pins the full mapping,
    /// including `FutexWakeCount` (added alongside #109's `is_sync_signal`).
    #[test]
    fn test_sync_type_from_str_covers_all_variants() {
        // (spelling, expected variant) — one canonical spelling each.
        let cases: &[(&str, SyncEventType)] = &[
            ("mutexlock", SyncEventType::MutexLock),
            ("mutexlocked", SyncEventType::MutexLocked),
            ("mutexunlock", SyncEventType::MutexUnlock),
            ("mutextrylock", SyncEventType::MutexTryLock),
            ("futexwait", SyncEventType::FutexWait),
            ("futexwake", SyncEventType::FutexWake),
            ("futexwakecount", SyncEventType::FutexWakeCount),
            ("condvarwait", SyncEventType::CondvarWait),
            ("condvarsignal", SyncEventType::CondvarSignal),
            ("condvarbroadcast", SyncEventType::CondvarBroadcast),
            ("rwlockread", SyncEventType::RwLockRead),
            ("rwlockwrite", SyncEventType::RwLockWrite),
            ("rwlockunlock", SyncEventType::RwLockUnlock),
            ("barrierwait", SyncEventType::BarrierWait),
            ("semwait", SyncEventType::SemWait),
            ("sempost", SyncEventType::SemPost),
        ];
        for &(spelling, expected) in cases {
            assert_eq!(
                sync_type_from_str(spelling),
                Some(expected),
                "spelling {:?} must map to {:?}",
                spelling,
                expected
            );
        }
        // Snake_case variants work too (frida scripts use either style).
        assert_eq!(sync_type_from_str("futex_wake_count"), Some(SyncEventType::FutexWakeCount));
        // Unknown spellings resolve to None (the drop path).
        assert_eq!(sync_type_from_str("not_a_real_sync_type"), None);
    }

    /// An unrecognized `result` string must NOT silently become `Success` —
    /// that would treat a possible failure as a successful acquire, building a
    /// phantom lock hold (see [[thread-analyzer]] #54/#109: only `Success`
    /// acquires hold). The adapter must default an unknown spelling to `Error`
    /// (conservative non-hold) while a *missing* `result` field stays `Success`
    /// (frida scripts commonly omit it for successful acquires).
    #[test]
    fn test_parse_sync_unknown_result_defaults_to_error_not_success() {
        // Missing result field → Success (backward-compatible default).
        let input = r#"{"type":"sync","tid":1,"sync_type":"mutexlock","sync_object_addr":"0x1000"}"#;
        let (events, _) = FridaAdapter.parse("stalker", input, 0).unwrap();
        let s = events.iter().find_map(|e| match e {
            TraceEvent::Sync(s) => Some(s.clone()),
            _ => None,
        }).unwrap();
        assert!(matches!(s.result, SyncResult::Success), "missing result defaults to Success");

        // Unknown result spelling → Error (NOT Success), so it is not treated as held.
        let input = r#"{"type":"sync","tid":1,"sync_type":"mutexlock","sync_object_addr":"0x1000","result":"retry"}"#;
        let (events, _) = FridaAdapter.parse("stalker", input, 0).unwrap();
        let s = events.iter().find_map(|e| match e {
            TraceEvent::Sync(s) => Some(s.clone()),
            _ => None,
        }).unwrap();
        assert!(matches!(s.result, SyncResult::Error), "unknown result spelling must default to Error, not Success");

        // Known result spellings still resolve correctly.
        let input = r#"{"type":"sync","tid":1,"sync_type":"mutexlock","sync_object_addr":"0x1000","result":"timeout"}"#;
        let (events, _) = FridaAdapter.parse("stalker", input, 0).unwrap();
        let s = events.iter().find_map(|e| match e {
            TraceEvent::Sync(s) => Some(s.clone()),
            _ => None,
        }).unwrap();
        assert!(matches!(s.result, SyncResult::Timeout));
    }

    #[test]
    fn test_parse_context_switch() {
        let input = r#"{"type":"switch","tid":2,"from_thread":1,"reason":"preemption","cpu_core":0}"#;
        let (events, stats) = FridaAdapter.parse("stalker", input, 0).unwrap();
        assert_eq!(stats.context_switches, 1);
        let sw = events.iter().find_map(|e| match e {
            TraceEvent::ContextSwitch(s) => Some(s.clone()),
            _ => None,
        }).unwrap();
        assert_eq!(sw.from_thread, 1);
        assert_eq!(sw.to_thread, 2);
        assert!(matches!(sw.switch_reason, crate::models::thread::SwitchReason::Preemption));
    }

    #[test]
    fn test_unknown_trace_type_errors() {
        let result = FridaAdapter.parse("dynamorio", "{}", 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ParseError::UnknownTraceType(_, _)));
    }

    #[test]
    fn test_skips_invalid_lines() {
        let input = "not json at all\n{\"type\":\"inst\",\"tid\":1,\"pc\":\"0x1000\"}\n// comment\n";
        let (events, stats) = FridaAdapter.parse("stalker", input, 0).unwrap();
        assert_eq!(stats.instructions, 1);
        assert_eq!(stats.skipped, 1); // "not json at all"
        assert!(events.iter().any(|e| matches!(e, TraceEvent::Instruction(_))));
    }

    #[test]
    fn test_empty_input() {
        let (events, stats) = FridaAdapter.parse("stalker", "", 0).unwrap();
        assert!(events.is_empty());
        assert_eq!(stats.events, 0);
    }

    #[test]
    fn test_auto_assigned_seq_monotonic() {
        // When seq is absent, the adapter assigns monotonically increasing seqs.
        let input = r#"{"type":"inst","tid":1,"pc":"0x1000"}
{"type":"inst","tid":1,"pc":"0x1004"}
{"type":"inst","tid":1,"pc":"0x1008"}"#;
        let (events, _) = FridaAdapter.parse("stalker", input, 0).unwrap();
        let seqs: Vec<u64> = events.iter().filter_map(|e| match e {
            TraceEvent::Instruction(i) => Some(i.seq),
            _ => None,
        }).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
    }

    #[test]
    fn test_thread_announcement_dedup() {
        // Multiple events from the same thread should yield only one Thread event.
        let input = r#"{"type":"inst","tid":7,"pc":"0x1000"}
{"type":"inst","tid":7,"pc":"0x1004"}
{"type":"inst","tid":7,"pc":"0x1008"}"#;
        let (events, stats) = FridaAdapter.parse("stalker", input, 0).unwrap();
        assert_eq!(stats.threads, 1);
        let thread_count = events.iter().filter(|e| matches!(e, TraceEvent::Thread(_))).count();
        assert_eq!(thread_count, 1);
    }

    #[test]
    fn test_parse_and_parse_reader_have_identical_thread_semantics() {
        let input = concat!(
            "{\"type\":\"inst\",\"seq\":10,\"tid\":7,\"pc\":\"0x1010\"}\n",
            "{\"type\":\"thread\",\"tid\":8,\"name\":\"worker\",\"create_step\":11}\n",
            "{\"type\":\"inst\",\"seq\":12,\"tid\":8,\"pc\":\"0x1014\"}\n",
        );
        let (buffered, buffered_stats) = FridaAdapter.parse("stalker", input, 0x1000).unwrap();
        let mut reader = Cursor::new(input.as_bytes());
        let mut streamed = Vec::new();
        let streamed_stats = FridaAdapter
            .parse_reader("stalker", &mut reader, 0x1000, &mut |event| {
                streamed.push(event);
                Ok(())
            })
            .unwrap();

        assert_eq!(
            serde_json::to_value(&buffered).unwrap(),
            serde_json::to_value(&streamed).unwrap(),
            "buffered and streaming adapters must emit the same event sequence",
        );
        assert_eq!(buffered_stats.events, streamed_stats.events);
        assert_eq!(buffered_stats.threads, streamed_stats.threads);
        assert_eq!(buffered_stats.instructions, streamed_stats.instructions);
        assert_eq!(buffered_stats.skipped, streamed_stats.skipped);
        assert_eq!(
            streamed.iter().filter(|event| matches!(event, TraceEvent::Thread(_))).count(),
            2,
            "an explicit thread announcement must not be duplicated",
        );
    }

    #[test]
    fn test_parse_reader_streams_events_and_tracks_stats() {
        let input = concat!(
            "{\"type\":\"inst\",\"seq\":10,\"tid\":7,\"pc\":\"0x1010\"}\n",
            "not json\n",
            "{\"type\":\"memwrite\",\"seq\":11,\"tid\":7,\"address\":\"0x1020\",\"data\":[1,2]}\n",
            "{\"type\":\"memread\",\"seq\":12,\"tid\":8,\"address\":\"0x1030\",\"size\":4}\n",
        );
        let mut reader = Cursor::new(input.as_bytes());
        let mut events = Vec::new();
        let stats = FridaAdapter
            .parse_reader("stalker", &mut reader, 0x1000, &mut |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();

        // A generated Thread event is emitted immediately before the first
        // event for each thread, so the callback never needs the full input.
        assert_eq!(events.len(), 5);
        assert!(matches!(events[0], TraceEvent::Thread(ref t) if t.thread_id == 7 && t.create_step == 10));
        assert!(matches!(events[1], TraceEvent::Instruction(ref i) if i.seq == 10 && i.address == 0x10));
        assert!(matches!(events[2], TraceEvent::MemoryWrite { step: 11, thread_id: 7, address: 0x20, ref data } if data == &vec![1, 2]));
        assert!(matches!(events[3], TraceEvent::Thread(ref t) if t.thread_id == 8 && t.create_step == 12));
        assert!(matches!(events[4], TraceEvent::MemoryRead { step: 12, thread_id: 8, address: 0x30, size: 4 }));
        assert_eq!(stats.events, 5);
        assert_eq!(stats.threads, 2);
        assert_eq!(stats.instructions, 1);
        assert_eq!(stats.memory_writes, 1);
        assert_eq!(stats.memory_reads, 1);
        assert_eq!(stats.skipped, 1);
    }

    #[test]
    fn test_parse_reader_emits_all_jnitrace_payload_records() {
        let input = r#"{"type":"async","payload":[{"tid":200,"type":"J2N","class":"App","method":"a","signature":"()V","address":"0x3000","env":"0x7f00"},{"tid":201,"type":"N2J","class":"Bar","method":"b","signature":"()I","address":"0x4000","env":"0x7f01"}]}"#;
        let mut reader = Cursor::new(input.as_bytes());
        let mut events = Vec::new();
        let stats = FridaAdapter
            .parse_reader("jnitrace", &mut reader, 0, &mut |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();

        assert_eq!(stats.jni_calls, 2);
        assert_eq!(stats.threads, 2);
        let jni: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                TraceEvent::JniCall(call) => Some(call),
                _ => None,
            })
            .collect();
        assert_eq!(jni.len(), 2);
        assert_eq!(jni[0].java_method, "a");
        assert_eq!(jni[1].java_method, "b");
        assert!(jni.iter().all(|call| call.thread_id == 200 || call.thread_id == 201));
        assert!(events.iter().any(|event| matches!(event, TraceEvent::Thread(t) if t.thread_id == 200 && t.is_jni_attached)));
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "test reader failure"))
        }
    }

    impl BufRead for FailingReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "test reader failure"))
        }

        fn consume(&mut self, _amt: usize) {}
    }

    #[test]
    fn test_parse_reader_propagates_reader_errors() {
        let mut reader = FailingReader;
        let result = FridaAdapter.parse_reader("stalker", &mut reader, 0, &mut |_| Ok(()));
        assert!(matches!(result, Err(ParseError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof));
    }
}
