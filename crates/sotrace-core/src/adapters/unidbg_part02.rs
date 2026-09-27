
fn parse_sync(obj: &Value, seq: u64, tid: u32) -> Result<TraceEvent, String> {
    let sync_type = get(obj, &["sync_type", "operation", "op"])
        .and_then(Value::as_str)
        .and_then(parse_sync_type)
        .ok_or_else(|| "sync event missing sync_type".to_string())?;
    let sync_object_addr = address(obj, &["sync_object_addr", "object", "addr", "address"])
        .ok_or_else(|| "sync event missing object address".to_string())?;
    let result = get(obj, &["result"])
        .and_then(Value::as_str)
        .and_then(parse_sync_result)
        .unwrap_or(SyncResult::Success);
    Ok(TraceEvent::Sync(ThreadSyncEvent {
        step: seq,
        thread_id: tid,
        sync_type,
        sync_object_addr,
        result,
        wait_duration_ns: get(obj, &["wait_duration_ns", "wait_ns"])
            .and_then(|value| parse_addr(Some(value))),
    }))
}

fn parse_bytes(value: &Value) -> Option<Vec<u8>> {
    if let Some(array) = value.as_array() {
        return Some(array.iter().filter_map(|v| parse_addr(Some(v)).map(|n| n as u8)).collect());
    }
    let s = value.as_str()?.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace() && *c != ':').collect();
    if compact.is_empty() || compact.len() % 2 != 0 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).ok())
        .collect()
}

fn value_bytes(value: &Value, size: Option<usize>) -> Option<Vec<u8>> {
    if let Some(number) = parse_addr(Some(value)) {
        let width = size.unwrap_or(8).min(8);
        return Some(number.to_le_bytes()[..width].to_vec());
    }
    parse_bytes(value)
}

fn parse_text_event(line: &str, seq: u64, base: u64) -> Option<(TraceEvent, bool)> {
    let lower = line.to_ascii_lowercase();
    let tid = find_named_u32(line).unwrap_or(1);
    if lower.contains("memory read") || lower.contains("memory write") {
        let is_write = lower.contains("memory write");
        let addr = after_marker_address(line, "at")?;
        let size = after_marker_number(line, "data size").unwrap_or(1) as usize;
        if is_write {
            let value = after_marker_address(line, "data value");
            let data = value.map(|v| v.to_le_bytes()[..size.min(8)].to_vec()).unwrap_or_else(|| vec![0; size]);
            return Some((TraceEvent::MemoryWrite {
                step: seq,
                thread_id: tid,
                address: to_so_offset(addr, base),
                data,
            }, false));
        }
        return Some((TraceEvent::MemoryRead {
            step: seq,
            thread_id: tid,
            address: to_so_offset(addr, base),
            size,
        }, false));
    }

    // A few custom FunctionCallListener implementations print a simple
    // `call 0xcaller -> 0xcallee`/`return ...` line.  The stock listener is
    // not a stable file protocol, so this intentionally remains permissive.
    if lower.contains(" call ") || lower.starts_with("call ") || lower.contains(" return ") || lower.starts_with("return ") {
        let addresses = all_hex_addresses(line);
        if addresses.len() >= 2 {
            let event_type = if lower.contains("return") { crate::models::call_trace::CallEventType::Return } else { crate::models::call_trace::CallEventType::Call };
            return Some((TraceEvent::Call(build_call_trace(
                seq,
                tid,
                event_type,
                to_so_offset(addresses[0], base),
                to_so_offset(addresses[1], base),
                0,
            )), false));
        }
    }

    // AssemblyCodeDumper prints `<address>: <disassembly>`.  The text after
    // the colon is intentionally not stored as opcode: the model's opcode
    // field means machine-code bytes, while this is a disassembly string.
    let (left, disassembly) = line.split_once(':')?;
    let pc = left.split_whitespace().rev().find_map(parse_text_number)?;
    if disassembly.trim().is_empty() {
        return None;
    }
    Some((TraceEvent::Instruction(InstructionTrace {
        seq,
        thread_id: tid,
        address: to_so_offset(pc, base),
        timestamp: None,
        is_branch: looks_like_branch(disassembly),
        branch_taken: false,
        opcode: None,
    }), false))
}

fn find_named_u32(line: &str) -> Option<u32> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    for pair in tokens.windows(2) {
        if pair[0].trim_end_matches(':').eq_ignore_ascii_case("tid")
            || pair[0].trim_end_matches(':').eq_ignore_ascii_case("thread_id")
        {
            if let Some(value) = parse_text_number(pair[1]) {
                return Some(value as u32);
            }
        }
    }
    None
}

fn after_marker_address(line: &str, marker: &str) -> Option<u64> {
    let lower = line.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    all_hex_addresses(&line[start..]).into_iter().next()
}

fn after_marker_number(line: &str, marker: &str) -> Option<u64> {
    let lower = line.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    let tail = &line[start..];
    tail.split(|c: char| !c.is_ascii_digit() && c != 'x' && c != 'X' && !c.is_ascii_hexdigit())
        .find_map(|part| parse_text_number(part))
}

fn all_hex_addresses(text: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(pos) = lower[offset..].find("0x") {
        let start = offset + pos + 2;
        let end = start + lower[start..].chars().take_while(|c| c.is_ascii_hexdigit()).count();
        if end > start {
            if let Ok(value) = u64::from_str_radix(&lower[start..end], 16) {
                out.push(value);
            }
        }
        offset = end.max(start);
        if offset >= lower.len() {
            break;
        }
    }
    out
}

fn parse_text_number(s: &str) -> Option<u64> {
    let s = s.trim().trim_matches(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X');
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn looks_like_branch(text: &str) -> bool {
    let op = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    op == "bl" || op == "blr" || op == "br" || op == "ret" || op.starts_with('b')
}

fn parse_sync_type(s: &str) -> Option<SyncEventType> {
    match s.to_ascii_lowercase().replace(['-', ' '], "_").as_str() {
        "mutexlock" | "mutex_lock" | "lock" => Some(SyncEventType::MutexLock),
        "mutexlocked" | "mutex_locked" => Some(SyncEventType::MutexLocked),
        "mutexunlock" | "mutex_unlock" | "unlock" => Some(SyncEventType::MutexUnlock),
        "mutextrylock" | "mutex_trylock" | "trylock" => Some(SyncEventType::MutexTryLock),
        "futexwait" | "futex_wait" => Some(SyncEventType::FutexWait),
        "futexwake" | "futex_wake" => Some(SyncEventType::FutexWake),
        "futexwakecount" | "futex_wake_count" => Some(SyncEventType::FutexWakeCount),
        "condvarwait" | "condvar_wait" | "cond_wait" => Some(SyncEventType::CondvarWait),
        "condvarsignal" | "condvar_signal" | "cond_signal" => Some(SyncEventType::CondvarSignal),
        "condvarbroadcast" | "condvar_broadcast" | "cond_broadcast" => Some(SyncEventType::CondvarBroadcast),
        "rwlockread" | "rwlock_read" | "rdlock" => Some(SyncEventType::RwLockRead),
        "rwlockwrite" | "rwlock_write" | "wrlock" => Some(SyncEventType::RwLockWrite),
        "rwlockunlock" | "rwlock_unlock" => Some(SyncEventType::RwLockUnlock),
        "barrierwait" | "barrier_wait" => Some(SyncEventType::BarrierWait),
        "semwait" | "sem_wait" => Some(SyncEventType::SemWait),
        "sempost" | "sem_post" => Some(SyncEventType::SemPost),
        _ => None,
    }
}

fn parse_sync_result(s: &str) -> Option<SyncResult> {
    match s.to_ascii_lowercase().replace(['-', ' '], "_").as_str() {
        "success" | "ok" => Some(SyncResult::Success),
        "timeout" => Some(SyncResult::Timeout),
        "wouldblock" | "would_block" | "busy" => Some(SyncResult::WouldBlock),
        "error" | "failed" => Some(SyncResult::Error),
        "interrupted" => Some(SyncResult::Interrupted),
        _ => None,
    }
}

fn parse_switch_reason(s: &str) -> Option<SwitchReason> {
    match s.to_ascii_lowercase().replace(['-', ' '], "_").as_str() {
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

fn parse_thread_state(s: &str) -> Option<ThreadState> {
    match s.to_ascii_lowercase().replace(['-', ' '], "_").as_str() {
        "running" => Some(ThreadState::Running),
        "runnable" => Some(ThreadState::Runnable),
        "blocked" => Some(ThreadState::Blocked),
        "waitingforlock" | "waiting_for_lock" => Some(ThreadState::WaitingForLock),
        "waitingforfutex" | "waiting_for_futex" => Some(ThreadState::WaitingForFutex),
        "waitingforcondvar" | "waiting_for_condvar" => Some(ThreadState::WaitingForCondvar),
        "waitingforio" | "waiting_for_io" => Some(ThreadState::WaitingForIO),
        "sleeping" => Some(ThreadState::Sleeping),
        "terminated" => Some(ThreadState::Terminated),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::TraceAdapter;

    #[test]
    fn jsonl_parses_callbacks_and_offsets_addresses() {
        let input = concat!(
            r#"{"type":"instruction","seq":10,"tid":7,"address":"0x71001000","opcode":[0,1]}"#, "\n",
            r#"{"type":"memory_read","tid":7,"address":"0x71002000","size":4}"#, "\n",
            r#"{"type":"memory_write","tid":7,"address":"0x71002010","size":2,"value":"0x1234"}"#, "\n",
            r#"{"type":"call","tid":7,"caller":"0x71001004","callee":"0x71001100","depth":2}"#, "\n",
            r#"{"type":"return","tid":7,"caller":"0x71001110","callee":"0x71001100","depth":1}"#, "\n",
        );
        let (events, stats) = UnidbgAdapter::new().parse("jsonl", input, 0x71000000).unwrap();
        assert_eq!(stats.threads, 1);
        assert_eq!(stats.instructions, 1);
        assert_eq!(stats.memory_reads, 1);
        assert_eq!(stats.memory_writes, 1);
        assert_eq!(stats.calls, 2);
        assert!(events.iter().any(|e| matches!(e, TraceEvent::Instruction(i) if i.address == 0x1000 && i.opcode == Some(vec![0, 1]))));
        assert!(events.iter().any(|e| matches!(e, TraceEvent::MemoryWrite { address: 0x2010, data, .. } if data == &vec![0x34, 0x12])));
    }

    #[test]
    fn jsonl_supports_jni_sync_and_explicit_thread() {
        let input = concat!(
            r#"{"type":"thread","tid":9,"name":"worker","create_step":3}"#, "\n",
            r#"{"type":"jni_call","tid":9,"direction":"j2n","java_class":"A","java_method":"f","signature":"()V","native_address":"0x1000"}"#, "\n",
            r#"{"type":"sync","tid":9,"op":"mutex_lock","addr":"0x2000","result":"ok"}"#, "\n",
        );
        let (events, stats) = UnidbgAdapter::new().parse("jsonl", input, 0).unwrap();
        assert_eq!(stats.threads, 1);
        assert_eq!(stats.jni_calls, 1);
        assert_eq!(stats.sync_events, 1);
        assert!(events.iter().any(|e| matches!(e, TraceEvent::Thread(t) if t.name.as_deref() == Some("worker"))));
    }

    #[test]
    fn text_parses_stock_unidbg_lines() {
        let input = "0x71001000: mov x0, x1\nMemory READ at 0x71002000, data size = 4, data value = 0x12, PC=0x71001000, LR=0x71001100\nMemory WRITE at 0x71002004, data size = 2, data value = 0xabcd, PC=0x71001004, LR=0\n";
        let (events, stats) = UnidbgAdapter::new().parse("text", input, 0x71000000).unwrap();
        assert_eq!(stats.instructions, 1);
        assert_eq!(stats.memory_reads, 1);
        assert_eq!(stats.memory_writes, 1);
        assert!(events.iter().any(|e| matches!(e, TraceEvent::MemoryRead { address: 0x2000, size: 4, .. })));
        assert!(events.iter().any(|e| matches!(e, TraceEvent::MemoryWrite { address: 0x2004, data, .. } if data == &vec![0xcd, 0xab])));
    }

    #[test]
    fn parse_reader_matches_parse() {
        let input = "{\"type\":\"instruction\",\"tid\":1,\"address\":\"0x1000\"}\n";
        let adapter = UnidbgAdapter::new();
        let (expected, expected_stats) = adapter.parse("jsonl", input, 0).unwrap();
        let mut streamed = Vec::new();
        let stats = adapter.parse_reader("jsonl", &mut Cursor::new(input), 0, &mut |event| {
            streamed.push(event);
            Ok(())
        }).unwrap();
        assert_eq!(format!("{streamed:?}"), format!("{expected:?}"));
        assert_eq!(stats.events, expected_stats.events);
        assert_eq!(stats.threads, expected_stats.threads);
    }

    #[test]
    fn unknown_type_errors() {
        assert!(matches!(UnidbgAdapter::new().parse("other", "", 0), Err(ParseError::UnknownTraceType(_, _))));
    }
}
