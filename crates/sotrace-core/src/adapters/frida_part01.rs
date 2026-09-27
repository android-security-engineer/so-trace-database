// Frida trace adapter
//
// Parses trace data from Frida Stalker, Interceptor, and jnitrace outputs.
//
// All three tools, when used with `send()`, emit newline-delimited JSON where
// each line is a wrapper object. Two wrapper shapes are supported:
//
// 1. Frida host-side `recv`/message format:
//    `{"type": "send", "payload": { ...actual event... }}`
// 2. Bare event objects written directly to a file (one JSON object per line):
//    `{ "type": "inst", "tid": 123, "pc": "0x1234", ... }`
//
// The adapter unwraps `payload` if present, then dispatches on the inner
// `type` field.
//
// # Event type mapping
//
// | Inner `type`       | TraceEvent        | Format        |
// |--------------------|-------------------|---------------|
// | `inst` / `instruction` | Instruction    | Stalker       |
// | `call` / `enter`   | Call(Call)        | Interceptor   |
// | `return` / `ret`   | Call(Return)      | Interceptor   |
// | `mem` / `memwrite` | MemoryWrite       | Stalker/custom|
// | `memread`          | MemoryRead        | Stalker/custom|
// | `sync`             | Sync              | custom        |
// | `switch`           | ContextSwitch     | custom        |
// | `thread`           | Thread            | custom        |
// | jnitrace `async` message | JniCall     | jnitrace      |

use crate::adapters::{
    build_call_trace, call_event_type_from_str, jni_direction_from_str, parse_addr, to_so_offset,
    ImportStats, ParseError, TraceAdapter, TraceEvent,
};
use crate::models::instruction_trace::InstructionTrace;
use crate::models::jni_call::{JNICall, JNICallDirection};
use crate::models::thread::{
    ContextSwitch, SyncEventType, SyncResult, ThreadInfo, ThreadSyncEvent,
};
use serde_json::Value;
use std::collections::HashSet;
use std::io::{BufRead, Cursor};

/// Frida trace adapter — parses Stalker / Interceptor / jnitrace outputs.
pub struct FridaAdapter;

impl FridaAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FridaAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceAdapter for FridaAdapter {
    fn name(&self) -> &str {
        "frida"
    }

    fn supported_trace_types(&self) -> &[&str] {
        &["stalker", "interceptor", "jnitrace"]
    }

    fn parse(
        &self,
        trace_type: &str,
        input: &str,
        so_base_addr: u64,
    ) -> Result<(Vec<TraceEvent>, ImportStats), ParseError> {
        let mut events = Vec::new();
        let mut reader = Cursor::new(input.as_bytes());
        let stats = self.parse_reader(trace_type, &mut reader, so_base_addr, &mut |event| {
            events.push(event);
            Ok(())
        })?;
        Ok((events, stats))
    }

    fn parse_reader(
        &self,
        trace_type: &str,
        reader: &mut dyn BufRead,
        so_base_addr: u64,
        sink: &mut dyn FnMut(TraceEvent) -> Result<(), ParseError>,
    ) -> Result<ImportStats, ParseError> {
        if !self.supported_trace_types().contains(&trace_type) {
            return Err(ParseError::UnknownTraceType(
                trace_type.to_string(),
                self.supported_trace_types().join(", "),
            ));
        }

        let mut stats = ImportStats::default();
        let mut next_seq = 0;
        let mut seen_threads = HashSet::new();
        let mut line = String::new();
        let mut line_no = 0;

        loop {
            line.clear();
            if reader.read_line(&mut line).map_err(ParseError::io)? == 0 {
                break;
            }
            line_no += 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            let wrapper: Value = match serde_json::from_str(trimmed) {
                Ok(value) => value,
                Err(error) => {
                    stats.skipped += 1;
                    tracing::debug!(line = line_no, error = %error, "skipping unparseable line");
                    continue;
                }
            };
            let event_obj = if wrapper.get("type").and_then(|v| v.as_str()) == Some("send") {
                wrapper.get("payload").cloned().unwrap_or(Value::Null)
            } else {
                wrapper
            };

            let events = match parse_one(&event_obj, so_base_addr, &mut next_seq) {
                Ok(events) => events,
                Err(reason) => {
                    stats.skipped += 1;
                    tracing::debug!(line = line_no, reason = %reason, "skipping line");
                    continue;
                }
            };

            for event in events {
                // Generated announcements are emitted immediately before the
                // first event for a thread. Keeping this as the single
                // implementation used by both parse APIs ensures that the
                // buffered and streaming paths produce identical sequences.
                if let Some(tid) = event.thread_id() {
                    if tid != 0 && seen_threads.insert(tid) {
                        if !matches!(&event, TraceEvent::Thread(_)) {
                            let announcement = TraceEvent::Thread(ThreadInfo {
                                thread_id: tid,
                                pthread_id: None,
                                parent_thread_id: 0,
                                create_step: event.step(),
                                exit_step: None,
                                name: None,
                                stack_base: 0,
                                stack_size: 0,
                                tls_addr: 0,
                                is_jni_attached: trace_type == "jnitrace",
                            });
                            stats.record(&announcement);
                            sink(announcement)?;
                        }
                    }
                }
                stats.record(&event);
                sink(event)?;
            }
        }

        Ok(stats)
    }
}

/// Parse a single event JSON object. Returns a Vec because some inputs (a
/// jnitrace `{"type":"async","payload":[...]}` line) carry multiple records,
/// each yielding its own event. Err for malformed lines.
fn parse_one(
    obj: &Value,
    so_base_addr: u64,
    next_seq: &mut u64,
) -> Result<Vec<TraceEvent>, String> {
    let ty = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    // jnitrace wraps events in {"type":"async","payload":[...]} where the
    // thread id lives inside the payload, not on the wrapper. Handle this
    // before the common tid extraction below.
    if ty == "async" || ty == "jnitrace" {
        return parse_jnitrace(obj, so_base_addr, next_seq);
    }

    let seq = obj
        .get("seq")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| {
            let s = *next_seq;
            *next_seq += 1;
            s
        });
    if seq >= *next_seq {
        *next_seq = seq + 1;
    }
    let tid = parse_addr(obj.get("tid").or_else(|| obj.get("thread_id")))
        .ok_or_else(|| "missing 'tid'/'thread_id'".to_string())? as u32;

    match ty {
        "inst" | "instruction" => parse_instruction(obj, seq, tid, so_base_addr).map(|e| vec![e]),
        "call" | "enter" | "onenter" | "return" | "ret" | "leave" | "onleave" | "tailcall" => {
            parse_call(obj, seq, tid, so_base_addr).map(|e| vec![e])
        }
        "mem" | "memwrite" | "write" => parse_mem_write(obj, seq, tid, so_base_addr).map(|e| vec![e]),
        "memread" | "read" => parse_mem_read(obj, seq, tid, so_base_addr).map(|e| vec![e]),
        "sync" => parse_sync(obj, seq, tid).map(|e| vec![e]),
        "switch" => parse_switch(obj, seq, tid).map(|e| vec![e]),
        "thread" => parse_thread(obj, seq, tid).map(|e| vec![e]),
        _ => {
            // Unknown type: if it looks like a jnitrace record (has java class
            // / method fields), parse as jni; otherwise skip.
            if obj.get("class").is_some() || obj.get("java_class").is_some() {
                parse_jni_call(obj, seq, tid, so_base_addr).map(|e| vec![e])
            } else {
                Err(format!("unknown event type '{}'", ty))
            }
        }
    }
}

fn parse_instruction(
    obj: &Value,
    seq: u64,
    tid: u32,
    so_base_addr: u64,
) -> Result<TraceEvent, String> {
    let pc = parse_addr(obj.get("pc").or_else(|| obj.get("address")))
        .ok_or_else(|| "instruction missing 'pc'/'address'".to_string())?;
    let address = to_so_offset(pc, so_base_addr);
    let is_branch = obj.get("is_branch").and_then(|v| v.as_bool()).unwrap_or(false);
    let branch_taken = obj.get("branch_taken").and_then(|v| v.as_bool()).unwrap_or(false);
    let timestamp = obj.get("timestamp").and_then(|v| v.as_u64());
    let opcode = obj
        .get("opcode")
        .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok());
    Ok(TraceEvent::Instruction(InstructionTrace {
        seq,
        thread_id: tid,
        address,
        timestamp,
        is_branch,
        branch_taken,
        opcode,
    }))
}

fn parse_call(obj: &Value, seq: u64, tid: u32, so_base_addr: u64) -> Result<TraceEvent, String> {
    let ty_str = obj.get("type").and_then(|v| v.as_str()).unwrap_or("call");
    let event_type = call_event_type_from_str(ty_str)
        .ok_or_else(|| format!("invalid call type '{}'", ty_str))?;
    let caller = parse_addr(obj.get("caller").or_else(|| obj.get("from")))
        .unwrap_or(0);
    let callee = parse_addr(obj.get("callee").or_else(|| obj.get("target")).or_else(|| obj.get("to")))
        .ok_or_else(|| "call missing 'callee'/'target'".to_string())?;
    let depth = obj.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    Ok(TraceEvent::Call(build_call_trace(
        seq,
        tid,
        event_type,
        to_so_offset(caller, so_base_addr),
        to_so_offset(callee, so_base_addr),
        depth,
    )))
}

fn parse_mem_write(
    obj: &Value,
    seq: u64,
    tid: u32,
    so_base_addr: u64,
) -> Result<TraceEvent, String> {
    let addr = parse_addr(obj.get("address").or_else(|| obj.get("addr")))
        .ok_or_else(|| "memwrite missing 'address'".to_string())?;
    let address = to_so_offset(addr, so_base_addr);
    let data: Vec<u8> = obj
        .get("data")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .or_else(|| {
            // Allow "value" as a single byte/u32
            obj.get("value").and_then(|v| parse_addr(Some(v))).map(|v| v.to_le_bytes().to_vec())
        })
        .unwrap_or_default();
    Ok(TraceEvent::MemoryWrite {
        step: seq,
        thread_id: tid,
        address,
        data,
    })
}

fn parse_mem_read(
    obj: &Value,
    seq: u64,
    tid: u32,
    so_base_addr: u64,
) -> Result<TraceEvent, String> {
    let addr = parse_addr(obj.get("address").or_else(|| obj.get("addr")))
        .ok_or_else(|| "memread missing 'address'".to_string())?;
    let size = obj.get("size").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
    Ok(TraceEvent::MemoryRead {
        step: seq,
        thread_id: tid,
        address: to_so_offset(addr, so_base_addr),
        size,
    })
}

fn parse_sync(obj: &Value, seq: u64, tid: u32) -> Result<TraceEvent, String> {
    let sync_type_str = obj
        .get("sync_type")
        .or_else(|| obj.get("op"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "sync missing 'sync_type'/'op'".to_string())?;
    let sync_type = sync_type_from_str(sync_type_str)
        .ok_or_else(|| format!("unknown sync_type '{}'", sync_type_str))?;
    let sync_object_addr = parse_addr(obj.get("sync_object_addr").or_else(|| obj.get("addr")))
        .ok_or_else(|| "sync missing 'sync_object_addr'/'addr'".to_string())?;
    // `result` resolution: a missing field defaults to `Success` (many frida
    // scripts emit only successful acquires and omit `result`), but an
    // *unrecognized* result string must NOT silently become `Success` — that
    // would treat a possible failure (a spelling the adapter doesn't know, e.g.
    // "retry"/"again") as a successful acquire, fabricating a lock hold and
    // potentially a false deadlock edge (see [[thread-analyzer]] #54/#109,
    // where only `Success` acquires build hold state). Default an unknown
    // spelling to `Error` instead: the event survives (so `is_sync_signal`
    // race-suppression still sees it) but it is conservatively NOT a hold.
    let result = match obj.get("result").and_then(|v| v.as_str()) {
        None => SyncResult::Success,
        Some(s) => sync_result_from_str(s).unwrap_or(SyncResult::Error),
    };
    let wait_duration_ns = obj.get("wait_duration_ns").and_then(|v| v.as_u64());
    Ok(TraceEvent::Sync(ThreadSyncEvent {
        step: seq,
        thread_id: tid,
        sync_type,
        sync_object_addr,
        result,
        wait_duration_ns,
    }))
}

fn parse_switch(obj: &Value, seq: u64, to_tid: u32) -> Result<TraceEvent, String> {
    let from_thread = parse_addr(obj.get("from_thread").or_else(|| obj.get("from")))
        .ok_or_else(|| "switch missing 'from_thread'/'from'".to_string())? as u32;
    let reason_str = obj.get("reason").and_then(|v| v.as_str()).unwrap_or("other");
    let switch_reason = switch_reason_from_str(reason_str)
        .ok_or_else(|| format!("unknown switch reason '{}'", reason_str))?;
    let cpu_core = obj.get("cpu_core").and_then(|v| v.as_u64()).map(|v| v as u32);
    Ok(TraceEvent::ContextSwitch(ContextSwitch {
        step: seq,
        from_thread,
        to_thread: to_tid,
        switch_reason,
        cpu_core,
    }))
}

#[allow(dead_code)] // public parsing capability for user-authored trace scripts
fn parse_thread(obj: &Value, _seq: u64, tid: u32) -> Result<TraceEvent, String> {
    let name = obj.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
    let create_step = obj.get("create_step").and_then(|v| v.as_u64()).unwrap_or(0);
    let exit_step = obj.get("exit_step").and_then(|v| v.as_u64());
    let parent = parse_addr(obj.get("parent_thread_id"))
        .unwrap_or(0) as u32;
    Ok(TraceEvent::Thread(ThreadInfo {
        thread_id: tid,
        pthread_id: parse_addr(obj.get("pthread_id")),
        parent_thread_id: parent,
        create_step,
        exit_step,
        name,
        stack_base: parse_addr(obj.get("stack_base")).unwrap_or(0),
        stack_size: parse_addr(obj.get("stack_size")).unwrap_or(0),
        tls_addr: parse_addr(obj.get("tls_addr")).unwrap_or(0),
        is_jni_attached: obj.get("is_jni_attached").and_then(|v| v.as_bool()).unwrap_or(false),
    }))
}

/// jnitrace wraps events in `{"type":"async","payload":[rec1, rec2, ...]}`.
/// We also accept a single bare jnitrace record. Every record in the payload
/// array yields its own event — previously only `payload[0]` survived and the
/// rest were silently dropped (#68).
fn parse_jnitrace(
    obj: &Value,
    so_base_addr: u64,
    next_seq: &mut u64,
) -> Result<Vec<TraceEvent>, String> {
    // Helper: parse one jnitrace record, allocating a seq if absent and
    // advancing next_seq past it.
    let parse_record = |rec: &Value, next_seq: &mut u64| -> Result<TraceEvent, String> {
        let tid = parse_addr(rec.get("tid"))
            .ok_or_else(|| "jnitrace record missing 'tid'".to_string())? as u32;
        let seq = rec.get("seq").and_then(|v| v.as_u64()).unwrap_or_else(|| {
            let s = *next_seq;
            *next_seq += 1;
            s
        });
        if seq >= *next_seq {
            *next_seq = seq + 1;
        }
        parse_jni_call(rec, seq, tid, so_base_addr)
    };

    let Some(payload) = obj.get("payload") else {
        return Ok(Vec::new());
    };

    if let Some(arr) = payload.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for rec in arr {
            out.push(parse_record(rec, next_seq)?);
        }
        return Ok(out);
    }
    // Single record as payload object
    Ok(vec![parse_record(payload, next_seq)?])
}

fn parse_jni_call(
    obj: &Value,
    seq: u64,
    tid: u32,
    so_base_addr: u64,
) -> Result<TraceEvent, String> {
    // jnitrace field names: "class", "method", "signature", "address",
    // "direction" (or "type" == "J2N"/"N2J").
    let direction = obj
        .get("direction")
        .and_then(|v| v.as_str())
        .and_then(jni_direction_from_str)
        .or_else(|| {
            obj.get("type").and_then(|v| v.as_str()).and_then(|t| {
                if t.eq_ignore_ascii_case("J2N") {
                    Some(JNICallDirection::JavaToNative)
                } else if t.eq_ignore_ascii_case("N2J") {
                    Some(JNICallDirection::NativeToJava)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| "jni call missing direction (J2N/N2J)".to_string())?;
    let java_class = obj
        .get("class")
        .or_else(|| obj.get("java_class"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let java_method = obj
        .get("method")
        .or_else(|| obj.get("java_method"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let java_signature = obj
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let native_address = to_so_offset(
        parse_addr(obj.get("address").or_else(|| obj.get("native_address"))).unwrap_or(0),
        so_base_addr,
    );
    let jni_env_address = parse_addr(obj.get("jni_env").or_else(|| obj.get("env")));
    Ok(TraceEvent::JniCall(JNICall {
        id: 0,
        seq,
        thread_id: tid,
        direction,
        java_class,
        java_method,
        java_signature,
        native_func_id: None,
        native_address,
        jni_env_address,
    }))
}
