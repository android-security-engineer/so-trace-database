// Unidbg trace adapter.
//
// Unidbg exposes tracing as Java callbacks rather than a stable, versioned
// file format.  The recommended integration is therefore to have the
// callback write one JSON object per line and import it with `jsonl`:
//
// ```json
// {"type":"instruction","seq":1,"tid":123,"address":"0x71001000"}
// {"type":"memory_read","seq":2,"tid":123,"address":"0x71002000","size":4}
// ```
//
// The `text` variant also accepts the human-readable output produced by
// Unidbg's `AssemblyCodeDumper` and `TraceMemoryHook`.  Text output does not
// carry a reliable OS thread id, so it is assigned to thread 1 unless a
// `tid`/`thread_id` prefix is present.  This is deliberately best-effort;
// applications that need thread-accurate analysis should use JSONL.

use crate::adapters::{
    build_call_trace, call_event_type_from_str, jni_direction_from_str, parse_addr, to_so_offset,
    ImportStats, ParseError, TraceAdapter, TraceEvent,
};
use crate::models::instruction_trace::InstructionTrace;
use crate::models::jni_call::{JNICall, JNICallDirection};
use crate::models::register_delta::RegisterDelta;
use crate::models::thread::{
    ContextSwitch, SwitchReason, SyncEventType, SyncResult, ThreadInfo, ThreadState,
    ThreadStateChange, ThreadSyncEvent,
};
use serde_json::Value;
use std::collections::HashSet;
use std::io::{BufRead, Cursor};

/// Unidbg callback/text trace adapter.
pub struct UnidbgAdapter;

impl UnidbgAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UnidbgAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceAdapter for UnidbgAdapter {
    fn name(&self) -> &str {
        "unidbg"
    }

    fn supported_trace_types(&self) -> &[&str] {
        &["jsonl", "text"]
    }

    fn parse(
        &self,
        trace_type: &str,
        input: &str,
        so_base_addr: u64,
    ) -> Result<(Vec<TraceEvent>, ImportStats), ParseError> {
        let mut events = Vec::new();
        let stats = self.parse_reader(
            trace_type,
            &mut Cursor::new(input.as_bytes()),
            so_base_addr,
            &mut |event| {
                events.push(event);
                Ok(())
            },
        )?;
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

        let mut parser = UnidbgParser {
            trace_type,
            so_base_addr,
            next_seq: 0,
            seen_threads: HashSet::new(),
            stats: ImportStats::default(),
            sink,
        };
        let mut line = String::new();
        let mut line_no = 0;
        loop {
            line.clear();
            if reader.read_line(&mut line).map_err(ParseError::io)? == 0 {
                break;
            }
            line_no += 1;
            parser.parse_line(&line, line_no)?;
        }
        Ok(parser.stats)
    }
}

struct UnidbgParser<'a> {
    trace_type: &'a str,
    so_base_addr: u64,
    next_seq: u64,
    seen_threads: HashSet<u32>,
    stats: ImportStats,
    sink: &'a mut dyn FnMut(TraceEvent) -> Result<(), ParseError>,
}

impl UnidbgParser<'_> {
    fn emit(&mut self, event: TraceEvent) -> Result<(), ParseError> {
        self.stats.record(&event);
        (self.sink)(event)
    }

    fn ensure_thread(&mut self, tid: u32, create_step: u64, jni_attached: bool) -> Result<(), ParseError> {
        if tid != 0 && self.seen_threads.insert(tid) {
            self.emit(TraceEvent::Thread(ThreadInfo {
                thread_id: tid,
                pthread_id: None,
                parent_thread_id: 0,
                create_step: create_step,
                exit_step: None,
                name: None,
                stack_base: 0,
                stack_size: 0,
                tls_addr: 0,
                is_jni_attached: jni_attached,
            }))?;
        }
        Ok(())
    }

    fn emit_with_thread(&mut self, event: TraceEvent, jni_attached: bool) -> Result<(), ParseError> {
        if !matches!(&event, TraceEvent::Thread(_)) {
            if let Some(tid) = event.thread_id() {
                self.ensure_thread(tid, event.step(), jni_attached)?;
            }
        }
        if matches!(&event, TraceEvent::Thread(_)) {
            if let TraceEvent::Thread(thread) = &event {
                self.seen_threads.insert(thread.thread_id);
            }
        }
        self.emit(event)
    }

    fn allocate_seq(&mut self, obj: &Value) -> u64 {
        let seq = get(obj, &["seq", "sequence", "step"])
            .and_then(|value| parse_addr(Some(value)))
            .unwrap_or(self.next_seq);
        if seq >= self.next_seq {
            self.next_seq = seq.saturating_add(1);
        }
        seq
    }

    fn parse_line(&mut self, raw_line: &str, line_no: usize) -> Result<(), ParseError> {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            return Ok(());
        }

        if self.trace_type == "jsonl" {
            let value: Value = match serde_json::from_str(trimmed) {
                Ok(value) => value,
                Err(error) => {
                    self.stats.skipped += 1;
                    tracing::debug!(line = line_no, error = %error, "unidbg: invalid JSONL");
                    return Ok(());
                }
            };
            let value = unwrap_message(value);
            let seq = self.allocate_seq(&value);
            match parse_json_event(&value, seq, self.so_base_addr) {
                Ok(Some((event, jni_attached))) => self.emit_with_thread(event, jni_attached)?,
                Ok(None) | Err(_) => {
                    self.stats.skipped += 1;
                    tracing::debug!(line = line_no, "unidbg: unsupported or incomplete JSON event");
                }
            }
        } else {
            match parse_text_event(trimmed, self.next_seq, self.so_base_addr) {
                Some((event, jni_attached)) => {
                    self.next_seq = self.next_seq.max(event.step().saturating_add(1));
                    self.emit_with_thread(event, jni_attached)?;
                }
                None => {
                    self.stats.skipped += 1;
                    tracing::debug!(line = line_no, "unidbg: unsupported text line");
                }
            }
        }
        Ok(())
    }
}

/// Unwrap the common host-side `send({ payload: ... })` shape used by trace
/// scripts.  It is harmless for a bare event object.
fn unwrap_message(mut value: Value) -> Value {
    loop {
        let ty = value.get("type").and_then(Value::as_str).unwrap_or("");
        if ty.eq_ignore_ascii_case("send") || ty.eq_ignore_ascii_case("message") {
            if let Some(payload) = value.get("payload").cloned() {
                value = payload;
                continue;
            }
        }
        break value;
    }
}

fn get<'a>(obj: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| obj.get(*name))
}

fn event_type(obj: &Value) -> String {
    get(obj, &["event", "kind", "type"])
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase()
        .replace(['-', ' ', '.'], "_")
}

fn thread_id(obj: &Value) -> Option<u32> {
    parse_addr(get(obj, &["tid", "thread_id", "threadId", "thread"]))
        .map(|value| value as u32)
}

fn address(obj: &Value, names: &[&str]) -> Option<u64> {
    parse_addr(get(obj, names))
}

fn timestamp(obj: &Value) -> Option<u64> {
    parse_addr(get(obj, &["timestamp", "time_ns", "time"]))
}

fn parse_json_event(
    obj: &Value,
    seq: u64,
    so_base_addr: u64,
) -> Result<Option<(TraceEvent, bool)>, String> {
    let ty = event_type(obj);
    let tid = thread_id(obj).unwrap_or(0);
    let result = match ty.as_str() {
        "instruction" | "inst" | "code" => {
            let tid = required_tid(obj)?;
            let pc = address(obj, &["address", "pc"])
                .ok_or_else(|| "instruction missing address".to_string())?;
            let is_branch = get(obj, &["is_branch", "branch"])
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let branch_taken = get(obj, &["branch_taken", "taken"])
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some((TraceEvent::Instruction(InstructionTrace {
                seq,
                thread_id: tid,
                address: to_so_offset(pc, so_base_addr),
                timestamp: timestamp(obj),
                is_branch,
                branch_taken,
                opcode: get(obj, &["opcode", "bytes", "machine_code"]).and_then(parse_bytes),
            }), false))
        }
        "memory_read" | "mem_read" | "read" => {
            let tid = required_tid(obj)?;
            let addr = address(obj, &["address", "addr"])
                .ok_or_else(|| "memory read missing address".to_string())?;
            let size = get(obj, &["size", "length", "len"])
                .and_then(|value| parse_addr(Some(value)))
                .or_else(|| get(obj, &["data"]).and_then(parse_bytes).map(|v| v.len() as u64))
                .unwrap_or(1) as usize;
            Some((TraceEvent::MemoryRead {
                step: seq,
                thread_id: tid,
                address: to_so_offset(addr, so_base_addr),
                size,
            }, false))
        }
        "memory_write" | "mem_write" | "write" => {
            let tid = required_tid(obj)?;
            let addr = address(obj, &["address", "addr"])
                .ok_or_else(|| "memory write missing address".to_string())?;
            let size = get(obj, &["size", "length", "len"])
                .and_then(|value| parse_addr(Some(value)))
                .map(|v| v as usize);
            let data = get(obj, &["data", "bytes"])
                .and_then(parse_bytes)
                .or_else(|| get(obj, &["value"]).and_then(|v| value_bytes(v, size)))
                .unwrap_or_default();
            let data = match size {
                Some(size) if data.len() > size => data[..size].to_vec(),
                Some(size) if data.len() < size => {
                    let mut padded = data;
                    padded.resize(size, 0);
                    padded
                }
                _ => data,
            };
            Some((TraceEvent::MemoryWrite {
                step: seq,
                thread_id: tid,
                address: to_so_offset(addr, so_base_addr),
                data,
            }, false))
        }
        "call" | "function_call" | "on_call" | "onenter" | "enter" | "return" | "ret"
        | "function_return" | "post_call" | "postcall" | "leave" => {
            let tid = required_tid(obj)?;
            let event_label = if ty == "post_call" || ty == "postcall" {
                "return"
            } else {
                ty.as_str()
            };
            let event_type = call_event_type_from_str(event_label)
                .ok_or_else(|| format!("invalid call event '{event_label}'"))?;
            let caller = address(obj, &["caller", "from", "caller_address"]).unwrap_or(0);
            let callee = address(obj, &["callee", "target", "to", "address", "callee_address"])
                .unwrap_or(0);
            let depth = get(obj, &["depth", "stack_depth"])
                .and_then(|value| parse_addr(Some(value)))
                .unwrap_or(0) as u16;
            Some((TraceEvent::Call(build_call_trace(
                seq,
                tid,
                event_type,
                to_so_offset(caller, so_base_addr),
                to_so_offset(callee, so_base_addr),
                depth,
            )), false))
        }
        "thread" | "thread_start" | "thread_create" => {
            let tid = required_tid(obj)?;
            Some((TraceEvent::Thread(ThreadInfo {
                thread_id: tid,
                pthread_id: address(obj, &["pthread_id", "pthread"]),
                parent_thread_id: address(obj, &["parent_thread_id", "parent"])
                    .unwrap_or(0) as u32,
                create_step: get(obj, &["create_step", "step"])
                    .and_then(|value| parse_addr(Some(value)))
                    .unwrap_or(seq),
                exit_step: get(obj, &["exit_step"]).and_then(|value| parse_addr(Some(value))),
                name: get(obj, &["name"]).and_then(Value::as_str).map(str::to_owned),
                stack_base: address(obj, &["stack_base"]).unwrap_or(0),
                stack_size: address(obj, &["stack_size"]).unwrap_or(0),
                tls_addr: address(obj, &["tls_addr", "tls"]).unwrap_or(0),
                is_jni_attached: get(obj, &["is_jni_attached", "jni_attached"])
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }), false))
        }
        "jni" | "jni_call" => {
            let tid = required_tid(obj)?;
            Some((parse_jni(obj, seq, tid, so_base_addr)?, true))
        }
        "sync" | "synchronization" => {
            let tid = required_tid(obj)?;
            Some((parse_sync(obj, seq, tid)?, false))
        }
        "switch" | "context_switch" | "context" => {
            let to_thread = required_tid(obj)?;
            let from_thread = address(obj, &["from_thread", "from", "previous_thread"])
                .ok_or_else(|| "context switch missing from_thread".to_string())? as u32;
            let reason = get(obj, &["reason"])
                .and_then(Value::as_str)
                .and_then(parse_switch_reason)
                .unwrap_or(SwitchReason::Other);
            Some((TraceEvent::ContextSwitch(ContextSwitch {
                step: seq,
                from_thread,
                to_thread,
                switch_reason: reason,
                cpu_core: get(obj, &["cpu_core", "cpu"])
                    .and_then(|value| parse_addr(Some(value)))
                    .map(|v| v as u32),
            }), false))
        }
        "state" | "state_change" | "thread_state" => {
            let tid = required_tid(obj)?;
            let state = get(obj, &["new_state", "state"])
                .and_then(Value::as_str)
                .and_then(parse_thread_state)
                .ok_or_else(|| "state change missing new_state".to_string())?;
            Some((TraceEvent::StateChange(ThreadStateChange {
                step: seq,
                thread_id: tid,
                new_state: state,
                prev_state: get(obj, &["prev_state", "previous_state"])
                    .and_then(Value::as_str)
                    .and_then(parse_thread_state),
                prev_running_thread: address(obj, &["prev_running_thread"])
                    .map(|v| v as u32),
            }), false))
        }
        "register" | "register_delta" => {
            let mask = get(obj, &["change_mask", "mask"])
                .and_then(|value| parse_addr(Some(value)))
                .ok_or_else(|| "register delta missing change_mask".to_string())?;
            let values = get(obj, &["values"])
                .and_then(|v| v.as_array())
                .map(|values| values.iter().filter_map(|v| parse_addr(Some(v))).collect())
                .unwrap_or_default();
            Some((TraceEvent::Register(RegisterDelta { seq, change_mask: mask, values }), false))
        }
        _ => None,
    };
    // Keep this local binding so the early `tid` extraction documents that a
    // JSON event may omit it only when it is an unsupported event.
    let _ = tid;
    Ok(result)
}

fn required_tid(obj: &Value) -> Result<u32, String> {
    thread_id(obj).ok_or_else(|| "event missing tid/thread_id".to_string())
}

fn parse_jni(obj: &Value, seq: u64, tid: u32, base: u64) -> Result<TraceEvent, String> {
    let direction = get(obj, &["direction"])
        .and_then(Value::as_str)
        .and_then(jni_direction_from_str)
        .or_else(|| {
            get(obj, &["jni_type", "type"])
                .and_then(Value::as_str)
                .and_then(|s| match s.to_ascii_lowercase().as_str() {
                    "j2n" | "java2native" => Some(JNICallDirection::JavaToNative),
                    "n2j" | "native2java" => Some(JNICallDirection::NativeToJava),
                    _ => None,
                })
        })
        .ok_or_else(|| "jni event missing direction".to_string())?;
    Ok(TraceEvent::JniCall(JNICall {
        id: 0,
        seq,
        thread_id: tid,
        direction,
        java_class: get(obj, &["java_class", "class"])
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        java_method: get(obj, &["java_method", "method"])
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        java_signature: get(obj, &["java_signature", "signature"])
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        native_func_id: get(obj, &["native_func_id"])
            .and_then(|value| parse_addr(Some(value)))
            .map(|v| v as u32),
        native_address: to_so_offset(
            address(obj, &["native_address", "address", "pc"]).unwrap_or(0),
            base,
        ),
        jni_env_address: address(obj, &["jni_env_address", "jni_env", "env"]),
    }))
}
