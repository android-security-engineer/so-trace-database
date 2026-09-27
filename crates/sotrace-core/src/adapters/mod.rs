//! Input adapters for various trace collection tools
//!
//! Adapters convert tool-native trace formats (Frida Stalker, Interceptor,
//! jnitrace, DynamoRIO drcachesim/memtrace, Pin pinatrace, ...) into a uniform
//! [`TraceEvent`] stream. The caller (CLI / MCP / HTTP server) then feeds these
//! events into a `TraceEngine`.
//!
//! This layer lives in `sotrace-core` and deliberately does NOT depend on
//! `sotrace-engine` — it only produces the intermediate representation.

pub mod frida;
pub mod dynamorio;
pub mod pin;
pub mod unidbg;

use std::io::BufRead;

use crate::models::call_trace::{CallEventType, CallTrace};
use crate::models::instruction_trace::InstructionTrace;
use crate::models::jni_call::{JNICall, JNICallDirection};
use crate::models::register_delta::RegisterDelta;
use crate::models::thread::{ContextSwitch, ThreadInfo, ThreadStateChange, ThreadSyncEvent};
use serde::{Deserialize, Serialize};

/// A single normalized trace event produced by an adapter.
///
/// Adapters emit events in chronological order; the consumer assigns final
/// sequence numbers while feeding them to the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TraceEvent {
    /// Thread metadata (emitted once when a thread is first seen)
    Thread(ThreadInfo),
    /// An executed instruction
    Instruction(InstructionTrace),
    /// A register-change delta (bitmask + changed values at a step)
    Register(RegisterDelta),
    /// A function call / return event
    Call(CallTrace),
    /// A JNI boundary crossing
    JniCall(JNICall),
    /// A memory write
    MemoryWrite {
        step: u64,
        thread_id: u32,
        address: u64,
        data: Vec<u8>,
    },
    /// A memory read (feeds the race detector; not persisted as a record)
    MemoryRead {
        step: u64,
        thread_id: u32,
        address: u64,
        size: usize,
    },
    /// A synchronization event (mutex / futex / condvar)
    Sync(ThreadSyncEvent),
    /// A context switch
    ContextSwitch(ContextSwitch),
    /// A thread state change
    StateChange(ThreadStateChange),
}

impl TraceEvent {
    /// The step number associated with this event, if any.
    /// Thread metadata has no step (use create_step).
    pub fn step(&self) -> u64 {
        match self {
            TraceEvent::Thread(t) => t.create_step,
            TraceEvent::Instruction(i) => i.seq,
            TraceEvent::Register(r) => r.seq,
            TraceEvent::Call(c) => c.seq,
            TraceEvent::JniCall(j) => j.seq,
            TraceEvent::MemoryWrite { step, .. } => *step,
            TraceEvent::MemoryRead { step, .. } => *step,
            TraceEvent::Sync(s) => s.step,
            TraceEvent::ContextSwitch(s) => s.step,
            TraceEvent::StateChange(s) => s.step,
        }
    }

    /// The thread id associated with this event, if any.
    pub fn thread_id(&self) -> Option<u32> {
        match self {
            TraceEvent::Thread(t) => Some(t.thread_id),
            TraceEvent::Instruction(i) => Some(i.thread_id),
            // RegisterDelta carries no thread id (merged onto the global timeline).
            TraceEvent::Register(_) => None,
            TraceEvent::Call(c) => Some(c.thread_id),
            TraceEvent::JniCall(j) => Some(j.thread_id),
            TraceEvent::MemoryWrite { thread_id, .. } => Some(*thread_id),
            TraceEvent::MemoryRead { thread_id, .. } => Some(*thread_id),
            TraceEvent::Sync(s) => Some(s.thread_id),
            TraceEvent::ContextSwitch(s) => Some(s.to_thread),
            TraceEvent::StateChange(s) => Some(s.thread_id),
        }
    }
}

/// Statistics from an adapter parse run.
#[derive(Debug, Default, Clone)]
pub struct ImportStats {
    pub events: usize,
    pub threads: usize,
    pub instructions: usize,
    pub register_deltas: usize,
    pub calls: usize,
    pub jni_calls: usize,
    pub memory_writes: usize,
    pub memory_reads: usize,
    pub sync_events: usize,
    pub context_switches: usize,
    pub state_changes: usize,
    /// Lines / records that were skipped due to parse errors
    pub skipped: usize,
}

impl ImportStats {
    pub fn record(&mut self, event: &TraceEvent) {
        self.events += 1;
        match event {
            TraceEvent::Thread(_) => self.threads += 1,
            TraceEvent::Instruction(_) => self.instructions += 1,
            TraceEvent::Register(_) => self.register_deltas += 1,
            TraceEvent::Call(_) => self.calls += 1,
            TraceEvent::JniCall(_) => self.jni_calls += 1,
            TraceEvent::MemoryWrite { .. } => self.memory_writes += 1,
            TraceEvent::MemoryRead { .. } => self.memory_reads += 1,
            TraceEvent::Sync(_) => self.sync_events += 1,
            TraceEvent::ContextSwitch(_) => self.context_switches += 1,
            TraceEvent::StateChange(_) => self.state_changes += 1,
        }
    }
}

/// Trace adapter trait — all input adapters must implement this.
///
/// Adapters are stateless parsers: given raw trace text (typically
/// newline-delimited JSON from Frida `send()`), they produce a stream of
/// normalized [`TraceEvent`]s.
pub trait TraceAdapter {
    /// Adapter name (e.g. "frida")
    fn name(&self) -> &str;

    /// Supported trace sub-types (e.g. "stalker", "interceptor", "jnitrace")
    fn supported_trace_types(&self) -> &[&str];

    /// Parse raw trace text into normalized events.
    ///
    /// `so_base_addr` is the runtime load address of the target SO; absolute
    /// addresses in the trace are converted to SO-relative offsets by
    /// subtracting this. Pass `0` to keep addresses as-is.
    fn parse(
        &self,
        trace_type: &str,
        input: &str,
        so_base_addr: u64,
    ) -> Result<(Vec<TraceEvent>, ImportStats), ParseError>;

    /// Parse a buffered trace without requiring the complete source text to
    /// remain in memory. The default implementation preserves compatibility
    /// for adapters that have not yet been converted to a line-oriented
    /// parser; adapters with large line-based formats should override it.
    ///
    /// Events are delivered in adapter order. The callback is invoked once
    /// for every normalized event and may stop the import by returning a
    /// [`ParseError`].
    fn parse_reader(
        &self,
        trace_type: &str,
        reader: &mut dyn BufRead,
        so_base_addr: u64,
        sink: &mut dyn FnMut(TraceEvent) -> Result<(), ParseError>,
    ) -> Result<ImportStats, ParseError> {
        let mut input = String::new();
        reader.read_to_string(&mut input).map_err(ParseError::io)?;
        let (events, stats) = self.parse(trace_type, &input, so_base_addr)?;
        for event in events {
            sink(event)?;
        }
        Ok(stats)
    }
}

/// Error from an adapter parse operation.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unknown trace type '{0}' for adapter; supported: {1}")]
    UnknownTraceType(String, String),
    #[error("invalid trace line {line}: {reason}")]
    InvalidLine { line: usize, reason: String },
    #[error("failed to read trace input: {0}")]
    Io(#[from] std::io::Error),
    #[error("trace event sink failed: {0}")]
    Sink(String),
}

impl ParseError {
    fn io(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Extract a u64 from a JSON value that may be a number or a hex/negative
/// string. Frida sometimes serializes 64-bit addresses as strings or as
/// negative numbers (signed reinterpretation of the high bit).
///
/// Accepts `Option<&Value>` for ergonomic chaining with `obj.get(...)`.
pub fn parse_addr(v: Option<&serde_json::Value>) -> Option<u64> {
    let v = v?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(n) = v.as_i64() {
        return Some(n as u64);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16).ok();
        }
        return s.parse::<u64>().ok();
    }
    None
}

/// Convert an absolute runtime address to an SO-relative offset.
pub fn to_so_offset(addr: u64, so_base_addr: u64) -> u64 {
    if so_base_addr == 0 {
        addr
    } else if addr >= so_base_addr {
        addr - so_base_addr
    } else {
        addr
    }
}

/// Map a `CallEventType` from a string label (case-insensitive).
pub fn call_event_type_from_str(s: &str) -> Option<CallEventType> {
    match s.to_ascii_lowercase().as_str() {
        "call" | "enter" | "onenter" => Some(CallEventType::Call),
        "return" | "ret" | "leave" | "onleave" => Some(CallEventType::Return),
        "tailcall" | "tail_call" | "tail-call" => Some(CallEventType::TailCall),
        _ => None,
    }
}

/// Map a `JNICallDirection` from a string label (case-insensitive).
pub fn jni_direction_from_str(s: &str) -> Option<JNICallDirection> {
    match s.to_ascii_lowercase().as_str() {
        "java2native" | "java_to_native" | "j2n" | "enter" => Some(JNICallDirection::JavaToNative),
        "native2java" | "native_to_java" | "n2j" | "leave" => Some(JNICallDirection::NativeToJava),
        _ => None,
    }
}

/// Re-export the CallTrace builder fields needed by adapters via a helper that
/// constructs a CallTrace with sensible defaults for the fields adapters
/// usually cannot infer.
pub fn build_call_trace(
    seq: u64,
    thread_id: u32,
    event_type: CallEventType,
    caller_address: u64,
    callee_address: u64,
    depth: u16,
) -> CallTrace {
    CallTrace {
        id: 0,
        thread_id,
        event_type,
        caller_address,
        callee_address,
        callee_func_id: None,
        seq,
        depth,
        return_seq: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_addr_number() {
        assert_eq!(parse_addr(Some(&json!(0x1000))), Some(0x1000));
    }

    #[test]
    fn test_parse_addr_negative_i64() {
        // High-bit-set address appears as negative i64
        assert_eq!(parse_addr(Some(&json!(-1))), Some(u64::MAX));
    }

    #[test]
    fn test_parse_addr_hex_string() {
        assert_eq!(parse_addr(Some(&json!("0x7fff1234"))), Some(0x7fff1234));
        assert_eq!(parse_addr(Some(&json!("0XABCD"))), Some(0xABCD));
    }

    #[test]
    fn test_parse_addr_decimal_string() {
        assert_eq!(parse_addr(Some(&json!("4096"))), Some(4096));
    }

    #[test]
    fn test_parse_addr_invalid() {
        assert_eq!(parse_addr(Some(&json!("not a number"))), None);
        assert_eq!(parse_addr(Some(&json!(null))), None);
        assert_eq!(parse_addr(None), None);
    }

    #[test]
    fn test_to_so_offset() {
        assert_eq!(to_so_offset(0x7fff1234, 0x7fff0000), 0x1234);
        assert_eq!(to_so_offset(0x1234, 0), 0x1234); // base 0 = passthrough
        assert_eq!(to_so_offset(0x1000, 0x2000), 0x1000); // addr < base = passthrough
    }

    #[test]
    fn test_call_event_type_from_str() {
        assert!(matches!(call_event_type_from_str("call"), Some(CallEventType::Call)));
        assert!(matches!(call_event_type_from_str("onLeave"), Some(CallEventType::Return)));
        assert!(matches!(call_event_type_from_str("tail-call"), Some(CallEventType::TailCall)));
        assert!(call_event_type_from_str("bogus").is_none());
    }

    #[test]
    fn test_jni_direction_from_str() {
        assert!(matches!(jni_direction_from_str("j2n"), Some(JNICallDirection::JavaToNative)));
        assert!(matches!(jni_direction_from_str("n2j"), Some(JNICallDirection::NativeToJava)));
        assert!(jni_direction_from_str("bogus").is_none());
    }

    #[test]
    fn test_import_stats_record() {
        let mut stats = ImportStats::default();
        stats.record(&TraceEvent::Instruction(InstructionTrace {
            seq: 1, thread_id: 1, address: 0x1000, timestamp: None,
            is_branch: false, branch_taken: false, opcode: None,
        }));
        stats.record(&TraceEvent::MemoryWrite { step: 2, thread_id: 1, address: 0x2000, data: vec![1] });
        assert_eq!(stats.events, 2);
        assert_eq!(stats.instructions, 1);
        assert_eq!(stats.memory_writes, 1);
    }
}
