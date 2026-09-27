//! Intel Pin trace adapter.
//!
//! Supports the classic `pinatrace` (Memory Trace) output format:
//!
//! ```text
//! 0x7f2c00000500: read  0x7ffeabcd0010
//! 0x7f2c00000500: write 0x7ffeabcd0020
//! ```
//!
//! Each line is `<tid>: <op> <addr>` where `<tid>` is hex (with optional `0x`
//! prefix), `<op>` is `read`/`write`/`r`/`w`, and `<addr>` is hex. The leading
//! token (before `:`) is the thread id, NOT an instruction pointer — pinatrace
//! records memory accesses, one per line.
//!
//! trace_type `"pinatrace"` produces MemoryRead/MemoryWrite events. An optional
//! `"calls"` trace_type is reserved for Pin call-trace clients that emit
//! `call 0x<caller> -> 0x<callee>` lines (currently parsed best-effort).

use crate::adapters::{ImportStats, ParseError, TraceAdapter, TraceEvent, build_call_trace, to_so_offset};
use crate::models::call_trace::CallEventType;
use std::io::{BufRead, Cursor};

/// Pin trace adapter.
pub struct PinAdapter;

impl PinAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PinAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceAdapter for PinAdapter {
    fn name(&self) -> &str {
        "pin"
    }

    fn supported_trace_types(&self) -> &[&str] {
        &["pinatrace", "calls"]
    }

    fn parse(
        &self,
        trace_type: &str,
        input: &str,
        so_base_addr: u64,
    ) -> Result<(Vec<TraceEvent>, ImportStats), ParseError> {
        let mut events = Vec::new();
        let mut sink = |event| {
            events.push(event);
            Ok(())
        };
        let stats = self.parse_reader(
            trace_type,
            &mut Cursor::new(input.as_bytes()),
            so_base_addr,
            &mut sink,
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
        let mut parser = PinParser {
            trace_type,
            so_base_addr,
            seen_threads: std::collections::HashSet::new(),
            next_step: 0,
            next_seq: 0,
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

struct PinParser<'a> {
    trace_type: &'a str,
    so_base_addr: u64,
    seen_threads: std::collections::HashSet<u32>,
    next_step: u64,
    next_seq: u64,
    stats: ImportStats,
    sink: &'a mut dyn FnMut(TraceEvent) -> Result<(), ParseError>,
}

impl PinParser<'_> {
    fn emit(&mut self, event: TraceEvent) -> Result<(), ParseError> {
        self.stats.record(&event);
        (self.sink)(event)
    }

    fn ensure_thread(&mut self, tid: u32, create_step: u64) -> Result<(), ParseError> {
        if self.seen_threads.insert(tid) {
            self.emit(TraceEvent::Thread(crate::models::thread::ThreadInfo {
                thread_id: tid,
                pthread_id: None,
                parent_thread_id: 0,
                create_step,
                exit_step: None,
                name: None,
                stack_base: 0,
                stack_size: 0,
                tls_addr: 0,
                is_jni_attached: false,
            }))?;
        }
        Ok(())
    }

    fn parse_line(&mut self, raw_line: &str, line_no: usize) -> Result<(), ParseError> {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            return Ok(());
        }

        match self.trace_type {
            "pinatrace" => {
                // Format: "<tid>: <op> <addr>" (tid is hex, may have 0x prefix)
                let (tid_str, rest) = match trimmed.split_once(':') {
                    Some(p) => p,
                    None => {
                        self.stats.skipped += 1;
                        tracing::debug!(line = line_no, "pinatrace: no ':' separator");
                        return Ok(());
                    }
                };
                let tid = match parse_hex_u32(tid_str.trim()) {
                    Some(t) => t,
                    None => {
                        self.stats.skipped += 1;
                        tracing::debug!(line = line_no, "pinatrace: bad tid");
                        return Ok(());
                    }
                };
                let rest_tokens: Vec<&str> = rest.split_whitespace().collect();
                let op = rest_tokens.iter().find_map(|t| {
                    let lt = t.to_ascii_lowercase();
                    match lt.as_str() {
                        "read" | "r" | "load" => Some(false),
                        "write" | "w" | "store" => Some(true),
                        _ => None,
                    }
                });
                let addr = rest_tokens.iter().find_map(|t| parse_hex_u64(t));
                let (Some(is_write), Some(addr)) = (op, addr) else {
                    self.stats.skipped += 1;
                    tracing::debug!(line = line_no, "pinatrace: missing op/addr");
                    return Ok(());
                };

                self.ensure_thread(tid, self.next_step)?;
                let step = self.next_step;
                self.next_step += 1;
                let ev = if is_write {
                    // pinatrace doesn't record the written value/size; emit a
                    // single-byte write so the race detector can still flag
                    // overlapping read/write addresses.
                    TraceEvent::MemoryWrite {
                        step,
                        thread_id: tid,
                        address: to_so_offset(addr, self.so_base_addr),
                        data: vec![0u8],
                    }
                } else {
                    // pinatrace doesn't record access size; assume a single-byte
                    // access so the race detector can still flag overlapping addresses.
                    TraceEvent::MemoryRead {
                        step,
                        thread_id: tid,
                        address: to_so_offset(addr, self.so_base_addr),
                        size: 1,
                    }
                };
                self.emit(ev)?;
            }
            "calls" => {
                // Expected: "tid <hex> call 0x<caller> 0x<callee>"
                // The tid token is the one immediately following a `tid` key.
                let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                let Some(tid) = find_tid_pair(&tokens) else {
                    self.stats.skipped += 1;
                    return Ok(());
                };
                // caller is the first 0x.. token that isn't the tid value;
                // callee is the next one after it.
                let tid_val = tid as u64;
                let mut addr_iter = tokens
                    .iter()
                    .filter_map(|t| parse_hex_u64(t))
                    .filter(|v| *v != tid_val);
                let Some(caller) = addr_iter.next() else {
                    self.stats.skipped += 1;
                    return Ok(());
                };
                let callee = addr_iter.next().unwrap_or(0);
                let event_type = if trimmed.to_ascii_lowercase().contains("ret")
                    || trimmed.to_ascii_lowercase().contains("return")
                {
                    CallEventType::Return
                } else {
                    CallEventType::Call
                };

                self.ensure_thread(tid, self.next_seq)?;
                let seq = self.next_seq;
                self.next_seq += 1;
                self.emit(TraceEvent::Call(build_call_trace(
                    seq,
                    tid,
                    event_type,
                    to_so_offset(caller, self.so_base_addr),
                    to_so_offset(callee, self.so_base_addr),
                    0,
                )))?;
            }
            _ => unreachable!("unsupported trace_type checked above"),
        }
        Ok(())
    }
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.trim().trim_end_matches(':');
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(h, 16).ok();
    }
    // pinatrace tids are always hex even without 0x prefix.
    u32::from_str_radix(s, 16).ok()
}

/// Find a `tid <hex>` token pair (case-insensitive `tid`).
fn find_tid_pair(tokens: &[&str]) -> Option<u32> {
    for i in 0..tokens.len().saturating_sub(1) {
        if tokens[i].eq_ignore_ascii_case("tid") {
            return parse_hex_u32(tokens[i + 1]);
        }
    }
    None
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches(':');
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::TraceAdapter;

    #[test]
    fn test_pinatrace_basic() {
        let input = "0x1f4: read 0x7ffeabcd0010\n\
                     0x1f4: write 0x7ffeabcd0020\n\
                     0x1f5: read 0x7ffeabcd0030\n";
        let (events, stats) = PinAdapter::new().parse("pinatrace", input, 0).unwrap();
        assert_eq!(stats.threads, 2, "two distinct tids (0x1f4, 0x1f5)");
        assert_eq!(stats.memory_reads, 2);
        assert_eq!(stats.memory_writes, 1);
        // tid 0x1f4 = 500
        let r = events.iter().find_map(|e| match e {
            TraceEvent::MemoryRead { thread_id, .. } if *thread_id == 500 => Some(()),
            _ => None,
        });
        assert!(r.is_some());
    }

    #[test]
    fn test_pinatrace_no_0x_tid_prefix() {
        // pinatrace tids are hex with or without 0x.
        let input = "1f4: read 0x1000\n";
        let (events, stats) = PinAdapter::new().parse("pinatrace", input, 0).unwrap();
        assert_eq!(stats.threads, 1);
        assert!(events.iter().any(|e| matches!(e,
            TraceEvent::MemoryRead { thread_id, .. } if *thread_id == 0x1f4)));
    }

    #[test]
    fn test_pinatrace_base_addr() {
        let input = "0x1: read 0x7fff1000\n";
        let (events, _) = PinAdapter::new().parse("pinatrace", input, 0x7fff0000).unwrap();
        let r = events.iter().find_map(|e| match e {
            TraceEvent::MemoryRead { address, .. } => Some(*address),
            _ => None,
        }).unwrap();
        assert_eq!(r, 0x1000);
    }

    #[test]
    fn test_pinatrace_skips_bad_lines() {
        let input = "garbage\n\
                     0x1: read 0x1000\n\
                     not_an_addr: read\n";
        let (_, stats) = PinAdapter::new().parse("pinatrace", input, 0).unwrap();
        assert_eq!(stats.skipped, 2);
        assert_eq!(stats.memory_reads, 1);
    }

    #[test]
    fn test_calls_trace_type() {
        let input = "tid 0x1 call 0x1000 0x2000\n";
        let (events, stats) = PinAdapter::new().parse("calls", input, 0).unwrap();
        assert_eq!(stats.calls, 1);
        let c = events.iter().find_map(|e| match e {
            TraceEvent::Call(c) => Some(c),
            _ => None,
        }).unwrap();
        assert_eq!(c.caller_address, 0x1000);
        assert_eq!(c.callee_address, 0x2000);
    }

    #[test]
    fn test_unknown_trace_type() {
        let err = PinAdapter::new().parse("bogus", "", 0).unwrap_err();
        assert!(matches!(err, ParseError::UnknownTraceType(_, _)));
    }

    #[test]
    fn test_name_and_types() {
        assert_eq!(PinAdapter::new().name(), "pin");
        assert_eq!(PinAdapter::new().supported_trace_types(), &["pinatrace", "calls"]);
    }

    #[test]
    fn test_comments_skipped() {
        let input = "# header comment\n\
                     // inline comment\n\
                     0x1: read 0x1000\n";
        let (_, stats) = PinAdapter::new().parse("pinatrace", input, 0).unwrap();
        assert_eq!(stats.memory_reads, 1);
        assert_eq!(stats.skipped, 0);
    }

    #[test]
    fn test_parse_reader_matches_parse_and_propagates_sink_errors() {
        let input = "0x1: read 0x1000\n0x2: write 0x1004\n";
        let adapter = PinAdapter::new();
        let (expected_events, expected_stats) = adapter.parse("pinatrace", input, 0).unwrap();

        let mut reader = Cursor::new(input.as_bytes());
        let mut streamed_events = Vec::new();
        let streamed_stats = adapter
            .parse_reader("pinatrace", &mut reader, 0, &mut |event| {
                streamed_events.push(event);
                Ok(())
            })
            .unwrap();

        assert_eq!(format!("{streamed_events:?}"), format!("{expected_events:?}"));
        assert_eq!(streamed_stats.events, expected_stats.events);
        assert_eq!(streamed_stats.threads, expected_stats.threads);
        assert_eq!(streamed_stats.memory_reads, expected_stats.memory_reads);
        assert_eq!(streamed_stats.memory_writes, expected_stats.memory_writes);

        let mut reader = Cursor::new(input.as_bytes());
        let result = adapter.parse_reader("pinatrace", &mut reader, 0, &mut |_| {
            Err(ParseError::Sink("stop".into()))
        });
        assert!(matches!(result, Err(ParseError::Sink(message)) if message == "stop"));
    }
}
