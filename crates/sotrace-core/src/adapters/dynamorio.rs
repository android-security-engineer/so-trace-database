//! DynamoRIO trace adapter.
//!
//! Supports two common DynamoRIO client output styles, selected by trace_type:
//!
//! - `"drcachesim"`: instruction-stream records from a custom client, one per
//!   line, TSV/whitespace-separated. Recognized line shapes:
//!     `tid <tid> pc 0x<hex> [branch|call|ret]`
//!     `<tid> 0x<hex> <disasm...>`        (compact form, optional)
//!   The first token, if it parses as a u32, is treated as the thread id;
//!   otherwise a `tid` field is looked for.
//!
//! - `"memtrace"`: memory-access records, one per line:
//!     `tid <tid> <read|write> 0x<addr> 0x<size>`
//!
//! Lines starting with `#` or `//` are comments and skipped. Unknown line
//! shapes are counted as skipped (not fatal).
//!
//! The adapter is intentionally lenient: real DynamoRIO clients emit a wide
//! variety of column layouts, so we parse by "find the recognizable tokens"
//! rather than by rigid column positions.

use std::io::{BufRead, Cursor};

use crate::adapters::{ImportStats, ParseError, TraceAdapter, TraceEvent, to_so_offset};
use crate::models::instruction_trace::InstructionTrace;

/// DynamoRIO trace adapter.
pub struct DynamoRioAdapter;

impl DynamoRioAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DynamoRioAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceAdapter for DynamoRioAdapter {
    fn name(&self) -> &str {
        "dynamorio"
    }

    fn supported_trace_types(&self) -> &[&str] {
        &["drcachesim", "memtrace"]
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

        let mut parser = DynamoRioParser {
            trace_type,
            so_base_addr,
            seen_threads: std::collections::HashSet::new(),
            next_seq: 0,
            next_step: 0,
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

struct DynamoRioParser<'a> {
    trace_type: &'a str,
    so_base_addr: u64,
    seen_threads: std::collections::HashSet<u32>,
    next_seq: u64,
    next_step: u64,
    stats: ImportStats,
    sink: &'a mut dyn FnMut(TraceEvent) -> Result<(), ParseError>,
}

impl DynamoRioParser<'_> {
    fn emit(&mut self, event: TraceEvent) -> Result<(), ParseError> {
        self.stats.record(&event);
        (self.sink)(event)
    }

    fn ensure_thread(&mut self, tid: u32) -> Result<(), ParseError> {
        if tid == 0 || !self.seen_threads.insert(tid) {
            return Ok(());
        }
        self.emit(TraceEvent::Thread(crate::models::thread::ThreadInfo {
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
        }))
    }

    fn parse_line(&mut self, raw_line: &str, line_no: usize) -> Result<(), ParseError> {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            return Ok(());
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            return Ok(());
        }
        let tid = find_tid(&tokens).or_else(|| {
            tokens[0]
                .parse::<u32>()
                .ok()
                .or_else(|| parse_hex_u32(tokens[0]))
        });

        match self.trace_type {
            "drcachesim" => {
                let pc = find_pc(&tokens, tid);
                if let (Some(tid), Some(pc)) = (tid, pc) {
                    self.ensure_thread(tid)?;
                    let is_branch = tokens.iter().any(|t| {
                        let lt = t.to_ascii_lowercase();
                        matches!(lt.as_str(),
                            "branch" | "call" | "ret" | "return" | "jmp" | "jmpq" |
                            "je" | "jne" | "jz" | "jnz" | "jb" | "ja" | "jl" | "jg" |
                            "jle" | "jge" | "callq" | "retq")
                    });
                    let taken = is_branch
                        && tokens.iter().any(|t| t.eq_ignore_ascii_case("taken"));
                    let ev = TraceEvent::Instruction(InstructionTrace {
                        seq: self.next_seq,
                        thread_id: tid,
                        address: to_so_offset(pc, self.so_base_addr),
                        timestamp: None,
                        is_branch,
                        branch_taken: taken,
                        opcode: disasm_after_pc(&tokens),
                    });
                    self.next_seq += 1;
                    self.emit(ev)?;
                } else {
                    self.stats.skipped += 1;
                    tracing::debug!(line = line_no, "drcachesim: no tid/pc");
                }
            }
            "memtrace" => {
                let op = tokens.iter().find_map(|t| {
                    let lt = t.to_ascii_lowercase();
                    match lt.as_str() {
                        "read" | "r" | "load" => Some(false),
                        "write" | "w" | "store" => Some(true),
                        _ => None,
                    }
                });
                let addr = find_addr_token(&tokens, tid);
                let size = find_size_token(&tokens);
                if let (Some(tid), Some(is_write), Some(addr), Some(size)) =
                    (tid, op, addr, size)
                {
                    self.ensure_thread(tid)?;
                    let step = self.next_step;
                    self.next_step += 1;
                    let ev = if is_write {
                        TraceEvent::MemoryWrite {
                            step,
                            thread_id: tid,
                            address: to_so_offset(addr, self.so_base_addr),
                            data: vec![0; size],
                        }
                    } else {
                        TraceEvent::MemoryRead {
                            step,
                            thread_id: tid,
                            address: to_so_offset(addr, self.so_base_addr),
                            size,
                        }
                    };
                    self.emit(ev)?;
                } else {
                    self.stats.skipped += 1;
                    tracing::debug!(line = line_no, "memtrace: missing fields");
                }
            }
            _ => unreachable!("unsupported trace_type checked above"),
        }
        Ok(())
    }
}

/// Find a `tid <n>` token pair (case-insensitive `tid`/`thread`).
fn find_tid(tokens: &[&str]) -> Option<u32> {
    for i in 0..tokens.len().saturating_sub(1) {
        let key = tokens[i].to_ascii_lowercase();
        if key == "tid" || key == "thread" || key == "tid:" {
            return parse_int_u32(tokens[i + 1]);
        }
    }
    None
}

/// Find a `pc 0x..` token pair (case-insensitive `pc`/`addr`).
fn find_pc(tokens: &[&str], tid: Option<u32>) -> Option<u64> {
    for i in 0..tokens.len().saturating_sub(1) {
        let key = tokens[i].to_ascii_lowercase();
        if key == "pc" || key == "pc:" || key == "addr" || key == "address" {
            return parse_int_u64(tokens[i + 1]);
        }
    }
    // Fallback: first 0x.. token that isn't the tid itself.
    let tid_v = tid.map(|t| t as u64);
    for t in tokens {
        if let Some(v) = parse_hex_u64(t) {
            if Some(v) != tid_v {
                return Some(v);
            }
        }
    }
    None
}

/// Find the first 0x.. token usable as an address (excluding the tid token).
fn find_addr_token(tokens: &[&str], tid: Option<u32>) -> Option<u64> {
    let tid_v = tid.map(|t| t as u64);
    for t in tokens {
        if let Some(v) = parse_hex_u64(t) {
            if Some(v) != tid_v {
                return Some(v);
            }
        }
    }
    None
}

/// Find a `size 0x..` pair, or the last 0x.. token.
fn find_size_token(tokens: &[&str]) -> Option<usize> {
    for i in 0..tokens.len().saturating_sub(1) {
        let key = tokens[i].to_ascii_lowercase();
        if key == "size" || key == "size:" || key == "len" {
            return parse_int_usize(tokens[i + 1]);
        }
    }
    // Fallback: last numeric token.
    tokens.iter().rev().find_map(|t| parse_int_usize(t))
}

/// Concatenate any tokens after the pc token as a disassembly byte string.
fn disasm_after_pc(tokens: &[&str]) -> Option<Vec<u8>> {
    let pc_idx = tokens
        .iter()
        .position(|t| t.eq_ignore_ascii_case("pc") || t.eq_ignore_ascii_case("addr"))?;
    let rest: Vec<&str> = tokens.iter().skip(pc_idx + 2).copied().collect();
    if rest.is_empty() {
        return None;
    }
    Some(rest.join(" ").into_bytes())
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.trim().trim_end_matches(':');
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(h, 16).ok();
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

fn parse_int_u32(s: &str) -> Option<u32> {
    let s = s.trim().trim_end_matches(':');
    parse_hex_u32(s).or_else(|| s.parse::<u32>().ok())
}

fn parse_int_u64(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches(':');
    parse_hex_u64(s).or_else(|| s.parse::<u64>().ok())
}

fn parse_int_usize(s: &str) -> Option<usize> {
    let s = s.trim().trim_end_matches(':');
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return usize::from_str_radix(h, 16).ok();
    }
    s.parse::<usize>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::TraceAdapter;

    #[test]
    fn test_drcachesim_basic() {
        let input = "tid 100 pc 0x1000\n\
                     tid 100 pc 0x1004 call\n\
                     tid 100 pc 0x1008 ret\n\
                     # comment\n\
                     tid 200 pc 0x2000\n";
        let (events, stats) = DynamoRioAdapter::new()
            .parse("drcachesim", input, 0)
            .unwrap();
        // 2 Thread infos + 4 instructions
        assert_eq!(stats.threads, 2);
        assert_eq!(stats.instructions, 4);
        assert_eq!(stats.skipped, 0);
        // First instruction at 0x1000, tid 100
        let inst = events.iter().find_map(|e| match e {
            TraceEvent::Instruction(i) if i.address == 0x1000 => Some(i),
            _ => None,
        }).expect("first instruction");
        assert_eq!(inst.thread_id, 100);
        assert!(!inst.is_branch);
        // The call line is a branch.
        let call_inst = events.iter().find_map(|e| match e {
            TraceEvent::Instruction(i) if i.address == 0x1004 => Some(i),
            _ => None,
        }).unwrap();
        assert!(call_inst.is_branch);
    }

    #[test]
    fn test_drcachesim_base_addr_conversion() {
        let input = "tid 1 pc 0x7fff1000\n";
        let (events, _) = DynamoRioAdapter::new()
            .parse("drcachesim", input, 0x7fff0000)
            .unwrap();
        let inst = events.iter().find_map(|e| match e {
            TraceEvent::Instruction(i) => Some(i),
            _ => None,
        }).unwrap();
        assert_eq!(inst.address, 0x1000);
    }

    #[test]
    fn test_drcachesim_compact_form() {
        // Compact form: leading numeric tid, bare 0x pc.
        let input = "100 0x1000\n100 0x1004\n";
        let (events, stats) = DynamoRioAdapter::new()
            .parse("drcachesim", input, 0)
            .unwrap();
        assert_eq!(stats.instructions, 2);
        assert_eq!(stats.threads, 1);
        assert_eq!(events.iter().filter(|e| matches!(e, TraceEvent::Instruction(_))).count(), 2);
    }

    #[test]
    fn test_memtrace_read_write() {
        let input = "tid 1 read 0x1000 0x4\n\
                     tid 1 write 0x2000 0x8\n";
        let (events, stats) = DynamoRioAdapter::new()
            .parse("memtrace", input, 0)
            .unwrap();
        assert_eq!(stats.memory_reads, 1);
        assert_eq!(stats.memory_writes, 1);
        let r = events.iter().find_map(|e| match e {
            TraceEvent::MemoryRead { address, size, .. } if *address == 0x1000 => Some(size),
            _ => None,
        }).unwrap();
        assert_eq!(*r, 4);
        let w = events.iter().find_map(|e| match e {
            TraceEvent::MemoryWrite { address, data, .. } if *address == 0x2000 => Some(data.len()),
            _ => None,
        }).unwrap();
        assert_eq!(w, 8);
    }

    #[test]
    fn test_unknown_trace_type_errors() {
        let err = DynamoRioAdapter::new().parse("bogus", "", 0).unwrap_err();
        assert!(matches!(err, ParseError::UnknownTraceType(_, _)));
    }

    #[test]
    fn test_skips_unrecognized_lines() {
        let input = "garbage line with no tokens\n\
                     tid 1 pc 0x1000\n";
        let (_, stats) = DynamoRioAdapter::new()
            .parse("drcachesim", input, 0)
            .unwrap();
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.instructions, 1);
    }

    #[test]
    fn test_supported_types() {
        assert_eq!(DynamoRioAdapter::new().name(), "dynamorio");
        assert_eq!(
            DynamoRioAdapter::new().supported_trace_types(),
            &["drcachesim", "memtrace"]
        );
    }

    #[test]
    fn test_disasm_captured() {
        let input = "tid 1 pc 0x1000 mov rax, rbx\n";
        let (events, _) = DynamoRioAdapter::new()
            .parse("drcachesim", input, 0)
            .unwrap();
        let inst = events.iter().find_map(|e| match e {
            TraceEvent::Instruction(i) => Some(i),
            _ => None,
        }).unwrap();
        assert_eq!(inst.opcode.as_deref(), Some(&b"mov rax, rbx"[..]));
    }

    #[test]
    fn test_parse_reader_matches_parse_and_propagates_sink_errors() {
        let input = "tid 1 pc 0x1000\ntid 2 write 0x2000 4\n";
        let adapter = DynamoRioAdapter::new();
        let (expected_events, expected_stats) = adapter.parse("drcachesim", input, 0).unwrap();

        let mut reader = Cursor::new(input.as_bytes());
        let mut streamed_events = Vec::new();
        let streamed_stats = adapter
            .parse_reader("drcachesim", &mut reader, 0, &mut |event| {
                streamed_events.push(event);
                Ok(())
            })
            .unwrap();

        assert_eq!(format!("{streamed_events:?}"), format!("{expected_events:?}"));
        assert_eq!(streamed_stats.events, expected_stats.events);
        assert_eq!(streamed_stats.threads, expected_stats.threads);
        assert_eq!(streamed_stats.instructions, expected_stats.instructions);
        assert_eq!(streamed_stats.skipped, expected_stats.skipped);

        let mut reader = Cursor::new(input.as_bytes());
        let result = adapter.parse_reader("drcachesim", &mut reader, 0, &mut |_| {
            Err(ParseError::Sink("stop".into()))
        });
        assert!(matches!(result, Err(ParseError::Sink(message)) if message == "stop"));
    }
}
