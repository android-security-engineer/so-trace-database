// Shipped append-only columnar encoding for mixed [`TraceEvent`] streams.
//
// On-disk layout (`SOTC` v1):
// ```text
// magic "SOTC" | version u8 | header_len u32le | bincode(SotcHeader)
// repeating chunks:
//   event_count u32le | payload_len u32le | zstd(columnar inner)
// ```
//
// The inner payload stores a type-tag RLE (preserving interleaving) plus
// per-variant columns. Instruction columns use delta + zigzag varints and
// bit-packing; other variants are grouped bincode. Later chunks are appended
// without rewriting earlier ones.
//
// Whole-blob bincode + zstd-3 (`encode_m0`) is kept as the size baseline
// that `TraceRepository` used before this codec.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sotrace_core::adapters::TraceEvent;
use sotrace_core::models::call_trace::CallTrace;
use sotrace_core::models::instruction_trace::InstructionTrace;
use sotrace_core::models::jni_call::JNICall;
use sotrace_core::models::register_delta::RegisterDelta;
use sotrace_core::models::thread::{ContextSwitch, ThreadInfo, ThreadStateChange, ThreadSyncEvent};
use std::io::{Read, Write};

use crate::storage::compression::{
    decode_varint, encode_signed_varint_into, encode_varint_into, pack_bits,
    trace_delta_bytes, trace_delta_decode, unpack_bits, zigzag_decode, zstd_compress,
    zstd_decompress,
};

/// File magic. Distinct from zstd (`28 B5 2F FD`) so load can sniff.
pub const MAGIC: [u8; 4] = *b"SOTC";
/// Codec version.
pub const VERSION: u8 = 1;
/// Default events per compressed chunk.
pub const DEFAULT_CHUNK_EVENTS: usize = 32_768;
/// zstd level matching the previous whole-blob persist path.
pub const ZSTD_LEVEL: i32 = 3;

const TAG_THREAD: u8 = 0;
const TAG_INSTR: u8 = 1;
const TAG_REG: u8 = 2;
const TAG_CALL: u8 = 3;
const TAG_JNI: u8 = 4;
const TAG_MEMW: u8 = 5;
const TAG_MEMR: u8 = 6;
const TAG_SYNC: u8 = 7;
const TAG_CSW: u8 = 8;
const TAG_STATE: u8 = 9;

/// Bookkeeping stored once at the start of an SOTC blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SotcHeader {
    pub trace_id: u64,
    pub so_file_id: u64,
    pub source: String,
    pub base_addr: u64,
    pub created_at: u64,
}

/// True when `bytes` starts with the SOTC magic.
pub fn is_sotc(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == MAGIC
}

/// Whole-blob bincode + zstd-3 — the persist encoding this codec replaces.
pub fn encode_m0(events: &[TraceEvent]) -> Result<Vec<u8>> {
    let raw = bincode::serialize(events).context("m0 bincode serialize")?;
    zstd_compress(&raw, ZSTD_LEVEL).context("m0 zstd")
}

/// Encode events to the uncompressed columnar inner form.
pub fn encode_columnar(events: &[TraceEvent]) -> Vec<u8> {
    let n = events.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&n.to_le_bytes());

    let mut tags = Vec::with_capacity(events.len());
    let mut threads: Vec<ThreadInfo> = Vec::new();
    let mut instrs: Vec<InstructionTrace> = Vec::new();
    let mut regs: Vec<RegisterDelta> = Vec::new();
    let mut calls: Vec<CallTrace> = Vec::new();
    let mut jnis: Vec<JNICall> = Vec::new();
    let mut memw: Vec<(u64, u32, u64, Vec<u8>)> = Vec::new();
    let mut memr: Vec<(u64, u32, u64, usize)> = Vec::new();
    let mut syncs: Vec<ThreadSyncEvent> = Vec::new();
    let mut csws: Vec<ContextSwitch> = Vec::new();
    let mut states: Vec<ThreadStateChange> = Vec::new();

    for e in events {
        match e {
            TraceEvent::Thread(t) => {
                tags.push(TAG_THREAD);
                threads.push(t.clone());
            }
            TraceEvent::Instruction(i) => {
                tags.push(TAG_INSTR);
                instrs.push(i.clone());
            }
            TraceEvent::Register(r) => {
                tags.push(TAG_REG);
                regs.push(r.clone());
            }
            TraceEvent::Call(c) => {
                tags.push(TAG_CALL);
                calls.push(c.clone());
            }
            TraceEvent::JniCall(j) => {
                tags.push(TAG_JNI);
                jnis.push(j.clone());
            }
            TraceEvent::MemoryWrite { step, thread_id, address, data } => {
                tags.push(TAG_MEMW);
                memw.push((*step, *thread_id, *address, data.clone()));
            }
            TraceEvent::MemoryRead { step, thread_id, address, size } => {
                tags.push(TAG_MEMR);
                memr.push((*step, *thread_id, *address, *size));
            }
            TraceEvent::Sync(s) => {
                tags.push(TAG_SYNC);
                syncs.push(s.clone());
            }
            TraceEvent::ContextSwitch(s) => {
                tags.push(TAG_CSW);
                csws.push(s.clone());
            }
            TraceEvent::StateChange(c) => {
                tags.push(TAG_STATE);
                states.push(c.clone());
            }
        }
    }

    encode_rle_tags(&tags, &mut out);
    encode_instr_cols(&instrs, &mut out);
    put_bincode(&mut out, &threads);
    put_bincode(&mut out, &regs);
    put_bincode(&mut out, &calls);
    put_bincode(&mut out, &jnis);
    encode_mem_writes(&memw, &mut out);
    encode_mem_reads(&memr, &mut out);
    put_bincode(&mut out, &syncs);
    put_bincode(&mut out, &csws);
    put_bincode(&mut out, &states);
    out
}

/// Decode a buffer produced by [`encode_columnar`].
pub fn decode_columnar(bytes: &[u8]) -> Result<Vec<TraceEvent>> {
    if bytes.len() < 4 {
        anyhow::bail!("columnar blob too short");
    }
    let n = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let mut pos = 4usize;
    let tags = decode_rle_tags(bytes, &mut pos, n)?;
    let instrs = decode_instr_cols(bytes, &mut pos)?;
    let threads: Vec<ThreadInfo> = take_bincode(bytes, &mut pos)?;
    let regs: Vec<RegisterDelta> = take_bincode(bytes, &mut pos)?;
    let calls: Vec<CallTrace> = take_bincode(bytes, &mut pos)?;
    let jnis: Vec<JNICall> = take_bincode(bytes, &mut pos)?;
    let memw = decode_mem_writes(bytes, &mut pos)?;
    let memr = decode_mem_reads(bytes, &mut pos)?;
    let syncs: Vec<ThreadSyncEvent> = take_bincode(bytes, &mut pos)?;
    let csws: Vec<ContextSwitch> = take_bincode(bytes, &mut pos)?;
    let states: Vec<ThreadStateChange> = take_bincode(bytes, &mut pos)?;

    let mut it = instrs.into_iter();
    let mut th = threads.into_iter();
    let mut rg = regs.into_iter();
    let mut ca = calls.into_iter();
    let mut jn = jnis.into_iter();
    let mut mw = memw.into_iter();
    let mut mr = memr.into_iter();
    let mut sy = syncs.into_iter();
    let mut cs = csws.into_iter();
    let mut st = states.into_iter();

    let mut out = Vec::with_capacity(n);
    for tag in tags {
        let ev = match tag {
            TAG_THREAD => TraceEvent::Thread(th.next().ok_or_else(|| anyhow!("thread underrun"))?),
            TAG_INSTR => TraceEvent::Instruction(it.next().ok_or_else(|| anyhow!("instr underrun"))?),
            TAG_REG => TraceEvent::Register(rg.next().ok_or_else(|| anyhow!("reg underrun"))?),
            TAG_CALL => TraceEvent::Call(ca.next().ok_or_else(|| anyhow!("call underrun"))?),
            TAG_JNI => TraceEvent::JniCall(jn.next().ok_or_else(|| anyhow!("jni underrun"))?),
            TAG_MEMW => {
                let (step, thread_id, address, data) =
                    mw.next().ok_or_else(|| anyhow!("memw underrun"))?;
                TraceEvent::MemoryWrite { step, thread_id, address, data }
            }
            TAG_MEMR => {
                let (step, thread_id, address, size) =
                    mr.next().ok_or_else(|| anyhow!("memr underrun"))?;
                TraceEvent::MemoryRead { step, thread_id, address, size }
            }
            TAG_SYNC => TraceEvent::Sync(sy.next().ok_or_else(|| anyhow!("sync underrun"))?),
            TAG_CSW => TraceEvent::ContextSwitch(cs.next().ok_or_else(|| anyhow!("csw underrun"))?),
            TAG_STATE => TraceEvent::StateChange(st.next().ok_or_else(|| anyhow!("state underrun"))?),
            other => anyhow::bail!("unknown tag {other}"),
        };
        out.push(ev);
    }
    Ok(out)
}

/// zstd-compress one columnar chunk.
pub fn compress_chunk(events: &[TraceEvent]) -> Result<Vec<u8>> {
    let inner = encode_columnar(events);
    zstd_compress(&inner, ZSTD_LEVEL).context("chunk zstd")
}

/// Decompress + decode one chunk payload.
pub fn decompress_chunk(payload: &[u8]) -> Result<Vec<TraceEvent>> {
    let inner = zstd_decompress(payload).context("chunk zstd decompress")?;
    decode_columnar(&inner)
}

/// Encode a complete SOTC blob (header + chunked events). Empty event lists
/// still write a valid header so later [`write_chunk`] calls can append.
pub fn encode_sotc(header: &SotcHeader, events: &[TraceEvent], chunk_events: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    write_sotc_header(&mut buf, header)?;
    let chunk_events = chunk_events.max(1);
    for chunk in events.chunks(chunk_events) {
        write_chunk_bytes(&mut buf, chunk)?;
    }
    Ok(buf)
}

/// Decode a complete SOTC blob.
pub fn decode_sotc(bytes: &[u8]) -> Result<(SotcHeader, Vec<TraceEvent>)> {
    let (header, mut pos) = read_sotc_header(bytes)?;
    let mut events = Vec::new();
    while pos < bytes.len() {
        let (chunk, next) = read_chunk_at(bytes, pos)?;
        events.extend(chunk);
        pos = next;
    }
    Ok((header, events))
}

/// Write the SOTC header (magic + version + bincode header) to `w`.
pub fn write_sotc_header<W: Write>(w: &mut W, header: &SotcHeader) -> Result<()> {
    let hdr = bincode::serialize(header).context("serialize SotcHeader")?;
    w.write_all(&MAGIC)?;
    w.write_all(&[VERSION])?;
    w.write_all(&(hdr.len() as u32).to_le_bytes())?;
    w.write_all(&hdr)?;
    Ok(())
}

/// Append one compressed event chunk to `w`.
pub fn write_chunk<W: Write>(w: &mut W, events: &[TraceEvent]) -> Result<()> {
    let mut buf = Vec::new();
    write_chunk_bytes(&mut buf, events)?;
    w.write_all(&buf)?;
    Ok(())
}

fn write_chunk_bytes(buf: &mut Vec<u8>, events: &[TraceEvent]) -> Result<()> {
    let payload = compress_chunk(events)?;
    buf.extend_from_slice(&(events.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&payload);
    Ok(())
}

/// Parse the header and return `(header, body_offset)`.
pub fn read_sotc_header(bytes: &[u8]) -> Result<(SotcHeader, usize)> {
    if bytes.len() < 9 || bytes[..4] != MAGIC {
        anyhow::bail!("not an SOTC blob");
    }
    if bytes[4] != VERSION {
        anyhow::bail!("unsupported SOTC version {}", bytes[4]);
    }
    let header_len = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let end = 9 + header_len;
    if bytes.len() < end {
        anyhow::bail!("truncated SOTC header");
    }
    let header: SotcHeader = bincode::deserialize(&bytes[9..end]).context("decode SotcHeader")?;
    Ok((header, end))
}

fn read_chunk_at(bytes: &[u8], pos: usize) -> Result<(Vec<TraceEvent>, usize)> {
    if pos + 8 > bytes.len() {
        anyhow::bail!("truncated SOTC chunk header");
    }
    let event_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    let payload_len = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
    let start = pos + 8;
    let end = start + payload_len;
    if bytes.len() < end {
        anyhow::bail!("truncated SOTC chunk payload");
    }
    let events = decompress_chunk(&bytes[start..end])?;
    if events.len() != event_count {
        anyhow::bail!(
            "SOTC chunk event count mismatch: header {} decoded {}",
            event_count,
            events.len()
        );
    }
    Ok((events, end))
}

/// Stream-decode chunks from a reader that is already positioned after the header.
pub fn read_chunks_from<R: Read>(mut reader: R) -> Result<Vec<TraceEvent>> {
    let mut events = Vec::new();
    loop {
        let mut hdr = [0u8; 8];
        match reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let event_count = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
        let payload_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload)?;
        let chunk = decompress_chunk(&payload)?;
        if chunk.len() != event_count {
            anyhow::bail!("SOTC chunk event count mismatch");
        }
        events.extend(chunk);
    }
    Ok(events)
}

// ---------------------------------------------------------------------------
// inner helpers
// ---------------------------------------------------------------------------

fn encode_rle_tags(tags: &[u8], out: &mut Vec<u8>) {
    if tags.is_empty() {
        return;
    }
    let mut i = 0;
    while i < tags.len() {
        let t = tags[i];
        let mut run = 1u64;
        i += 1;
        while i < tags.len() && tags[i] == t {
            run += 1;
            i += 1;
        }
        out.push(t);
        encode_varint_into(out, run);
    }
}

fn decode_rle_tags(buf: &[u8], pos: &mut usize, n: usize) -> Result<Vec<u8>> {
    let mut tags = Vec::with_capacity(n);
    while tags.len() < n {
        if *pos >= buf.len() {
            anyhow::bail!("truncated tag RLE");
        }
        let t = buf[*pos];
        *pos += 1;
        let run = get_varint(buf, pos)? as usize;
        if tags.len() + run > n {
            anyhow::bail!("tag RLE overflow");
        }
        tags.extend(std::iter::repeat(t).take(run));
    }
    Ok(tags)
}

fn encode_instr_cols(instrs: &[InstructionTrace], out: &mut Vec<u8>) {
    encode_varint_into(out, instrs.len() as u64);
    if instrs.is_empty() {
        return;
    }
    let mut prev_seq = 0i64;
    for (i, ins) in instrs.iter().enumerate() {
        let s = ins.seq as i64;
        if i == 0 {
            encode_signed_varint_into(out, s);
        } else {
            encode_signed_varint_into(out, s.wrapping_sub(prev_seq));
        }
        prev_seq = s;
    }

    let mut dict: Vec<u32> = Vec::new();
    let mut index: Vec<u64> = Vec::with_capacity(instrs.len());
    for ins in instrs {
        match dict.iter().position(|&x| x == ins.thread_id) {
            Some(i) => index.push(i as u64),
            None => {
                dict.push(ins.thread_id);
                index.push((dict.len() - 1) as u64);
            }
        }
    }
    encode_varint_into(out, dict.len() as u64);
    for t in &dict {
        encode_varint_into(out, *t as u64);
    }
    for i in &index {
        encode_varint_into(out, *i);
    }

    let addrs: Vec<u64> = instrs.iter().map(|i| i.address).collect();
    let addr_bytes = trace_delta_bytes(&addrs);
    encode_varint_into(out, addr_bytes.len() as u64);
    out.extend_from_slice(&addr_bytes);

    let ts_presence: Vec<bool> = instrs.iter().map(|i| i.timestamp.is_some()).collect();
    let packed = pack_bits(&ts_presence);
    out.extend_from_slice(&packed);
    for ins in instrs {
        if let Some(t) = ins.timestamp {
            encode_varint_into(out, t);
        }
    }

    let mut bt = Vec::with_capacity(instrs.len() * 2);
    for ins in instrs {
        bt.push(ins.is_branch);
        bt.push(ins.branch_taken);
    }
    out.extend_from_slice(&pack_bits(&bt));

    let op_presence: Vec<bool> = instrs.iter().map(|i| i.opcode.is_some()).collect();
    out.extend_from_slice(&pack_bits(&op_presence));
    for ins in instrs {
        if let Some(op) = &ins.opcode {
            encode_varint_into(out, op.len() as u64);
            out.extend_from_slice(op);
        }
    }
}
