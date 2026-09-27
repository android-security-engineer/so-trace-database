
fn decode_instr_cols(buf: &[u8], pos: &mut usize) -> Result<Vec<InstructionTrace>> {
    let n = get_varint(buf, pos)? as usize;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut seqs = Vec::with_capacity(n);
    let mut prev = 0i64;
    for i in 0..n {
        let d = get_signed(buf, pos)?;
        let s = if i == 0 { d } else { prev.wrapping_add(d) };
        seqs.push(s as u64);
        prev = s;
    }

    let dict_len = get_varint(buf, pos)? as usize;
    let mut dict = Vec::with_capacity(dict_len);
    for _ in 0..dict_len {
        dict.push(get_varint(buf, pos)? as u32);
    }
    let mut threads = Vec::with_capacity(n);
    for _ in 0..n {
        let idx = get_varint(buf, pos)? as usize;
        threads.push(*dict.get(idx).ok_or_else(|| anyhow!("thread dict oob"))?);
    }

    let addr_len = get_varint(buf, pos)? as usize;
    let addr_bytes = take_bytes(buf, pos, addr_len)?;
    let addrs = trace_delta_decode(addr_bytes);
    if addrs.len() != n {
        anyhow::bail!("address column length {} != {n}", addrs.len());
    }

    let ts_pack_len = n.div_ceil(8);
    let ts_pack = take_bytes(buf, pos, ts_pack_len)?;
    let ts_presence = unpack_bits(ts_pack, n);
    let mut timestamps = Vec::with_capacity(n);
    for present in &ts_presence {
        if *present {
            timestamps.push(Some(get_varint(buf, pos)?));
        } else {
            timestamps.push(None);
        }
    }

    let bt_len = (n * 2).div_ceil(8);
    let bt_pack = take_bytes(buf, pos, bt_len)?;
    let bt = unpack_bits(bt_pack, n * 2);

    let op_pack_len = n.div_ceil(8);
    let op_pack = take_bytes(buf, pos, op_pack_len)?;
    let op_presence = unpack_bits(op_pack, n);
    let mut opcodes = Vec::with_capacity(n);
    for present in &op_presence {
        if *present {
            let len = get_varint(buf, pos)? as usize;
            opcodes.push(Some(take_bytes(buf, pos, len)?.to_vec()));
        } else {
            opcodes.push(None);
        }
    }

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(InstructionTrace {
            seq: seqs[i],
            thread_id: threads[i],
            address: addrs[i],
            timestamp: timestamps[i],
            is_branch: bt[i * 2],
            branch_taken: bt[i * 2 + 1],
            opcode: opcodes[i].clone(),
        });
    }
    Ok(out)
}

fn encode_mem_writes(writes: &[(u64, u32, u64, Vec<u8>)], out: &mut Vec<u8>) {
    encode_varint_into(out, writes.len() as u64);
    let mut prev_step = 0i64;
    let mut prev_addr = 0i64;
    for (i, (step, tid, addr, data)) in writes.iter().enumerate() {
        let s = *step as i64;
        let a = *addr as i64;
        if i == 0 {
            encode_signed_varint_into(out, s);
            encode_signed_varint_into(out, a);
        } else {
            encode_signed_varint_into(out, s.wrapping_sub(prev_step));
            encode_signed_varint_into(out, a.wrapping_sub(prev_addr));
        }
        prev_step = s;
        prev_addr = a;
        encode_varint_into(out, *tid as u64);
        encode_varint_into(out, data.len() as u64);
        out.extend_from_slice(data);
    }
}

fn decode_mem_writes(buf: &[u8], pos: &mut usize) -> Result<Vec<(u64, u32, u64, Vec<u8>)>> {
    let n = get_varint(buf, pos)? as usize;
    let mut out = Vec::with_capacity(n);
    let mut prev_step = 0i64;
    let mut prev_addr = 0i64;
    for i in 0..n {
        let ds = get_signed(buf, pos)?;
        let da = get_signed(buf, pos)?;
        let step = if i == 0 { ds } else { prev_step.wrapping_add(ds) };
        let addr = if i == 0 { da } else { prev_addr.wrapping_add(da) };
        prev_step = step;
        prev_addr = addr;
        let tid = get_varint(buf, pos)? as u32;
        let len = get_varint(buf, pos)? as usize;
        let data = take_bytes(buf, pos, len)?.to_vec();
        out.push((step as u64, tid, addr as u64, data));
    }
    Ok(out)
}

fn encode_mem_reads(reads: &[(u64, u32, u64, usize)], out: &mut Vec<u8>) {
    encode_varint_into(out, reads.len() as u64);
    let mut prev_step = 0i64;
    let mut prev_addr = 0i64;
    for (i, (step, tid, addr, size)) in reads.iter().enumerate() {
        let s = *step as i64;
        let a = *addr as i64;
        if i == 0 {
            encode_signed_varint_into(out, s);
            encode_signed_varint_into(out, a);
        } else {
            encode_signed_varint_into(out, s.wrapping_sub(prev_step));
            encode_signed_varint_into(out, a.wrapping_sub(prev_addr));
        }
        prev_step = s;
        prev_addr = a;
        encode_varint_into(out, *tid as u64);
        encode_varint_into(out, *size as u64);
    }
}

fn decode_mem_reads(buf: &[u8], pos: &mut usize) -> Result<Vec<(u64, u32, u64, usize)>> {
    let n = get_varint(buf, pos)? as usize;
    let mut out = Vec::with_capacity(n);
    let mut prev_step = 0i64;
    let mut prev_addr = 0i64;
    for i in 0..n {
        let ds = get_signed(buf, pos)?;
        let da = get_signed(buf, pos)?;
        let step = if i == 0 { ds } else { prev_step.wrapping_add(ds) };
        let addr = if i == 0 { da } else { prev_addr.wrapping_add(da) };
        prev_step = step;
        prev_addr = addr;
        let tid = get_varint(buf, pos)? as u32;
        let size = get_varint(buf, pos)? as usize;
        out.push((step as u64, tid, addr as u64, size));
    }
    Ok(out)
}

fn put_bincode<T: Serialize>(out: &mut Vec<u8>, v: &T) {
    let raw = bincode::serialize(v).expect("bincode serialize column");
    encode_varint_into(out, raw.len() as u64);
    out.extend_from_slice(&raw);
}

fn take_bincode<T: serde::de::DeserializeOwned>(buf: &[u8], pos: &mut usize) -> Result<T> {
    let len = get_varint(buf, pos)? as usize;
    let raw = take_bytes(buf, pos, len)?;
    bincode::deserialize(raw).context("bincode column")
}

fn get_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let (v, n) = decode_varint(&buf[*pos..]).ok_or_else(|| anyhow!("truncated varint"))?;
    *pos += n;
    Ok(v)
}

fn get_signed(buf: &[u8], pos: &mut usize) -> Result<i64> {
    Ok(zigzag_decode(get_varint(buf, pos)?))
}

fn take_bytes<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *pos + n > buf.len() {
        anyhow::bail!("truncated byte slice");
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

/// Representative instruction-heavy mixed stream used by tests and benches.
pub fn synthesize_mixed(instruction_count: usize, threads: u32) -> Vec<TraceEvent> {
    let threads = threads.max(1);
    let mut events = Vec::new();
    let tids: Vec<u32> = (1000..1000 + threads).collect();
    let mut seq: u64 = 0;
    let mut produced = 0usize;
    let mut round = 0u64;
    while produced < instruction_count {
        let tid = tids[(round % threads as u64) as usize];
        for slot in 0..32u64 {
            if produced >= instruction_count {
                break;
            }
            let mut addr = 0x1000u64 + slot * 4;
            let is_branch = slot % 20 == 0 && slot > 0;
            if is_branch {
                addr = addr.wrapping_sub(1000);
            }
            let opcode = if slot < 12 {
                Some(vec![0x00 | slot as u8, 0x80, 0x10, 0x02])
            } else {
                None
            };
            events.push(TraceEvent::Instruction(InstructionTrace {
                seq,
                thread_id: tid,
                address: addr,
                timestamp: if slot % 7 == 0 { Some(seq * 1000) } else { None },
                is_branch,
                branch_taken: is_branch,
                opcode,
            }));
            seq += 1;
            produced += 1;
            if slot == 15 {
                events.push(TraceEvent::Register(RegisterDelta {
                    seq,
                    change_mask: 0x21,
                    values: vec![seq, seq + 4],
                }));
                seq += 1;
            }
            if slot == 31 && round % 3 == 0 {
                events.push(TraceEvent::MemoryWrite {
                    step: seq,
                    thread_id: tid,
                    address: addr,
                    data: vec![0xAA; 8],
                });
                seq += 1;
            }
        }
        round += 1;
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_mixed_stream_event_for_event() {
        let events = synthesize_mixed(512, 2);
        let inner = encode_columnar(&events);
        let back = decode_columnar(&inner).unwrap();
        assert_eq!(back, events);
        let blob = encode_sotc(
            &SotcHeader {
                trace_id: 3,
                so_file_id: 7,
                source: "test".into(),
                base_addr: 0x1000,
                created_at: 1,
            },
            &events,
            128,
        )
        .unwrap();
        assert!(is_sotc(&blob));
        let (h, decoded) = decode_sotc(&blob).unwrap();
        assert_eq!(h.trace_id, 3);
        assert_eq!(decoded, events);
    }

    #[test]
    fn compressed_chunk_is_strictly_smaller_than_m0() {
        let events = synthesize_mixed(8_192, 2);
        let m0 = encode_m0(&events).unwrap();
        let shipped = compress_chunk(&events).unwrap();
        assert!(
            shipped.len() < m0.len(),
            "shipped {} B must beat m0 {} B",
            shipped.len(),
            m0.len()
        );
        assert_eq!(decompress_chunk(&shipped).unwrap(), events);
    }

    #[test]
    fn append_chunk_does_not_rewrite_prefix() {
        let a = synthesize_mixed(64, 1);
        let b = synthesize_mixed(32, 1);
        let header = SotcHeader {
            trace_id: 1,
            so_file_id: 0,
            source: "a".into(),
            base_addr: 0,
            created_at: 0,
        };
        let mut blob = encode_sotc(&header, &a, 64).unwrap();
        let prefix_len = blob.len();
        write_chunk_bytes(&mut blob, &b).unwrap();
        assert_eq!(&blob[..prefix_len], &encode_sotc(&header, &a, 64).unwrap());
        let (_, all) = decode_sotc(&blob).unwrap();
        let mut expected = a.clone();
        expected.extend(b);
        assert_eq!(all, expected);
    }

    #[test]
    fn empty_stream_roundtrips() {
        let header = SotcHeader {
            trace_id: 9,
            so_file_id: 0,
            source: String::new(),
            base_addr: 0,
            created_at: 0,
        };
        let blob = encode_sotc(&header, &[], 16).unwrap();
        let (h, ev) = decode_sotc(&blob).unwrap();
        assert_eq!(h, header);
        assert!(ev.is_empty());
    }
}
