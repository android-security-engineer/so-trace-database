//! Compression and encoding utilities

/// Delta-encode a slice of u64 values
/// Output: first value as-is, then differences
pub fn delta_encode_u64(values: &[u64]) -> Vec<u64> {
    if values.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(values.len());
    result.push(values[0]);
    for i in 1..values.len() {
        result.push(values[i].wrapping_sub(values[i - 1]));
    }
    result
}

/// Delta-decode a slice of u64 values (inverse of delta_encode_u64)
pub fn delta_decode_u64(deltas: &[u64]) -> Vec<u64> {
    if deltas.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(deltas.len());
    result.push(deltas[0]);
    for i in 1..deltas.len() {
        result.push(result[i - 1].wrapping_add(deltas[i]));
    }
    result
}

/// Encode a u64 value as a varint (LEB128)
pub fn encode_varint(value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_varint_into(&mut buf, value);
    buf
}

/// Append a LEB128 varint to `buf` without allocating a fresh vector.
pub fn encode_varint_into(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Decode a varint from a byte slice, returning (value, bytes_consumed)
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None; // Overflow
        }
    }
    None // Incomplete
}

// ------------------------------------------------------------------
// Trace-aware signed delta encoding (Zigzag)
// ------------------------------------------------------------------

/// Zigzag encode a signed value (i64) into an unsigned u64.
/// Maps small-magnitude signed values to small unsigned values:
///   0 → 0, -1 → 1, 1 → 2, -2 → 3, 2 → 4, ...
/// This keeps the dominant small positive+negative deltas down to a
/// single varint byte, unlike raw i64 which wastes 8 bytes on "4".
pub fn zigzag_encode(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Zigzag decode an unsigned value back to a signed i64 (inverse of zigzag_encode).
#[inline]
pub fn zigzag_decode(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

/// Encode an i64 as a zigzag varint (signed-aware LEB128).
pub fn encode_signed_varint(v: i64) -> Vec<u8> {
    encode_varint(zigzag_encode(v))
}

/// Append a zigzag varint to `buf`.
pub fn encode_signed_varint_into(buf: &mut Vec<u8>, v: i64) {
    encode_varint_into(buf, zigzag_encode(v));
}

/// Pack booleans LSB-first into a byte vector.
pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let n = bits.len().div_ceil(8);
    let mut out = vec![0u8; n];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Unpack `count` LSB-first booleans from `bytes`.
pub fn unpack_bits(bytes: &[u8], count: usize) -> Vec<bool> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let bit = bytes.get(i / 8).copied().unwrap_or(0);
        out.push((bit >> (i % 8)) & 1 == 1);
    }
    out
}

/// Decode a zigzag varint (inverse of encode_signed_varint), advancing `pos`.
pub fn decode_signed_varint(buf: &[u8], pos: &mut usize) -> Option<i64> {
    let (z, consumed) = decode_varint(&buf[*pos..])?;
    *pos += consumed;
    Some(zigzag_decode(z))
}

/// Delta-encode a stream of absolute address u64s into zigzag varint bytes.
///
/// This is the key Trace storage primitive: instruction addresses advance
/// almost always by the instruction width (+4 on AArch64), occasionally with
/// a branch (negative or large). Delta + zigzag turns those +4s into a single
/// byte (encoded as 8 → 8) instead of 8 bytes each.
pub fn trace_delta_bytes(addresses: &[u64]) -> Vec<u8> {
    if addresses.is_empty() {
        return Vec::new();
    }
    let deltas = delta_encode_u64(addresses); // first element = base address
    let mut out = Vec::with_capacity(addresses.len());
    for d in deltas {
        // Convert the unsigned delta into a signed difference so zigzag can
        // compress the back-jumps. The first value (base) is huge as a signed
        // difference but zigzag still keeps its magnitude reasonable; callers
        // that want tighter base handling can store the base out-of-band.
        out.extend_from_slice(&encode_signed_varint(d as i64));
    }
    out
}

/// Decode a stream produced by `trace_delta_bytes` back into absolute addresses.
pub fn trace_delta_decode(bytes: &[u8]) -> Vec<u64> {
    let mut pos = 0usize;
    let mut deltas = Vec::with_capacity(bytes.len());
    while pos < bytes.len() {
        match decode_signed_varint(bytes, &mut pos) {
            Some(v) => deltas.push(v),
            None => break,
        }
    }
    delta_decode_u64(&deltas.iter().map(|&v| v as u64).collect::<Vec<_>>())
}

// ------------------------------------------------------------------
// Block-level generic compression (Zstd / LZ4) — applied AFTER columnar
// trace encoding when a whole block needs additional density.
// ------------------------------------------------------------------

/// Compress a byte block using Zstandard at the given compression level.
/// Level 1 = fast, level 19+ = high compression; 3 is a good default.
pub fn zstd_compress(data: &[u8], level: i32) -> std::io::Result<Vec<u8>> {
    zstd::bulk::compress(data, level)
}

/// Decompress a Zstandard block.
pub fn zstd_decompress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    zstd::bulk::decompress(data, 128 * 1024 * 1024)
}

/// Compress a byte block using LZ4 (very fast, good ratio for repetitive bytes).
pub fn lz4_compress(data: &[u8]) -> Vec<u8> {
    lz4_flex::block::compress(data)
}

/// Decompress an LZ4 block into a buffer of the original `uncompressed_size`.
pub fn lz4_decompress_uncompressed(data: &[u8], uncompressed_size: usize) -> Result<Vec<u8>, String> {
    lz4_flex::block::decompress(data, uncompressed_size).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zstd_roundtrip() {
        let data = vec![b'a'; 4096];
        let comp = zstd_compress(&data, 3).unwrap();
        let decomp = zstd_decompress(&comp).unwrap();
        assert_eq!(data, decomp);
    }

    #[test]
    fn test_lz4_roundtrip() {
        let data = vec![b'b'; 4096];
        let comp = lz4_compress(&data);
        let decomp = lz4_decompress_uncompressed(&comp, data.len()).unwrap();
        assert_eq!(data, decomp);
    }

    #[test]
    fn test_delta_encode_decode() {
        let values = vec![100u64, 105, 110, 200, 205];
        let deltas = delta_encode_u64(&values);
        assert_eq!(deltas, vec![100, 5, 5, 90, 5]);
        let decoded = delta_decode_u64(&deltas);
        assert_eq!(decoded, values);
    }

    #[test]
    fn test_zigzag_roundtrip() {
        for v in [0i64, -1, 1, -2, 2, 4, -8, 1000, -1000, i32::MIN as i64, i64::MIN] {
            assert_eq!(zigzag_decode(zigzag_encode(v)), v);
        }
    }

    #[test]
    fn test_zigzag_mapping() {
        assert_eq!(zigzag_encode(0), 0);
        assert_eq!(zigzag_encode(-1), 1);
        assert_eq!(zigzag_encode(1), 2);
        assert_eq!(zigzag_encode(-2), 3);
        assert_eq!(zigzag_encode(2), 4);
    }

    #[test]
    fn test_signed_varint_compactness() {
        // +4 (the dominant AArch64 instruction delta) → single byte.
        let enc = encode_signed_varint(4);
        assert_eq!(enc.len(), 1);
        assert_eq!(encode_signed_varint(-4).len(), 1);
        assert_eq!(encode_signed_varint(0).len(), 1);
    }

    #[test]
    fn test_trace_delta_roundtrip() {
        // 100k mostly-sequential addresses with occasional back-jumps.
        let mut addrs: Vec<u64> = Vec::with_capacity(100_000);
        let mut a: u64 = 0x1000;
        for i in 0..100_000u64 {
            if i > 0 && i % 20 == 0 {
                a = a.wrapping_sub(1000); // branch back
            } else {
                a = a.wrapping_add(4); // sequential
            }
            addrs.push(a);
        }
        let decoded = trace_delta_decode(&trace_delta_bytes(&addrs));
        assert_eq!(decoded, addrs);
    }

    #[test]
    fn test_trace_delta_compresses_below_raw() {
        let mut addrs: Vec<u64> = Vec::with_capacity(100_000);
        let mut a: u64 = 0x1000;
        for i in 0..100_000u64 {
            if i > 0 && i % 20 == 0 {
                a = a.wrapping_sub(1000);
            } else {
                a = a.wrapping_add(4);
            }
            addrs.push(a);
        }
        let raw_bytes = addrs.len() * 8;
        let encoded = trace_delta_bytes(&addrs);
        let ratio = raw_bytes as f64 / encoded.len() as f64;
        assert!(encoded.len() < raw_bytes, "expected compression, got {} bytes", encoded.len());
        // On a mostly-sequential stream we expect a healthy ratio (>4x).
        assert!(ratio > 4.0, "expected >4x compression, got {:.2}x", ratio);
    }

    #[test]
    fn test_varint_encode_decode() {
        let values = vec![0u64, 1, 127, 128, 255, 16384, u64::MAX];
        for value in values {
            let encoded = encode_varint(value);
            let (decoded, consumed) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
    }
}
