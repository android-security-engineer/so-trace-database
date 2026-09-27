//! PForDelta — Patched Frame-of-Reference bit-packing for trace columns.
//!
//! PForDelta is the classic block-compression used by search engines and
//! column stores (e.g. the original Lucene/doc-list compression). It is well
//! suited to trace data because many trace columns have a tight value
//! distribution after delta/zigzag:
//!
//! - Instruction addresses: deltas are almost always small (dominant +4),
//!   occasionally large (branches). A frame where 90%+ of deltas fit in a
//!   few bits packs those in `b` bits each; the rare large values are
//!   *patched* out and stored separately full-width.
//! - Timestamps / seq: monotonically increasing, deltas tiny → 1 bit often
//!   suffices for whole frames.
//!
//! This module operates on **zigzag-encoded** u64 values so that both forward
//! (+N) and backward (−N) deltas become small unsigned numbers.

/// A single PForDelta-encoded frame.
#[derive(Debug, Clone, PartialEq)]
pub struct PForFrame {
    /// Bit width used for the common (packed) values. 0 means the frame is
    /// entirely exceptions or empty.
    pub bit_width: u8,
    /// Number of packed (common) values.
    pub packed_count: usize,
    /// Packed values: `packed_count` values each of `bit_width` bits, packed
    /// into u64 words.
    pub packed: Vec<u64>,
    /// Exception (outlier) values — those that did not fit in `bit_width`
    /// bits, kept full-width in frame order (excluding packed ones).
    pub exceptions: Vec<u64>,
    /// Original frame position (0-based) of each value in `exceptions`.
    pub exception_positions: Vec<u16>,
}

/// Encode a single frame of zigzag-encoded u64s using PForDelta.
///
/// `target_bits` is the target bit width; a frame that doesn't get at least
/// `min_fraction` of values under `target_bits` is stored raw (bit_width = 64,
/// everything an exception) to avoid pathological blowups.
pub fn encode_frame(values: &[u64], target_bits: u32) -> PForFrame {
    if values.is_empty() {
        return PForFrame { bit_width: 0, packed_count: 0, packed: vec![], exceptions: vec![], exception_positions: vec![] };
    }

    let max_bits = if target_bits > 0 { target_bits } else { 32 };
    let max_val = if max_bits >= 64 { u64::MAX } else { (1u64 << max_bits) - 1 };

    // Split values into packed (<= max_val) vs exceptions.
    let mut packed_vals: Vec<u64> = Vec::with_capacity(values.len());
    let mut exceptions: Vec<u64> = Vec::new();
    let mut exc_pos: Vec<u16> = Vec::new();
    for (i, &v) in values.iter().enumerate() {
        if v <= max_val {
            packed_vals.push(v);
        } else {
            exceptions.push(v);
            exc_pos.push(i as u16);
        }
    }

    // If exceptions dominate, store raw (treat all as exceptions, no packing).
    if packed_vals.len() as f64 / values.len() as f64 < 0.5 {
        return PForFrame {
            bit_width: 64,
            packed_count: 0,
            packed: vec![],
            exceptions: values.to_vec(),
            exception_positions: (0..values.len() as u16).collect(),
        };
    }

    let packed = bit_pack(&packed_vals, max_bits as u8);
    PForFrame {
        bit_width: max_bits as u8,
        packed_count: packed_vals.len(),
        packed,
        exceptions,
        exception_positions: exc_pos,
    }
}

/// Decode a PForFrame back into the original zigzag-encoded u64 slice.
pub fn decode_frame(frame: &PForFrame) -> Vec<u64> {
    let total = frame.packed_count + frame.exceptions.len();
    let mut out = vec![0u64; total];

    if frame.bit_width == 64 || frame.packed.is_empty() {
        // Raw frame: every position is an exception.
        for (i, &v) in frame.exceptions.iter().enumerate() {
            out[frame.exception_positions[i] as usize] = v;
        }
        return out;
    }

    let packed_vals = bit_unpack(&frame.packed, frame.bit_width as u32, frame.packed_count);
    let mut packed_idx = 0usize;
    let mut exc_idx = 0usize;
    for i in 0..total {
        // Determine if position i is an exception by scanning positions.
        if exc_idx < frame.exception_positions.len() && frame.exception_positions[exc_idx] as usize == i {
            out[i] = frame.exceptions[exc_idx];
            exc_idx += 1;
        } else {
            out[i] = packed_vals[packed_idx];
            packed_idx += 1;
        }
    }
    out
}

/// Pack `values` (each `width` bits) into u64 words (LSB-first bit layout).
pub fn bit_pack(values: &[u64], width: u8) -> Vec<u64> {
    if values.is_empty() || width == 0 {
        return vec![];
    }
    let total_bits = values.len() * width as usize;
    let words = total_bits.div_ceil(64);
    let mut out = vec![0u64; words];
    let mut bit_cursor = 0usize;
    for &v in values {
        let mut remaining = width as usize;
        let mut shifted = v;
        while remaining > 0 {
            let word_idx = bit_cursor / 64;
            let bit_off = bit_cursor % 64;
            let space = 64 - bit_off;
            let take = remaining.min(space);
            let mask = if take >= 64 { u64::MAX } else { (1u64 << take) - 1 };
            out[word_idx] |= (shifted & mask) << bit_off;
            shifted >>= take;
            bit_cursor += take;
            remaining -= take;
        }
    }
    out
}

/// Unpack `count` values of `width` bits each from `packed` (inverse of bit_pack).
pub fn bit_unpack(packed: &[u64], width: u32, count: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(count);
    let mut bit_cursor = 0usize;
    for _ in 0..count {
        let mut v: u64 = 0;
        let mut got = 0usize;
        while got < width as usize {
            let word_idx = bit_cursor / 64;
            let bit_off = bit_cursor % 64;
            let space = 64 - bit_off;
            let take = (width as usize - got).min(space);
            let mask = if take >= 64 { u64::MAX } else { (1u64 << take) - 1 };
            let word = *packed.get(word_idx).unwrap_or(&0u64);
            v |= ((word >> bit_off) & mask) << got;
            bit_cursor += take;
            got += take;
        }
        out.push(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_pack_unpack_roundtrip() {
        let vals = vec![1u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 15];
        let packed = bit_pack(&vals, 4);
        let unpacked = bit_unpack(&packed, 4, vals.len());
        assert_eq!(unpacked, vals);
    }

    #[test]
    fn test_bit_pack_odd_width() {
        let vals = vec![0u64, 1, 1, 0, 1, 1, 1, 0]; // 8 values * 1 bit = 1 word
        let packed = bit_pack(&vals, 1);
        assert_eq!(unpacked, bit_unpack(&packed, 1, 8));
        let unpacked = bit_unpack(&packed, 1, 8);
        assert_eq!(unpacked, vals);
    }

    #[test]
    fn test_pfor_roundtrip_small_deltas() {
        // Simulate instruction deltas: mostly +4 (zigzag → 8), a few back-jumps.
        let mut vals = vec![8u64; 128];
        vals[10] = 1999; // large forward jump (outlier)
        vals[50] = 100000; // big outlier
        let frame = encode_frame(&vals, 12);
        assert!(frame.bit_width <= 12);
        let decoded = decode_frame(&frame);
        assert_eq!(decoded, vals);
    }

    #[test]
    fn test_pfor_raw_fallback() {
        // Uniform random big values → packed not helpful → raw storage.
        let mut vals = vec![0u64; 64];
        for (i, v) in vals.iter_mut().enumerate() {
            *v = 0xDEAD_BEEF_0000_0000u64 + i as u64;
        }
        let frame = encode_frame(&vals, 8);
        assert_eq!(frame.bit_width, 64); // fell back to raw
        let decoded = decode_frame(&frame);
        assert_eq!(decoded, vals);
    }

    #[test]
    fn test_pfor_compression_ratio() {
        // 10_000 values, 95% fit in 8 bits → 8 bits each ≈ 10KB vs 80KB raw.
        let mut vals = Vec::with_capacity(10_000);
        for i in 0..10_000u64 {
            if i % 100 == 0 {
                vals.push(1u64 << 40); // rare outlier
            } else {
                vals.push(i % 256); // fits 8 bits
            }
        }
        let frame = encode_frame(&vals, 8);
        let packed_bytes = frame.packed.len() * 8;
        let exc_bytes = frame.exceptions.len() * 8 + frame.exception_positions.len() * 2;
        let total_bytes = packed_bytes + exc_bytes + 4;
        let raw_bytes = vals.len() * 8;
        assert!(total_bytes < raw_bytes / 3, "expected strong compression, got {total_bytes} vs {raw_bytes}");
    }
}
