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
    let mut v = value;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
    buf
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_encode_decode() {
        let values = vec![100u64, 105, 110, 200, 205];
        let deltas = delta_encode_u64(&values);
        assert_eq!(deltas, vec![100, 5, 5, 90, 5]);
        let decoded = delta_decode_u64(&deltas);
        assert_eq!(decoded, values);
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
