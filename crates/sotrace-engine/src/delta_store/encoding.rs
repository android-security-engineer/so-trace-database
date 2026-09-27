//! Delta encoding — strategies for compact representation of changes
//!
//! The encoding choice depends on the nature of the data:
//! - Memory pages: byte-level changes (few bytes change per instruction)
//! - Register values: bitmask + changed values (few registers change per instruction)
//! - Instruction addresses: numeric delta (monotonically increasing or small jumps)
//! - Thread IDs: dictionary reference (few unique threads, highly repetitive)
//! - Timestamps: numeric delta (monotonically increasing)

use super::types::*;

/// Encode a memory write as a byte-level delta
///
/// Returns ByteLevel encoding if changes are small enough,
/// otherwise returns FullValue encoding.
pub fn encode_memory_delta(
    old_page: &[u8],
    new_page: &[u8],
    threshold: usize,
) -> DeltaPayload<Vec<u8>> {
    // Find all changed byte ranges
    let changes = find_byte_changes(old_page, new_page);
    let total_changed_bytes = changes.iter().map(|c| c.size as usize).sum::<usize>();

    if total_changed_bytes <= threshold {
        DeltaPayload::ByteChanges(changes)
    } else {
        DeltaPayload::FullValue(new_page.to_vec())
    }
}

/// Find byte-level changes between two values
pub fn find_byte_changes(old: &[u8], new: &[u8]) -> Vec<ByteChange> {
    assert_eq!(old.len(), new.len(), "values must have same length for byte-level comparison");

    let mut changes = Vec::new();
    let mut i = 0;

    while i < old.len() {
        if old[i] != new[i] {
            // Find the end of this change region
            let start = i;
            let mut end = i;
            while end < old.len() && old[end] != new[end] {
                end += 1;
            }

            changes.push(ByteChange {
                offset: start as u16,
                size: (end - start) as u8,
                new_bytes: new[start..end].to_vec(),
            });

            i = end;
        } else {
            i += 1;
        }
    }

    changes
}

/// Encode register changes using bitmask approach
///
/// ARM64: 31 GPRs + SP + PC + NZCV = 35 values
/// Only changed registers are stored.
pub fn encode_register_delta(
    old_regs: &[u64],
    new_regs: &[u64],
) -> (u64, Vec<u64>) {
    assert_eq!(old_regs.len(), new_regs.len());

    let mut mask: u64 = 0;
    let mut changed_values = Vec::new();

    for (i, (old_val, new_val)) in old_regs.iter().zip(new_regs.iter()).enumerate() {
        if old_val != new_val {
            mask |= 1u64 << i;
            changed_values.push(*new_val);
        }
    }

    (mask, changed_values)
}

/// Decode register delta using bitmask
pub fn decode_register_delta(
    base_regs: &[u64],
    mask: u64,
    changed_values: &[u64],
) -> Vec<u64> {
    let mut result = base_regs.to_vec();
    let mut value_idx = 0;

    for i in 0..base_regs.len() {
        if mask & (1u64 << i) != 0 {
            result[i] = changed_values[value_idx];
            value_idx += 1;
        }
    }

    result
}

/// Encode a numeric delta (for addresses, timestamps, sequence numbers)
pub fn encode_numeric_delta(old: u64, new: u64) -> DeltaPayload<u64> {
    let delta = new as i64 - old as i64;
    DeltaPayload::NumericDelta(delta)
}

/// Decode a numeric delta
pub fn decode_numeric_delta(old: u64, delta: i64) -> u64 {
    (old as i64 + delta) as u64
}

/// Choose the best encoding for a given change
pub fn choose_encoding(
    old_value_size: usize,
    changed_bytes: usize,
    is_first_occurrence: bool,
) -> DeltaEncoding {
    if is_first_occurrence {
        return DeltaEncoding::FullValue;
    }

    // If less than 10% changed, use byte-level
    if changed_bytes * 10 < old_value_size {
        DeltaEncoding::ByteLevel
    }
    // If less than 50% changed, use binary diff (future)
    else if changed_bytes * 2 < old_value_size {
        DeltaEncoding::BinaryDiff
    }
    // Otherwise, store full value
    else {
        DeltaEncoding::FullValue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_changes_detection() {
        let old = vec![0u8; 16];
        let mut new = vec![0u8; 16];
        new[4] = 0xFF;
        new[5] = 0xFF;
        new[10] = 0xAA;

        let changes = find_byte_changes(&old, &new);
        assert_eq!(changes.len(), 2); // Two change regions
        assert_eq!(changes[0].offset, 4);
        assert_eq!(changes[0].size, 2);
        assert_eq!(changes[1].offset, 10);
        assert_eq!(changes[1].size, 1);
    }

    #[test]
    fn test_memory_delta_encoding() {
        let old_page = vec![0u8; PAGE_SIZE];
        let mut new_page = vec![0u8; PAGE_SIZE];
        new_page[100] = 0x42;
        new_page[101] = 0x42;

        let payload = encode_memory_delta(&old_page, &new_page, BYTE_LEVEL_THRESHOLD);
        match payload {
            DeltaPayload::ByteChanges(changes) => {
                assert_eq!(changes.len(), 1);
                assert_eq!(changes[0].offset, 100);
                assert_eq!(changes[0].size, 2);
            }
            _ => panic!("Expected ByteChanges for small modifications"),
        }
    }

    #[test]
    fn test_register_delta_encoding() {
        let old_regs = vec![0u64, 0, 0, 100, 0, 0, 200, 0];
        let new_regs = vec![0u64, 50, 0, 100, 0, 300, 200, 0];

        let (mask, values) = encode_register_delta(&old_regs, &new_regs);
        assert_eq!(mask, 0b0100010); // bits 1 and 5 changed
        assert_eq!(values, vec![50, 300]);

        let reconstructed = decode_register_delta(&old_regs, mask, &values);
        assert_eq!(reconstructed, new_regs);
    }

    #[test]
    fn test_numeric_delta() {
        let old = 100u64;
        let new = 105u64;
        let delta = encode_numeric_delta(old, new);
        match delta {
            DeltaPayload::NumericDelta(d) => {
                assert_eq!(d, 5);
                let reconstructed = decode_numeric_delta(old, d);
                assert_eq!(reconstructed, new);
            }
            _ => panic!("Expected NumericDelta"),
        }
    }

    #[test]
    fn test_encoding_choice() {
        // First occurrence → FullValue
        assert_eq!(choose_encoding(4096, 8, true), DeltaEncoding::FullValue);

        // <10% changed → ByteLevel
        assert_eq!(choose_encoding(4096, 8, false), DeltaEncoding::ByteLevel);

        // >50% changed → FullValue
        assert_eq!(choose_encoding(100, 60, false), DeltaEncoding::FullValue);
    }
}
