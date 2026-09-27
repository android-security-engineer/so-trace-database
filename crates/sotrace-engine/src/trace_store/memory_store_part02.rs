
#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> MemoryStore {
        MemoryStore::new(DeltaStoreConfig::default())
    }

    fn write(s: &mut MemoryStore, step: u64, address: u64, data: Vec<u8>) {
        s.write(MemoryWrite { step, thread_id: 1, address, data }).unwrap();
    }

    /// A later partial write must be folded on top of earlier writes to the same
    /// page — not applied alone to a zero page. This is the core regression: a
    /// byte-level delta only records the changed byte, so querying wider than
    /// that byte must still see the earlier bytes.
    #[test]
    fn test_query_value_folds_partial_overwrite() {
        let mut s = store();
        write(&mut s, 5, 0x1000, vec![0xEF, 0xBE, 0xAD, 0xDE]); // DEADBEEF (LE)
        write(&mut s, 10, 0x1000, vec![0x11]); // overwrite byte 0 only

        // Before the overwrite: the original 4 bytes.
        let at5 = s.query_value(0x1000, 4, 5).unwrap();
        assert_eq!(at5.value, vec![0xEF, 0xBE, 0xAD, 0xDE]);

        // After: byte 0 changed, bytes 1-3 preserved from step 5.
        let at10 = s.query_value(0x1000, 4, 10).unwrap();
        assert_eq!(at10.value, vec![0x11, 0xBE, 0xAD, 0xDE]);
        // Two deltas were folded to reach this state.
        assert_eq!(at10.deltas_applied, 2);
    }

    /// Querying a non-zero offset within the page also reflects all folded
    /// writes, including ones to different offsets.
    #[test]
    fn test_query_value_multiple_offsets_same_page() {
        let mut s = store();
        write(&mut s, 1, 0x2000, vec![0xAA]); // offset 0
        write(&mut s, 2, 0x2010, vec![0xBB, 0xCC]); // offset 16
        write(&mut s, 3, 0x2000, vec![0xDD]); // overwrite offset 0

        // Offset 16 bytes survive across the later offset-0 overwrite.
        let v = s.query_value(0x2010, 2, 3).unwrap();
        assert_eq!(v.value, vec![0xBB, 0xCC]);
        let v0 = s.query_value(0x2000, 1, 3).unwrap();
        assert_eq!(v0.value, vec![0xDD]);
    }

    /// A page never modified at or before the step yields `None` from
    /// `query_value` (distinct from a page written with zero bytes).
    #[test]
    fn test_query_value_none_before_first_write() {
        let mut s = store();
        write(&mut s, 100, 0x3000, vec![0x42]);
        assert!(s.query_value(0x3000, 1, 50).is_none()); // before the write
        assert!(s.query_value(0x9000, 1, 200).is_none()); // untouched page
    }

    /// `reconstruct_page` returns a zero page (Some) for an untouched page, and
    /// the folded page for a modified one.
    #[test]
    fn test_reconstruct_page_zero_vs_folded() {
        let mut s = store();
        let zero = s.reconstruct_page(0x4000, 10).unwrap();
        assert_eq!(zero.len(), PAGE_SIZE);
        assert!(zero.iter().all(|&b| b == 0));

        write(&mut s, 5, 0x4000, vec![0x01, 0x02]);
        let folded = s.reconstruct_page(0x4000, 10).unwrap();
        assert_eq!(&folded[0..2], &[0x01, 0x02]);
        assert!(folded[2..].iter().all(|&b| b == 0));
    }

    /// Core regression for the per-page log split: two writes at the SAME step
    /// but on DIFFERENT pages must both survive. A single step-keyed log would
    /// have kept only the last-appended record, so folding the first page would
    /// have replayed the second page's delta and returned wrong bytes.
    #[test]
    fn test_same_step_different_pages_no_collision() {
        let mut s = store();
        // One logical event at step 7 touches two distinct pages.
        write(&mut s, 7, 0x5000, vec![0xAA, 0xBB]); // page 0x5000
        write(&mut s, 7, 0x6000, vec![0xCC, 0xDD]); // page 0x6000

        let p5 = s.query_value(0x5000, 2, 7).unwrap();
        assert_eq!(p5.value, vec![0xAA, 0xBB]);
        assert_eq!(p5.page_address, 0x5000);

        let p6 = s.query_value(0x6000, 2, 7).unwrap();
        assert_eq!(p6.value, vec![0xCC, 0xDD]);
        assert_eq!(p6.page_address, 0x6000);
    }

    /// A single write that straddles a page boundary is split across two page
    /// logs at the same step; both halves must reconstruct correctly.
    #[test]
    fn test_write_straddling_page_boundary() {
        let mut s = store();
        // Start 3 bytes before the boundary: 3 bytes land on page 0x7000,
        // the next 3 on page 0x8000, all at step 9.
        let last = PAGE_SIZE as u64 - 3;
        write(&mut s, 9, 0x7000 + last, vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);

        // Tail of the first page holds the first 3 bytes.
        let first = s.query_value(0x7000 + last, 3, 9).unwrap();
        assert_eq!(first.value, vec![0x10, 0x20, 0x30]);
        assert_eq!(first.page_address, 0x7000);

        // Head of the next page holds the last 3 bytes.
        let second = s.query_value(0x8000, 3, 9).unwrap();
        assert_eq!(second.value, vec![0x40, 0x50, 0x60]);
        assert_eq!(second.page_address, 0x8000);
    }

    /// A single `query_value` spanning the page boundary returns the full
    /// value stitched across both pages — it must NOT silently truncate to
    /// the first page's tail. `page_address` stays at the first page.
    #[test]
    fn test_query_value_straddling_boundary_not_truncated() {
        let mut s = store();
        let last = PAGE_SIZE as u64 - 3;
        write(&mut s, 9, 0x7000 + last, vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);

        let v = s.query_value(0x7000 + last, 6, 9).unwrap();
        assert_eq!(v.value, vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
        assert_eq!(v.page_address, 0x7000);
        // Deltas from both pages were folded (one write per page at step 9).
        assert_eq!(v.deltas_applied, 2);
    }

    /// A straddling read whose tail lands on a never-modified page fills the
    /// missing tail with zero bytes rather than truncating or returning None.
    #[test]
    fn test_query_value_straddle_into_unmodified_page_is_zero_filled() {
        let mut s = store();
        let last = PAGE_SIZE as u64 - 2;
        // Write only 2 bytes on the tail of page 0x7000; page 0x8000 untouched.
        write(&mut s, 4, 0x7000 + last, vec![0xAA, 0xBB]);

        // Read 5 bytes: 2 from page 0x7000, 3 from the untouched page 0x8000.
        let v = s.query_value(0x7000 + last, 5, 4).unwrap();
        assert_eq!(v.value, vec![0xAA, 0xBB, 0x00, 0x00, 0x00]);
        assert_eq!(v.page_address, 0x7000);
        assert_eq!(v.deltas_applied, 1);
    }

    /// Two writes to the SAME page at the SAME step are both retained (EventLog
    /// keeps a Vec per step), applied in insertion order — the later one wins on
    /// overlapping bytes, and non-overlapping bytes from the earlier one survive.
    #[test]
    fn test_same_page_same_step_both_applied() {
        let mut s = store();
        write(&mut s, 3, 0x9000, vec![0x01, 0x02, 0x03, 0x04]); // bytes 0..4
        write(&mut s, 3, 0x9002, vec![0xFF, 0xFF]); // overwrite bytes 2..4, same step

        let v = s.query_value(0x9000, 4, 3).unwrap();
        // Bytes 0-1 from the first write, bytes 2-3 from the second.
        assert_eq!(v.value, vec![0x01, 0x02, 0xFF, 0xFF]);
        // Both same-step records folded (not one dropped).
        assert_eq!(v.deltas_applied, 2);
    }

    /// A write that straddles u64::MAX must not overflow the page cursor.
    /// Before saturation, once the cursor advanced past u64::MAX it wrapped
    /// back to a low page (release) or panicked (debug), so the trailing bytes
    /// of the write landed on page 0 — corrupting an unrelated page. With
    /// saturation the cursor clamps at u64::MAX and the loop still terminates
    /// (driven by `offset` over `data.len()`); the bytes that fit in the final
    /// page are stored correctly, and no low page is touched.
    #[test]
    fn test_write_straddling_u64_max_no_overflow() {
        let mut s = store();
        // 4 bytes starting 2 bytes before the address-space end: the first 3
        // land in the last page, then the cursor must advance across u64::MAX
        // for the remaining 1 — the overflow site.
        let addr = u64::MAX - 2;
        let last_page = page_align(addr);
        let off = page_offset(addr);
        // u64::MAX & 0xFFF == 0xFFF (4095), so (u64::MAX-2) offset == 4093.
        assert_eq!(off, PAGE_SIZE - 3, "test setup: start at page tail - 3");

        write(&mut s, 1, addr, vec![0x10, 0x20, 0x30, 0x40]);

        // The first 3 bytes (the ones that fit in the last page) survive.
        let v = s.query_value(addr, 3, 1).unwrap();
        assert_eq!(v.value, vec![0x10, 0x20, 0x30]);
        assert_eq!(v.page_address, last_page);

        // No stray write landed on a low page from a wrapped cursor — only
        // the final page (and saturating keeps the cursor there) is touched.
        assert!(
            s.page_logs.keys().all(|&p| p >= u64::MAX - PAGE_SIZE as u64),
            "no low page should be touched, got {:?}",
            s.page_logs.keys().collect::<Vec<_>>()
        );
    }

    /// A read that straddles u64::MAX must not panic on the slow path, where
    /// the page cursor advances with `addr += PAGE_SIZE`. The first page
    /// contributes its tail bytes; the bytes that would live past u64::MAX have
    /// no legal page, so they come back zero-filled — matching the
    /// never-modified-page contract. Before the fix this was a debug-panic
    /// `attempt to add with overflow`, the read-side twin of #86's write bug.
    #[test]
    fn test_query_value_straddling_u64_max_no_overflow() {
        let mut s = store();
        // Write 3 bytes into the very last page (offset 4093..4095).
        let addr = u64::MAX - 2;
        write(&mut s, 1, addr, vec![0x10, 0x20, 0x30]);

        // Read 5 bytes starting 2 before the end: 3 real bytes from the last
        // page, then 2 bytes that fall off the address space → zero-filled.
        let v = s.query_value(addr, 5, 1).unwrap();
        assert_eq!(v.value, vec![0x10, 0x20, 0x30, 0x00, 0x00],
            "tail bytes past u64::MAX are zero-filled, not a panic");
        assert_eq!(v.value.len(), 5);
    }
}
