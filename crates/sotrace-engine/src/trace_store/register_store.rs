//! Register store — stores register value changes using bitmask delta encoding
//!
//! ARM64 has 31 GPRs + SP + PC + NZCV = 35 register values.
//! Typically only 1-3 registers change per instruction.
//!
//! Delta encoding strategy:
//! - **Bitmask**: u64 bitmask indicating which registers changed (bit i = register i changed)
//! - **Values**: only the changed register values are stored, in order
//!
//! This gives ~90% compression for typical traces:
//! - Full state: 35 × 8 = 280 bytes
//! - Delta (2 regs changed): 8 (mask) + 16 (2 values) = 24 bytes
//! - Compression ratio: ~11.7:1
//!
//! Query acceleration:
//! - RegisterIndex maps (register_id, step) → value
//! - For "what was register X at step N?", we find the last delta
//!   that touched register X before step N, using the index

use anyhow::Result;

use sotrace_core::models::register_delta::{RegisterDelta, RegisterState};

use crate::delta_store::delta_log::EventLog;
use crate::delta_store::delta_index::insert_step_sorted_dedup;
use crate::delta_store::types::*;

/// ARM64 register count: 31 GPRs + SP + PC + NZCV = 34 (using u64 for NZCV)
const ARM64_REGISTER_COUNT: usize = 34;

/// Register store — bitmask delta encoding for register changes
pub struct RegisterStore {
    /// Event log for register delta records.
    ///
    /// `seq` comes from the caller's `trace.seq`, not an engine-assigned
    /// counter, so it is NOT guaranteed unique — a single instruction could be
    /// reported as multiple deltas (e.g. an adapter splitting GPR and PC
    /// updates into two records at the same `seq`). A keyed `DeltaLog` would
    /// keep only the last, silently dropping the others' register changes.
    /// `EventLog` retains every same-step delta; `reconstruct_state`'s replay
    /// applies them in insertion order (last-writer-wins per register slot),
    /// which is the correct merge for overlapping masks.
    delta_log: EventLog<RegisterDelta>,
    /// Register index: for each register, which steps modified it
    /// register_index[reg_id] → sorted list of step numbers
    register_index: Vec<Vec<u64>>,
    /// Last full register state (for reconstruction)
    last_full_state: Option<RegisterState>,
}

impl RegisterStore {
    /// Create a new register store
    pub fn new(config: DeltaStoreConfig) -> Self {
        // `config.compression` configures the EventLog; the rest of `config` is
        // not retained — no query path reads it back, so keeping the field
        // would be dead state. Mirrors the other stores' constructor shape.
        Self {
            delta_log: EventLog::new(config.compression),
            register_index: (0..ARM64_REGISTER_COUNT).map(|_| Vec::new()).collect(),
            last_full_state: None,
        }
    }

    /// Write a register delta (changed registers only)
    pub fn write_delta(&mut self, delta: RegisterDelta) -> Result<()> {
        // Index: for each changed register, record this step.
        // Dedup the step list: two deltas at the same `seq` touching the same
        // register would register the step twice, but `query_register` only
        // needs one pointer to that step (it then scans all same-step deltas
        // via `get_all`). A duplicated step would be harmless to the binary
        // search but inconsistent with the deduplicated
        // ThreadIndex/FunctionIndex.
        let mut bit = delta.change_mask;
        let mut reg_idx = 0usize;
        while bit != 0 {
            if bit & 1 != 0 {
                if reg_idx < self.register_index.len() {
                    insert_step_sorted_dedup(&mut self.register_index[reg_idx], delta.seq);
                }
            }
            bit >>= 1;
            reg_idx += 1;
        }

        let record = DeltaRecord {
            step: delta.seq,
            encoding: DeltaEncoding::ByteLevel, // bitmask is a form of byte-level delta
            payload: DeltaPayload::FullValue(delta),
            prev_hash: None,
        };

        self.delta_log.append(record)?;
        Ok(())
    }

    /// Number of register-delta records retained (one per accepted `Register` event).
    pub fn record_count(&self) -> u64 {
        self.delta_log.total_count()
    }

    /// Write a full register state (used as snapshot)
    pub fn write_full_state(&mut self, state: RegisterState) -> Result<()> {
        // Convert full state to a delta from previous state
        // If no previous state, all registers are "changed"
        let mask = if let Some(ref prev) = self.last_full_state {
            // Compute bitmask of changed registers
            let mut m: u64 = 0;
            for i in 0..31 {
                if state.gp_regs[i] != prev.gp_regs[i] {
                    m |= 1u64 << i;
                }
            }
            if state.sp != prev.sp { m |= 1u64 << 31; }
            if state.pc != prev.pc { m |= 1u64 << 32; }
            if state.nzcv != prev.nzcv { m |= 1u64 << 33; }
            m
        } else {
            // First state: all registers are "new"
            (1u64 << ARM64_REGISTER_COUNT) - 1
        };

        // Extract changed values
        let mut values = Vec::new();
        for i in 0..31 {
            if mask & (1u64 << i) != 0 {
                values.push(state.gp_regs[i]);
            }
        }
        if mask & (1u64 << 31) != 0 { values.push(state.sp); }
        if mask & (1u64 << 32) != 0 { values.push(state.pc); }
        if mask & (1u64 << 33) != 0 { values.push(state.nzcv as u64); }

        let delta = RegisterDelta {
            seq: state.seq,
            change_mask: mask,
            values,
        };

        self.write_delta(delta)?;
        self.last_full_state = Some(state);
        Ok(())
    }

    /// Query register value at a specific step
    ///
    /// Uses the register index to find the last delta that touched
    /// the target register before the target step — O(log K) where
    /// K = number of changes to this specific register.
    pub fn query_register(&self, register_id: usize, target_step: u64) -> Option<u64> {
        if register_id >= self.register_index.len() {
            return None;
        }

        // Find the last step where this register was modified before target_step.
        // `steps` is kept sorted by `write_delta`, so binary-search it — O(log K).
        let steps = &self.register_index[register_id];
        let idx = steps.partition_point(|&s| s <= target_step);
        let last_mod_step = steps.get(idx.checked_sub(1)?)?;

        // A step may hold several deltas (same `seq`, e.g. an adapter splitting
        // GPR and PC updates). Scan all same-step deltas in insertion order and
        // return the value from the LAST one that touches this register —
        // matching `reconstruct_state`'s last-writer-wins replay semantics.
        let records = self.delta_log.get_all(*last_mod_step);
        let mut value = None;
        for record in records {
            if let DeltaPayload::FullValue(delta) = &record.payload {
                if let Some(v) = self.extract_register_value(delta, register_id) {
                    value = Some(v);
                }
            }
        }
        value
    }

    /// List every step at which a given register was modified, in ascending
    /// step order, optionally restricted to `[start, end]`.
    ///
    /// Backed by `register_index` (the per-register sorted step list maintained
    /// by `write_delta`), so this is an O(log K + R) slice — not a scan of the
    /// whole delta log. Each entry is the step at which the register changed;
    /// the new value at that step is recoverable via [`Self::query_register`].
    ///
    /// This exposes the index that `query_register` was already using for its
    /// single-point lookup — the "when did register X change?" list query was
    /// previously unreachable even though the index was maintained on every
    /// delta.
    pub fn query_register_history(&self, register_id: usize, start: u64, end: u64) -> Vec<u64> {
        if register_id >= self.register_index.len() {
            return Vec::new();
        }
        let steps = &self.register_index[register_id];
        let lo = steps.partition_point(|&s| s < start);
        let hi = steps.partition_point(|&s| s <= end);
        steps[lo..hi].to_vec()
    }

    /// Extract a specific register value from a delta record
    fn extract_register_value(&self, delta: &RegisterDelta, register_id: usize) -> Option<u64> {
        if delta.change_mask & (1u64 << register_id) == 0 {
            return None; // This register wasn't changed in this delta
        }

        // Count set bits before register_id to find value index
        let value_idx = (0..register_id)
            .filter(|&i| delta.change_mask & (1u64 << i) != 0)
            .count();

        delta.values.get(value_idx).copied()
    }

    /// Reconstruct the full ARM64 register file as of a given step.
    ///
    /// Replays every delta in `[0, target_step]` in step order, applying each
    /// changed register into a running register file: a slot holds the value
    /// from the most recent delta (<= `target_step`) that touched it, and slots
    /// never written retain 0. This is the multi-register generalization of
    /// [`Self::query_register`] — one coherent snapshot instead of 34 separate
    /// point queries.
    ///
    /// Iteration is backed by [`EventLog::get_range`], which flattens every
    /// same-step delta (insertion order within a step), so it is a single
    /// O(log N + K) pass over the K deltas in range rather than O(target_step).
    /// When two deltas share a step, both are applied in order — the second
    /// overwrites the first on any overlapping register slot, matching
    /// [`Self::query_register`]'s last-writer-wins scan. Returns `None` when no
    /// delta exists at or before `target_step` (nothing to reconstruct).
    pub fn reconstruct_state(&self, target_step: u64) -> Option<RegisterState> {
        let records = self.delta_log.get_range(0, target_step);
        if records.is_empty() {
            return None;
        }

        let mut state = RegisterState {
            seq: target_step,
            gp_regs: [0u64; 31],
            sp: 0,
            pc: 0,
            nzcv: 0,
        };

        for record in records {
            let DeltaPayload::FullValue(delta) = &record.payload else {
                continue;
            };
            // Walk the change mask; for each set bit, route the register's new
            // value into the matching field of the register file.
            let mut bit = delta.change_mask;
            let mut reg_idx = 0usize;
            while bit != 0 {
                if bit & 1 != 0 {
                    if let Some(value) = self.extract_register_value(delta, reg_idx) {
                        match reg_idx {
                            0..=30 => state.gp_regs[reg_idx] = value,
                            31 => state.sp = value,
                            32 => state.pc = value,
                            33 => state.nzcv = value as u32,
                            _ => {} // beyond the ARM64 register set; ignore
                        }
                    }
                }
                bit >>= 1;
                reg_idx += 1;
            }
        }

        Some(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> RegisterStore {
        RegisterStore::new(DeltaStoreConfig::default())
    }

    /// A single-register delta: register `reg` set to `value` at step `seq`.
    fn reg_delta(seq: u64, reg: usize, value: u64) -> RegisterDelta {
        RegisterDelta { seq, change_mask: 1u64 << reg, values: vec![value] }
    }

    #[test]
    fn test_query_register_binary_search_out_of_order() {
        let mut s = store();
        // Feed X0 changes out of step order — the index must stay sorted so the
        // binary search picks the correct "last change <= target".
        s.write_delta(reg_delta(30, 0, 0xC0)).unwrap();
        s.write_delta(reg_delta(10, 0, 0xA0)).unwrap();
        s.write_delta(reg_delta(20, 0, 0xB0)).unwrap();

        assert_eq!(s.query_register(0, 10), Some(0xA0)); // exact first
        assert_eq!(s.query_register(0, 25), Some(0xB0)); // between 20 and 30
        assert_eq!(s.query_register(0, 30), Some(0xC0)); // exact last
        assert_eq!(s.query_register(0, 999), Some(0xC0)); // past the end
        assert_eq!(s.query_register(0, 5), None); // before the first change
    }

    #[test]
    fn test_query_register_isolated_per_register() {
        let mut s = store();
        s.write_delta(reg_delta(10, 0, 0xAA)).unwrap();
        s.write_delta(reg_delta(15, 5, 0x55)).unwrap();

        // X5 was only touched at step 15; querying X5 before that yields nothing,
        // and querying X0 must not see X5's change.
        assert_eq!(s.query_register(5, 20), Some(0x55));
        assert_eq!(s.query_register(5, 10), None);
        assert_eq!(s.query_register(0, 20), Some(0xAA));
    }

    #[test]
    fn test_query_register_multi_register_delta_extraction() {
        let mut s = store();
        // One step changes both X0 and X5; values are stored in bit order.
        s.write_delta(RegisterDelta {
            seq: 7,
            change_mask: (1u64 << 0) | (1u64 << 5),
            values: vec![0x11, 0x99], // X0 = 0x11, X5 = 0x99
        }).unwrap();

        assert_eq!(s.query_register(0, 7), Some(0x11));
        assert_eq!(s.query_register(5, 7), Some(0x99));
        // A register that never changed returns None.
        assert_eq!(s.query_register(3, 7), None);
    }

    #[test]
    fn test_query_register_out_of_bounds_id() {
        let s = store();
        assert_eq!(s.query_register(ARM64_REGISTER_COUNT, 100), None);
        assert_eq!(s.query_register(ARM64_REGISTER_COUNT + 50, 100), None);
    }

    /// With no deltas at or before the step there is nothing to reconstruct.
    #[test]
    fn test_reconstruct_state_empty_is_none() {
        let s = store();
        assert!(s.reconstruct_state(100).is_none());

        let mut s2 = store();
        s2.write_delta(reg_delta(50, 0, 0xAA)).unwrap();
        // The only delta is after the query step.
        assert!(s2.reconstruct_state(10).is_none());
    }

    /// The reconstructed file holds each register's last value <= target_step,
    /// and untouched slots stay zero.
    #[test]
    fn test_reconstruct_state_accumulates_last_values() {
        let mut s = store();
        s.write_delta(reg_delta(10, 0, 0xA0)).unwrap(); // x0
        s.write_delta(reg_delta(20, 2, 0xC2)).unwrap(); // x2
        s.write_delta(reg_delta(30, 0, 0xA1)).unwrap(); // x0 overwritten

        let st = s.reconstruct_state(25).unwrap();
        assert_eq!(st.seq, 25);
        assert_eq!(st.gp_regs[0], 0xA0); // last x0 change <= 25 is step 10
        assert_eq!(st.gp_regs[2], 0xC2);
        assert_eq!(st.gp_regs[1], 0); // never written

        // Past the last overwrite, x0 reflects step 30.
        let st2 = s.reconstruct_state(30).unwrap();
        assert_eq!(st2.gp_regs[0], 0xA1);
        assert_eq!(st2.gp_regs[2], 0xC2);
    }

    /// SP/PC/NZCV live in the high mask bits (31/32/33) and route into their
    /// own fields, with NZCV narrowed to u32.
    #[test]
    fn test_reconstruct_state_special_registers() {
        let mut s = store();
        // One step sets SP, PC and NZCV together; values are in bit order.
        s.write_delta(RegisterDelta {
            seq: 5,
            change_mask: (1u64 << 31) | (1u64 << 32) | (1u64 << 33),
            values: vec![0x7fff_0000, 0x4000_1234, 0x6000_0000], // SP, PC, NZCV
        }).unwrap();

        let st = s.reconstruct_state(5).unwrap();
        assert_eq!(st.sp, 0x7fff_0000);
        assert_eq!(st.pc, 0x4000_1234);
        assert_eq!(st.nzcv, 0x6000_0000);
        assert_eq!(st.gp_regs[0], 0);
    }

    /// A multi-register delta is unpacked into the right slots, matching what
    /// per-register `query_register` returns.
    #[test]
    fn test_reconstruct_state_matches_query_register() {
        let mut s = store();
        s.write_delta(RegisterDelta {
            seq: 7,
            change_mask: (1u64 << 0) | (1u64 << 5) | (1u64 << 30),
            values: vec![0x11, 0x99, 0x30], // x0, x5, x30
        }).unwrap();

        let st = s.reconstruct_state(7).unwrap();
        assert_eq!(st.gp_regs[0], s.query_register(0, 7).unwrap());
        assert_eq!(st.gp_regs[5], s.query_register(5, 7).unwrap());
        assert_eq!(st.gp_regs[30], s.query_register(30, 7).unwrap());
        assert_eq!(st.gp_regs[0], 0x11);
        assert_eq!(st.gp_regs[5], 0x99);
        assert_eq!(st.gp_regs[30], 0x30);
    }

    /// Two deltas at the same `seq` (e.g. an adapter splitting a GPR update and
    /// a PC update into separate records) must both survive. A keyed DeltaLog
    /// would keep only the last and lose the GPR change; the EventLog retains
    /// both, and `reconstruct_state`'s replay applies them in order.
    #[test]
    fn test_same_seq_multiple_deltas_both_survive() {
        let mut s = store();
        // seq=7: first delta sets x0, second sets PC — same step, disjoint masks.
        s.write_delta(reg_delta(7, 0, 0xAA)).unwrap(); // x0
        s.write_delta(RegisterDelta {
            seq: 7,
            change_mask: 1u64 << 32,
            values: vec![0x4000_1234], // PC
        }).unwrap();

        // Point query on x0 still finds it despite the later same-step delta.
        assert_eq!(s.query_register(0, 7), Some(0xAA));
        assert_eq!(s.query_register(32, 7), Some(0x4000_1234));

        // Reconstructed snapshot holds both.
        let st = s.reconstruct_state(7).unwrap();
        assert_eq!(st.gp_regs[0], 0xAA);
        assert_eq!(st.pc, 0x4000_1234);
    }

    /// When two same-step deltas touch the SAME register, the later one wins —
    /// matching last-writer-wins replay semantics. `query_register` must return
    /// the value from the last same-step delta that touches the register, not
    /// the first.
    #[test]
    fn test_same_seq_overlapping_register_last_wins() {
        let mut s = store();
        s.write_delta(reg_delta(7, 0, 0xAA)).unwrap();
        s.write_delta(reg_delta(7, 0, 0xBB)).unwrap(); // same step, same reg, later

        assert_eq!(s.query_register(0, 7), Some(0xBB), "later same-step delta wins");
        let st = s.reconstruct_state(7).unwrap();
        assert_eq!(st.gp_regs[0], 0xBB);
    }
}
