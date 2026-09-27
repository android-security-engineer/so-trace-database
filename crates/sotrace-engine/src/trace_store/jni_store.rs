//! JNI store — stores JNI boundary call records
//!
//! JNI calls are less frequent than instructions but carry rich metadata
//! (Java class, method, signature). They bridge the Java-Native boundary.
//!
//! Delta encoding strategy:
//! - **Direction**: DictionaryRef (only 2 values: JavaToNative, NativeToJava)
//! - **Java class/method**: DictionaryRef (same classes/methods repeat)
//! - **Native address**: NumericDelta (often sequential or within same function)
//! - **Signature**: DictionaryRef (same signatures repeat)

use anyhow::Result;

use sotrace_core::models::jni_call::{JNICall, JNICallDirection};

use crate::delta_store::delta_log::EventLog;
use crate::delta_store::delta_index::AddressIndex;
use crate::delta_store::types::*;

/// JNI store — stores JNI boundary call records
pub struct JNIStore {
    /// Event log for JNI call records. JNI calls are discrete events (not a
    /// reducible delta stream), and `seq` comes from the caller/adapter
    /// (`trace.seq`) — NOT a monotonic engine counter — so two calls can share
    /// a step. `EventLog` keeps a `Vec` per step so same-step calls all survive
    /// (a keyed `DeltaLog` would silently clobber all but the last). Mirrors
    /// the thread_store sync/state/switch logs (#52).
    delta_log: EventLog<JNICall>,
    /// Address index for native address queries
    address_index: AddressIndex,
}

impl JNIStore {
    /// Create a new JNI store
    pub fn new(config: DeltaStoreConfig) -> Self {
        // `config.compression` configures the EventLog; the rest is not retained.
        Self {
            delta_log: EventLog::new(config.compression),
            address_index: AddressIndex::new(),
        }
    }

    /// Write a JNI call record
    pub fn write(&mut self, call: JNICall) -> Result<()> {
        // Index by native address. Dedup: a repeated (address, step) is the
        // same function entry indexed twice (e.g. two threads sharing a `seq`),
        // not two distinct writes — `find_by_address` consumers must not
        // double-count. Call multiplicity lives in the EventLog.
        self.address_index.register_dedup(call.native_address, call.seq);

        let record = DeltaRecord {
            step: call.seq,
            encoding: DeltaEncoding::FullValue,
            payload: DeltaPayload::FullValue(call),
            prev_hash: None,
        };

        self.delta_log.append(record)?;
        Ok(())
    }

    /// Get the JNI calls recorded at exactly `step` (in insertion order).
    /// Returns a Vec because multiple calls can share a step.
    pub fn get_at_step(&self, step: u64) -> Vec<&JNICall> {
        self.delta_log.get_all(step).iter().filter_map(|record| {
            match &record.payload {
                DeltaPayload::FullValue(call) => Some(call),
                _ => None,
            }
        }).collect()
    }

    /// Find JNI calls by native address
    pub fn find_by_address(&self, address: u64) -> &[u64] {
        self.address_index.find_steps_for_address(address)
    }

    /// Query JNI calls in a step range
    pub fn query_range(&self, start: u64, end: u64) -> Vec<&JNICall> {
        self.delta_log.get_range(start, end)
            .into_iter()
            .filter_map(|record| {
                match &record.payload {
                    DeltaPayload::FullValue(call) => Some(call),
                    _ => None,
                }
            })
            .collect()
    }

    /// All JNI calls (sorted by step, insertion order within a step), for
    /// snapshot/persistence.
    pub fn all_jni_calls(&self) -> Vec<JNICall> {
        self.delta_log
            .all_records_sorted()
            .into_iter()
            .filter_map(|r| match r.payload {
                DeltaPayload::FullValue(t) => Some(t),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call(seq: u64, thread_id: u32, direction: JNICallDirection, native_address: u64) -> JNICall {
        JNICall {
            id: seq,
            seq,
            thread_id,
            direction,
            java_class: "com.app.Foo".to_string(),
            java_method: "doWork".to_string(),
            java_signature: "()V".to_string(),
            native_func_id: None,
            native_address,
            jni_env_address: None,
        }
    }

    /// Two JNI calls at the SAME step (different threads/addresses) must both
    /// survive. The old `DeltaLog` (keyed insert) silently clobbered the first.
    #[test]
    fn test_same_step_calls_both_survive() {
        let mut store = JNIStore::new(DeltaStoreConfig::default());

        // Feed the lower-thread call FIRST so a keyed-insert log would keep
        // the second and drop the first — mis-attributing step 100.
        store.write(make_call(100, 1, JNICallDirection::JavaToNative, 0x1000)).unwrap();
        store.write(make_call(100, 2, JNICallDirection::NativeToJava, 0x2000)).unwrap();

        let at_step = store.get_at_step(100);
        assert_eq!(at_step.len(), 2, "both same-step calls must survive");
        assert_eq!(at_step[0].thread_id, 1, "insertion order preserved");
        assert_eq!(at_step[1].thread_id, 2);

        let range = store.query_range(0, 200);
        assert_eq!(range.len(), 2, "query_range keeps both");

        let all = store.all_jni_calls();
        assert_eq!(all.len(), 2, "all_jni_calls (persistence path) keeps both");
    }

    /// `query_range` returns calls in step order (and insertion order within a
    /// step), not arbitrary HashMap/DeltaLog order.
    #[test]
    fn test_query_range_step_order() {
        let mut store = JNIStore::new(DeltaStoreConfig::default());
        // Feed out of step order.
        store.write(make_call(30, 1, JNICallDirection::JavaToNative, 0x30)).unwrap();
        store.write(make_call(10, 1, JNICallDirection::JavaToNative, 0x10)).unwrap();
        store.write(make_call(20, 1, JNICallDirection::NativeToJava, 0x20)).unwrap();

        let seqs: Vec<u64> = store.query_range(0, 100).iter().map(|c| c.seq).collect();
        assert_eq!(seqs, vec![10, 20, 30]);
    }

    /// `find_by_address` returns the steps at which a given native address was
    /// reached (the address index is a separate structure; this guards it
    /// staying wired after the EventLog migration).
    #[test]
    fn test_find_by_address() {
        let mut store = JNIStore::new(DeltaStoreConfig::default());
        store.write(make_call(10, 1, JNICallDirection::JavaToNative, 0x4000)).unwrap();
        store.write(make_call(20, 2, JNICallDirection::JavaToNative, 0x5000)).unwrap();
        store.write(make_call(30, 1, JNICallDirection::JavaToNative, 0x4000)).unwrap();

        let steps = store.find_by_address(0x4000);
        assert!(steps.contains(&10));
        assert!(steps.contains(&30));
        assert!(!steps.contains(&20));
    }

    /// Two JNI calls to the same native address at the same `seq` (e.g. two
    /// threads entering the same native method) must not produce a duplicated
    /// step in `find_by_address` — a repeated step would double-count in any
    /// consumer that does `find_by_address(addr).iter().flat_map(get_at_step)`.
    /// Both calls still survive in the EventLog.
    #[test]
    fn test_find_by_address_dedups_repeated_step() {
        let mut store = JNIStore::new(DeltaStoreConfig::default());
        store.write(make_call(5, 1, JNICallDirection::JavaToNative, 0x4000)).unwrap();
        store.write(make_call(5, 2, JNICallDirection::JavaToNative, 0x4000)).unwrap();
        store.write(make_call(9, 1, JNICallDirection::JavaToNative, 0x5000)).unwrap();

        assert_eq!(store.find_by_address(0x4000), &[5], "no duplicated step");
        // Both real calls survive in the keyed log.
        assert_eq!(store.get_at_step(5).len(), 2);
    }
}
