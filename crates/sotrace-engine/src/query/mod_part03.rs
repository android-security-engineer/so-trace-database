
#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta_store::types::DeltaStoreConfig;
    use crate::trace_store::memory_store::MemoryWrite;
    use sotrace_core::models::instruction_trace::InstructionTrace;
    use sotrace_core::models::register_delta::RegisterDelta;
    use sotrace_core::models::thread::{
        ThreadInfo, ThreadSyncEvent, SyncEventType, SyncResult,
        ContextSwitch, SwitchReason,
    };

    fn make_config() -> DeltaStoreConfig {
        DeltaStoreConfig::default()
    }

    fn make_engine_with_data() -> TraceEngine {
        let mut engine = TraceEngine::new(1, make_config());

        // Register threads
        for tid in [1, 2] {
            engine.register_thread(ThreadInfo {
                thread_id: tid, pthread_id: None, parent_thread_id: 0,
                create_step: 0, exit_step: None, name: None,
                stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
            }).unwrap();
        }

        // Import instructions
        for i in 0..20 {
            engine.import_instruction(InstructionTrace {
                seq: i, thread_id: 1 + (i % 2) as u32, address: 0x4000 + i * 4,
                timestamp: None, is_branch: false, branch_taken: false, opcode: None,
            }).unwrap();
        }

        // Import sync events
        engine.record_sync_event(ThreadSyncEvent {
            step: 5, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();
        engine.record_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 2,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xABCD0000,
            result: SyncResult::Success,
            wait_duration_ns: Some(500),
        }).unwrap();

        // Import context switches
        engine.record_context_switch(ContextSwitch {
            step: 8, from_thread: 1, to_thread: 2,
            switch_reason: SwitchReason::Preemption,
            cpu_core: None,
        }).unwrap();

        engine
    }

    #[test]
    fn test_query_instructions_range() {
        let engine = make_engine_with_data();

        let results = QueryEngine::query_instructions(&engine, InstructionQuery {
            so_file_id: 1,
            start_step: Some(5),
            end_step: Some(10),
            address_range: None,
            thread_id: None,
            limit: None,
        }).unwrap();

        assert_eq!(results.len(), 6); // steps 5-10 inclusive
    }

    #[test]
    fn test_query_instructions_by_thread() {
        let engine = make_engine_with_data();

        let results = QueryEngine::query_instructions(&engine, InstructionQuery {
            so_file_id: 1,
            start_step: None,
            end_step: None,
            address_range: None,
            thread_id: Some(1),
            limit: None,
        }).unwrap();

        assert!(results.iter().all(|t| t.thread_id == 1));
    }

    #[test]
    fn test_query_instructions_with_limit() {
        let engine = make_engine_with_data();

        let results = QueryEngine::query_instructions(&engine, InstructionQuery {
            so_file_id: 1,
            start_step: None,
            end_step: None,
            address_range: None,
            thread_id: None,
            limit: Some(5),
        }).unwrap();

        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_query_instructions_by_address_range() {
        let engine = make_engine_with_data();

        let results = QueryEngine::query_instructions(&engine, InstructionQuery {
            so_file_id: 1,
            start_step: None,
            end_step: None,
            address_range: Some((0x4000, 0x4010)),
            thread_id: None,
            limit: None,
        }).unwrap();

        // Steps 0-4 produce addresses 0x4000, 0x4004, 0x4008, 0x400C, 0x4010
        assert!(results.iter().all(|t| t.address >= 0x4000 && t.address <= 0x4010));
    }

    #[test]
    fn test_query_thread() {
        let engine = make_engine_with_data();

        let results = QueryEngine::query_thread(&engine, ThreadQuery {
            so_file_id: 1,
            thread_id: Some(1),
            step: None,
            include_info: true,
            include_stats: false,
        }).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].info.is_some());
        assert_eq!(results[0].info.as_ref().unwrap().thread_id, 1);
    }

    #[test]
    fn test_query_thread_all() {
        let engine = make_engine_with_data();

        let results = QueryEngine::query_thread(&engine, ThreadQuery {
            so_file_id: 1,
            thread_id: None,
            step: None,
            include_info: true,
            include_stats: true,
        }).unwrap();

        assert_eq!(results.len(), 2);
        // Each result should have info
        assert!(results.iter().all(|r| r.info.is_some()));
    }

    #[test]
    fn test_query_thread_sync_by_lock() {
        let engine = make_engine_with_data();

        let result = QueryEngine::query_thread_sync(&engine, ThreadSyncQuery {
            so_file_id: 1,
            thread_id: None,
            sync_object_addr: Some(0xABCD0000),
            start_step: 0,
            end_step: 100,
        }).unwrap();

        assert_eq!(result.total_count, 2); // Two mutex lock events on this lock
    }

    #[test]
    fn test_query_thread_sync_by_thread() {
        let engine = make_engine_with_data();

        let result = QueryEngine::query_thread_sync(&engine, ThreadSyncQuery {
            so_file_id: 1,
            thread_id: Some(1),
            sync_object_addr: None,
            start_step: 0,
            end_step: 100,
        }).unwrap();

        assert_eq!(result.total_count, 1); // Thread 1 has one sync event
    }

    #[test]
    fn test_query_context_switches() {
        let engine = make_engine_with_data();

        let result = QueryEngine::query_context_switches(&engine, ContextSwitchQuery {
            so_file_id: 1,
            start_step: 0,
            end_step: 100,
            thread_id: None,
        }).unwrap();

        assert_eq!(result.total_count, 1);
        assert_eq!(result.switches[0].from_thread, 1);
        assert_eq!(result.switches[0].to_thread, 2);
    }

    #[test]
    fn test_query_context_switches_by_thread() {
        let engine = make_engine_with_data();

        let result = QueryEngine::query_context_switches(&engine, ContextSwitchQuery {
            so_file_id: 1,
            start_step: 0,
            end_step: 100,
            thread_id: Some(1),
        }).unwrap();

        assert_eq!(result.total_count, 1); // Thread 1 is involved

        let result2 = QueryEngine::query_context_switches(&engine, ContextSwitchQuery {
            so_file_id: 1,
            start_step: 0,
            end_step: 100,
            thread_id: Some(99),
        }).unwrap();

        assert_eq!(result2.total_count, 0); // Thread 99 is not involved
    }

    #[test]
    fn test_query_thread_instructions() {
        let engine = make_engine_with_data();

        // Query all instructions for thread 1
        let results = QueryEngine::query_thread_instructions(&engine, ThreadInstructionQuery {
            so_file_id: 1,
            thread_id: 1,
            start_step: None,
            end_step: None,
            address_range: None,
            limit: None,
        }).unwrap();

        // Thread 1 executes at even steps (0, 2, 4, 6, 8, 10, 12, 14, 16, 18)
        assert!(results.iter().all(|t| t.thread_id == 1));
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn test_query_thread_instructions_with_range() {
        let engine = make_engine_with_data();

        let results = QueryEngine::query_thread_instructions(&engine, ThreadInstructionQuery {
            so_file_id: 1,
            thread_id: 2,
            start_step: Some(5),
            end_step: Some(15),
            address_range: None,
            limit: None,
        }).unwrap();

        // Thread 2 at odd steps: 5, 7, 9, 11, 13, 15
        assert!(results.iter().all(|t| t.thread_id == 2));
        assert_eq!(results.len(), 6);
    }

    #[test]
    fn test_query_thread_instructions_with_address_filter() {
        let engine = make_engine_with_data();

        let results = QueryEngine::query_thread_instructions(&engine, ThreadInstructionQuery {
            so_file_id: 1,
            thread_id: 1,
            start_step: None,
            end_step: None,
            address_range: Some((0x4000, 0x4008)),
            limit: None,
        }).unwrap();

        // Thread 1 at even steps: step 0→0x4000, step 2→0x4008, step 4→0x4010
        // Address range [0x4000, 0x4008] matches steps 0 and 2
        assert!(results.iter().all(|t| t.address >= 0x4000 && t.address <= 0x4008));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_threads_at_address() {
        let engine = make_engine_with_data();

        // Address 0x4000 is executed at step 0 by thread 1
        let result = QueryEngine::query_threads_at_address(&engine, 0x4000).unwrap();
        assert_eq!(result.address, 0x4000);
        assert!(!result.accesses.is_empty());
        assert_eq!(result.accesses[0], (1, 0)); // Thread 1 at step 0
    }

    /// `QueryEngine::query_register` delegates to `engine.query_register` — it
    /// must NOT be the always-None stub it used to be. x0 set at step 5 is
    /// visible at step 5/after, None before. `register_id == None` returns None
    /// (full-state queries go through `reconstruct_register_state` on the engine).
    #[test]
    fn test_query_register_delegates_to_engine() {
        let mut engine = TraceEngine::new(1, make_config());
        engine.import_register_delta(RegisterDelta {
            seq: 5,
            change_mask: 1u64 << 0, // x0
            values: vec![0xAA],
        }).unwrap();

        let some = QueryEngine::query_register(&engine, RegisterQuery {
            so_file_id: 1, register_id: Some(0), step: 5,
        }).unwrap();
        assert_eq!(some, Some(0xAA));

        let before = QueryEngine::query_register(&engine, RegisterQuery {
            so_file_id: 1, register_id: Some(0), step: 3,
        }).unwrap();
        assert_eq!(before, None, "no delta before step 5");

        let none = QueryEngine::query_register(&engine, RegisterQuery {
            so_file_id: 1, register_id: None, step: 5,
        }).unwrap();
        assert_eq!(none, None, "None register_id is not a single-register query");
    }
}
