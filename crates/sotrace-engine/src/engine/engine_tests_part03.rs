    #[test]
    fn test_step_snapshot_replays_register_and_lists_only_this_steps_writes() {
        let mut engine = TraceEngine::new(1, make_config());
        let inst = |seq, address| InstructionTrace {
            seq,
            thread_id: 1,
            address,
            timestamp: None,
            is_branch: false,
            branch_taken: false,
            opcode: None,
        };
        engine.import_instruction(inst(1, 0x1000)).unwrap();
        engine.import_instruction(inst(5, 0x2000)).unwrap();
        engine
            .import_register_delta(RegisterDelta {
                seq: 5,
                change_mask: 1,
                values: vec![0x1234_ABCD],
            })
            .unwrap();
        engine
            .import_memory_write(MemoryWrite {
                step: 5,
                thread_id: 1,
                address: 0x3000,
                data: vec![9, 8, 7],
            })
            .unwrap();
        engine.import_instruction(inst(9, 0x2004)).unwrap();

        let early = engine.query_step_snapshot(1);
        assert_eq!(early.instruction.as_ref().unwrap().address, 0x1000);
        assert_eq!(early.instruction.as_ref().unwrap().thread_id, 1);
        assert!(early.registers.is_none(), "no register delta yet");
        assert!(early.memory_writes.is_empty());

        let mid = engine.query_step_snapshot(5);
        assert_eq!(mid.instruction.as_ref().unwrap().address, 0x2000);
        assert_eq!(mid.instruction.as_ref().unwrap().thread_id, 1);
        assert_eq!(mid.registers.as_ref().unwrap().gp_regs[0], 0x1234_ABCD);
        assert_eq!(mid.memory_writes.len(), 1);
        assert_eq!(mid.memory_writes[0].address, 0x3000);
        assert_eq!(mid.memory_writes[0].data, vec![9, 8, 7]);

        let later = engine.query_step_snapshot(9);
        assert_eq!(later.instruction.as_ref().unwrap().address, 0x2004);
        assert_eq!(later.registers.as_ref().unwrap().gp_regs[0], 0x1234_ABCD);
        assert!(
            later.memory_writes.is_empty(),
            "a later step must not invent a memory write"
        );

        assert!(engine.query_memory_value(0x4000, 4, 9).is_none());
        assert_eq!(
            engine.query_memory_value(0x3000, 3, 9).unwrap().value,
            vec![9, 8, 7]
        );
    }
