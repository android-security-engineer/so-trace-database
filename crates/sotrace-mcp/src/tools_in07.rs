
    #[tokio::test]
    async fn test_save_load_list_delete_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        import_test_data(&server).await;

        // Save the in-memory trace 7.
        let saved = dispatch_tool(&server, "save_trace", &json!({"trace_id": 7})).await.unwrap();
        assert_eq!(saved["status"], "ok");
        let persisted_id = saved["persisted_id"].as_u64().unwrap();

        // It appears in the persisted listing.
        let listed = dispatch_tool(&server, "list_persisted_traces", &json!({})).await.unwrap();
        assert_eq!(listed["trace_count"], 1);
        assert_eq!(listed["traces"][0]["trace_id"], persisted_id);
        assert_eq!(listed["traces"][0]["source"], "mcp");

        // A fresh server (empty pool) loads it by id and can query its threads.
        let server2 = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let loaded = dispatch_tool(&server2, "load_trace", &json!({"persisted_id": persisted_id})).await.unwrap();
        assert_eq!(loaded["status"], "ok");
        assert_eq!(loaded["persisted_id"], persisted_id);
        // event_count matches what import_test_data fed (2 threads + 3 instrs + 1 write + 2 sync + 1 switch = 9).
        assert_eq!(loaded["event_count"], 9);

        // The replayed trace has the same threads as the original.
        let threads = dispatch_tool(&server2, "list_threads", &json!({"trace_id": persisted_id})).await.unwrap();
        assert_eq!(threads["thread_count"], 2);

        // Delete it.
        let deleted = dispatch_tool(&server2, "delete_persisted_trace", &json!({"trace_id": persisted_id})).await.unwrap();
        assert_eq!(deleted["status"], "deleted");
        // Listing now empty.
        let listed2 = dispatch_tool(&server2, "list_persisted_traces", &json!({})).await.unwrap();
        assert_eq!(listed2["trace_count"], 0);
        // Re-delete is not_found.
        let deleted2 = dispatch_tool(&server2, "delete_persisted_trace", &json!({"trace_id": persisted_id})).await.unwrap();
        assert_eq!(deleted2["status"], "not_found");
    }

    #[tokio::test]
    async fn test_load_trace_missing_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "load_trace", &json!({"persisted_id": 9999})).await.unwrap_err();
        assert!(err.message.contains("no persisted trace") || err.message.contains("9999"));
    }

    /// Build a ParsedSoFile with one "decrypt" function at 0x4000 (size 100),
    /// persist it, return the assigned so_file_id. Mirrors the persistence
    /// test helper and the HTTP test fixture.
    fn save_decrypt_so(data_dir: &std::path::Path) -> u64 {
        use sotrace_core::elf::ParsedSoFile;
        use sotrace_core::models::so_file::{Architecture, SOFile};
        use sotrace_core::models::so_function::SOFunction;
        use sotrace_core::models::so_segment::{SOSegment, SegmentType};
        use sotrace_core::models::so_symbol::{SOSymbol, SymbolType, SymbolBind};
        let parsed = ParsedSoFile {
            so_file: SOFile {
                id: 0, path: "/fake/libtest.so".into(), build_id: Some(vec![0xab; 20]),
                arch: Architecture::AArch64, file_size: 4096, md5: [1; 16], sha256: [2; 32],
                loaded_base_address: 0, created_at: 1_700_000_000,
            },
            segments: vec![SOSegment {
                id: 0, so_file_id: 0, name: ".text".into(),
                seg_type: SegmentType::Load, offset: 0, vaddr: 0, size: 100, flags: 0,
            }],
            symbols: vec![SOSymbol {
                id: 0, so_file_id: 0, name: "decrypt".into(), value: 0x4000, size: 100,
                sym_type: SymbolType::Func, bind: SymbolBind::Global,
                is_imported: false, is_exported: true,
            }],
            functions: vec![SOFunction {
                id: 0, so_file_id: 0, symbol_id: Some(0), name: "decrypt".into(),
                offset: 0x4000, size: 100, is_jni: false, is_imported: false,
                is_exported: true, is_thunk: false,
            }],
        };
        sotrace_engine::persistence::SoRepository::open(data_dir)
            .and_then(|repo| repo.save(&parsed).map(|o| o.id))
            .expect("save ParsedSoFile")
    }

    /// #106: MCP import_trace with so_file_id registers the SO function table,
    /// so analyze_function_assoc resolves a function-internal callee PC (0x4034,
    /// within [0x4000, 0x4064) — exercising #105's range query) to "decrypt".
    #[tokio::test]
    async fn test_import_with_so_file_id_resolves_function_name() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let so_id = save_decrypt_so(tmp.path());

        let args = json!({
            "trace_id": 700,
            "so_file_id": so_id,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");

        let result = dispatch_tool(&server, "analyze_function_assoc", &json!({"trace_id": 700})).await.unwrap();
        let assocs = result["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0]["function_address"], 0x4034);
        assert_eq!(assocs[0]["function_name"], "decrypt",
                   "function name must be backfilled from the registered SO; got {:?}", assocs[0]);
    }

    /// #106 boundary: MCP import without a data_dir but so_file_id == 0 must
    /// still succeed (no SO requested → no data_dir needed).
    #[tokio::test]
    async fn test_import_without_so_file_id_no_data_dir() {
        let server = McpServer::new(); // no data_dir
        let args = json!({
            "trace_id": 701,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");

        let result = dispatch_tool(&server, "analyze_function_assoc", &json!({"trace_id": 701})).await.unwrap();
        let assocs = result["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1);
        // No SO → function_name absent/null.
        assert!(assocs[0].get("function_name").is_none() || assocs[0]["function_name"].is_null(),
                "function_name must be absent without an SO; got {:?}", assocs[0]);
    }

    /// #106 boundary: MCP import with so_file_id > 0 but NO data_dir must
    /// return a ToolError (cannot load the SO without a repository), not
    /// silently degrade.
    #[tokio::test]
    async fn test_import_with_so_file_id_but_no_data_dir_errors() {
        let server = McpServer::new(); // no data_dir
        let args = json!({
            "trace_id": 702,
            "so_file_id": 5,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
        });
        let err = dispatch_tool(&server, "import_trace", &args).await.unwrap_err();
        assert!(err.message.contains("persistence is disabled"),
                "expected persistence-disabled error, got: {}", err.message);
    }

    /// #106: MCP load_trace re-registers the SO. import(so_file_id) → save →
    /// load into a fresh server; function name still resolves after load.
    #[tokio::test]
    async fn test_load_trace_re_registers_so_function_name() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let so_id = save_decrypt_so(&data_dir);

        let server = McpServer::new_with_data_dir(Some(data_dir.clone()));
        let args = json!({
            "trace_id": 702,
            "so_file_id": so_id,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
            "calls": [
                {"id": 1, "thread_id": 1, "event_type": "Call", "caller_address": 0x3000,
                 "callee_address": 0x4034, "callee_func_id": null, "seq": 10,
                 "depth": 1, "return_seq": null},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok");

        let save_args = json!({"trace_id": 702, "so_file_id": so_id, "source": "test"});
        let saved = dispatch_tool(&server, "save_trace", &save_args).await.unwrap();
        let persisted_id = saved["persisted_id"].as_u64().unwrap();

        // Fresh server + engine (no in-memory state shared) to force a replay.
        // load_trace keys the replayed engine under `persisted_id` (not the
        // original trace_id 702), so analyze must query persisted_id.
        let server2 = McpServer::new_with_data_dir(Some(data_dir));
        let result = dispatch_tool(&server2, "load_trace", &json!({"persisted_id": persisted_id})).await.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["so_file_id"], so_id);

        let result = dispatch_tool(&server2, "analyze_function_assoc", &json!({"trace_id": persisted_id})).await.unwrap();
        let assocs = result["thread_function_assocs"].as_array().unwrap();
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0]["function_name"], "decrypt",
                   "load_trace must re-register the SO; got {:?}", assocs[0]);
    }

    /// #106 boundary: MCP import with a non-existent so_file_id must still
    /// succeed (load failure is warned + swallowed, names stay None).
    #[tokio::test]
    async fn test_import_with_nonexistent_so_file_id_degrades() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let args = json!({
            "trace_id": 703,
            "so_file_id": 999987,
            "threads": [
                {"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                 "create_step": 0, "exit_step": null, "name": "main",
                 "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false},
            ],
        });
        let result = dispatch_tool(&server, "import_trace", &args).await.unwrap();
        assert_eq!(result["status"], "ok",
                   "import must succeed despite a bad so_file_id (graceful degradation)");
    }

    // ======================================================================
    // #107: SO management tools (import_so / list_so_files / get_so_file /
    // delete_so) — mirror the HTTP /so-files endpoints so MCP is CRUD-symmetric
    // with CLI and HTTP.
    // ======================================================================

    /// Base64-encode a byte slice for the `bytes` arg of `import_so`.
    fn b64(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    /// Read the system libc.so.6 if present (x86_64 Linux only). Returns None
    /// on any other platform / missing file so callers can `return` to skip.
    fn read_libc_if_present() -> Option<Vec<u8>> {
        let path = std::path::Path::new("/lib/x86_64-linux-gnu/libc.so.6");
        if !path.exists() {
            return None;
        }
        std::fs::read(path).ok()
    }

    #[tokio::test]
    async fn test_import_so_missing_bytes_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "import_so", &json!({})).await.unwrap_err();
        assert!(err.message.contains("bytes"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_import_so_invalid_base64_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "import_so",
            &json!({"bytes": "!!!not-base64!!!"})).await.unwrap_err();
        assert!(err.message.contains("base64"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_import_so_empty_bytes_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        // b64("") == "".
        let err = dispatch_tool(&server, "import_so", &json!({"bytes": b64(b"")})).await.unwrap_err();
        assert!(err.message.contains("empty"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_import_so_invalid_elf_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "import_so",
            &json!({"bytes": b64(b"not an elf")})).await.unwrap_err();
        assert!(err.message.contains("ELF") || err.message.contains("parse"),
                "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_import_so_without_data_dir_errors() {
        // No data dir → persistence disabled.
        let server = McpServer::new();
        let err = dispatch_tool(&server, "import_so",
            &json!({"bytes": b64(b"not an elf")})).await.unwrap_err();
        assert!(err.message.contains("data directory") || err.message.contains("persistence"),
                "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_list_so_files_seeded() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        save_decrypt_so(tmp.path());

        let r = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(r["count"], 1);
        let so = &r["so_files"][0];
        assert_eq!(so["path"], "/fake/libtest.so");
        assert_eq!(so["function_count"], 1);
    }

    #[tokio::test]
    async fn test_list_so_files_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let r = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(r["count"], 0);
    }

    #[tokio::test]
    async fn test_get_so_file_seeded() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let so_id = save_decrypt_so(tmp.path());

        let r = dispatch_tool(&server, "get_so_file", &json!({"so_id": so_id})).await.unwrap();
        let so = &r["so_file"];
        assert_eq!(so["id"], so_id);
        assert_eq!(so["path"], "/fake/libtest.so");
        assert_eq!(so["function_count"], 1);
        assert!(so["build_id"].is_string(), "build_id present as hex string");
    }

    #[tokio::test]
    async fn test_get_so_file_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "get_so_file", &json!({"so_id": 9999})).await.unwrap_err();
        assert!(err.message.contains("not found") && err.message.contains("9999"),
                "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_get_so_file_missing_id_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let err = dispatch_tool(&server, "get_so_file", &json!({})).await.unwrap_err();
        assert!(err.message.contains("so_id"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn test_delete_so_seeded_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let so_id = save_decrypt_so(tmp.path());

        // Delete → deleted.
        let r = dispatch_tool(&server, "delete_so", &json!({"so_id": so_id})).await.unwrap();
        assert_eq!(r["status"], "deleted");
        assert_eq!(r["so_id"], so_id);

        // List now empty.
        let listed = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(listed["count"], 0);

        // Re-delete → not_found.
        let r2 = dispatch_tool(&server, "delete_so", &json!({"so_id": so_id})).await.unwrap();
        assert_eq!(r2["status"], "not_found");
    }

    #[tokio::test]
    async fn test_delete_so_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));
        let r = dispatch_tool(&server, "delete_so", &json!({"so_id": 9999})).await.unwrap();
        assert_eq!(r["status"], "not_found");
    }

    /// import_so success path against a real ELF (libc). Skipped when the
    /// fixture is absent (non x86_64 Linux). Verifies so_id assignment,
    /// function-count population, build_id, list/get roundtrip, and that
    /// re-importing the same bytes deduplicates to the same so_id.
    #[tokio::test]
    async fn test_import_so_from_libc() {
        let bytes = match read_libc_if_present() {
            Some(b) => b,
            None => {
                eprintln!("skipping: /lib/x86_64-linux-gnu/libc.so.6 not present");
                return;
            }
        };
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer::new_with_data_dir(Some(tmp.path().to_path_buf()));

        let args = json!({"bytes": b64(&bytes), "path": "/lib/x86_64-linux-gnu/libc.so.6"});
        let r = dispatch_tool(&server, "import_so", &args).await.unwrap();
        let so_id = r["so_id"].as_u64().unwrap();
        assert!(so_id >= 1, "so_id assigned: {:?}", r);
        // Fresh import — no prior entry with this sha256, so NOT deduped.
        assert_eq!(r["deduped"], false, "first import must not be deduped: {:?}", r);
        assert!(r["summary"]["function_count"].as_u64().unwrap() > 0,
                "parsed functions: {:?}", r["summary"]);
        assert!(r["summary"]["build_id"].is_string(),
                "libc has a GNU build-id: {:?}", r["summary"]);

        // list shows exactly this one.
        let listed = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(listed["count"], 1);

        // get roundtrip.
        let got = dispatch_tool(&server, "get_so_file", &json!({"so_id": so_id})).await.unwrap();
        assert_eq!(got["so_file"]["id"], so_id);
        assert_eq!(got["so_file"]["path"], "/lib/x86_64-linux-gnu/libc.so.6");

        // Re-import the same bytes → same id, no new row, and deduped is now
        // deterministically true: the flag comes straight from save's index
        // lookup (find_by_sha256 hit), not a second-grained created_at
        // heuristic, so same-second re-imports are flagged correctly.
        let r2 = dispatch_tool(&server, "import_so", &args).await.unwrap();
        assert_eq!(r2["so_id"], so_id, "dedup keeps the same id: {:?}", r2);
        assert_eq!(r2["deduped"], true, "re-import must be flagged deduped: {:?}", r2);
        let listed2 = dispatch_tool(&server, "list_so_files", &json!({})).await.unwrap();
        assert_eq!(listed2["count"], 1, "no duplicate row added");
    }
