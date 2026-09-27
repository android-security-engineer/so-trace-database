
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_req(method: &str, params: Value, id: Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: Some("2.0".to_string()),
            id: Some(id),
            method: method.to_string(),
            params,
        }
    }

    #[tokio::test]
    async fn test_initialize() {
        let server = McpServer::new();
        let req = make_req("initialize", json!({}), json!(1));
        let result = server.handle_method(&req).await.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "so-trace-database");
    }

    #[tokio::test]
    async fn test_tools_list() {
        let server = McpServer::new();
        let req = make_req("tools/list", json!({}), json!(2));
        let result = server.handle_method(&req).await.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty(), "should expose at least one tool");
        // Verify expected tools are present
        let names: Vec<&str> = tools.iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"import_trace"));
        assert!(names.contains(&"analyze_threads"));
        assert!(names.contains(&"detect_races"));
        assert!(names.contains(&"detect_deadlocks"));
        assert!(names.contains(&"analyze_contentions"));
        assert!(names.contains(&"classify_function_safety"));
        assert!(names.contains(&"analyze_function_assoc"));
        assert!(names.contains(&"analyze_data_flows"));
        assert!(names.contains(&"detect_producer_consumer"));
        assert!(names.contains(&"analyze_scheduling"));
        assert!(names.contains(&"analyze_thread_lifecycle"));
        assert!(names.contains(&"analyze_thread_states"));
        assert!(names.contains(&"analyze_critical_sections"));
        assert!(names.contains(&"analyze_jni_boundary"));
        assert!(names.contains(&"save_trace"));
        assert!(names.contains(&"load_trace"));
        assert!(names.contains(&"list_persisted_traces"));
        assert!(names.contains(&"delete_persisted_trace"));
        assert!(names.contains(&"query_register"));
        assert!(names.contains(&"query_register_state"));
        assert!(names.contains(&"query_memory_value"));
        assert!(names.contains(&"query_memory_page"));
        assert!(names.contains(&"query_call_stack"));
        // Each tool must have a description and inputSchema
        for t in tools {
            assert!(t["description"].is_string(), "tool missing description");
            assert!(t["inputSchema"].is_object(), "tool missing inputSchema");
        }
    }

    #[tokio::test]
    async fn test_method_not_found() {
        let server = McpServer::new();
        let req = make_req("nonexistent/method", json!({}), json!(3));
        let err = server.handle_method(&req).await.unwrap_err();
        match err {
            HandlerError::Rpc(e) => assert_eq!(e.code, -32601),
            _ => panic!("expected Rpc error"),
        }
    }

    #[tokio::test]
    async fn test_ping() {
        let server = McpServer::new();
        let req = make_req("ping", json!({}), json!(4));
        let result = server.handle_method(&req).await.unwrap();
        assert!(result.is_object());
    }

    #[tokio::test]
    async fn test_unknown_tool_returns_error() {
        let server = McpServer::new();
        let req = make_req(
            "tools/call",
            json!({ "name": "bogus_tool", "arguments": {} }),
            json!(5),
        );
        let err = server.handle_method(&req).await.unwrap_err();
        match err {
            HandlerError::Tool(te) => assert!(te.message.contains("unknown tool")),
            _ => panic!("expected Tool error"),
        }
    }

    #[tokio::test]
    async fn test_tools_call_missing_name() {
        let server = McpServer::new();
        let req = make_req("tools/call", json!({ "arguments": {} }), json!(6));
        let err = server.handle_method(&req).await.unwrap_err();
        match err {
            HandlerError::Rpc(e) => assert_eq!(e.code, -32602),
            _ => panic!("expected Rpc invalid_params error"),
        }
    }

    #[tokio::test]
    async fn test_resources_list() {
        let server = McpServer::new();
        let req = make_req("resources/list", json!({}), json!(7));
        let result = server.handle_method(&req).await.unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert!(resources.iter().any(|r| r["uri"] == "sotrace://traces"));
        for r in resources {
            assert!(r["mimeType"].is_string(), "resource missing mimeType");
        }
    }

    #[tokio::test]
    async fn test_resources_read_traces_list() {
        let server = McpServer::new();
        // Import a trace first so the list is non-empty
        let import_args = json!({
            "trace_id": 11,
            "threads": [{"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                "create_step": 0, "exit_step": null, "name": "t",
                "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}],
        });
        crate::tools::dispatch_tool(&server, "import_trace", &import_args).await.unwrap();

        let req = make_req("resources/read", json!({ "uri": "sotrace://traces" }), json!(8));
        let result = server.handle_method(&req).await.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["mimeType"], "application/json");
        // text is a JSON-encoded string; parse it back
        let text = contents[0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["trace_count"], 1);
        assert_eq!(parsed["traces"][0]["trace_id"], 11);
    }

    #[tokio::test]
    async fn test_resources_read_summary() {
        let server = McpServer::new();
        let import_args = json!({
            "trace_id": 11,
            "threads": [{"thread_id": 1, "pthread_id": null, "parent_thread_id": 0,
                "create_step": 0, "exit_step": null, "name": "t",
                "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": false}],
            "context_switches": [
                {"step": 4, "from_thread": 1, "to_thread": 2, "switch_reason": "Preemption", "cpu_core": 0},
            ],
        });
        crate::tools::dispatch_tool(&server, "import_trace", &import_args).await.unwrap();

        let req = make_req("resources/read", json!({ "uri": "sotrace://traces/11/summary" }), json!(9));
        let result = server.handle_method(&req).await.unwrap();
        let text = result["contents"][0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["trace_id"], 11);
        assert_eq!(parsed["thread_count"], 1);
        assert!(parsed["total_context_switches"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn test_resources_read_missing_uri() {
        let server = McpServer::new();
        let req = make_req("resources/read", json!({}), json!(10));
        let err = server.handle_method(&req).await.unwrap_err();
        match err {
            HandlerError::Rpc(e) => assert_eq!(e.code, -32602),
            _ => panic!("expected Rpc invalid_params error"),
        }
    }

    #[tokio::test]
    async fn test_resources_read_unknown_uri() {
        let server = McpServer::new();
        let req = make_req("resources/read", json!({ "uri": "sotrace://bogus" }), json!(11));
        let err = server.handle_method(&req).await.unwrap_err();
        match err {
            HandlerError::Resource(re) => assert!(re.message.contains("unknown resource")),
            _ => panic!("expected Resource error"),
        }
    }
}
