    #[tokio::test]
    async fn test_import_and_instructions_require_a_validated_credential() {
        let state = empty_state();
        let import = serde_json::json!({
            "trace_id": 1,
            "instructions": [
                {"seq": 1, "thread_id": 1, "address": 4096, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 2, "thread_id": 1, "address": 4100, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
            ],
        })
        .to_string();

        async fn raw(
            router: axum::Router,
            method: &str,
            uri: &str,
            body: Option<String>,
            auth: Option<&str>,
        ) -> (StatusCode, String) {
            let mut builder = Request::builder().method(method).uri(uri);
            if let Some(token) = auth {
                builder = builder.header("authorization", token);
            }
            let request = if let Some(json) = body {
                builder = builder.header("content-type", "application/json");
                builder.body(Body::from(json)).unwrap()
            } else {
                builder.body(Body::empty()).unwrap()
            };
            let resp = router.oneshot(request).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }

        let (status, health) = raw(
            build_app_with_state(state.clone()),
            "GET",
            "/api/v1/health",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!health.is_empty());

        let (status, _) = raw(
            build_app_with_state(state.clone()),
            "POST",
            "/api/v1/traces/import",
            Some(import.clone()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = raw(
            build_app_with_state(state.clone()),
            "GET",
            "/api/v1/traces/1/instructions",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = raw(
            build_app_with_state(state.clone()),
            "POST",
            "/api/v1/traces/import",
            Some(import.clone()),
            Some("Bearer not-the-token"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = raw(
            build_app_with_state(state.clone()),
            "GET",
            "/api/v1/traces/1/instructions",
            None,
            Some("Bearer not-the-token"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let good = format!("Bearer {}", crate::middleware::auth::TEST_BEARER_TOKEN);
        let (status, body) = raw(
            build_app_with_state(state.clone()),
            "POST",
            "/api/v1/traces/import",
            Some(import),
            Some(&good),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["imported"]["instructions_imported"], 2);

        let (status, body) = raw(
            build_app_with_state(state.clone()),
            "GET",
            "/api/v1/traces/1/instructions",
            None,
            Some(&good),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["instruction_count"], 2);

        let (status, metrics) = raw(
            build_app_with_state(state),
            "GET",
            "/api/v1/metrics",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{metrics}");
        assert!(metrics.contains("sotrace_import_failures_total "));
        assert!(metrics.contains("sotrace_save_failures_total "));
    }

    #[tokio::test]
    async fn test_save_reopen_matches_and_import_alone_does_not() {
        let (state, dir) = temp_state();
        let import = serde_json::json!({
            "trace_id": 9,
            "instructions": [
                {"seq": 1, "thread_id": 1, "address": 4096, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
                {"seq": 2, "thread_id": 1, "address": 4100, "timestamp": null,
                 "is_branch": false, "branch_taken": false, "opcode": null},
            ],
        });
        let (status, body) = send(
            build_app_with_state(state.clone()),
            "POST",
            "/api/v1/traces/import",
            Some(import.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let before_save = sotrace_engine::persistence::TraceRepository::open(dir.path()).unwrap();
        assert!(
            before_save.list().unwrap().is_empty(),
            "import without save must not leave a loadable batch"
        );
        drop(before_save);

        let (status, body) = send(
            build_app_with_state(state.clone()),
            "POST",
            "/api/v1/traces/9/save",
            Some("{}".to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let saved: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(saved["status"], "ok");
        let persisted_id = saved["persisted_id"].as_u64().unwrap();
        drop(state);

        let reopened = sotrace_engine::persistence::TraceRepository::open(dir.path()).unwrap();
        let loaded = reopened.load(persisted_id).unwrap();
        assert_eq!(loaded.events.len(), 2);
    }
