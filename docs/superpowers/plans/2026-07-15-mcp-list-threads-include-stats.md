# MCP list_threads include_stats Symmetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]` syntax.

**Goal:** 给 MCP `list_threads` 工具加 `include_stats` 可选参数，使三路径（CLI/HTTP/MCP）对称暴露 `ThreadStats`——兑现 CLAUDE.md 的三条接入路径对称契约。

**Architecture:** #114 调研发现三路径不对称：HTTP `list_threads` 有 `?include_stats=true` 附加顶层 `stats` 数组，CLI `Threads` 命令每项内联 `info`+`stats`，但 MCP `list_threads`（:692）**只返回 ThreadInfo，无 stats**。AI agent 经 MCP 查线程时拿不到 lock_acquire_count/lock_release_count 等统计。本次给 MCP `list_threads` 加 `include_stats: Option<bool>`（默认 false），true 时在响应顶层附加 `stats` 数组（与 HTTP 形状一致：`{trace_id, thread_count, threads: [ThreadInfo], stats?: [ThreadStats]}`）。沿用 MCP 既有的 Option 参数解析模式（`args.get("x").and_then(as_bool).unwrap_or(false)`，:670 so_file_id 同款）。

**Tech Stack:** Rust Cargo Workspace（sotrace-mcp），serde_json，无新依赖。

**Risks:**
- 默认 false 不改变既有 `list_threads` 行为（向后兼容）。
- MCP stats 经 `engine.all_thread_stats()` + serde，与 HTTP 同源，#114 的 lock_release_count 自动包含。

---

### Task 1: MCP list_threads 加 include_stats + 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-mcp/src/tools.rs:85-93`（schema）
- Modify: `crates/sotrace-mcp/src/tools.rs:692-708`（tool body）
- Test: `crates/sotrace-mcp/src/tools.rs`（新增 include_stats 测试）

- [ ] **Step 1: 修改 list_threads schema — 加 include_stats 属性**
文件: `crates/sotrace-mcp/src/tools.rs:85-93`

```rust
        json!({
            "name": "list_threads",
            "description": "List all threads in a trace with metadata. Set include_stats=true to also return per-thread statistics (lock acquire/release counts, contentions, etc.) alongside the thread metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace_id": { "type": "integer" },
                    "include_stats": { "type": "boolean", "default": false, "description": "If true, include a top-level `stats` array of ThreadStats (lock_acquire_count, lock_release_count, contention, …) alongside `threads`." }
                },
                "required": ["trace_id"]
            }
        }),
```

- [ ] **Step 2: 修改 tool_list_threads — 读 include_stats，true 时附加 stats 数组**
文件: `crates/sotrace-mcp/src/tools.rs:692-708`

```rust
async fn tool_list_threads(server: &McpServer, args: &Value) -> Result<Value, ToolError> {
    let trace_id = get_trace_id(args)?;
    let include_stats = args.get("include_stats").and_then(|v| v.as_bool()).unwrap_or(false);
    let engine = server.get_or_create_engine(trace_id).await;
    let engine = engine.lock().await;

    let threads: Vec<Value> = engine.all_thread_ids()
        .into_iter()
        .filter_map(|tid| engine.get_thread_info(tid).cloned())
        .map(|info| serde_json::to_value(&info).unwrap_or(Value::Null))
        .collect();

    let mut response = serde_json::json!({
        "trace_id": trace_id,
        "thread_count": threads.len(),
        "threads": threads,
    });
    if include_stats {
        response["stats"] = serde_json::to_value(engine.all_thread_stats())
            .unwrap_or(serde_json::Value::Null);
    }

    Ok(response)
}
```

- [ ] **Step 3: 新增测试 — include_stats=true 返回 stats 数组 + 字段断言**
文件: `crates/sotrace-mcp/src/tools.rs`（在 `test_list_threads` 之后）

```rust
    /// #115: list_threads with include_stats=true surfaces ThreadStats
    /// (lock_acquire_count / lock_release_count / …), matching HTTP's
    /// `?include_stats=true`. Without the flag, `stats` is absent.
    #[tokio::test]
    async fn test_list_threads_include_stats() {
        let server = McpServer::new();
        import_test_data(&server).await;

        // Without the flag: no stats key.
        let result = dispatch_tool(&server, "list_threads", &json!({"trace_id": 7})).await.unwrap();
        assert!(result.get("stats").is_none() || result["stats"].is_null());

        // With include_stats=true: stats array present, with #114's fields.
        let result = dispatch_tool(&server, "list_threads", &json!({"trace_id": 7, "include_stats": true})).await.unwrap();
        assert!(result["stats"].is_array(), "stats should be present when include_stats=true");
        let stats = &result["stats"].as_array().unwrap()[0];
        assert!(stats["lock_acquire_count"].is_u64());
        assert!(stats["lock_release_count"].is_u64());
    }
```

- [ ] **Step 4: 验证 MCP 编译与测试**
Run: `cargo test -p sotrace-mcp 2>&1 | grep -E "test result|FAILED|error\[" | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "test result: ok"，新测试 + 既有全过

- [ ] **Step 5: 全工作区测试 + 重 build + MCP 冒烟**
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected: 全 ok，比 #114 基线（461）多 1 个新测试

Run: `touch crates/sotrace-mcp/src/tools.rs && cargo build -p sotrace-mcp 2>&1 | tail -3`
然后 MCP 冒烟（stdin JSON-RPC dispatch 或复用 dispatch_tool 模式）——新测试已覆盖功能，冒烟可选。

- [ ] **Step 6: 更新内存**
追加到 thread-analyzer.md（或 server-api 条目）：MCP list_threads 加 include_stats（#115，三路径对称兑现）；HTTP `?include_stats=true`、CLI 总返回、MCP 现可 include_stats=true；形状 `{threads:[ThreadInfo], stats?:[ThreadStats]}`。

- [ ] **Step 7: 提交**
Run: `git add crates/sotrace-mcp/src/tools.rs docs/superpowers/plans/2026-07-15-mcp-list-threads-include-stats.md && git commit -m "feat(mcp): add include_stats to list_threads for three-path symmetry (#115)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-mcp/src/tools.rs` | list_threads schema 加 include_stats + tool body 读参数附加 stats + 1 新测试 |

## 陷阱

- **默认 false 向后兼容**：既有 `list_threads` 调用（无 include_stats）行为不变——`unwrap_or(false)` 使 stats 缺省不附加。既有 `test_list_threads` 不断言 stats 缺失（只查 thread_count/names），故不 break。
- **stats 数组形状与 HTTP 一致**：顶层 `stats: [ThreadStats]`（不是每线程内联），与 HTTP `list_threads` 对齐。CLI 内联形状是 CLI 既定设计，不改。
- **import_test_data 的 seed**：MCP 测试用 `import_test_data`（含 sync events），故 stats 非空、有 acquire_count——`stats[0]` 安全。若 seed 无 sync events 则 stats 全 0，断言 `is_u64()` 仍成立（0 是 u64）。
