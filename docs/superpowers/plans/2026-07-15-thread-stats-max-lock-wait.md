# ThreadStats max_lock_wait_ns 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 给 `ThreadStats` 加 `max_lock_wait_ns: Option<u64>`（最大单次锁等待时间），让逆向工程师诊断锁争用长尾——`avg_lock_wait_ns`（已有）掩盖极端长等待，而某次 5s 等待（平均 100ms 时）才是真瓶颈。

**Architecture:** `ThreadStats`（core 定义）已有 `lock_wait_total_ns`（Builder 内部）+ `avg_lock_wait_ns`（= total / contention_count），但缺最大值。`write_sync_event`（thread_store.rs:402）的 `waited = wait > 0` 分支（#53 语义：任何结果只要真等了就计）已在累加 `lock_wait_total_ns`，在同分支用 `max()` 更新 `max_lock_wait_ns` 即可——零额外遍历。无 contention 时 `None`（与 `avg_lock_wait_ns` 一致语义）。`ThreadStats` 不 bincode 落盘（#114 已确认，纯 serde JSON 暴露给 CLI `Threads`/`Thread` 命令 + HTTP `list_threads?include_stats=true` + MCP `list_threads?include_stats=true` #115），加字段对旧 JSON 消费者透明（`default` 缺省），无 #110 那种 bincode schema 锁定问题。

**Tech Stack:** Rust Cargo Workspace（sotrace-core 模型 + sotrace-engine thread_store + sotrace-cli/mcp/server 测试），serde，无新依赖。

**Risks:**
- `max_lock_wait_ns` 在 `waited` 分支用 `max()` 更新——复用 #53 `waited = wait > 0`（Timeout/Interrupted/Error 带 wait 现计，承 #53 修正），与 `lock_wait_total_ns` 同分支，语义对齐。
- 无 contention 时 `None`（与 `avg_lock_wait_ns` 一致），不误报 0。
- 加字段非改类型，serde 向后兼容，无 #110/#116 缓存假象——但仍 `touch`+重 build bin + 杀旧 server 冒烟（防御性，承 #114）。

---

### Task 1: max_lock_wait_ns 字段 + Builder 累加 + engine 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-core/src/models/thread.rs`（`ThreadStats` 加字段）
- Modify: `crates/sotrace-engine/src/trace_store/thread_store.rs`（Builder 加字段 + new/build + `write_sync_event` max 更新 + 测试）

- [ ] **Step 1: 给 ThreadStats 加 max_lock_wait_ns 字段**
文件: `crates/sotrace-core/src/models/thread.rs:430`（`avg_lock_wait_ns` 之后）

```rust
    /// Maximum single lock-wait duration in nanoseconds (across all of this
    /// thread's contended acquisitions that actually waited). `None` if the
    /// thread never waited on a lock. Surfaces the long tail that
    /// `avg_lock_wait_ns` hides — one pathological stall among many fast
    /// acquisitions is the real bottleneck for an RE.
    pub max_lock_wait_ns: Option<u64>,
```

- [ ] **Step 2: ThreadStatsBuilder 加字段 + new() + build()**
文件: `crates/sotrace-engine/src/trace_store/thread_store.rs`（Builder struct :113、new :126、build :138-149）

struct 加字段（`lock_wait_total_ns` 之后）：

```rust
    lock_wait_total_ns: u64,
    /// Max single wait, tracked alongside the running total.
    max_lock_wait_ns: u64,
    function_call_count: u64,
```

`new()` 加初始化：

```rust
            lock_wait_total_ns: 0,
            max_lock_wait_ns: 0,
            function_call_count: 0,
```

`build()` 加填值（在 `avg_lock_wait_ns` 计算后、构造 `ThreadStats` 前加 `max`，并传入）：

```rust
        let avg_lock_wait_ns = if self.lock_contention_count > 0 {
            Some(self.lock_wait_total_ns / self.lock_contention_count)
        } else {
            None
        };
        // max is only meaningful when the thread actually waited at least once;
        // mirror avg's None-when-no-contention semantics.
        let max_lock_wait_ns = if self.max_lock_wait_ns > 0 {
            Some(self.max_lock_wait_ns)
        } else {
            None
        };

        ThreadStats {
            thread_id,
            steps_executed: self.steps_executed,
            running_time_ns: None, // Requires timestamp support
            context_switch_count: self.context_switch_count,
            sync_event_count: self.sync_event_count,
            lock_acquire_count: self.lock_acquire_count,
            lock_release_count: self.lock_release_count,
            lock_contention_count: self.lock_contention_count,
            avg_lock_wait_ns,
            max_lock_wait_ns,
            function_call_count: self.function_call_count,
        }
```

- [ ] **Step 3: write_sync_event 的 waited 分支用 max 更新**
文件: `crates/sotrace-engine/src/trace_store/thread_store.rs:407`（`stats.lock_wait_total_ns += wait;` 之后）

```rust
                    stats.lock_wait_total_ns += wait;
                    if wait > stats.max_lock_wait_ns {
                        stats.max_lock_wait_ns = wait;
                    }
```

（复用 #53 的 `waited = wait > 0` 守卫——`waited` 分支内 `wait > 0` 必然成立，故 `max` 用 0 初值首次必更新。）

- [ ] **Step 4: 新增测试 + 更新既有测试**
文件: `crates/sotrace-engine/src/trace_store/thread_store.rs`

新增 2 个测试 + 更新既有 #53 测试加 `max_lock_wait_ns` 断言：

```rust
    /// #118: max_lock_wait_ns tracks the longest single wait, not just the
    /// running average. A thread that waits 3ms then 5ms then 1ms must report
    /// max=5ms even though avg=3ms.
    #[test]
    fn test_stats_max_lock_wait_tracks_longest() {
        let mut store = make_store();
        store.register_thread(make_thread_info(1, "t1"));
        let lock = 0xA000;
        let mk = |step, wait_ns| ThreadSyncEvent {
            step, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: lock,
            result: SyncResult::Success,
            wait_duration_ns: Some(wait_ns),
        };
        store.write_sync_event(mk(10, 3_000_000)).unwrap();
        store.write_sync_event(mk(20, 5_000_000)).unwrap();
        store.write_sync_event(mk(30, 1_000_000)).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_contention_count, 3);
        assert_eq!(stats.avg_lock_wait_ns, Some(3_000_000)); // (3+5+1)/3 = 3ms
        assert_eq!(stats.max_lock_wait_ns, Some(5_000_000)); // long tail
    }

    /// #118: max_lock_wait_ns is None when the thread never waited (no
    /// contention with a real wait), mirroring avg_lock_wait_ns.
    #[test]
    fn test_stats_max_lock_wait_none_when_no_wait() {
        let mut store = make_store();
        store.register_thread(make_thread_info(1, "t1"));
        // A successful acquire with zero wait is not a contention.
        store.write_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1,
            sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000,
            result: SyncResult::Success,
            wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_contention_count, 0);
        assert_eq!(stats.avg_lock_wait_ns, None);
        assert_eq!(stats.max_lock_wait_ns, None);
    }
```

既有 #53 测试 `test_stats_wait_time_counted_for_nonsuccess_results`（Timeout+3ms & Interrupted+5ms → contention=2、avg=(3+5)/2=4ms）加 `max_lock_wait_ns == Some(5_000_000)` 断言。`test_stats_wouldblock_zero_wait_is_contention_without_wait`（WouldBlock trylock 无等待）加 `max_lock_wait_ns == None` 断言（无真等待）。

（执行前读既有 #53 测试的 `make_store`/`make_thread_info` 夹具确认签名。）

- [ ] **Step 5: 验证 thread_store 编译与测试**
Run: `cargo test -p sotrace-engine --lib thread_store:: 2>&1 | grep -E "test result|FAILED|error\[" | tail -10`
Expected: ok，新测试 + 既有 #53 测试全过

- [ ] **Step 6: 回退验证**
临时把 `write_sync_event` 的 `max` 更新注释掉跑 2 新测试 + #53 max 断言 → 应 fail（max 始终 None/0），证测试有效。恢复后全绿。

- [ ] **Step 7: 提交**
Run: `git add crates/sotrace-core/src/models/thread.rs crates/sotrace-engine/src/trace_store/thread_store.rs && git commit -m "feat(core,engine): track max_lock_wait_ns in thread stats (#118)"`

---

### Task 2: 三路径对称暴露 + 冒烟 + 内存

**Depends on:** Task 1
**Files:**
- Modify: `crates/sotrace-cli/src/main.rs`（CLI `Threads`/`Thread` 用 serde JSON 自动含，测试加断言）
- Modify: `crates/sotrace-mcp/src/tools.rs`（`test_list_threads_include_stats` 加断言）
- Modify: `crates/sotrace-server/src/handlers/thread_analysis.rs`（`test_list_threads_with_stats` 加断言）
- 内存 `thread-analyzer.md` + `MEMORY.md`

- [ ] **Step 1: 更新 CLI/HTTP/MCP list_threads stats 测试断言**
文件: `crates/sotrace-cli/src/main.rs`（`test_query_threads_and_sync` 附近）、`crates/sotrace-mcp/src/tools.rs`（`test_list_threads_include_stats`）、`crates/sotrace-server/src/handlers/thread_analysis.rs`（`test_list_threads_with_stats`）

CLI 加（既有 `t1_stats.lock_release_count == 0` 之后）：

```rust
        // #118: max_lock_wait_ns is present; seed has no waited acquire so None.
        assert_eq!(t1_stats.max_lock_wait_ns, None);
```

MCP `test_list_threads_include_stats`（include_stats=true 分支）加：

```rust
        // #118: max_lock_wait_ns field present per thread.
        assert!(stats.iter().all(|s| s["max_lock_wait_ns"].is_null() || s["max_lock_wait_ns"].is_u64()));
```

HTTP `test_list_threads_with_stats` 加（既有 `lock_release_count` 断言之后）：

```rust
        assert!(stats["max_lock_wait_ns"].is_null() || stats["max_lock_wait_ns"].is_u64());
```

（三路径 seed 均无 waited acquire，故 `max_lock_wait_ns` 为 `null`/`None`——字段存在性验证，功能本身靠 engine 单测 + 专门冒烟 trace。）

- [ ] **Step 2: 验证三路径 + 全工作区**
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected: 全 ok，比 #117 基线（465）多 2 个新测试

- [ ] **Step 3: 重 build + 杀旧进程 + CLI/HTTP 冒烟**
Run: `touch crates/sotrace-engine/src/trace_store/thread_store.rs crates/sotrace-core/src/models/thread.rs && cargo build -p sotrace-cli -p sotrace-server 2>&1 | tail -3`
杀旧 server。构造含 waited acquire 的 trace，CLI `query threads` → JSON `max_lock_wait_ns: <N>`；HTTP GET `list_threads?include_stats=true` → JSON `max_lock_wait_ns` 字段。

- [ ] **Step 4: 提交三路径改动**
Run: `git add crates/sotrace-cli/src/main.rs crates/sotrace-mcp/src/tools.rs crates/sotrace-server/src/handlers/thread_analysis.rs && git commit -m "test(cli,mcp,server): assert max_lock_wait_ns in thread stats (#118)"`

- [ ] **Step 5: 更新内存 thread-analyzer.md — 加 #118 段**
追加：`ThreadStats` 加 `max_lock_wait_ns: Option<u64>`（最大单次锁等待，长尾诊断）；`ThreadStatsBuilder` 加 `max_lock_wait_ns` 字段 + new/build + `write_sync_event` `waited` 分支用 `max()` 更新（复用 #53 `waited = wait > 0`）；无 contention 时 `None`（与 avg 一致）；不 bincode 落盘故无兼容问题；CLI `Threads`/`Thread` serde JSON 自动含；2 新测试 + #53 测试加断言。

- [ ] **Step 6: 更新 MEMORY.md 索引行**
thread-analyzer 行追加 `#118`。

- [ ] **Step 7: 提交计划文档**
Run: `git add docs/superpowers/plans/2026-07-15-thread-stats-max-lock-wait.md && git commit -m "docs: add plan for thread stats max_lock_wait_ns (#118)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-core/src/models/thread.rs` | `ThreadStats` 加 `max_lock_wait_ns` |
| `crates/sotrace-engine/src/trace_store/thread_store.rs` | `ThreadStatsBuilder` 加字段 + new/build + `write_sync_event` max 更新 + 2 新测试 |
| `crates/sotrace-cli/src/main.rs` / `crates/sotrace-mcp/src/tools.rs` / `crates/sotrace-server/src/handlers/thread_analysis.rs` | list_threads stats 测试加 `max_lock_wait_ns` 断言 |

## 陷阱

- **`waited` 分支复用 #53 语义**：`waited = wait > 0`（Timeout/Interrupted/Error 带 wait 现计），`max` 在同分支用 `wait > stats.max_lock_wait_ns` 更新——`waited` 分支内 `wait > 0` 必然成立，故 `max` 用 0 初值首次必更新。
- **无 contention 时 `None`**：`max_lock_wait_ns == 0` 时返回 `None`（与 `avg_lock_wait_ns` 的 `lock_contention_count == 0` 时 `None` 一致语义）。
- **不 bincode 落盘**（#114 已确认）：`ThreadStats` 纯 serde JSON 暴露，加字段无向后兼容问题，无 #110 缓存假象——但仍 `touch`+重 build bin + 杀旧 server 冒烟（防御性）。
- **CLI 无专门 print 函数**：`Threads`/`Thread` 命令用 serde JSON 直接序列化 `stats`，加字段后 JSON 自动含 `max_lock_wait_ns`，无需改打印逻辑。
- **三路径 seed 无 waited acquire**：测试 `max_lock_wait_ns` 为 `null`/`None`（字段存在性），功能验证靠 engine 单测 + 专门冒烟 trace。
