# ProducerConsumerPattern max_latency_steps（任务 #120）

> **For agentic workers:** REQUIRED SUB-SKILL `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

## Context

`ProducerConsumerPattern` 当前只暴露 `avg_latency_steps`——produce→consume 的平均延迟步数。但平均值掩盖长尾：如果 10 个 cycle 里 9 个延迟 5 步、1 个延迟 200 步，avg≈24 步看不出那次卡顿。逆向工程师诊断卡顿/丢帧/抖动时，恰恰是**最慢的那次** cycle 才是瓶颈信号——它指向某个特定 produce→consume 间隔里发生了争用、调度抖动或 GC 停顿。

这与 #118 给 `ThreadStats` 加 `max_lock_wait_ns` 补全 `avg_lock_wait_ns` 的长尾是**同一模式**：avg 给基线、max 给长尾，两者配合才能定位「平时没事、偶发卡」的问题。`LockContentionInfo` 也早有 `avg_wait_ns` + `max_wait_ns` 双指标——producer-consumer 的 latency 至今只有 avg，是个对称缺口。

## Goal

给 `ProducerConsumerPattern` 加 `max_latency_steps: u64`——所有 cycle 里最慢的 produce→consume 步数差（`read_step - write_step` 的最大值，saturating）。

## Architecture

**数据怎么流**：`analyze_producer_consumer`（thread_analyzer.rs:2030）按 `(producer, consumer)` 分组 `ThreadDataFlow`，每组至少 2 cycle 才成 pattern。当前对 `group_flows` 做 `.map(|f| f.read_step.saturating_sub(f.write_step)).sum()` 算 `total_latency`，除以 len 得 `avg_latency`。在同一次遍历里加 `.max()` 即得 `max_latency`——零额外遍历，与 #118 的「同分支 max 更新」同构。

**关键组件**：只改 `ProducerConsumerPattern` struct 加 1 字段 + `analyze_prosumer` 构造点填值 + CLI 打印 + 三路径测试断言。serde 加字段向后兼容（旧 JSON `default` 缺省），无 #110/#116 改类型触发的缓存假象——但仍 touch + 重 build bin + 杀旧 server 冒烟（防御性，承 #114/#117/#118/#119）。

**为什么这样做**：复用既有 `group_flows` 遍历，把求和与求 max 合在同一个 iterator 链里（或两个并行 `.map`），不引入新数据结构、不动分组逻辑。最小改动面、最大对称性。

## Tech Stack

Rust Cargo Workspace（sotrace-engine analyzer + sotrace-cli + sotrace-mcp + sotrace-server），serde，无新依赖。

## Risks

- **max 与 avg 分离的测试**：既有 `test_producer_consumer_detection` 两个 cycle latency 都是 30 步（100→130、200→230），avg=max=30，无法证 max 独立于 avg。**必须**新增一个 cycle 用不同 latency 的测试（如 30 步 + 70 步 → avg=50 max=70），否则 max 字段可能与「永远等于 avg」的实现混同。回归验证时禁用 max 计算应让该测试 fail。
- **group_flows 顺序**：`.max()` 对顺序无要求（只取最大），与 `.sum()` 一样不受 HashMap 迭代序影响——确定性输出由 patterns 排序保证，字段值本身确定。
- **加字段非改类型**：serde 新增字段向后兼容，无缓存假象，但仍 touch+重 build+杀旧 server（防御性）。

---

### Task 1: max_latency_steps 字段 + analyze_producer_consumer 计算 + analyzer 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`ProducerConsumerPattern` 加 1 字段 + `analyze_producer_consumer` 构造点 + 测试）

- [ ] **Step 1: 给 ProducerConsumerPattern 加 max_latency_steps 字段**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`pub struct ProducerConsumerPattern`，`avg_latency_steps` 之后，:269）

```rust
    /// Longest single produce→consume latency in steps across all detected
    /// cycles (`max(read_step - write_step)`). Surfaces the tail that
    /// `avg_latency_steps` hides — the one pathological stall among many fast
    /// cycles is the real bottleneck for an RE (GC pause, contention spike,
    /// scheduling jitter). Mirrors `ThreadStats::max_lock_wait_ns` (#118) and
    /// `LockContentionInfo::max_wait_ns`.
    pub max_latency_steps: u64,
```

- [ ] **Step 2: analyze_producer_consumer 算 max_latency 并填值**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:2061-2076`（替换 avg 计算块 + 构造点）

替换 `// Compute average latency` 块为同时算 avg 与 max：

```rust
            // Compute average and max latency. Both derive from the same
            // produce→consume step gap (read_step - write_step, saturating),
            // so a single pass gives both. max surfaces the tail that avg
            // hides (#120, mirroring #118's max_lock_wait_ns).
            let latencies: Vec<u64> = group_flows.iter()
                .map(|f| f.read_step.saturating_sub(f.write_step))
                .collect();
            let total_latency: u64 = latencies.iter().sum();
            let avg_latency = total_latency / group_flows.len() as u64;
            let max_latency = latencies.iter().copied().max().unwrap_or(0);
```

构造点加字段（在 `avg_latency_steps` 之后）：

```rust
            patterns.push(ProducerConsumerPattern {
                producer_thread: *producer,
                consumer_thread: *consumer,
                shared_addresses,
                cycle_count: group_flows.len() as u64,
                avg_latency_steps: avg_latency,
                max_latency_steps: max_latency,
                sync_mechanism,
            });
```

- [ ] **Step 3: 既有 PC 测试加 max 断言 + 新增 max 独立于 avg 的测试**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（PC 测试附近）

既有 `test_producer_consumer_detection`（两 cycle 都 latency 30）加 `assert_eq!(pc.max_latency_steps, 30);`。新增 1 个测试，两 cycle 不同 latency 证 max ≠ avg：

```rust
    /// #120: max_latency_steps captures the slowest produce→consume cycle,
    /// distinct from avg when cycles have unequal latencies. Cycle 1: 30
    /// steps (100→130), cycle 2: 70 steps (200→270) → avg=50, max=70.
    #[test]
    fn test_producer_consumer_max_latency_distinct_from_avg() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));
        let mutex_addr = 0xABCD0000;

        // Cycle 1: latency 30 (write 100 → read 130)
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 110, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr, result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 120, thread_id: 2, sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr, result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_read(130, 2, 0x5000, 4);

        // Cycle 2: latency 70 (write 200 → read 270)
        analyzer.feed_memory_write(200, 1, 0x5000, 4);
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 210, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: mutex_addr, result: SyncResult::Success,
            wait_duration_ns: None,
        });
        analyzer.feed_sync_event(ThreadSyncEvent {
            step: 220, thread_id: 2, sync_type: SyncEventType::MutexLock,
            sync_object_addr: mutex_addr, result: SyncResult::Success,
            wait_duration_ns: Some(1000),
        });
        analyzer.feed_memory_read(270, 2, 0x5000, 4);

        let patterns = analyzer.detect_producer_consumer();
        let pc = patterns.iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert_eq!(pc.cycle_count, 2);
        assert_eq!(pc.avg_latency_steps, 50); // (30 + 70) / 2
        assert_eq!(pc.max_latency_steps, 70); // tail, not the avg
    }
```

（执行前读既有 `test_producer_consumer_detection` 确认 `make_thread_info`/`feed_memory_write`/`feed_sync_event`/`feed_memory_read` 夹具签名与 `ThreadSyncEvent` 字段顺序。）

- [ ] **Step 4: 验证 analyzer 编译与测试**
Run: `cargo test -p sotrace-engine --lib producer_consumer 2>&1 | grep -E "test result|FAILED|error\[" | tail -10`
Expected: ok，新测试 + 既有 4 个 PC 测试全过

- [ ] **Step 5: 回退验证**
临时把 `max_latency = ... .max()` 改成 `let max_latency = avg_latency;`（或注释掉 max 计算填 0）跑 `test_producer_consumer_max_latency_distinct_from_avg` → 应 fail（期望 70 得 50/0），证测试有效。既有 detection 测试加的 `max==30` 断言在两值相等时仍过（不独立验证，故依赖新测试）。恢复后全绿。

- [ ] **Step 6: 提交**
Run: `git add crates/sotrace-engine/src/analyzer/thread_analyzer.rs && git commit -m "feat(analyzer): add max_latency_steps to producer-consumer pattern (#120)"`

---

### Task 2: 三路径对称暴露 + 冒烟 + 内存

**Depends on:** Task 1
**Files:**
- Modify: `crates/sotrace-cli/src/main.rs:1346`（`print_producer_consumer`）
- Modify: `crates/sotrace-mcp/src/tools.rs`（PC 测试断言）
- Modify: `crates/sotrace-server/src/handlers/thread_analysis.rs`（PC 测试断言）
- 内存 `thread-analyzer.md` + `MEMORY.md`

- [ ] **Step 1: 修改 CLI print_producer_consumer — 打印 max_latency**
文件: `crates/sotrace-cli/src/main.rs:1346-1348`（替换 println 格式串）

```rust
        println!(
            "  [{}] T{} → T{}  cycles={} avg_latency={} max_latency={}  addrs=[{}]  sync={}",
            i, p.producer_thread, p.consumer_thread, p.cycle_count, p.avg_latency_steps,
            p.max_latency_steps,
            addrs.join(", "), sync
        );
```

- [ ] **Step 2: 更新 MCP/HTTP PC 测试断言 — max_latency_steps 存在**
文件: `crates/sotrace-mcp/src/tools.rs`（`test_detect_producer_consumer`，:1743）+ `crates/sotrace-server/src/handlers/thread_analysis.rs`（`test_detect_producer_consumer`，:787）

在既有 PC pattern 断言后追加（具体结构按实际测试读确认）：

```rust
        // #120: max_latency_steps surfaces the slowest cycle's tail.
        assert!(pat["max_latency_steps"].is_u64());
        assert!(pat["max_latency_steps"].as_u64().unwrap() >= pat["avg_latency_steps"].as_u64().unwrap());
```

（用既有 patterns 数组里的第一个 pattern 变量名；若既有断言没解出单 pattern，加 `.first().unwrap()` 取。）

- [ ] **Step 3: 验证三路径 + 全工作区**
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected: 全 ok，比 #119 基线（469）多 1 个新测试

- [ ] **Step 4: 重 build + 杀旧进程 + CLI/HTTP 冒烟**
Run: `touch crates/sotrace-engine/src/analyzer/thread_analyzer.rs && cargo build -p sotrace-cli -p sotrace-server 2>&1 | tail -3`
杀旧 server（`ss -ltnp | grep 18099` 取 pid kill）。CLI `analyze --only producer-consumer` 输出含 `max_latency=N`；HTTP `GET /api/v1/traces/<id>/analyze/threads/producer-consumer` → JSON `max_latency_steps`。

- [ ] **Step 5: 提交三路径改动**
Run: `git add crates/sotrace-cli/src/main.rs crates/sotrace-mcp/src/tools.rs crates/sotrace-server/src/handlers/thread_analysis.rs && git commit -m "feat(cli,mcp,server): surface producer-consumer max latency (#120)"`

- [ ] **Step 6: 更新内存 thread-analyzer.md — 加 #120 段**
追加：`ProducerConsumerPattern` 加 `max_latency_steps`（所有 cycle 里最慢 produce→consume 步数差）；`analyze_producer_consumer` 把 latency 收集成 Vec 后同时 `.sum()`/`.max()`，零额外遍历；镜像 #118 `max_lock_wait_ns` 补 `avg` 长尾的模式；加字段非改类型无缓存假象但 touch+重 build+杀旧进程；1 新测试（不同 latency cycle 证 max≠avg）+ 既有 detection 测试加 max 断言。

- [ ] **Step 7: 更新 MEMORY.md 索引行**
thread-analyzer 行追加 `#120`。

- [ ] **Step 8: 提交计划文档**
Run: `git add docs/superpowers/plans/2026-07-15-pc-max-latency.md && git commit -m "docs: add plan for producer-consumer max latency (#120)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-engine/src/analyzer/thread_analyzer.rs` | `ProducerConsumerPattern` 加 1 字段 + `analyze_producer_consumer` 算 max + 1 新测试 + 既有测试加断言 |
| `crates/sotrace-cli/src/main.rs` | `print_producer_consumer` 打印 `max_latency={}` |
| `crates/sotrace-mcp/src/tools.rs` / `crates/sotrace-server/src/handlers/thread_analysis.rs` | PC 测试加 `max_latency_steps` 存在性 + ≥avg 断言 |

## 验证

1. `cargo test -p sotrace-engine --lib producer_consumer` — 4 既有 + 1 新测试全过。
2. `cargo test --workspace` — 全工作区无回归（469→470）。
3. 冒烟（CLI/HTTP）：构造一个两 cycle 不同 latency 的 trace → `max_latency` 严格大于 `avg_latency`。

## 陷阱

- **max ≠ avg 的测试**：既有 detection 测试两 cycle latency 都 30，avg=max=30，无法独立验证 max。必须新测试用不同 latency cycle（30+70→avg 50 max 70），否则 max 字段可能与「恒等于 avg」的错实现混同。回归验证禁用 max 计算应让该新测试 fail。
- **latency Vec 顺序**：`.max()` 不依赖顺序，与 `.sum()` 同样不受 HashMap 迭代序影响——patterns 排序保证字段输出确定性。
- **加字段非改类型**：serde 新增字段向后兼容（旧 JSON `default` 缺省），无 #110/#116 缓存假象——但仍 touch+重 build bin + 杀旧 server 冒烟（防御性，承 #114/#117/#118/#119）。
- **夹具签名**：执行前读既有 PC 测试确认 `feed_memory_write(step, tid, addr, size)`/`feed_memory_read(step, tid, addr, size)`/`ThreadSyncEvent{step, thread_id, sync_type, sync_object_addr, result, wait_duration_ns}` 参数顺序（#67/#116 定义）。
