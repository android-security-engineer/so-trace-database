# ThreadStats lock_release_count Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 给线程统计加 `lock_release_count` 字段，让逆向工程师能检测锁泄漏——一个线程 `lock_acquire_count` 远多于 `lock_release_count` 说明它获取锁后未释放（持有不配对），这是 Android SO 常见的资源泄漏/死锁前兆。

**Architecture:** `ThreadStats` 已有 `lock_acquire_count`（统计 `is_acquire()` 事件），但**无对称的 release 计数**——`is_release()` 谓词在 #109 已就绪且语义清晰，但 `feed_sync_event` 的统计分支只处理 acquire 不处理 release。本次对称补全：core `ThreadStats` 加 `lock_release_count: u64` 字段，engine `ThreadStatsBuilder` 加对应字段，`feed_sync_event` 在 acquire 分支后加 `else if is_release() { lock_release_count += 1 }`。`ThreadStats` 不经 bincode 落盘（纯 serde JSON 暴露给 API），加字段无向后兼容问题。三路径（CLI `Threads`/`Thread` 命令 + HTTP `list_threads` `include_stats=true`）都直接 serde `ThreadStats`，新字段自动出现。

**Tech Stack:** Rust Cargo Workspace（sotrace-core + sotrace-engine + sotrace-cli + sotrace-mcp + sotrace-server），serde，无新依赖。

**Risks:**
- `is_release()` 是 #109 的宽超集（含 `CondvarSignal`/`CondvarBroadcast`/`FutexWake`/`FutexWakeCount`），release 计数会把 signal/broadcast/wake 也计入。语义上这些是「释放类同步操作」（唤醒等待者），统计为 release 合理，但 doc 须说明它不是「纯 unlock 计数」——要看 unlock 数应过滤 `MutexUnlock`/`RwLockUnlock`。这与 `lock_acquire_count` 对称（acquire 也含 CondvarWait……#109 后已移除，acquire 现在是 holdable acquire 子集，但 release 仍是宽超集——不对称，见陷阱）。
- 加 core 字段不改旧字段类型，serde 向后兼容；冒烟前须 `touch`+重 build bin + **杀旧 server 进程**（#112/#113 踩过）。

---

### Task 1: core ThreadStats 加字段 + engine builder + feed 统计 + 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-core/src/models/thread.rs:406-425`（`ThreadStats` 加字段）
- Modify: `crates/sotrace-engine/src/trace_store/thread_store.rs:106-145`（`ThreadStatsBuilder` 加字段 + new + build）
- Modify: `crates/sotrace-engine/src/trace_store/thread_store.rs:397-410`（`feed_sync_event` 加 release 统计）
- Test: `crates/sotrace-engine/src/trace_store/thread_store.rs`（新增 release 计数测试）

- [ ] **Step 1: 修改 ThreadStats 结构 — 加 lock_release_count 字段**
文件: `crates/sotrace-core/src/models/thread.rs:406-425`

```rust
pub struct ThreadStats {
    /// Thread ID
    pub thread_id: u32,
    /// Total steps executed by this thread
    pub steps_executed: u64,
    /// Total time spent running (in nanoseconds, if timestamps available)
    pub running_time_ns: Option<u64>,
    /// Number of context switches involving this thread
    pub context_switch_count: u64,
    /// Number of synchronization events
    pub sync_event_count: u64,
    /// Number of lock acquisitions (holdable acquires: MutexLock/Locked/TryLock,
    /// RwLockRead/Write, SemWait, FutexWait — per #109's `is_acquire()`).
    pub lock_acquire_count: u64,
    /// Number of lock releases / wake operations. Counted via #109's
    /// `is_release()`, which is a wide superset: besides `MutexUnlock`/
    /// `RwLockUnlock`/`SemPost`/`FutexWake` it also includes `CondvarSignal`/
    /// `CondvarBroadcast`/`FutexWakeCount` (wake-the-waiter semantics). To get
    /// pure unlock counts, filter on the holdable-release subset. Comparing
    /// this against `lock_acquire_count` flags lock leaks (acquire ≫ release).
    pub lock_release_count: u64,
    /// Number of lock contentions (had to wait)
    pub lock_contention_count: u64,
    /// Average lock wait duration (in nanoseconds)
    pub avg_lock_wait_ns: Option<u64>,
    /// Number of functions called by this thread
    pub function_call_count: u64,
}
```

- [ ] **Step 2: 修改 ThreadStatsBuilder — 加字段 + new 初始化 + build 填值**
文件: `crates/sotrace-engine/src/trace_store/thread_store.rs:106-145`

```rust
struct ThreadStatsBuilder {
    steps_executed: u64,
    context_switch_count: u64,
    sync_event_count: u64,
    lock_acquire_count: u64,
    lock_release_count: u64,
    lock_contention_count: u64,
    lock_wait_total_ns: u64,
    function_call_count: u64,
}

impl ThreadStatsBuilder {
    fn new() -> Self {
        Self {
            steps_executed: 0,
            context_switch_count: 0,
            sync_event_count: 0,
            lock_acquire_count: 0,
            lock_release_count: 0,
            lock_contention_count: 0,
            lock_wait_total_ns: 0,
            function_call_count: 0,
        }
    }

    fn build(&self, thread_id: u32) -> ThreadStats {
        let avg_lock_wait_ns = if self.lock_contention_count > 0 {
            Some(self.lock_wait_total_ns / self.lock_contention_count)
        } else {
            None
        };
        ThreadStats {
            thread_id,
            steps_executed: self.steps_executed,
            running_time_ns: None,
            context_switch_count: self.context_switch_count,
            sync_event_count: self.sync_event_count,
            lock_acquire_count: self.lock_acquire_count,
            lock_release_count: self.lock_release_count,
            lock_contention_count: self.lock_contention_count,
            avg_lock_wait_ns,
            function_call_count: self.function_call_count,
        }
    }
}
```

- [ ] **Step 3: 修改 feed_sync_event — 加 release 统计分支**
文件: `crates/sotrace-engine/src/trace_store/thread_store.rs:397-410`

在既有 `if event.sync_type.is_acquire() { ... }` 块后加 `else if`：

```rust
        if let Some(stats) = self.thread_stats.get_mut(&event.thread_id) {
            stats.sync_event_count += 1;
            if event.sync_type.is_acquire() {
                stats.lock_acquire_count += 1;
                let wait = event.wait_duration_ns.unwrap_or(0);
                let waited = wait > 0;
                let blocked = event.result == SyncResult::WouldBlock
                    || event.result == SyncResult::Timeout;
                if waited {
                    stats.lock_wait_total_ns += wait;
                }
                if waited || blocked {
                    stats.lock_contention_count += 1;
                }
            } else if event.sync_type.is_release() {
                // #114: symmetric to acquire counting — release/wake ops
                // (MutexUnlock, RwLockUnlock, SemPost, FutexWake, and the
                // wider CondvarSignal/Broadcast/FutexWakeCount per #109's
                // is_release superset). acquire ≫ release flags a lock leak.
                stats.lock_release_count += 1;
            }
        }
```

- [ ] **Step 4: 新增测试 — release 计数配对 + signal 计入 + 泄漏检测**
文件: `crates/sotrace-engine/src/trace_store/thread_store.rs`（在既有 lock_acquire 测试 :798 附近）

```rust
    /// #114: a MutexUnlock increments lock_release_count symmetric to acquire.
    #[test]
    fn test_lock_release_count_tracks_unlocks() {
        let mut store = ThreadStore::new(DeltaStoreConfig::default());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some("t1".into()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        store.record_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.record_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 1);
        assert_eq!(stats.lock_release_count, 1);
    }

    /// #114: CondvarSignal counts as a release (wake-the-waiter semantics,
    /// per #109's is_release superset).
    #[test]
    fn test_lock_release_count_includes_condvar_signal() {
        let mut store = ThreadStore::new(DeltaStoreConfig::default());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some("t1".into()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        store.record_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::CondvarSignal,
            sync_object_addr: 0xB000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 0);
        assert_eq!(stats.lock_release_count, 1);
    }

    /// #114: acquire without release is detectable (acquire > release → leak).
    #[test]
    fn test_lock_release_count_detects_leak() {
        let mut store = ThreadStore::new(DeltaStoreConfig::default());
        store.register_thread(ThreadInfo {
            thread_id: 1, pthread_id: None, parent_thread_id: 0,
            create_step: 0, exit_step: None, name: Some("t1".into()),
            stack_base: 0, stack_size: 0, tls_addr: 0, is_jni_attached: false,
        }).unwrap();
        // Two acquires, one release → leak (acquire=2, release=1)
        store.record_sync_event(ThreadSyncEvent {
            step: 10, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.record_sync_event(ThreadSyncEvent {
            step: 20, thread_id: 1, sync_type: SyncEventType::MutexLock,
            sync_object_addr: 0xA001, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        store.record_sync_event(ThreadSyncEvent {
            step: 30, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
            sync_object_addr: 0xA000, result: SyncResult::Success, wait_duration_ns: None,
        }).unwrap();
        let stats = store.get_thread_stats(1).unwrap();
        assert_eq!(stats.lock_acquire_count, 2);
        assert_eq!(stats.lock_release_count, 1);
        assert!(stats.lock_acquire_count > stats.lock_release_count);
    }
```

- [ ] **Step 5: 验证 core + engine 编译与测试**
Run: `cargo test -p sotrace-core -p sotrace-engine --lib 2>&1 | grep -E "test result|FAILED|error\[" | tail -10`
Expected:
  - Exit code: 0
  - 所有 crate "test result: ok"，3 新测试全过

- [ ] **Step 6: 提交**
Run: `git add crates/sotrace-core/src/models/thread.rs crates/sotrace-engine/src/trace_store/thread_store.rs && git commit -m "feat(core,engine): add lock_release_count to ThreadStats (#114)"`

---

### Task 2: 三路径对称暴露 + 冒烟 + 内存

**Depends on:** Task 1
**Files:**
- Modify: 内存 `thread-analyzer.md` + `MEMORY.md`（ThreadStats 统计属 thread_store，但归入线程分析器记忆条目）
- 三路径不需改代码（CLI `Threads`/`Thread` 命令 + HTTP `list_threads` 直接 serde `ThreadStats`，新字段自动出现）——仅加测试断言

- [ ] **Step 1: 三路径测试断言 — 验证 lock_release_count 出现在 JSON**

CLI（既有 threads 测试附近，若有；若无跳过）、MCP（`list_threads` 测试）、HTTP（`list_threads?include_stats=true` 测试）追加：

```rust
        // #114: lock_release_count present in stats
        assert!(stats["lock_release_count"].is_u64());   // JSON 路径按实际调整
```

先 `grep -n "lock_acquire_count\|include_stats\|list_threads" 各 crate 测试` 定位既有断言，按其形状追加 release 断言。

- [ ] **Step 2: 验证三路径编译与测试**
Run: `cargo test -p sotrace-cli -p sotrace-mcp -p sotrace-server 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected: 三 crate 各自 ok

- [ ] **Step 3: 全工作区测试**
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected: 全 ok，比 #113 基线（458）多 3 个新测试

- [ ] **Step 4: 强制重 build + 杀旧进程 + HTTP 冒烟**
Run: `touch crates/sotrace-core/src/models/thread.rs crates/sotrace-engine/src/trace_store/thread_store.rs && cargo build -p sotrace-cli -p sotrace-server 2>&1 | tail -3`
杀占端口旧 server，启动新二进制，构造 acquire+release trace，GET `/threads?include_stats=true`，断言 JSON 含 `lock_release_count`。
Expected: JSON `lock_release_count` 非零数值

- [ ] **Step 5: 提交三路径测试改动**
Run: `git add <三路径测试文件> && git commit -m "test(cli,mcp,server): assert lock_release_count in thread stats (#114)"`

- [ ] **Step 6: 更新内存 thread-analyzer.md — 加 #114 段**
追加段：`ThreadStats` 加 `lock_release_count`（对称 `lock_acquire_count`），`feed_sync_event` 加 `else if is_release()` 分支；`is_release()` 是 #109 宽超集（含 CondvarSignal/Broadcast/FutexWakeCount），release 计数含 signal/broadcast（wake 语义，doc 说明非纯 unlock）；ThreadStats 不 bincode 落盘（纯 serde JSON）故加字段无兼容问题；3 新测试（unlock 配对、condvar signal 计入、泄漏检测 acquire>release）；三路径直接 serde 自动出现。

- [ ] **Step 7: 更新 MEMORY.md 索引行**
thread-analyzer 行追加 `#114`。

- [ ] **Step 8: 提交计划文档**
Run: `git add docs/superpowers/plans/2026-07-15-thread-stats-lock-release-count.md && git commit -m "docs: add plan for ThreadStats lock_release_count (#114)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-core/src/models/thread.rs` | `ThreadStats` 加 `lock_release_count` 字段 + doc |
| `crates/sotrace-engine/src/trace_store/thread_store.rs` | `ThreadStatsBuilder` 加字段 + new + build + `feed_sync_event` 加 release 分支 + 3 新测试 |
| `crates/sotrace-cli/src/main.rs` / `crates/sotrace-mcp/src/tools.rs` / `crates/sotrace-server/src/handlers/thread_analysis.rs` | 三路径测试断言（代码不改，serde 自动） |

## 陷阱

- **`is_release()` 宽超集不对称**：#109 后 `is_acquire()` 是 holdable 子集（已移除 CondvarWait/BarrierWait），但 `is_release()` **保留宽超集**（含 CondvarSignal/Broadcast/FutexWakeCount）——因为 release 臂只用于 has_sync_between race 抑制，宽超集无 depth 损害。所以 `lock_release_count` 会含 signal/broadcast（wake 语义），`lock_acquire_count` 不含 condvar wait。这不对称是 #109 的有意设计（release 宽是安全的，acquire 窄是必须的）。doc 须说明 release 不是纯 unlock 计数——RE 要纯 unlock 数应自行过滤 `MutexUnlock`/`RwLockUnlock`。
- **`else if` 而非 `if`**：release 分支必须是 `else if is_release()`，不能是独立 `if is_release()`——因为 `is_acquire()` 和 `is_release()` 互斥（一个事件不会既是 acquire 又是 release），但用 `else if` 表达「acquire 否则 release」更清晰，且防未来谓词重叠时双重计数。
- **ThreadStats 不 bincode 落盘**：grep 确认无 bincode/persist 引用，纯 serde JSON 暴露。加字段对旧 JSON 消费者透明（新字段缺省 `default`），无 #110 那种改 bincode schema 的兼容问题。但仍 `touch`+重 build bin + 杀旧 server 进程冒烟。
- **既有 `lock_acquire_count` 测试**（thread_store.rs:798）：加 release 字段后这些测试不 break（只断言 acquire_count==1，不检查 release）。但 `build()` 新增字段须初始化为 0，否则未配 release 的既有测试 stats 会是 0（正确）。
