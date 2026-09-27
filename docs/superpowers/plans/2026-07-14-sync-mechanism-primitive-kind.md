# sync_mechanism 同步原语类型标注 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 把 `ProducerConsumerPattern.sync_mechanism` 从裸地址 `Option<u64>` 升级为「地址 + 原语类型」的 `Option<SyncMechanism>`，让生产者-消费者模式的同步机制不再只报一个看不懂的地址数字，而是同时给出它是 mutex / rwlock / semaphore / futex / condvar / barrier。

**Architecture:** sync 事件流 → `build_indexes` 在现有 per-thread 锁用量统计循环里**同趟**记录每个同步对象地址→原语类型映射（`sync_types_by_addr`）→ `find_sync_mechanism` 选出最常用地址后，用该映射把裸地址包成 `SyncMechanism { addr, kind }` → `ProducerConsumerPattern.sync_mechanism` 字段类型升级 → core 新增 `SyncPrimitiveKind` 枚举 + `SyncEventType::primitive_kind()` 归类方法（复用 #109 的三分类语义：holdable acquire/release 的原语类 + sync signal 的原语类）→ CLI 人读输出加 `(kind)`、MCP/HTTP 序列化自动反映字段形状变更。复用现有 `SyncEventType` 谓词体系，不引入新分析逻辑。

**Tech Stack:** Rust 2021 edition, serde 1 + bincode, Cargo Workspace（sotrace-core / sotrace-engine / sotrace-cli / sotrace-mcp / sotrace-server）

**Risks:**
- **序列化破坏性变更**：`sync_mechanism` JSON 形状从 `2882408448`（数字）变 `{"addr": 2882408448, "kind": "Mutex"}`（对象）。前端目前 Mock 无真实消费者（见 [[frontend-thread-analysis-mock]]），既有 MCP/HTTP 测试只断言 `is_array()`（tools.rs:1702 / thread_analysis.rs:769）不检查字段形状 → 不破现有测试，但需补新断言验证新形状。**缓解**：Task 2 更新既有测试断言到新形状 + Task 3 冒烟确认 MCP/HTTP 实际输出。
- **同地址多类型归并**：一个同步对象的地址在生命周期内可能被多种 `SyncEventType` 操作（如 mutex 的 `MutexLock`+`MutexUnlock`，condvar 的 `CondvarWait`+`CondvarSignal`）。但这些变体都归同一个 `SyncPrimitiveKind`（`Mutex` 或 `Condvar`），不会冲突。真正的冲突场景（同地址既是 `MutexLock` 又是 `FutexWait`）实际不发生——一个地址是同一原语。**缓解**：`sync_types_by_addr: HashMap<u64, SyncPrimitiveKind>` 用「首次见到的类型」记录，遇到同址不同类时保留首次（保守，注释说明）；`primitive_kind()` 的归类保证同原语类内部不冲突。
- **既有测试断言破坏**：`test_producer_consumer_detection`（:3818）`assert_eq!(pc.sync_mechanism, Some(mutex_addr))` 会因字段类型变 `Option<SyncMechanism>` 而编译失败；`test_find_sync_mechanism_*`（:3860/:3886）同理。**缓解**：Task 2 同步更新这些断言到 `Some(SyncMechanism { addr: mutex_addr, kind: SyncPrimitiveKind::Mutex })`。

---

### Task 1: core 新增 SyncPrimitiveKind 枚举与 primitive_kind() 归类方法

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-core/src/models/thread.rs:170-270`（`SyncEventType` 枚举与 `impl SyncEventType` 块）
- Test: `crates/sotrace-engine/src/trace_store/thread_store.rs:1050-1058` 区（既有 `is_acquire`/`is_release` 单测相邻，补 `primitive_kind` 单测）

- [ ] **Step 1: 新增 SyncPrimitiveKind 枚举 — 归类同步原语的语义类别**

在 `crates/sotrace-core/src/models/thread.rs` 的 `SyncEventType` 枚举（:170 闭合的 `}`）之后、`impl SyncEventType`（:172）之前，插入新枚举：

```rust
/// The synchronization *primitive class* an address represents, derived from
/// the `SyncEventType` of operations seen on it.
///
/// Coarser than `SyncEventType`: the various mutex operations
/// (`MutexLock`/`MutexLocked`/`MutexTryLock`/`MutexUnlock`) all collapse to
/// `Mutex`, because they operate on the same pthread_mutex_t object. Used to
/// annotate producer-consumer `sync_mechanism` so the reported mechanism is a
/// typed primitive, not a bare address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncPrimitiveKind {
    /// pthread_mutex_* — exclusive lock
    Mutex,
    /// pthread_rwlock_* — reader/writer lock
    RwLock,
    /// sem_* — counting semaphore
    Semaphore,
    /// futex(FUTEX_WAIT/WAKE) — kernel-level wait/wake word
    Futex,
    /// pthread_cond_* — condition variable
    Condvar,
    /// pthread_barrier_* — rendezvous barrier
    Barrier,
}
```

- [ ] **Step 2: 新增 primitive_kind() 归类方法 — 把 SyncEventType 映射到原语类**

在 `crates/sotrace-core/src/models/thread.rs` 的 `impl SyncEventType` 块内，`is_release()`（:258-269）之后、块闭合 `}`（:270）之前，追加方法。映射复用 #109 三分类的语义分组：

```rust
    /// Classify this sync operation into its primitive kind.
    ///
    /// The kind is determined purely by the operation type — all variants that
    /// operate on the same primitive collapse together (every mutex operation
    /// is `Mutex`, every condvar operation is `Condvar`, etc.). This is the
    /// inverse of the #109 three-way classification: holdable acquires/releases
    /// map to their concrete primitive, sync signals map to condvar/barrier/
    /// futex, and `FutexWakeCount` (a sync signal) maps to `Futex` since it
    /// operates on a futex word.
    pub fn primitive_kind(&self) -> SyncPrimitiveKind {
        match self {
            SyncEventType::MutexLock
            | SyncEventType::MutexLocked
            | SyncEventType::MutexUnlock
            | SyncEventType::MutexTryLock => SyncPrimitiveKind::Mutex,

            SyncEventType::RwLockRead
            | SyncEventType::RwLockWrite
            | SyncEventType::RwLockUnlock => SyncPrimitiveKind::RwLock,

            SyncEventType::SemWait | SyncEventType::SemPost => SyncPrimitiveKind::Semaphore,

            SyncEventType::FutexWait
            | SyncEventType::FutexWake
            | SyncEventType::FutexWakeCount => SyncPrimitiveKind::Futex,

            SyncEventType::CondvarWait
            | SyncEventType::CondvarSignal
            | SyncEventType::CondvarBroadcast => SyncPrimitiveKind::Condvar,

            SyncEventType::BarrierWait => SyncPrimitiveKind::Barrier,
        }
    }
```

- [ ] **Step 3: 新增 primitive_kind() 单测 — 覆盖全部 16 变体的归类**

在 `crates/sotrace-engine/src/trace_store/thread_store.rs` 的 `is_acquire`/`is_release` 单测相邻位置（约 :1050-1058 附近），追加 `primitive_kind` 单测。需先确认该测试模块已 import `SyncPrimitiveKind`——若未 import，在该测试模块的 `use` 语句补 `SyncPrimitiveKind`。

```rust
    #[test]
    fn test_primitive_kind_classifies_all_variants() {
        use sotrace_core::models::thread::SyncPrimitiveKind as K;
        use sotrace_core::models::thread::SyncEventType as T;

        // Mutex family — all four operations collapse to Mutex.
        assert_eq!(T::MutexLock.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexLocked.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexTryLock.primitive_kind(), K::Mutex);
        assert_eq!(T::MutexUnlock.primitive_kind(), K::Mutex);

        // RwLock family.
        assert_eq!(T::RwLockRead.primitive_kind(), K::RwLock);
        assert_eq!(T::RwLockWrite.primitive_kind(), K::RwLock);
        assert_eq!(T::RwLockUnlock.primitive_kind(), K::RwLock);

        // Semaphore family.
        assert_eq!(T::SemWait.primitive_kind(), K::Semaphore);
        assert_eq!(T::SemPost.primitive_kind(), K::Semaphore);

        // Futex family — including the #109 sync-signal FutexWakeCount.
        assert_eq!(T::FutexWait.primitive_kind(), K::Futex);
        assert_eq!(T::FutexWake.primitive_kind(), K::Futex);
        assert_eq!(T::FutexWakeCount.primitive_kind(), K::Futex);

        // Condvar family.
        assert_eq!(T::CondvarWait.primitive_kind(), K::Condvar);
        assert_eq!(T::CondvarSignal.primitive_kind(), K::Condvar);
        assert_eq!(T::CondvarBroadcast.primitive_kind(), K::Condvar);

        // Barrier.
        assert_eq!(T::BarrierWait.primitive_kind(), K::Barrier);
    }
```

- [ ] **Step 4: 验证 core 谓词与归类编译**
Run: `cargo test -p sotrace-core -p sotrace-engine --lib primitive_kind 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "test primitive_kind" and "ok"
  - Output does NOT contain: "error["

- [ ] **Step 5: 提交**
Run: `git add crates/sotrace-core/src/models/thread.rs crates/sotrace-engine/src/trace_store/thread_store.rs && git commit -m "feat(core): add SyncPrimitiveKind + SyncEventType::primitive_kind() classification"`

---

### Task 2: analyzer 升级 sync_mechanism 为带类型的 SyncMechanism

**Depends on:** Task 1
**Files:**
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:56-60`（import 行）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:193-206`（`ProducerConsumerPattern` 结构）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:402-460`（`ThreadAnalyzer` 结构字段声明区，加 `sync_types_by_addr`）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:708-740`（`build_indexes` sync 统计循环）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1923-1944`（`find_sync_mechanism`）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:3818`（`test_producer_consumer_detection` 断言）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:3860`（`test_find_sync_mechanism_tie_breaks_lowest_address` 断言）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:3886`（`test_find_sync_mechanism_recognizes_condvar_signal_wait` 断言）
- Test: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（mod tests 末尾新增归类测试）

- [ ] **Step 1: 在 ThreadAnalyzer 导入列表加入新类型 — 让 analyzer 可引用 SyncMechanism/SyncPrimitiveKind**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:56-60`

```rust
// 替换 :56-60 的 use 块（在现有 SyncEventType, SyncResult 后追加 SyncMechanism, SyncPrimitiveKind）
use sotrace_core::models::thread::{
    ThreadInfo, ThreadSyncEvent, SyncEventType, SyncResult,
    SyncMechanism, SyncPrimitiveKind,
};
```

- [ ] **Step 2: 在 analyzer 模块新增 SyncMechanism 结构 — 与 ProducerConsumerPattern 相邻**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:191-206`（在 `ProducerConsumerPattern` 定义之前插入）

在 `/// Producer-consumer pattern detection result`（:191）之前插入新结构：

```rust
/// A synchronization mechanism identified by both its address AND its
/// primitive kind. Richer than a bare `u64` address: when the analyzer reports
/// the mechanism coordinating a producer-consumer pair, it now says *what*
/// primitive lives at that address (mutex / rwlock / semaphore / futex /
/// condvar / barrier), derived from the `SyncEventType` of operations seen on
/// it during `build_indexes`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncMechanism {
    /// Address of the synchronization object (mutex, futex word, condvar, etc.)
    pub addr: u64,
    /// Primitive kind, derived from the SyncEventType observed on this address
    pub kind: SyncPrimitiveKind,
}
```

- [ ] **Step 3: 升级 ProducerConsumerPattern.sync_mechanism 字段类型**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:204-205`

```rust
// 替换 :204-205 的 sync_mechanism 字段
    /// Synchronization mechanism used (typed: address + primitive kind), or
    /// `None` if no sync object was shared between the two threads.
    pub sync_mechanism: Option<SyncMechanism>,
```

- [ ] **Step 4: 在 ThreadAnalyzer 结构声明新索引字段 — 记录地址→类型**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:402-460`（`ThreadAnalyzer` 结构字段区，找到 `sync_locks_by_thread` 字段声明处，在其后相邻追加）

```rust
// 在 sync_locks_by_thread 字段声明之后相邻追加（保持 sync 索引聚集）
    /// Address → primitive-kind mapping, built in the same pass as
    /// `sync_locks_by_thread`. Lets `find_sync_mechanism` annotate the chosen
    /// address with its primitive class without rescanning sync events. First
    /// kind seen for an address wins (in practice a single address is one
    /// primitive, so there is no real conflict).
    sync_types_by_addr: HashMap<u64, SyncPrimitiveKind>,
```

- [ ] **Step 5: 在 ThreadAnalyzer::new 初始化新字段**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`ThreadAnalyzer::new` 构造体，找到 `sync_locks_by_thread: HashMap::new()` 处，相邻追加 `sync_types_by_addr: HashMap::new()`）

```rust
// 在 sync_locks_by_thread: HashMap::new() 之后相邻追加
            sync_types_by_addr: HashMap::new(),
```

- [ ] **Step 6: 在 build_indexes sync 循环同趟记录地址→类型**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:708-725`

把 :708 `self.sync_locks_by_thread.clear();` 那一行所在的清空区，扩展为同时清空新索引；并在 :715-724 的统计 if 块内同趟记录类型：

```rust
// 替换 :708-725 区（从 sync_locks_by_thread.clear() 到统计 if 块结束）
        self.sync_locks_by_thread.clear();
        self.sync_types_by_addr.clear();
        for (_, events) in &self.sync_events {
            for event in events {
                if let Some(func_addr) = self.active_function_at(event.thread_id, event.step) {
                    *self.function_sync_count.entry(func_addr).or_insert(0) += 1;
                }
                if event.sync_type.is_acquire()
                    || event.sync_type.is_release()
                    || event.sync_type.is_sync_signal()
                {
                    *self
                        .sync_locks_by_thread
                        .entry(event.thread_id)
                        .or_default()
                        .entry(event.sync_object_addr)
                        .or_insert(0) += 1;
                    // Record the primitive kind for this address. First kind
                    // seen wins; in practice one address is one primitive so the
                    // variants that share an address (MutexLock + MutexUnlock)
                    // all map to the same kind and never conflict.
                    self.sync_types_by_addr
                        .entry(event.sync_object_addr)
                        .or_insert(event.sync_type.primitive_kind());
                }
                if event.sync_type.is_holdable_acquire() && !event.sync_type.is_shared_acquire() {
                    self.exclusive_locks.insert(event.sync_object_addr);
                }
            }
        }
```

- [ ] **Step 7: 升级 find_sync_mechanism 返回带类型的 SyncMechanism**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1923-1944`

```rust
// 替换 :1923-1944 整个 find_sync_mechanism 方法
    /// Find the primary synchronization mechanism between two threads.
    ///
    /// Returns the lock most used across these two threads, annotated with its
    /// primitive kind (looked up in `sync_types_by_addr`, built during
    /// `build_indexes`). Merges their precomputed per-thread lock-usage tallies
    /// instead of rescanning all sync events. Ties broken by lowest address for
    /// deterministic output. If the chosen address has no recorded kind (e.g.
    /// `build_indexes` not yet run), falls back to `Mutex` — the most common
    /// primitive — so the result is never a bare address.
    fn find_sync_mechanism(&self, thread_a: u32, thread_b: u32) -> Option<SyncMechanism> {
        let mut lock_usage: HashMap<u64, u64> = HashMap::new();
        for tid in [thread_a, thread_b] {
            if let Some(usage) = self.sync_locks_by_thread.get(&tid) {
                for (&addr, &count) in usage {
                    *lock_usage.entry(addr).or_insert(0) += count;
                }
            }
        }

        // Pick the most-used lock; on ties pick the LOWEST address so the
        // choice is deterministic and stable. `(count, Reverse(addr))` ordered
        // ascending-by-max_by means: highest count wins, and among equal counts
        // the smallest address wins (Reverse flips the addr ordering).
        lock_usage
            .into_iter()
            .max_by_key(|&(addr, count)| (count, std::cmp::Reverse(addr)))
            .map(|(addr, _)| SyncMechanism {
                addr,
                kind: self
                    .sync_types_by_addr
                    .get(&addr)
                    .copied()
                    .unwrap_or(SyncPrimitiveKind::Mutex),
            })
    }
```

- [ ] **Step 8: 更新 detect_producer_consumer 对 sync_mechanism 的使用 — 类型已自动反映**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1854-1920`（`detect_producer_consumer` 内调用 `find_sync_mechanism` 处）

`detect_producer_consumer` 内 `let sync = self.find_sync_mechanism(prod, cons);` 的赋值类型已从 `Option<u64>` 变 `Option<SyncMechanism>`，直接赋给 `ProducerConsumerPattern.sync_mechanism` 字段（也是 `Option<SyncMechanism>`），**无需改赋值代码**——字段类型同步升级即可。确认该行无额外 `.map(|a| a)` 之类地址解包（若有则去掉）。无代码改动，仅确认编译通过。

- [ ] **Step 9: 更新既有 producer-consumer 测试断言到新形状**

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:3818`

```rust
// 替换 :3818 的断言
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: mutex_addr,
                kind: SyncPrimitiveKind::Mutex,
            })
        );
```

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:3860`

```rust
// 替换 :3860 的断言（tie-break 测试，两锁都是 MutexLock → Mutex）
        assert_eq!(
            analyzer.find_sync_mechanism(1, 2),
            Some(SyncMechanism {
                addr: low,
                kind: SyncPrimitiveKind::Mutex,
            })
        );
```

文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:3886-3888`

```rust
// 替换 :3886-3888 的断言（condvar wait-only → Condvar）
        assert_eq!(
            analyzer.find_sync_mechanism(1, 2),
            Some(SyncMechanism {
                addr: cv,
                kind: SyncPrimitiveKind::Condvar,
            }),
            "condvar wait-only rendezvous must be recognized as a condvar sync mechanism"
        );
```

- [ ] **Step 10: 新增归类回归测试 — 验证不同原语类的 sync_mechanism 类型正确**

在 `crates/sotrace-engine/src/analyzer/thread_analyzer.rs` mod tests 内，`test_find_sync_mechanism_recognizes_condvar_signal_wait`（:3871-3889）之后追加。复用既有 `hold_ev` helper（Step 11 会确认它的签名）：

```rust
    /// `sync_mechanism` must report the *primitive kind*, not just the address.
    /// A futex-only producer-consumer rendezvous must yield `kind: Futex`,
    /// proving the address→kind annotation flows through `find_sync_mechanism`.
    #[test]
    fn test_producer_consumer_sync_mechanism_kind_is_futex() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));

        let futex_word = 0xF071_0000u64;
        // Producer wakes (FutexWake), consumer waits (FutexWait) on the same word.
        analyzer.feed_sync_event(hold_ev(110, 1, futex_word, SyncEventType::FutexWake));
        analyzer.feed_sync_event(hold_ev(120, 2, futex_word, SyncEventType::FutexWait));
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_memory_read(130, 2, 0x5000, 4);

        let patterns = analyzer.detect_producer_consumer();
        let pc = patterns
            .iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: futex_word,
                kind: SyncPrimitiveKind::Futex,
            })
        );
    }

    /// A semaphore rendezvous must yield `kind: Semaphore`, covering the #109
    /// holdable-acquire family that was previously mis-tallied.
    #[test]
    fn test_producer_consumer_sync_mechanism_kind_is_semaphore() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));

        let sem = 0x5E80_0000u64;
        analyzer.feed_sync_event(hold_ev(110, 1, sem, SyncEventType::SemPost));
        analyzer.feed_sync_event(hold_ev(120, 2, sem, SyncEventType::SemWait));
        analyzer.feed_memory_write(100, 1, 0x5000, 4);
        analyzer.feed_memory_read(130, 2, 0x5000, 4);

        let patterns = analyzer.detect_producer_consumer();
        let pc = patterns
            .iter()
            .find(|p| p.producer_thread == 1 && p.consumer_thread == 2)
            .unwrap();
        assert_eq!(
            pc.sync_mechanism,
            Some(SyncMechanism {
                addr: sem,
                kind: SyncPrimitiveKind::Semaphore,
            })
        );
    }
```

- [ ] **Step 11: 确认 hold_ev helper 兼容新测试 — 无需改动则跳过**

`hold_ev` helper（既有，#109 引入）签名形如 `fn hold_ev(step, tid, addr, ty) -> ThreadSyncEvent`，用 `SyncResult::Success`。Step 10 的新测试直接复用，不需改 helper。若 mod tests 内无 `hold_ev`（只有 `sync_ev` 带 result+wait_ns），则把 Step 10 测试里的 `hold_ev(...)` 改用 `sync_ev(step, tid, addr, ty, SyncResult::Success, None)`。**运行编译确认**，无代码改动。

- [ ] **Step 12: 验证 analyzer 编译与新测试通过**
Run: `cargo test -p sotrace-engine --lib sync_mechanism 2>&1 | tail -25`
Expected:
  - Exit code: 0
  - Output contains: "test test_producer_consumer_sync_mechanism_kind_is_futex" and "ok"
  - Output contains: "test test_producer_consumer_sync_mechanism_kind_is_semaphore" and "ok"

- [ ] **Step 13: 全工作区测试无回归**
Run: `cargo test --workspace 2>&1 | tail -15`
Expected:
  - Exit code: 0
  - Output contains: "test result: ok"
  - Output does NOT contain: "error[" or "FAILED"

- [ ] **Step 14: 提交**
Run: `git add crates/sotrace-engine/src/analyzer/thread_analyzer.rs && git commit -m "feat(engine): type sync_mechanism with SyncPrimitiveKind in producer-consumer"`

---

### Task 3: CLI 人读输出与三路径冒烟验证

**Depends on:** Task 2
**Files:**
- Modify: `crates/sotrace-cli/src/main.rs:1328-1339`（`print_producer_consumer`）
- Modify: `crates/sotrace-mcp/src/tools.rs:1702`（MCP 测试断言加形状验证）
- Modify: `crates/sotrace-server/src/handlers/thread_analysis.rs:769`（HTTP 测试断言加形状验证）

- [ ] **Step 1: 升级 CLI 人读输出 — sync 行加 (kind) 标注**

文件: `crates/sotrace-cli/src/main.rs:1328-1339`

```rust
// 替换 :1328-1339 整个 print_producer_consumer 函数
fn print_producer_consumer(pcs: &[sotrace_engine::analyzer::thread_analyzer::ProducerConsumerPattern]) {
    println!("\n=== Producer-Consumer Patterns ({}) ===", pcs.len());
    for (i, p) in pcs.iter().enumerate() {
        let addrs: Vec<String> = p.shared_addresses.iter().map(|a| format!("0x{:x}", a)).collect();
        // sync_mechanism now carries the primitive kind alongside the address,
        // so the human-readable line reports "0x.. (mutex)" instead of a bare
        // address the reverse engineer would have to cross-reference manually.
        let sync = p
            .sync_mechanism
            .as_ref()
            .map(|m| format!("0x{:x} ({:?})", m.addr, m.kind))
            .unwrap_or_else(|| "none".into());
        println!(
            "  [{}] T{} → T{}  cycles={} avg_latency={}  addrs=[{}]  sync={}",
            i, p.producer_thread, p.consumer_thread, p.cycle_count, p.avg_latency_steps,
            addrs.join(", "), sync
        );
    }
}
```

- [ ] **Step 2: 升级 MCP 测试断言 — 验证 sync_mechanism 新形状**

文件: `crates/sotrace-mcp/src/tools.rs:1697-1702`（`test_detect_producer_consumer`）

在现有 `assert!(result["producer_consumer_patterns"].is_array());`（:1702）之后追加形状验证（需该测试已构造一个含 sync 的 producer-consumer trace；若该测试用空 trace 只断言 is_array，则追加一条**新**测试构造 mutex producer-consumer 并验证 `sync_mechanism.kind == "Mutex"`）。先读该测试确认它喂了什么 trace 再决定改法。**若现有测试 trace 含 sync**：追加断言 `assert_eq!(result["producer_consumer_patterns"][0]["sync_mechanism"]["kind"], "Mutex");`。**若为空 trace**：新增独立测试 `test_detect_producer_consumer_sync_mechanism_typed`。

- [ ] **Step 3: 升级 HTTP 测试断言 — 验证 sync_mechanism 新形状**

文件: `crates/sotrace-server/src/handlers/thread_analysis.rs:764-769`（`test_detect_producer_consumer`）

同 Step 2 逻辑：先读该测试确认 trace 内容，再追加形状断言或新增独立测试验证 `json["producer_consumer_patterns"][0]["sync_mechanism"]["kind"]`。

- [ ] **Step 4: 构建三个二进制 — 冒烟前必须重建（cargo test 不重建 bin）**
Run: `cargo build -p sotrace-cli -p sotrace-mcp -p sotrace-server 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "Finished" or "Compiling"
  - Output does NOT contain: "error["

- [ ] **Step 5: CLI 冒烟 — mutex producer-consumer 输出含 (Mutex)**
Run: `printf 'T1 mutexunlock @0xABCD0000\\nT2 mutexlock @0xABCD0000 wait=1000\\nT1 write 0x5000\\nT2 read 0x5000\n' > /tmp/pc_mutex.txt && SOTRACE_DATA_DIR=/tmp/sotrace_smoke sotrace analyze --format frida-stalker /tmp/pc_mutex.txt 2>&1 | grep -A2 "Producer-Consumer" | head -5`
Expected:
  - Exit code: 0
  - Output contains: "sync=0xabcd0000 (Mutex)" 或类似的 "Mutex" 标注

- [ ] **Step 6: MCP 冒烟 — detect_producer_consumer 返回 typed sync_mechanism**

启动 MCP stdio 会话（或复用既有冒烟脚本），import 同一 mutex trace，调 `detect_producer_consumer`，确认返回 JSON 含 `"sync_mechanism": {"addr": ..., "kind": "Mutex"}`。

Run: `echo '{"jsonrpc":"2.0","id":1,"method":"initialize",...}' | sotrace-mcp ... 2>&1 | grep sync_mechanism`
（具体 stdio 握手序列复用既有 MCP 冒烟模式；若无现成脚本则用 CLI --format native 喂一个含 producer-consumer 的 envelope 然后经 HTTP 端点验证。）
Expected:
  - 输出包含 `"sync_mechanism":` 且其后跟 `{"addr":` 与 `"kind":"Mutex"}`

- [ ] **Step 7: HTTP 冒烟 — producer-consumer 端点返回 typed sync_mechanism**

启动 server（`SOTRACE_BIND=127.0.0.1:18099 sotrace-server`），import trace，GET `/api/v1/traces/:id/analyze/threads/producer-consumer`，确认响应 `producer_consumer_patterns[0].sync_mechanism.kind == "Mutex"`。

Run: `SOTRACE_BIND=127.0.0.1:18099 sotrace-server & sleep 1 && curl -s http://127.0.0.1:18099/api/v1/traces/1/analyze/threads/producer-consumer | grep -o '"kind":"[A-Za-z]*"' | head -1; kill %1 2>/dev/null`
Expected:
  - 输出包含 `"kind":"Mutex"`

- [ ] **Step 8: 全工作区测试最终确认**
Run: `cargo test --workspace 2>&1 | tail -8`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAILED" or "error["

- [ ] **Step 9: 提交**
Run: `git add crates/sotrace-cli/src/main.rs crates/sotrace-mcp/src/tools.rs crates/sotrace-server/src/handlers/thread_analysis.rs && git commit -m "feat(cli): show sync primitive kind in producer-consumer output + typed assertion"`

---

## 验证汇总

1. `cargo test -p sotrace-core` — `SyncPrimitiveKind` 枚举 + `primitive_kind()` 编译通过（谓词未动，无回归）。
2. `cargo test -p sotrace-engine` — 16 变体 `primitive_kind` 单测全过 + 2 个新归类测试（futex/semaphore kind）+ 既有 producer-consumer/find_sync_mechanism 测试断言更新后通过。
3. `cargo test --workspace` — 全工作区无回归（thread_store primitive_kind 单测 + MCP/HTTP 形状断言）。
4. 三路径冒烟：CLI 输出 `sync=0x.. (Mutex)`、MCP/HTTP 返回 `{"addr":..,"kind":"Mutex"}`。

## 陷阱

- **find_sync_mechanism 的 Mutex 回退**：`sync_types_by_addr` 在 `build_indexes` 里填充。若调用方没先 `build_indexes`（单测里 `detect_producer_consumer` 内部会调），`sync_types_by_addr` 为空 → 回退 `Mutex`。既有 `test_find_sync_mechanism_*` 测试都显式 `analyzer.build_indexes()` 再调，所以正常取到真实 kind。但**未调 build_indexes 直接调 find_sync_mechanism** 的路径会拿到 `Mutex`——这是保守回退，注释已说明，不算 bug。
- **同址多类只记首次**：`or_insert` 只在首次插入。若某地址先见 `FutexWait` 后见（理论上不会的）`MutexLock`，记 `Futex`。现实里一个地址是单一原语，故安全。注释已说明。
- **回退验证**：Task 2 的 2 个新归类测试（futex/semaphore）应做回退验证——临时把 `find_sync_mechanism` 的 `kind` 改回 `unwrap_or(Mutex)`（即不查 `sync_types_by_addr`），futex 测试应 fail（期望 `Futex` 得到 `Mutex`），证测试有效。恢复后通过。
- **MCP/HTTP 测试形状断言前置**：Task 3 Step 2/3 必须先读现有测试确认它喂的 trace 是否含 sync。若测试用空 trace，直接断言 `sync_mechanism.kind` 会 panic（无 pattern），需改为新增独立测试而非在原测试追加。
- **cargo test 不重建二进制**：Task 3 Step 4 必须先 `cargo build -p sotrace-cli -p sotrace-mcp -p sotrace-server` 再冒烟，否则跑的是旧二进制。
