# ProducerConsumerPattern shared_addresses typed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 把 `ProducerConsumerPattern.shared_addresses` 从裸 `Vec<u64>` 升级为 `Vec<SharedAddress>`（地址 + 访问大小 + 传递范围），让逆向工程师看 producer-consumer 模式时知道每个通信槽传多少字节、精确传递范围——与 #112/#113 的访问大小对称。

**Architecture:** #113 给 `ThreadDataFlow` 加了 `write_size`/`read_size`/`overlap_address`/`overlap_size`，但 `ProducerConsumerPattern.shared_addresses`（:244）仍是 `Vec<u64>`——它来自 `group_flows.iter().map(|f| f.address)`（写基址 dedup），丢了每个槽的访问大小和传递范围。RE 看「producer-consumer 用 0x5000, 0x6000 通信」不知每槽传多少字节（单字段 vs 整结构体）。本次新增 `SharedAddress { address: u64, access_size: u64, overlap_size: u64 }` 结构，`shared_addresses` 升级为 `Vec<SharedAddress>`。构造点（:1995）从 flow 收集时带 `f.write_size` 和 `f.overlap_size`，dedup 按 address（保留首个 flow 的 size/overlap——实践中同槽同大小，多 cycle 不同大小取首个与既有 dedup 语义一致）。三路径 serde 自动暴露 + CLI 打印。

**Tech Stack:** Rust Cargo Workspace（sotrace-engine analyzer + sotrace-cli + sotrace-mcp + sotrace-server），serde，无新依赖。

**Risks:**
- **改字段类型**（`Vec<u64>` → `Vec<SharedAddress>`）触发 #110/#111 那种增量缓存假象——冒烟前须 `touch`+重 build bin + 杀旧 server 进程。serde JSON 从 `[2882408448]` 变 `[{"address":..,"access_size":..,"overlap_size":..}]`，旧消费者需适配（无 bincode 锁定，PC 不落盘）。
- **dedup 语义**：既有 :1998-1999 `sort_unstable` + `dedup` 按 `address` 去重。升级后 `SharedAddress` 须实现 `Ord`/`PartialOrd`/`Eq` 才能复用 `sort`+`dedup`——但按 `address` 排序/去重（size/overlap 不参与比较），否则同地址不同 size 会保留多条。用 `derive(PartialEq, Eq)` + 手动 `Ord` 按 address，或改用 `HashMap`/`BTreeSet` 按 address dedup 后取首个。
- **多 cycle 不同大小**：同地址多个 flow 大小不同时取首个（与既有 dedup 保留首个一致），doc 说明。实践中 PC 同槽同大小，少见分歧。

---

### Task 1: SharedAddress 结构 + shared_addresses 升级 + 构造点 + analyzer 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（加 `SharedAddress` 结构 + `shared_addresses` 字段 + 构造点 + 测试）

- [ ] **Step 1: 新增 SharedAddress 结构 — 在 ProducerConsumerPattern 之前定义**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`pub struct ProducerConsumerPattern` 之前，:238 附近）

```rust
/// A shared-memory slot used by a producer-consumer pair. Richer than a bare
/// `u64` address: it also reports the access size (how many bytes the producer
/// writes per cycle) and the precise transferred range, so an RE can tell
/// whether the slot carries a single field or an entire struct. Derived from
/// the underlying `ThreadDataFlow`s; when the same slot is used across multiple
/// cycles with differing sizes, the first cycle's values are kept (consistent
/// with the address-level deduplication of `shared_addresses`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedAddress {
    /// Write base address of the slot (page-aligned). The dedup key for
    /// `shared_addresses`: each distinct slot appears once.
    pub address: u64,
    /// Byte size of the producer's write to this slot (1, 2, 4, 8, …).
    pub access_size: u64,
    /// Length in bytes of the precise transferred range (the write/read
    /// overlap) for this slot. From the first cycle's flow.
    pub overlap_size: u64,
}
```

- [ ] **Step 2: 修改 ProducerConsumerPattern.shared_addresses 字段类型**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:244`

```rust
    /// Shared memory slots used for communication, each typed with its address,
    /// access size, and transferred range. Sorted by address for deterministic
    /// output; each distinct slot appears once.
    pub shared_addresses: Vec<SharedAddress>,
```

- [ ] **Step 3: 修改构造点 — 从 flow 收集 SharedAddress，按 address dedup**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1995-2013`

既有逻辑：`group_flows.iter().map(|f| f.address).collect()` → sort → dedup。改为收集 `SharedAddress`，按 address dedup 保留首个：

```rust
            // Collect the distinct shared slots. A producer typically writes
            // the same slot every cycle, so the raw per-flow list repeats the
            // address once per cycle; report each slot once, sorted by address
            // for deterministic output. Each slot carries the access size and
            // transferred range from the first cycle's flow (consistent with
            // the address-level dedup — in practice a slot keeps one size).
            let mut shared_addresses: Vec<SharedAddress> = group_flows.iter()
                .map(|f| SharedAddress {
                    address: f.address,
                    access_size: f.write_size,
                    overlap_size: f.overlap_size,
                })
                .collect();
            // Dedup by address: keep the first occurrence per address. A stable
            // sort by address groups duplicates, then `dedup_by` on address.
            shared_addresses.sort_by_key(|s| s.address);
            shared_addresses.dedup_by(|a, b| a.address == b.address);
```

- [ ] **Step 4: 更新既有 PC 测试断言 — vec![0x5000] 改 SharedAddress**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:4126`

执行前先读该测试的 setup 确认 write size（`feed_memory_write(..., 0x5000, 4)` → access_size 4）。

```rust
        assert_eq!(
            pc.shared_addresses,
            vec![SharedAddress { address: 0x5000, access_size: 4, overlap_size: 4 }]
        );
```

（若 setup 的 read 完全重叠 0x5000+4，overlap_size=4；若部分重叠按实际填。）

- [ ] **Step 5: 新增测试 — 部分重叠 slot 的 access_size/overlap_size**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（PC 测试附近）

```rust
    /// #116: shared_addresses reports access_size and overlap_size per slot,
    /// not just the bare address. A slot written 8B and read 8B with a 4B
    /// overlap (partial) reports access_size=8, overlap_size=4.
    #[test]
    fn test_producer_consumer_shared_address_carries_sizes() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));
        let mutex_addr = 0xABCD0000;
        // Two cycles on slot 0x5000: write 8B, read 8B at +4 (4B overlap).
        for &(ws, rs) in &[(100u64, 200u64), (300, 400)] {
            analyzer.feed_memory_write(ws, 1, 0x5000, 8);
            analyzer.feed_sync_event(ThreadSyncEvent {
                step: ws + 10, thread_id: 1, sync_type: SyncEventType::MutexUnlock,
                sync_object_addr: mutex_addr, result: SyncResult::Success, wait_duration_ns: None,
            }).unwrap();
            analyzer.feed_sync_event(ThreadSyncEvent {
                step: rs - 10, thread_id: 2, sync_type: SyncEventType::MutexLock,
                sync_object_addr: mutex_addr, result: SyncResult::Success, wait_duration_ns: Some(1000),
            }).unwrap();
            analyzer.feed_memory_read(rs, 2, 0x5004, 8);
        }
        let pcs = analyzer.detect_producer_consumer();
        assert_eq!(pcs.len(), 1);
        let pc = &pcs[0];
        assert_eq!(pc.shared_addresses.len(), 1);
        let slot = &pc.shared_addresses[0];
        assert_eq!(slot.address, 0x5000);
        assert_eq!(slot.access_size, 8);
        assert_eq!(slot.overlap_size, 4);
    }
```

- [ ] **Step 6: 验证 analyzer 编译与测试**
Run: `cargo test -p sotrace-engine --lib thread_analyzer:: 2>&1 | grep -E "test result|FAILED|error\[" | tail -10`
Expected: ok，新测试 + 更新的 PC 测试全过

- [ ] **Step 7: 提交**
Run: `git add crates/sotrace-engine/src/analyzer/thread_analyzer.rs && git commit -m "feat(analyzer): type shared_addresses with access size and overlap (#116)"`

---

### Task 2: 三路径对称暴露 + 冒烟 + 内存

**Depends on:** Task 1
**Files:**
- Modify: `crates/sotrace-cli/src/main.rs:1334`（print_producer_consumer）
- Modify: `crates/sotrace-mcp/src/tools.rs`（PC 测试断言，若有）
- Modify: `crates/sotrace-server/src/handlers/thread_analysis.rs`（PC 测试断言，若有）
- 内存 `thread-analyzer.md` + `MEMORY.md`

- [ ] **Step 1: 修改 CLI print_producer_consumer — 打印 slot 大小**
文件: `crates/sotrace-cli/src/main.rs:1334`

```rust
        let addrs: Vec<String> = p.shared_addresses.iter()
            .map(|a| format!("0x{:x} ({}B, xfer {}B)", a.address, a.access_size, a.overlap_size))
            .collect();
```

（具体打印行格式按既有 print_producer_consumer 上下文调整。）

- [ ] **Step 2: 更新 MCP/HTTP PC 测试断言 — JSON shared_addresses 是对象数组**

在既有 PC 测试（`grep -n "shared_addresses\|producer_consumer" tools.rs / thread_analysis.rs`）追加：

```rust
        // #116: shared_addresses entries are objects with address + sizes
        let slot = &body["producer_consumer_patterns"][0]["shared_addresses"][0];  // 路径按实际
        assert!(slot["address"].is_u64());
        assert!(slot["access_size"].is_u64());
        assert!(slot["overlap_size"].is_u64());
```

- [ ] **Step 3: 验证三路径 + 全工作区**
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected: 全 ok，比 #115 基线（462）多 1 个新测试

- [ ] **Step 4: 重 build + 杀旧进程 + CLI/HTTP 冒烟**
Run: `touch crates/sotrace-engine/src/analyzer/thread_analyzer.rs && cargo build -p sotrace-cli -p sotrace-server 2>&1 | tail -3`
杀旧 server，CLI analyze PC trace → 输出含 slot 大小；HTTP GET producer-consumer → JSON `shared_addresses:[{address,access_size,overlap_size}]`。

- [ ] **Step 5: 提交三路径改动**
Run: `git add crates/sotrace-cli/src/main.rs crates/sotrace-mcp/src/tools.rs crates/sotrace-server/src/handlers/thread_analysis.rs && git commit -m "feat(cli,mcp,server): surface shared_address sizes in producer-consumer (#116)"`

- [ ] **Step 6: 更新内存 thread-analyzer.md — 加 #116 段**
追加：`shared_addresses: Vec<u64>` → `Vec<SharedAddress{address,access_size,overlap_size}>`（#113 下游，PC 槽带大小）；构造点从 flow 收集 write_size/overlap_size，按 address dedup 保留首个（同槽多 cycle 取首）；`SharedAddress` derive PartialEq,Eq + sort_by_key(address) + dedup_by(address)；改字段类型触发缓存假象须 touch+重 build+杀旧进程；1 新测试 + PC 测试更新。

- [ ] **Step 7: 更新 MEMORY.md 索引行**
thread-analyzer 行追加 `#116`。

- [ ] **Step 8: 提交计划文档**
Run: `git add docs/superpowers/plans/2026-07-15-pc-shared-addresses-typed.md && git commit -m "docs: add plan for typed producer-consumer shared_addresses (#116)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-engine/src/analyzer/thread_analyzer.rs` | 加 `SharedAddress` 结构 + `shared_addresses` 升级 + 构造点 + 1 新测试 + PC 测试更新 |
| `crates/sotrace-cli/src/main.rs` | `print_producer_consumer` slot 打印加 size |
| `crates/sotrace-mcp/src/tools.rs` / `crates/sotrace-server/src/handlers/thread_analysis.rs` | PC 测试断言加对象字段 |

## 陷阱

- **改字段类型缓存假象**（#110/#111/#114 踩过）：`Vec<u64>` → `Vec<SharedAddress>` 改 serde schema，`cargo build` 增量缓存可能跑旧 bin，冒烟看到裸 `[addr]` 假象。必须 `touch` 源文件强制重 build bin + 杀旧 server 进程。unit test 用 test profile 重编故 pass，bin 用 dev profile 缓存故旧。
- **dedup 必须按 address**：`SharedAddress` 含 size/overlap，若直接 `sort`+`dedup`（按全部字段）则同地址不同 size 会保留多条（违背「每槽一次」）。用 `sort_by_key(|s| s.address)` + `dedup_by(|a,b| a.address == b.address)`，size/overlap 不参与比较。`SharedAddress` derive `PartialEq,Eq` 即可（不需 `Ord`，因用 `sort_by_key` 而非 `sort`）。
- **多 cycle 不同 size 取首个**：`dedup_by` 保留首个（`dedup_by` 保留前一个、移除后一个匹配）。doc 说明。实践中 PC 同槽同 size，少见分歧。
- **PC 测试断言形状**：既有 `assert_eq!(pc.shared_addresses, vec![0x5000])`（:4126）须改 `vec![SharedAddress{address:0x5000, access_size:?, overlap_size:?}]`——执行前读该测试 setup 确认 size（`feed_memory_write(...,0x5000,4)` → access_size 4；read 完全重叠 → overlap 4）。
