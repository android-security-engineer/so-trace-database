# ThreadDataFlow 访问大小与精确传递范围 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 让跨线程数据流报告携带读写访问的字节大小和实际重叠（即真正传递）的字节范围，与 #112 的 `RaceCondition` 对称——RE 追踪 data flow 时能判断传递的是一个字段还是整个结构体、精确字节位置。

**Architecture:** `analyze_data_flows` 与 `detect_race_conditions` 共用 `reads_overlapping`（已按 byte-range 真实重叠、saturating 端点），但 data flow 构造点（:1915）**主动丢弃了** `r_addr`/`r_size`（解构成 `_r_addr`/`_r_size` 下划线忽略），且 `ThreadDataFlow.address` 只存 `*w_addr`（写基址），同样丢了访问大小、读真实地址、重叠范围。本次给 `ThreadDataFlow` 加 4 字段——`write_size`/`read_size`（读写字节大小）+ `overlap_address`/`overlap_size`（写 `[w_addr, w_end)` ∩ 读 `[r_addr, r_end)` 的交集），与 `RaceCondition` 的 `first/second_access_size`+`overlap_*` 完全对称。单一构造点（不像 race 三处）解开 `_r_addr`/`_r_size` 填值。dedup key（:1924 用 `address` 写基址）不变——加字段不破坏 dedup 语义。三路径（CLI/MCP/HTTP）serde 自动暴露 + CLI 打印加 size/range。

**Tech Stack:** Rust Cargo Workspace（sotrace-engine analyzer + sotrace-cli + sotrace-mcp + sotrace-server），serde，无新依赖。

**Risks:**
- `_r_addr`/`_r_size` 解开后需正确用于交集：`overlap_address = w_addr.max(r_addr)`、`overlap_end = w_end.min(r_end)`、`overlap_size = overlap_end.saturating_sub(overlap_address)`，端点用 saturating（与 #112 一致）。`w_end` 在 :1910 上层 `let w_end = w_addr.saturating_add(*w_size as u64)` 已定义（需确认——见陷阱）。
- 新增字段不改旧类型，serde 向后兼容，无 #110 缓存假象；但冒烟前须 `touch`+重 build bin + **杀旧 server 进程**（#112 踩过：旧进程占端口跑旧 schema）。
- `ThreadDataFlow` 无 `Ord`，dedup/排序不受影响（dedup 用 HashSet key，无排序）。

---

### Task 1: ThreadDataFlow 结构加字段 + 构造点填值 + analyzer 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:192-200`（`ThreadDataFlow` 结构）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1905-1925`（`analyze_data_flows` 构造点）
- Test: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（新增 + 更新既有 data flow 测试）

- [ ] **Step 1: 修改 ThreadDataFlow 结构 — 加 4 字段**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:192-200`

```rust
pub struct ThreadDataFlow {
    /// Source thread (writer)
    pub from_thread: u32,
    /// Destination thread (reader)
    pub to_thread: u32,
    /// Memory address of the data transfer (page-aligned base of the write).
    /// Kept for backwards compatibility and the dedup key; the *precise*
    /// transferred region is in `overlap_address`/`overlap_size`.
    pub address: u64,
    /// Step when the write occurred
    pub write_step: u64,
    /// Step when the read occurred
    pub read_step: u64,
    /// Whether there was proper synchronization between write and read
    pub is_synchronized: bool,
    /// Byte size of the writer's access (1, 2, 4, 8, …). Lets the RE judge
    /// whether the transfer is a single field or an entire struct.
    pub write_size: u64,
    /// Byte size of the reader's access.
    pub read_size: u64,
    /// Start address of the *actual* overlapping byte range between the write
    /// and the read — the precise set of bytes the reader could have observed
    /// from the writer (the intersection of `[w, w+w_size)` and `[r, r+r_size)`).
    /// Saturating arithmetic keeps it safe near `u64::MAX`.
    pub overlap_address: u64,
    /// Length in bytes of the overlapping range. Zero only for degenerate
    /// boundary-touching accesses.
    pub overlap_size: u64,
}
```

- [ ] **Step 2: 修改 analyze_data_flows 构造点 — 解开 _r_addr/_r_size，算交集填值**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1905-1925`

执行前先 `grep -n "reads_overlapping.*w_addr" 确认 w_end 是否在该作用域定义。若无，就地算 `let w_end = w_addr.saturating_add(*w_size as u64);`（构造点内 :1910 附近上层循环，与 race 的 write→read 一致）。

```rust
        for (w_step, w_tid, w_addr, w_size) in &writes {
            // Use the page index to scan only reads sharing a page with this write.
            for (r_step, r_tid, r_addr, r_size) in self.reads_overlapping(*w_addr, *w_size) {
                if r_tid == *w_tid { continue; } // Same thread
                if r_step <= *w_step { continue; } // Read before write

                let is_sync = self.has_sync_between(*w_tid, r_tid, *w_step, r_step);

                // Precise transferred byte range: intersection of the write
                // `[w_addr, w_end)` and the read `[r_addr, r_end)`.
                let w_end = (*w_addr).saturating_add(*w_size as u64);
                let r_end = r_addr.saturating_add(r_size as u64);
                let overlap_address = (*w_addr).max(r_addr);
                let overlap_end = w_end.min(r_end);
                let overlap_size = overlap_end.saturating_sub(overlap_address);

                flows.push(ThreadDataFlow {
                    from_thread: *w_tid,
                    to_thread: r_tid,
                    address: *w_addr,
                    write_step: *w_step,
                    read_step: r_step,
                    is_synchronized: is_sync,
                    write_size: *w_size as u64,
                    read_size: r_size as u64,
                    overlap_address,
                    overlap_size,
                });
            }
        }
```

注：`w_end`/`r_end` 就地在构造点算（不依赖外层），避免作用域假设。若外层已有 `w_end` 可复用，但就地算更安全（构造点自洽）。

- [ ] **Step 3: 更新既有 data flow 测试断言 — 验证 size/overlap 字段填充**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`test_data_flow_analysis`，:3987 附近）

在既有 `assert!(!flow.is_synchronized);` 后追加：

```rust
        // #113: access sizes and precise transfer range are now reported
        assert_eq!(flow.write_size, 4);
        assert_eq!(flow.read_size, 4);
        assert_eq!(flow.overlap_address, 0x3000);
        assert_eq!(flow.overlap_size, 4);
```

（需先确认该测试的写/读 size——若 `feed_memory_write(..., 0x3000, 4)` + `feed_memory_read(..., 0x3000, 4)` 则上面断言成立；若 size 不同，按实际填。）

- [ ] **Step 4: 新增测试 — 部分重叠 data flow 的 overlap 精确性 + 防溢出**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`test_data_flow_analysis` 之后）

```rust
    /// #113: when the write and read only partially overlap, the transferred
    /// range must be the *intersection*. Thread 1 writes 8 bytes at 0x5000
    /// (0x5000-0x5007), thread 2 reads 8 bytes at 0x5004 (0x5004-0x500B) — the
    /// actual transfer is 0x5004-0x5007 (4 bytes).
    #[test]
    fn test_data_flow_partial_overlap_transfer_range() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));
        analyzer.feed_memory_write(100, 1, 0x5000, 8);
        analyzer.feed_memory_read(200, 2, 0x5004, 8);
        let flows = analyzer.analyze_data_flows();
        assert!(!flows.is_empty());
        let f = &flows[0];
        assert_eq!(f.write_size, 8);
        assert_eq!(f.read_size, 8);
        assert_eq!(f.overlap_address, 0x5004);
        assert_eq!(f.overlap_size, 4);
    }

    /// #113: accesses near `u64::MAX` must not overflow when computing the
    /// transfer range (saturating arithmetic, mirroring #112 race overlap).
    #[test]
    fn test_data_flow_overlap_no_overflow_near_u64_max() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "producer"));
        analyzer.feed_thread_info(make_thread_info(2, "consumer"));
        analyzer.feed_memory_write(100, 1, u64::MAX - 7, 8);
        analyzer.feed_memory_read(200, 2, u64::MAX - 3, 8);
        let flows = analyzer.analyze_data_flows();
        assert!(!flows.is_empty());
        let f = &flows[0];
        assert_eq!(f.overlap_address, u64::MAX - 3);
        // Saturating end clamps both ranges to MAX, so overlap is 3 bytes.
        assert_eq!(f.overlap_size, 3);
    }
```

- [ ] **Step 5: 验证 analyzer 编译与测试**
Run: `cargo test -p sotrace-engine --lib thread_analyzer:: 2>&1 | tail -15`
Expected:
  - Exit code: 0
  - Output contains: "test result: ok"
  - 2 新测试 + 更新的 `test_data_flow_analysis` 全过

- [ ] **Step 6: 提交**
Run: `git add crates/sotrace-engine/src/analyzer/thread_analyzer.rs && git commit -m "feat(analyzer): report transfer sizes and precise range in ThreadDataFlow (#113)"`

---

### Task 2: 三路径对称暴露 + 冒烟 + 内存

**Depends on:** Task 1
**Files:**
- Modify: `crates/sotrace-cli/src/main.rs`（`print_data_flows` 加 size/overlap，若存在）
- Modify: `crates/sotrace-mcp/src/tools.rs`（data flow 测试断言）
- Modify: `crates/sotrace-server/src/handlers/thread_analysis.rs`（data flow 测试断言）
- Modify: 内存 `thread-analyzer.md` + `MEMORY.md`

- [ ] **Step 1: 修改 CLI print_data_flows — 打印大小与传递范围**
文件: `crates/sotrace-cli/src/main.rs`（`grep -n "fn print_data_flows" 定位`）

若存在格式化打印（仿 #112 的 `print_races`），加 `write_size`/`read_size`/`overlap_*`：

```rust
fn print_data_flows(flows: &[sotrace_engine::analyzer::thread_analyzer::ThreadDataFlow]) {
    println!("\n=== Data Flows ({}) ===", flows.len());
    for (i, f) in flows.iter().enumerate() {
        let sync = if f.is_synchronized { "synced" } else { "unsynced" };
        println!(
            "  [{}] T{} →write ({}B) @ step {}  →  T{} read ({}B) @ step {}  transfer=0x{:x}+{}B  ({})",
            i, f.from_thread, f.write_size, f.write_step,
            f.to_thread, f.read_size, f.read_step,
            f.overlap_address, f.overlap_size, sync,
        );
    }
}
```

若 CLI 无 `print_data_flows`（data flow 只走 JSON 模式），跳过本步，仅在 Step 2 的 CLI 测试断言加字段检查。

- [ ] **Step 2: 更新 MCP/HTTP data flow 测试断言 — 断言新字段出现在 JSON**

在既有 MCP data flow 测试（`grep -n "data_flow\|data-flows" tools.rs` 定位）和 HTTP 测试（`/analyze/threads/data-flows`）的断言块里追加：

```rust
        // #113: transfer sizes and overlap range are present in the JSON
        let flow = &body["data_flows"].as_array().unwrap()[0];   // HTTP
        // 或 MCP: let flow = &result["data_flows"].as_array().unwrap()[0];
        assert!(flow["write_size"].is_u64());
        assert!(flow["read_size"].is_u64());
        assert!(flow["overlap_address"].is_u64());
        assert!(flow["overlap_size"].is_u64());
```

（字段名/数组键按实际 MCP/HTTP 响应结构调整——MCP 可能是 `result["data_flows"]`，HTTP 可能是 `json["data_flows"]`。）

- [ ] **Step 3: 验证三路径编译与测试**
Run: `cargo test -p sotrace-cli -p sotrace-mcp -p sotrace-server 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected:
  - Exit code: 0
  - 三 crate 各自 "test result: ok"

- [ ] **Step 4: 全工作区测试**
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected:
  - Exit code: 0，所有 crate ok，无 FAIL
  - 比 #112 基线（456）多 2 个新测试

- [ ] **Step 5: 强制重 build + 杀旧进程 + CLI/HTTP 冒烟**
Run: `touch crates/sotrace-engine/src/analyzer/thread_analyzer.rs && cargo build -p sotrace-cli -p sotrace-server 2>&1 | tail -3`
然后 `kill` 任何占用冒烟端口的旧 sotrace-server 进程，启动新二进制：
- CLI: 构造部分重叠 data flow trace → `analyze` → 输出含 `transfer=0x5004+4B`
- HTTP: POST import + GET `/analyze/threads/data-flows` → JSON 含 `overlap_address`/`overlap_size`
Expected: CLI 输出 `transfer=0x5004+4B`；HTTP JSON `overlap_size:4`

- [ ] **Step 6: 提交三路径改动**
Run: `git add crates/sotrace-cli/src/main.rs crates/sotrace-mcp/src/tools.rs crates/sotrace-server/src/handlers/thread_analysis.rs && git commit -m "feat(cli,mcp,server): surface data flow transfer sizes and range (#113)"`

- [ ] **Step 7: 更新内存 thread-analyzer.md — 加 #113 段**
追加段：`ThreadDataFlow` 加 `write_size`/`read_size`/`overlap_address`/`overlap_size`（#112 的镜像，data flow 维度）；构造点解开 `_r_addr`/`_r_size`（之前下划线丢弃），就地算 `w_end`/`r_end` 求交集；dedup key 用 `address`（写基址）不变；三路径 serde 自动 + CLI `print_data_flows` 加 `transfer=`；2 新测试（partial_overlap/no_overflow）；冒烟须杀旧 server 进程。

- [ ] **Step 8: 更新 MEMORY.md 索引行**
thread-analyzer 行追加 `#113`。

- [ ] **Step 9: 提交计划文档**
Run: `git add docs/superpowers/plans/2026-07-15-data-flow-transfer-size.md && git commit -m "docs: add plan for data flow transfer size and range (#113)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-engine/src/analyzer/thread_analyzer.rs` | `ThreadDataFlow` 加 4 字段 + 构造点解开 `_r_addr`/`_r_size` 填交集 + 2 新测试 + 1 既有测试更新 |
| `crates/sotrace-cli/src/main.rs` | `print_data_flows` 加 size/transfer（若存在）+ 测试断言 |
| `crates/sotrace-mcp/src/tools.rs` | data flow 测试断言加 4 字段 is_u64 |
| `crates/sotrace-server/src/handlers/thread_analysis.rs` | data flow 测试断言加 4 字段 is_u64 |

## 陷阱

- **`_r_addr`/`_r_size` 之前被丢弃**：构造点 :1915 解构写成 `_r_addr`/`_r_size`（下划线前缀=故意忽略）。Step 2 必须去掉下划线前缀变 `r_addr`/`r_size`，否则无法在交集计算中引用（Rust 会警告 unused 或重复绑定）。这是 #113 与 #112 的关键差异——race 三处本来就用 `r_addr`/`r_size`，data flow 是主动忽略的，需「解锁」。
- **`w_end` 作用域**：race 的 write→read 有外层 `w_end`（:903）可复用；但 `analyze_data_flows` 的外层循环（:1907 `for (w_step, w_tid, w_addr, w_size) in &writes`）**未**算 `w_end`（构造点内也没用）。所以 Step 2 就地算 `w_end`（构造点内），不依赖外层——比复用更安全。
- **dedup key 不变**：:1924 `key = (from_thread, to_thread, address, write_step)` 仍用 `address`（写基址）。加 `overlap_*` 字段不进 key——同一 (from,to,address,write_step) 但不同 read 的 flow 仍 dedup 成一条（保留首个），这是既有语义，#113 不改变。
- **冒烟旧进程陷阱**（#112 踩过）：重 build 后必须 `kill` 占端口的旧 sotrace-server 进程，否则 curl 命中旧 schema 返回缺字段 JSON。CLI 冒烟无此问题（每次 `cargo run` 起新进程）。
- **u64::MAX 饱和语义**（#112 踩过）：8B@(MAX-7) 的 `saturating_add(8)` clamp 到 MAX，与 8B@(MAX-3) 重叠 3B 不是 4B——`test_data_flow_overlap_no_overflow_near_u64_max` 期望 3。
