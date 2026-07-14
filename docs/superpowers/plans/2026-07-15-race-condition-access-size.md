# RaceCondition 访问大小与精确冲突字节范围 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 让竞态报告携带每次访问的字节大小和两个访问**实际重叠**的字节范围，使逆向工程师能判断冲突的是一个字段还是整个结构体，并精确定位冲突字节。

**Architecture:** race 检测的 `reads_overlapping`/`writes_overlapping` 已按 byte-range 真实重叠检测（不只 page-align），但 `RaceCondition` 只输出 `address = *w_addr`（page-aligned 写地址），丢失了三件事：每次访问的字节大小、读访问的真实起始地址（write→read race 中读地址 ≠ 写地址）、以及两端访问的**交集字节范围**。本次在 `RaceCondition` 加 4 个字段——`first_access_size`/`second_access_size`（各自字节大小）+ `overlap_address`/`overlap_size`（两端区间 `[a, a+a_size)` ∩ `[b, b+b_size)` 的交集）。三处构造点（write→read :930、write→write :970、read→write :1011）都有 `w_size`/`r_size`/`w2_size` 在手，直接填值并计算交集（saturating 运算，与既有 `reads_overlapping` 一致）。description 字符串也带大小与重叠范围。三路径（CLI 打印 / MCP serde / HTTP serde）对称暴露——MCP/HTTP 直接 serde 自动出现新字段，CLI `print_races` 加一行大小与重叠范围。

**Tech Stack:** Rust Cargo Workspace（sotrace-engine analyzer + sotrace-cli + sotrace-mcp + sotrace-server），serde 序列化，无新依赖。

**Risks:**
- 交集计算需正确处理区间求交：`overlap_address = max(a_start, b_start)`、`overlap_size = min(a_end, b_end) - overlap_address`（端点用 saturating_add 防溢出，与既有 `reads_overlapping` 的 `w_end`/`r_end` 计算一致）。零大小访问退化为单点。
- 本次是**新增字段**（不改旧字段类型），serde 向后兼容（旧 JSON 反序列化新字段用 `default`），无 #110 那种增量缓存假象——但仍需 `touch`+重 build bin 才能冒烟（cargo test 不重建二进制）。
- 三处构造点对 `first`/`second` 的语义不同（write→read 是 w 在前 r 在后；read→write 是 r 在前 w 在后），交集的 a/b 端需对应 first/second 而非 w/r，避免张冠李戴。

---

### Task 1: RaceCondition 结构加字段 + 三处构造点填值 + analyzer 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:69-88`（`RaceCondition` 结构）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:930-944`（write→read 构造点）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:970-990`（write→write 构造点）
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1011-1030`（read→write 构造点）
- Test: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（新增 + 更新既有 race 测试）

- [ ] **Step 1: 修改 RaceCondition 结构 — 加 4 个字段**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:69-88`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaceCondition {
    /// Memory address where the race occurred (page-aligned base of the first
    /// access). Kept for backwards compatibility; the *precise* conflict region
    /// is in `overlap_address`/`overlap_size`.
    pub address: u64,
    /// Step of the first access (write)
    pub first_step: u64,
    /// Thread that performed the first access
    pub first_thread: u32,
    /// Step of the second access (read or write)
    pub second_step: u64,
    /// Thread that performed the second access
    pub second_thread: u32,
    /// Whether the first access was a write
    pub first_is_write: bool,
    /// Whether the second access was a write
    pub second_is_write: bool,
    /// Byte size of the first access (1, 2, 4, 8, …). Lets the RE judge whether
    /// the conflict is a single field or an entire struct.
    pub first_access_size: u64,
    /// Byte size of the second access.
    pub second_access_size: u64,
    /// Start address of the *actual* overlapping byte range between the two
    /// accesses (the intersection of `[a, a+a_size)` and `[b, b+b_size)`). This
    /// is the precise set of contended bytes — not page-aligned, not an
    /// approximation. Saturating arithmetic keeps it safe near `u64::MAX`.
    pub overlap_address: u64,
    /// Length in bytes of the overlapping range (`overlap_size` bytes starting
    /// at `overlap_address`). Zero only if the two accesses are degenerate.
    pub overlap_size: u64,
    /// Confidence level (0.0-1.0)
    pub confidence: f64,
    /// Description of the race condition
    pub description: String,
}
```

- [ ] **Step 2: 修改 write→read 构造点 — first=write, second=read，交集按 first/second 计算**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:930-944`

first access = write `[w_addr, w_addr+w_size)`，second access = read `[r_addr, r_addr+r_size)`。

```rust
                    // first=write [w_addr, w_end), second=read [r_addr, r_end)
                    let overlap_address = (*w_addr).max(r_addr);
                    let overlap_end = w_end.min(r_end);
                    let overlap_size = overlap_end.saturating_sub(overlap_address);
                    races.push(RaceCondition {
                        address: *w_addr,
                        first_step: *w_step,
                        first_thread: *w_tid,
                        second_step: r_step,
                        second_thread: r_tid,
                        first_is_write: true,
                        second_is_write: false,
                        first_access_size: *w_size as u64,
                        second_access_size: r_size as u64,
                        overlap_address,
                        overlap_size,
                        confidence,
                        description: format!(
                            "Thread {} wrote {} bytes at 0x{:X} (step {}), then thread {} read {} bytes at 0x{:X} (step {}) without synchronization; conflict range 0x{:X}-0x{:X} ({} bytes)",
                            w_tid, w_size, w_addr, w_step, r_tid, r_size, r_addr, r_step,
                            overlap_address, overlap_end, overlap_size,
                        ),
                    });
```

注：`w_end`（:903 `let w_end = w_addr.saturating_add(*w_size as u64)`）和 `r_end`（:917 `let r_end = r_addr.saturating_add(r_size as u64)`）在该构造点的上层作用域已定义，直接复用。

- [ ] **Step 3: 修改 write→write 构造点 — first=write1, second=write2**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:970-990`

first = `[w_addr, w_addr+w_size)`，second = `[w2_addr, w2_addr+w2_size)`。`w2_end` 在该作用域（:949 循环解构出 `w2_size`）需就地算。

```rust
                    let w2_end = w2_addr.saturating_add(*w2_size as u64);
                    let overlap_address = (*w_addr).max(*w2_addr);
                    let overlap_end = w_end.min(w2_end);
                    let overlap_size = overlap_end.saturating_sub(overlap_address);
                    races.push(RaceCondition {
                        address: *w_addr,
                        first_step: *w_step,
                        first_thread: *w_tid,
                        second_step: w2_step,
                        second_thread: w2_tid,
                        first_is_write: true,
                        second_is_write: true,
                        first_access_size: *w_size as u64,
                        second_access_size: *w2_size as u64,
                        overlap_address,
                        overlap_size,
                        confidence: confidence * 0.8, // Write-write slightly less severe
                        description: format!(
                            "Thread {} wrote {} bytes at 0x{:X} (step {}), then thread {} wrote {} bytes at 0x{:X} (step {}) without synchronization; conflict range 0x{:X}-0x{:X} ({} bytes)",
                            w_tid, w_size, w_addr, w_step, w2_tid, w2_size, w2_addr, w2_step,
                            overlap_address, overlap_end, overlap_size,
                        ),
                    });
```

- [ ] **Step 4: 修改 read→write 构造点 — first=read, second=write**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1011-1030`

first = read `[r_addr, r_addr+r_size)`，second = write `[w_addr, w_addr+w_size)`。该处 :993 循环解构出 `r_step`/`r_tid`/`r_addr`/`r_size`，:1000 算了 `r_end`，`w_end`/`w_addr`/`w_size` 来自外层 `for (w_step, w_tid, w_addr, w_size) in &writes`（:992 附近，需确认作用域——见陷阱）。

```rust
                    let overlap_address = r_addr.max(*w_addr);
                    let overlap_end = r_end.min(w_end);
                    let overlap_size = overlap_end.saturating_sub(overlap_address);
                    races.push(RaceCondition {
                        address: *w_addr,
                        first_step: r_step,
                        first_thread: r_tid,
                        second_step: *w_step,
                        second_thread: *w_tid,
                        first_is_write: false,
                        second_is_write: true,
                        first_access_size: r_size as u64,
                        second_access_size: *w_size as u64,
                        overlap_address,
                        overlap_size,
                        confidence,
                        description: format!(
                            "Thread {} read {} bytes at 0x{:X} (step {}), then thread {} wrote {} bytes at 0x{:X} (step {}) without synchronization; conflict range 0x{:X}-0x{:X} ({} bytes)",
                            r_tid, r_size, r_addr, r_step, w_tid, w_size, w_addr, w_step,
                            overlap_address, overlap_end, overlap_size,
                        ),
                    });
```

- [ ] **Step 5: 更新既有 race 测试断言 — 验证 size/overlap 字段填充**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:2303-2321`（`test_race_condition_detection`）

```rust
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        assert_eq!(races[0].first_thread, 1);
        assert_eq!(races[0].second_thread, 2);
        assert_eq!(races[0].address, 0x1000);
        assert!(races[0].first_is_write);
        assert!(!races[0].second_is_write);
        // #112: access sizes and precise conflict range are now reported
        assert_eq!(races[0].first_access_size, 4);
        assert_eq!(races[0].second_access_size, 4);
        assert_eq!(races[0].overlap_address, 0x1000);
        assert_eq!(races[0].overlap_size, 4);
```

- [ ] **Step 6: 新增测试 — 部分重叠 race 的 overlap 精确性**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（在 `test_race_condition_detection` 之后）

```rust
    /// #112: when two accesses only partially overlap, the conflict range must
    /// be the *intersection*, not either access's full span. Thread 1 writes 8
    /// bytes at 0x5000 (0x5000-0x5007), thread 2 reads 8 bytes at 0x5004
    /// (0x5004-0x500B) — the real conflict is 0x5004-0x5007 (4 bytes).
    #[test]
    fn test_race_partial_overlap_conflict_range() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, 0x5000, 8);
        analyzer.feed_memory_read(200, 2, 0x5004, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert_eq!(r.first_access_size, 8);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x5004);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: write-write race also reports per-access sizes and the overlap.
    #[test]
    fn test_write_write_race_reports_access_sizes() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, 0x6000, 4);
        analyzer.feed_memory_write(200, 2, 0x6000, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert!(r.first_is_write && r.second_is_write);
        assert_eq!(r.first_access_size, 4);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x6000);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: read-then-write race reports the read's real address as first
    /// access size source, not the write's page-aligned address.
    #[test]
    fn test_read_then_write_race_reports_access_sizes() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_read(100, 1, 0x7004, 8);
        analyzer.feed_memory_write(200, 2, 0x7000, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert!(!r.first_is_write && r.second_is_write);
        assert_eq!(r.first_access_size, 8);
        assert_eq!(r.second_access_size, 8);
        assert_eq!(r.overlap_address, 0x7004);
        assert_eq!(r.overlap_size, 4);
    }

    /// #112: accesses near `u64::MAX` must not overflow when computing the
    /// overlap range (saturating arithmetic, mirroring `reads_overlapping`).
    #[test]
    fn test_race_overlap_no_overflow_near_u64_max() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "thread-1"));
        analyzer.feed_thread_info(make_thread_info(2, "thread-2"));
        analyzer.feed_memory_write(100, 1, u64::MAX - 7, 8);
        analyzer.feed_memory_read(200, 2, u64::MAX - 3, 8);
        let races = analyzer.detect_race_conditions();
        assert!(!races.is_empty());
        let r = &races[0];
        assert_eq!(r.overlap_address, u64::MAX - 3);
        assert_eq!(r.overlap_size, 4);
    }
```

- [ ] **Step 7: 验证 analyzer 编译与测试**
Run: `cargo test -p sotrace-engine --lib thread_analyzer:: 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "test result: ok"
  - 新增 4 测试 + 更新的 `test_race_condition_detection` 全过

- [ ] **Step 8: 提交**
Run: `git add crates/sotrace-engine/src/analyzer/thread_analyzer.rs && git commit -m "feat(analyzer): report access sizes and precise conflict range in RaceCondition (#112)"`

---

### Task 2: 三路径对称暴露（CLI 打印 + MCP/HTTP serde + 三路径测试断言）

**Depends on:** Task 1
**Files:**
- Modify: `crates/sotrace-cli/src/main.rs:1258-1269`（`print_races` 加 size/overlap）
- Modify: `crates/sotrace-cli/src/main.rs:1543-1545`（CLI 测试断言）
- Modify: `crates/sotrace-cli/src/main.rs:1834-1837`（CLI 测试断言）
- Modify: `crates/sotrace-mcp/src/tools.rs`（race 测试断言）
- Modify: `crates/sotrace-server/src/handlers/thread_analysis.rs`（race 测试断言）

- [ ] **Step 1: 修改 print_races — 打印访问大小与冲突范围**
文件: `crates/sotrace-cli/src/main.rs:1258-1269`

```rust
fn print_races(races: &[sotrace_engine::analyzer::thread_analyzer::RaceCondition]) {
    println!("\n=== Race Conditions ({}) ===", races.len());
    for (i, r) in races.iter().enumerate() {
        let first = if r.first_is_write { "write" } else { "read" };
        let second = if r.second_is_write { "write" } else { "read" };
        println!(
            "  [{}] addr=0x{:x}  T{} {} ({}B) @ step {}  →  T{} {} ({}B) @ step {}  conflict=0x{:x}+{}B",
            i, r.address, r.first_thread, first, r.first_access_size, r.first_step,
            r.second_thread, second, r.second_access_size, r.second_step,
            r.overlap_address, r.overlap_size,
        );
    }
}
```

- [ ] **Step 2: 更新 CLI race 测试断言**
文件: `crates/sotrace-cli/src/main.rs:1543-1545`

```rust
        let races = engine.detect_race_conditions();
        assert!(!races.is_empty(), "should detect at least one race");
        assert!(races.iter().any(|r| r.address == 4096));
        // #112: sizes + conflict range present
        assert!(races.iter().any(|r| r.overlap_address == 4096 && r.overlap_size > 0));
```

文件: `crates/sotrace-cli/src/main.rs:1834-1837`（同样模式，地址 0x1000）

```rust
        let races = engine.detect_race_conditions();
        assert!(!races.is_empty(), "should detect the cross-thread race");
        assert!(races.iter().any(|r| r.address == 0x1000));
        assert!(races.iter().any(|r| r.overlap_address == 0x1000 && r.overlap_size > 0));
```

- [ ] **Step 3: 更新 MCP race 测试断言 — 断言新字段出现在 JSON**

在既有 MCP race 测试（grep `detect_races` / `"race_conditions"` 定位）的断言块里追加：

```rust
        // #112: access sizes and overlap range are present in the JSON
        let race = &body["race_conditions"][0];
        assert!(race["first_access_size"].is_u64());
        assert!(race["second_access_size"].is_u64());
        assert!(race["overlap_address"].is_u64());
        assert!(race["overlap_size"].is_u64());
```

- [ ] **Step 4: 更新 HTTP race 测试断言 — 断言新字段出现在 JSON**

在既有 HTTP race 测试（`GET /analyze/threads/races`）的断言块里追加同样的 4 行 `is_u64()` 断言。

- [ ] **Step 5: 验证三路径编译与测试**
Run: `cargo test -p sotrace-cli -p sotrace-mcp -p sotrace-server 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "test result: ok"（三 crate 各自）

- [ ] **Step 6: 提交**
Run: `git add crates/sotrace-cli/src/main.rs crates/sotrace-mcp/src/tools.rs crates/sotrace-server/src/handlers/thread_analysis.rs && git commit -m "feat(cli,mcp,server): surface race access sizes and conflict range (#112)"`

---

### Task 3: 全工作区测试 + 端到端冒烟 + 内存

**Depends on:** Task 1, Task 2
**Files:**
- Modify: `/home/cc11001100/.claude/projects/-home-cc11001100-github-android-security-engineer-so-trace-database/memory/thread-analyzer.md`
- Modify: `/home/cc11001100/.claude/projects/-home-cc11001100-github-android-security-engineer-so-trace-database/memory/MEMORY.md`

- [ ] **Step 1: 全工作区测试**
Run: `cargo test --workspace 2>&1 | tail -30`
Expected:
  - Exit code: 0
  - 所有 crate "test result: ok"，无 FAIL
  - 比基线（#111 后 ~452）多 4 个新测试

- [ ] **Step 2: 强制重 build 三个二进制（防增量缓存假象）**
Run: `touch crates/sotrace-engine/src/analyzer/thread_analyzer.rs && cargo build -p sotrace-cli -p sotrace-mcp -p sotrace-server 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - 三个二进制重 build 成功

- [ ] **Step 3: CLI 端到端冒烟 — race 报告含 size 与 conflict**
构造一个部分重叠 race trace JSON，CLI analyze，断言输出含 `conflict=`：

Run: `SOTRACE_BIND=127.0.0.1:18099 cargo run -p sotrace-cli -- analyze /tmp/race_overlap.json 2>&1 | grep -E "Race Conditions|conflict="`
Expected:
  - Exit code: 0
  - Output contains: "conflict=0x5004+4B"（部分重叠场景）

- [ ] **Step 4: HTTP 端到端冒烟 — JSON 含新字段**
启动 server，POST trace，GET /analyze/threads/races，断言 JSON 含 `overlap_address`/`overlap_size`。

Run: `SOTRACE_BIND=127.0.0.1:18099 cargo run -p sotrace-server &` 然后 `curl -s 127.0.0.1:18099/api/v1/traces/1/analyze/threads/races | python3 -c "import sys,json; r=json.load(sys.stdin)['race_conditions'][0]; print(r['overlap_address'], r['overlap_size'], r['first_access_size'])"`
Expected:
  - 输出含非零 overlap_size 与 access_size 数值

- [ ] **Step 5: 更新内存 thread-analyzer.md — 加 #112 段**
追加段：RaceCondition 加 `first_access_size`/`second_access_size`/`overlap_address`/`overlap_size` 4 字段（新增不改旧类型，无 #110 缓存假象）；三处构造点用 `w_end`/`r_end`/`w2_end` 求交集（`max(start) .. min(end)`，saturating）；description 带 size+range；三路径 serde 自动 + CLI print_races 加 conflict=；4 新测试（部分重叠/write-write/read→write/u64_max 防溢出）。

- [ ] **Step 6: 更新 MEMORY.md 索引行**
thread-analyzer 行追加 `#112` 标记。

- [ ] **Step 7: 提交**
Run: `git add docs/superpowers/plans/2026-07-15-race-condition-access-size.md && git commit -m "docs: add plan for race condition access size and conflict range (#112)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-engine/src/analyzer/thread_analyzer.rs` | `RaceCondition` 加 4 字段 + 3 处构造点填值 + description + 4 新测试 + 1 既有测试更新 |
| `crates/sotrace-cli/src/main.rs` | `print_races` 加 size/conflict 打印 + 2 处测试断言 |
| `crates/sotrace-mcp/src/tools.rs` | race 测试断言加 4 字段 is_u64 |
| `crates/sotrace-server/src/handlers/thread_analysis.rs` | race 测试断言加 4 字段 is_u64 |

## 陷阱

- **三处构造点 first/second 语义不同**：write→read first=w second=r；write→write first=w1 second=w2；read→write first=r second=w。交集端点必须对应 first/second 的区间，不能一律用 w/r 变量，否则 read→write 会把读地址当 second、写地址当 first 弄反。
- **`w_end` 作用域**：write→read 构造点（:930）和 write→write 构造点（:970）能直接用外层 :903 的 `w_end`；但 read→write 构造点（:1011）的外层循环变量名需 Step 4 执行时用 grep 确认（可能是 `w_addr`/`w_size` 或 `*w_addr`/`*w_size`），按实际解构模式调整 `*`。
- **新增字段不改旧类型**：serde 向后兼容（旧 JSON 反序列化新字段缺省 `default`），无 #110 那种改类型触发的缓存假象。但冒烟前仍 `touch`+重 build bin（cargo test 不重建二进制）。
- **零大小访问**：`pages_covering` 把 size==0 当单点；交集计算 `overlap_size` 可能为 0（两端仅边界相切），description 里 `overlap_size` 字节为 0 是合法的退化情形，不算 bug。
- **u64::MAX 防溢出**：所有端点用 `saturating_add`/`saturating_sub`，与既有 `reads_overlapping` 的 `w_end`/`r_end` 一致；新增 `test_race_overlap_no_overflow_near_u64_max` 守卫。
