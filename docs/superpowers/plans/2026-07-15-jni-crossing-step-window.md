# JniBoundaryStats first/last crossing step 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 给 `JniBoundaryStats` 加 `first_crossing_step: Option<u64>` + `last_crossing_step: Option<u64>`，让逆向工程师定位 JNI 活动时序——该线程首次/末次跨 JNI 边界在哪个 step，用于定位初始化阶段（首次 J2N）与收尾阶段（末次 N2J 回调）。

**Architecture:** `analyze_jni_boundary`（analyzer）遍历 `jni_calls`（`BTreeMap<u64 seq, Vec<JNICall>>`，按 seq 升序）。在累加 `total` 的同循环里，用「首次设 first、每次更新 last」记录每线程首末 crossing 的 seq（`call.seq`）。因 BTreeMap 按 key 升序遍历，首次遇该线程的 call 即全局最早的 crossing，末次即最晚——无需额外排序。attached-but-idle 线程（seed 出现、零 crossing）→ first/last 都 `None`（与 `total_crossings == 0` 一致）。加字段非改类型，serde 向后兼容，无 #110/#116 缓存假象——但仍 `touch`+重 build bin + 杀旧 server 冒烟（防御性）。

**Tech Stack:** Rust Cargo Workspace（sotrace-engine analyzer + sotrace-cli + sotrace-mcp + sotrace-server），serde，无新依赖。

**Risks:**
- `jni_calls` 是 `BTreeMap<seq, Vec>`——按 seq 升序遍历保证 first=最早、last=最晚。同 seq 多 call（不同线程）由 Vec 插入序处理，每线程独立记首末故无歧义。
- attached-but-idle 线程（`is_jni_attached=true` 但零 crossing）→ first/last 都 `None`，与 `total_crossings == 0` 一致语义。
- 加字段非改类型，serde 新增字段向后兼容（旧 JSON `default` 缺省），无 #110/#116 缓存假象——但仍 `touch`+重 build bin + 杀旧 server 冒烟（防御性，承 #114/#117/#118）。

---

### Task 1: first/last_crossing_step 字段 + analyze_jni_boundary 记录 + analyzer 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`JniBoundaryStats` 加 2 字段 + `analyze_jni_boundary` Acc 加字段 + 记录 + 测试）

- [ ] **Step 1: 给 JniBoundaryStats 加 first/last_crossing_step 字段**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`pub struct JniBoundaryStats`，`java_methods` 之后）

```rust
    /// Step (seq) of the thread's first JNI boundary crossing. `None` when the
    /// thread has no recorded crossings (attached-but-idle, or no crossings
    /// captured). Locates the initialization phase for an RE.
    pub first_crossing_step: Option<u64>,
    /// Step (seq) of the thread's last JNI boundary crossing. `None` when the
    /// thread has no recorded crossings. Locates the teardown / final callback.
    pub last_crossing_step: Option<u64>,
```

- [ ] **Step 2: Acc 加 first/last 字段 + analyze_jni_boundary 记录首末 seq**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:1746-1806`（替换 Acc struct + new + 遍历循环 + 构造点）

Acc 加字段：

```rust
        struct Acc {
            total: u64,
            j2n: u64,
            n2j: u64,
            native_addrs: HashSet<u64>,
            java_methods: HashSet<String>,
            first_step: Option<u64>,
            last_step: Option<u64>,
        }
        impl Acc {
            fn new() -> Self {
                Acc {
                    total: 0, j2n: 0, n2j: 0,
                    native_addrs: HashSet::new(),
                    java_methods: HashSet::new(),
                    first_step: None,
                    last_step: None,
                }
            }
        }
```

遍历循环里（`acc.total += 1;` 之后）记录：

```rust
                acc.total += 1;
                // Record first/last crossing step. jni_calls is a BTreeMap<seq,
                // Vec> iterated in ascending seq order, so the first call we
                // see for a thread is its globally-earliest crossing.
                if acc.first_step.is_none() {
                    acc.first_step = Some(call.seq);
                }
                acc.last_step = Some(call.seq);
```

构造点填值：

```rust
                JniBoundaryStats {
                    thread_id,
                    is_jni_attached,
                    total_crossings: acc.total,
                    java_to_native_count: acc.j2n,
                    native_to_java_count: acc.n2j,
                    native_addresses,
                    native_functions,
                    java_methods,
                    first_crossing_step: acc.first_step,
                    last_crossing_step: acc.last_step,
                }
```

- [ ] **Step 3: 更新既有 JNI 测试 + 新增 first/last 测试**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（JNI 测试附近）

既有 `test_jni_boundary_basic_split`（3 跨越）加 `first_crossing_step`/`last_crossing_step` 断言。新增 1 个测试：

```rust
    /// #119: first/last_crossing_step locate the JNI activity window. A thread
    /// with crossings at seq 50, 120, 300 reports first=50, last=300.
    #[test]
    fn test_jni_boundary_first_last_crossing_step() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "jni-worker"));
        analyzer.feed_jni_call(make_jni_call(50, 1, JNICallDirection::JavaToNative, "C", "m", 0x2000));
        analyzer.feed_jni_call(make_jni_call(120, 1, JNICallDirection::NativeToJava, "C", "cb", 0x0));
        analyzer.feed_jni_call(make_jni_call(300, 1, JNICallDirection::JavaToNative, "C", "m2", 0x3000));
        let stats = analyzer.analyze_jni_boundary();
        let s = &stats[0];
        assert_eq!(s.thread_id, 1);
        assert_eq!(s.total_crossings, 3);
        assert_eq!(s.first_crossing_step, Some(50));
        assert_eq!(s.last_crossing_step, Some(300));
    }

    /// #119: attached-but-idle thread (no crossings) has None for both
    /// first/last, consistent with total_crossings == 0.
    #[test]
    fn test_jni_boundary_attached_idle_has_no_crossing_steps() {
        let mut analyzer = ThreadAnalyzer::new();
        // Attached but no crossings fed.
        analyzer.feed_thread_info(make_thread_info(2, "attached-idle"));
        let stats = analyzer.analyze_jni_boundary();
        let s = stats.iter().find(|s| s.thread_id == 2).unwrap();
        assert_eq!(s.total_crossings, 0);
        assert_eq!(s.first_crossing_step, None);
        assert_eq!(s.last_crossing_step, None);
    }
```

（执行前读既有 `test_jni_boundary_basic_split` 确认 `make_jni_call` 夹具签名 `make_jni_call(seq, tid, direction, class, method, addr)`。）

- [ ] **Step 4: 验证 analyzer 编译与测试**
Run: `cargo test -p sotrace-engine --lib thread_analyzer:: 2>&1 | grep -E "test result|FAILED|error\[" | tail -10`
Expected: ok，新测试 + 既有 JNI 测试全过

- [ ] **Step 5: 回退验证**
临时把 `first_step`/`last_step` 记录注释掉跑 2 新测试 + 既有 basic_split 的 first/last 断言 → 应 fail（None），证测试有效。恢复后全绿。

- [ ] **Step 6: 提交**
Run: `git add crates/sotrace-engine/src/analyzer/thread_analyzer.rs && git commit -m "feat(analyzer): add first/last crossing step to jni boundary stats (#119)"`

---

### Task 2: 三路径对称暴露 + 冒烟 + 内存

**Depends on:** Task 1
**Files:**
- Modify: `crates/sotrace-cli/src/main.rs:1425`（`print_jni_boundary`）
- Modify: `crates/sotrace-mcp/src/tools.rs`（jni 测试断言）
- Modify: `crates/sotrace-server/src/handlers/thread_analysis.rs`（jni 测试断言）
- 内存 `thread-analyzer.md` + `MEMORY.md`

- [ ] **Step 1: 修改 CLI print_jni_boundary — 打印 first/last step**
文件: `crates/sotrace-cli/src/main.rs:1425-1440`（替换 `print_jni_boundary` 的 println）

```rust
        let window = match (s.first_crossing_step, s.last_crossing_step) {
            (Some(f), Some(l)) => format!("steps {}..{}", f, l),
            _ => "no crossings".to_string(),
        };
        println!(
            "  [{}] T{} attached={} crossings={} (j2n={} n2j={})  native=[{}]  java={}  window={}",
            i, s.thread_id, s.is_jni_attached, s.total_crossings,
            s.java_to_native_count, s.native_to_java_count,
            addrs.join(", "),
            s.java_methods.join(", "),
            window
        );
```

- [ ] **Step 2: 更新 MCP/HTTP jni 测试断言 — first/last_crossing_step 存在**
文件: `crates/sotrace-mcp/src/tools.rs`（`test_analyze_jni_boundary`）+ `crates/sotrace-server/src/handlers/thread_analysis.rs`（`test_analyze_jni_boundary`）

追加：

```rust
        // #119: first/last_crossing_step locate the JNI activity window.
        assert!(row["first_crossing_step"].is_u64() || row["first_crossing_step"].is_null());
        assert!(row["last_crossing_step"].is_u64() || row["last_crossing_step"].is_null());
```

（具体路径按实际测试结构调整。）

- [ ] **Step 3: 验证三路径 + 全工作区**
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected: 全 ok，比 #118 基线（467）多 2 个新测试

- [ ] **Step 4: 重 build + 杀旧进程 + CLI/HTTP 冒烟**
Run: `touch crates/sotrace-engine/src/analyzer/thread_analyzer.rs && cargo build -p sotrace-cli -p sotrace-server 2>&1 | tail -3`
杀旧 server，CLI `analyze --only jni-boundary` 输出含 `window=steps N..M`；HTTP GET jni-boundary → JSON `first_crossing_step`/`last_crossing_step`。

- [ ] **Step 5: 提交三路径改动**
Run: `git add crates/sotrace-cli/src/main.rs crates/sotrace-mcp/src/tools.rs crates/sotrace-server/src/handlers/thread_analysis.rs && git commit -m "feat(cli,mcp,server): surface jni crossing step window (#119)"`

- [ ] **Step 6: 更新内存 thread-analyzer.md — 加 #119 段**
追加：`JniBoundaryStats` 加 `first_crossing_step`/`last_crossing_step`（Option<u64>，首末 crossing seq）；`analyze_jni_boundary` Acc 加 `first_step`/`last_step`，BTreeMap<seq,Vec> 升序遍历保证 first=最早 last=最晚；attached-but-idle 线程 first/last 都 None（与 total==0 一致）；加字段非改类型无缓存假象但 touch+重 build+杀旧进程；2 新测试 + 既有 basic_split 加断言。

- [ ] **Step 7: 更新 MEMORY.md 索引行**
thread-analyzer 行追加 `#119`。

- [ ] **Step 8: 提交计划文档**
Run: `git add docs/superpowers/plans/2026-07-15-jni-crossing-step-window.md && git commit -m "docs: add plan for jni crossing step window (#119)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-engine/src/analyzer/thread_analyzer.rs` | `JniBoundaryStats` 加 2 字段 + `analyze_jni_boundary` Acc 记录首末 + 2 新测试 |
| `crates/sotrace-cli/src/main.rs` | `print_jni_boundary` 打印 `window=steps N..M` |
| `crates/sotrace-mcp/src/tools.rs` / `crates/sotrace-server/src/handlers/thread_analysis.rs` | jni 测试加 first/last 存在断言 |

## 陷阱

- **BTreeMap 升序保证**：`jni_calls` 是 `BTreeMap<seq, Vec>`，按 key=seq 升序遍历，故首次遇该线程 call=全局最早、末次=最晚。无需额外排序。
- **attached-but-idle**：`is_jni_attached=true` 但零 crossing 的线程 seed 出现 → first/last 都 None（与 `total_crossings == 0` 一致），不误报 0。
- **加字段非改类型**：serde 新增字段向后兼容（旧 JSON `default` 缺省），无 #110/#116 缓存假象——但仍 `touch`+重 build bin + 杀旧 server 冒烟（防御性）。
- **`make_jni_call` 夹具签名**：执行前读既有 JNI 测试确认 `make_jni_call(seq, tid, direction, class, method, addr)` 参数顺序（#67 定义）。
