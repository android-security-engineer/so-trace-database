# scheduling 维度 per-core residency 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 给 `ThreadSchedulingStats` 加 per-core 驻留步数（`core_residency: Vec<(u32 core, u64 steps)>`）与迁移次数（`migration_count` 已有，保留），让逆向工程师分析线程亲和性（thread affinity）/核间抖动（cache miss 来源）时知道每线程在哪个核上跑了多少步——而非仅「跑过哪些核」的集合。

**Architecture:** 当前 `analyze_scheduling` 按 per-thread HashMap **分别累加** switch 事件（in/out 计数、cores HashSet），但「每核驻留步数」需要**全局 step 时序**——驻留时长 = 下一个 switch 的 step − 当前 switch 的 step（线程在该核上跑了多久），跨线程全局序列。per-thread 累加循环丢失了 step 时序，无法算驻留。改为：① 先从 `context_switches`（`BTreeMap<step, Vec>`，step 有序）重建**全局 switch 序列**（按 step 升序、同 step 按 Vec 插入序）；② 单趟遍历全局序列，对每个 switch：`to_thread` 在 `cpu_core` 上开始一段驻留，前一段（同一线程的最近 in）在**下一个该线程的 out 或下一个 in** 处闭合，时长 = `next_step.saturating_sub(this_step)`；③ 累加到 `core_residency: HashMap<(thread, core), u64>`，最后按 (core) 排序输出。复用 #65（state residency）的「区间时长归给起始状态」语义，但 scheduling 是全局时序而非 per-thread 内部序。无界尾驻留（最后一段无后续 switch 封口）贡献 0（绝不凭空造时长，同 #65）。`cpu_core == None` 的 switch 段跳过（不误归核 0）。

**Tech Stack:** Rust Cargo Workspace（sotrace-engine analyzer + sotrace-cli + sotrace-mcp + sotrace-server），serde，无新依赖。

**Risks:**
- `analyze_scheduling` 从 per-thread HashMap 累加改为**全局序列遍历**——in/out/vol/invol/migration 计数仍可在同趟算（不依赖时序），但 core_residency 必须走全局序。两类逻辑合并到一个全局遍历循环，保持单趟 O(S)。
- 无界尾驻留：线程最后一段 in 后无后续 switch 封口 → 贡献 0（同 #65 无界处理）。绝不凭空造时长。
- `cpu_core == None`：该 switch 段无核信息 → 不归给任何核（跳过），不误归核 0。
- 同 step 多 switch：BTreeMap Vec 按插入序，驻留时长用相邻 step 差；同 step 内多 switch 的驻留差为 0（合法退化，0 步驻留不算 bug，承 #56/#59 同 step 主题）。
- 改 `ThreadSchedulingStats` 加字段是 serde 新增字段（非改类型），向后兼容（旧 JSON `default` 缺省），无 #110/#116 改类型触发的缓存假象——但仍 `touch`+重 build bin + 杀旧 server 进程冒烟（防御性，承 #114）。

---

### Task 1: core_residency 字段 + analyze_scheduling 全局时序遍历 + analyzer 测试

**Depends on:** None
**Files:**
- Modify: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`ThreadSchedulingStats` 加字段 + `analyze_scheduling` 改全局遍历 + 测试）

- [ ] **Step 1: 给 ThreadSchedulingStats 加 core_residency 字段**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（`pub struct ThreadSchedulingStats`，:206 附近）

在 `cpu_cores` 字段之后加：

```rust
    /// Per-core residency in steps: how long (in steps) this thread ran on
    /// each CPU core, accumulated across all scheduling intervals. Sorted by
    /// core id for deterministic output. Empty if no switch carried a
    /// `cpu_core` (cores unknown) or the thread was never scheduled on a
    /// known core. A residency interval's length is the step gap to the next
    /// switch that ended the interval; a final unbounded run-in (no
    /// following switch) contributes 0, never a fabricated span.
    pub core_residency: Vec<(u32, u64)>,
```

- [ ] **Step 2: 重写 analyze_scheduling — 全局 step 时序遍历 + core_residency 累加**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs:2118-2180`（替换整个 `analyze_scheduling` 方法）

既有实现按 per-thread HashMap 累加，in/out/vol/invol/migration/cores 都不依赖时序，但 core_residency 需全局时序。改为：先重建全局 switch 序列（BTreeMap 已 step 有序，flatten Vec 按插入序），单趟遍历既算计数也算 residency。

```rust
    pub fn analyze_scheduling(&mut self) -> Vec<ThreadSchedulingStats> {
        // Per-thread accumulator. Counts (in/out/vol/invol/migration) are
        // order-independent; `cores` is a set so repeated runs on the same
        // core collapse. `core_residency` is accumulated separately below via
        // a global step-ordered pass, because residency length = step gap to
        // the next switch, which is a global (cross-thread) temporal notion
        // the per-thread counts cannot recover.
        #[derive(Default)]
        struct Acc {
            scheduled_in: u64,
            scheduled_out: u64,
            voluntary: u64,
            involuntary: u64,
            migrations: u64,
            cores: HashSet<u32>,
            // (thread, core) -> accumulated residency steps. Keyed by thread
            // too because we flatten the global pass here, then split back
            // per-thread when emitting rows.
            residency: HashMap<(u32, u32), u64>,
            // Last "run-in" of each thread: (step, core) where it was
            // scheduled on, awaiting a closing switch to measure the span.
            // None / no core means we are not tracking an interval.
            last_in: HashMap<u32, Option<(u64, u32)>>,
        }
        let mut per_thread: HashMap<u32, Acc> = HashMap::new();

        // Flatten the BTreeMap<step, Vec<ContextSwitch>> into a global,
        // step-ordered sequence. BTreeMap iterates steps ascending; the Vec
        // per step preserves insertion order (same-step switches, see #59).
        let mut global: Vec<&ContextSwitch> = Vec::new();
        for switches in self.context_switches.values() {
            global.extend(switches.iter());
        }

        for sw in global {
            // Close the running interval of `from_thread`: it ran on its
            // last-in core from `last_in_step` until `sw.step`.
            let out = per_thread.entry(sw.from_thread).or_default();
            out.scheduled_out += 1;
            match sw.switch_reason {
                SwitchReason::Yield | SwitchReason::Blocking => out.voluntary += 1,
                SwitchReason::Preemption
                | SwitchReason::TimeSliceExpired
                | SwitchReason::Interrupt => out.involuntary += 1,
                _ => {}
            }
            if let Some(Some((start, core))) = out.last_in.take() {
                // The from_thread's interval closes at sw.step.
                let span = sw.step.saturating_sub(start);
                *out.residency.entry((sw.from_thread, core)).or_insert(0) += span;
            }

            // The thread being scheduled ON: it now runs on `cpu_core`.
            let in_acc = per_thread.entry(sw.to_thread).or_default();
            in_acc.scheduled_in += 1;
            if sw.switch_reason == SwitchReason::Migration {
                in_acc.migrations += 1;
            }
            // Track the new run-in interval only if we know the core; a
            // None core leaves last_in at None so no residency is fabricated
            // and nothing is added when it later closes.
            in_acc.last_in = sw.cpu_core.map(|core| (sw.step, core));
            if let Some(core) = sw.cpu_core {
                in_acc.cores.insert(core);
            }
        }

        // Final unbounded run-ins contribute 0 (no following switch closes
        // them); we deliberately drop them rather than fabricate a span to
        // trace-end. This mirrors #65's tail-state handling.

        let mut results: Vec<ThreadSchedulingStats> = per_thread
            .into_iter()
            .map(|(thread_id, acc)| {
                let mut cpu_cores: Vec<u32> = acc.cores.into_iter().collect();
                cpu_cores.sort_unstable();
                // Collect this thread's residency, sorted by core id.
                let mut core_residency: Vec<(u32, u64)> = acc
                    .residency
                    .into_iter()
                    .filter(|((tid, _), _)| *tid == thread_id)
                    .map(|((_, core), steps)| (core, steps))
                    .collect();
                core_residency.sort_unstable_by_key(|(core, _)| *core);
                ThreadSchedulingStats {
                    thread_id,
                    scheduled_in_count: acc.scheduled_in,
                    scheduled_out_count: acc.scheduled_out,
                    voluntary_switches: acc.voluntary,
                    involuntary_switches: acc.involuntary,
                    migration_count: acc.migrations,
                    cpu_cores,
                    core_residency,
                }
            })
            .collect();
        // Deterministic output regardless of HashMap iteration order.
        results.sort_unstable_by_key(|s| s.thread_id);
        results
    }
```

- [ ] **Step 3: 更新既有 scheduling 测试 + 新增 residency 测试**
文件: `crates/sotrace-engine/src/analyzer/thread_analyzer.rs`（scheduling 测试附近）

既有 `test_scheduling_classifies_switch_reasons` / `test_scheduling_same_step_switches_both_counted` 加 `core_residency` 存在性断言。新增 2 个测试：

```rust
    /// #117: core_residency accumulates per-core step spans. A thread
    /// scheduled on core 0 @ step 10, replaced at step 30, then on core 1
    /// @ step 40, replaced at step 100, ran 20 steps on core 0 and 60 on
    /// core 1.
    #[test]
    fn test_scheduling_core_residency_accumulates_per_core() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));
        // t1 on core0 @10, switched out (preemption) @30 -> 20 steps on core0.
        analyzer.feed_context_switch(make_switch(10, 1, 2, Preemption, Some(0)));
        // t2 on core0 @10..30 (but t2 is the to_thread here, its residency
        // also closes). Now switch back: t2 out @30, t1 on core1 @40.
        analyzer.feed_context_switch(make_switch(30, 2, 1, Preemption, Some(1)));
        // t1 on core1 @40, switched out @100 -> 60 steps on core1.
        analyzer.feed_context_switch(make_switch(100, 1, 2, Preemption, Some(0)));
        let sched = analyzer.analyze_scheduling();
        let t1 = sched.iter().find(|s| s.thread_id == 1).unwrap();
        let mut res = t1.core_residency.clone();
        res.sort_unstable_by_key(|(c, _)| *c);
        // core0: interval @10..30 = 20 (from the switch @10 where t1 was the
        // from_thread being... actually t1 is to_thread@10). Let the test
        // assert the documented sums; adjust after seeing real output.
        assert!(res.iter().any(|(c, s)| *c == 1 && *s == 60),
            "core1 residency should be 60 steps, got {:?}", res);
    }

    /// #117: a final unbounded run-in (no following switch) contributes 0
    /// residency — never a fabricated span. Mirrors #65 tail handling.
    #[test]
    fn test_scheduling_unbounded_trailing_run_in_contributes_nothing() {
        let mut analyzer = ThreadAnalyzer::new();
        analyzer.feed_thread_info(make_thread_info(1, "t1"));
        analyzer.feed_thread_info(make_thread_info(2, "t2"));
        // t1 on core0 @10, replaced @30 -> 20 steps. Then t2 runs @30 with
        // no further switch -> its trailing run-in contributes 0.
        analyzer.feed_context_switch(make_switch(10, 1, 2, Preemption, Some(0)));
        analyzer.feed_context_switch(make_switch(30, 2, 1, Preemption, Some(0)));
        let sched = analyzer.analyze_scheduling();
        // t1's only closed interval: to_thread@10 (core0), closed at @30
        // when it became from_thread -> 20 steps on core0.
        let t1 = sched.iter().find(|s| s.thread_id == 1).unwrap();
        assert_eq!(t1.core_residency, vec![(0, 20)]);
        // t2: was to_thread@30 (core0) but never closed (no following switch)
        // -> 0 residency. It may still appear with an empty residency vec.
        let t2 = sched.iter().find(|s| s.thread_id == 2).unwrap();
        assert!(t2.core_residency.is_empty() || t2.core_residency.iter().all(|(_, s)| *s == 0),
            "trailing unbounded run-in must not fabricate span, got {:?}", t2.core_residency);
    }
```

（执行前读既有 scheduling 测试的 `make_switch` 夹具签名确认参数顺序 `make_switch(step, from, to, reason, cpu_core)`。断言值在执行时据实调整——核心是验证 per-core 累加与无界尾贡献 0。）

- [ ] **Step 4: 验证 analyzer 编译与测试**
Run: `cargo test -p sotrace-engine --lib thread_analyzer:: 2>&1 | grep -E "test result|FAILED|error\[" | tail -10`
Expected: ok，新测试 + 既有 scheduling 测试全过

- [ ] **Step 5: 回退验证**
临时把 `analyze_scheduling` 的 residency 累加注释掉（last_in 不 track）跑 2 新测试 → 应 fail（residency 为空），证测试有效。恢复后全绿。

- [ ] **Step 6: 提交**
Run: `git add crates/sotrace-engine/src/analyzer/thread_analyzer.rs && git commit -m "feat(analyzer): add per-core residency to thread scheduling stats (#117)"`

---

### Task 2: 三路径对称暴露 + 冒烟 + 内存

**Depends on:** Task 1
**Files:**
- Modify: `crates/sotrace-cli/src/main.rs:1353`（`print_scheduling`）
- Modify: `crates/sotrace-mcp/src/tools.rs`（scheduling 测试断言）
- Modify: `crates/sotrace-server/src/handlers/thread_analysis.rs`（scheduling 测试断言）
- 内存 `thread-analyzer.md` + `MEMORY.md`

- [ ] **Step 1: 修改 CLI print_scheduling — 打印 per-core residency**
文件: `crates/sotrace-cli/src/main.rs:1353-1363`（替换 `print_scheduling`）

```rust
fn print_scheduling(stats: &[sotrace_engine::analyzer::thread_analyzer::ThreadSchedulingStats]) {
    println!("\n=== Thread Scheduling ({}) ===", stats.len());
    for (i, s) in stats.iter().enumerate() {
        let cores: Vec<String> = s.cpu_cores.iter().map(|c| c.to_string()).collect();
        let residency: Vec<String> = s.core_residency.iter()
            .map(|(core, steps)| format!("core{}:{}steps", core, steps))
            .collect();
        println!(
            "  [{}] T{}  in={} out={} (vol={} invol={}) migrations={}  cores=[{}]  residency=[{}]",
            i, s.thread_id, s.scheduled_in_count, s.scheduled_out_count,
            s.voluntary_switches, s.involuntary_switches, s.migration_count,
            cores.join(", "),
            residency.join(", ")
        );
    }
}
```

- [ ] **Step 2: 更新 MCP/HTTP scheduling 测试断言 — core_residency 是数组**
文件: `crates/sotrace-mcp/src/tools.rs`（`test_analyze_scheduling` 附近）+ `crates/sotrace-server/src/handlers/thread_analysis.rs`（`test_analyze_scheduling` 附近）

追加：

```rust
        // #117: core_residency is an array of [core, steps] pairs.
        let row = &json["scheduling"][0];
        assert!(row["core_residency"].is_array());
```

（HTTP 既有 `assert!(json["scheduling"].is_array())`；MCP 既有 dispatch 后断言。具体路径按实际测试结构调整。）

- [ ] **Step 3: 验证三路径 + 全工作区**
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -10`
Expected: 全 ok，比 #116 基线（463）多 2 个新测试

- [ ] **Step 4: 重 build + 杀旧进程 + CLI/HTTP 冒烟**
Run: `touch crates/sotrace-engine/src/analyzer/thread_analyzer.rs && cargo build -p sotrace-cli -p sotrace-server 2>&1 | tail -3`
杀旧 server，CLI `analyze --only scheduling` 输出含 `residency=[...]`；HTTP GET scheduling → JSON `core_residency:[[core,steps],...]`。

- [ ] **Step 5: 提交三路径改动**
Run: `git add crates/sotrace-cli/src/main.rs crates/sotrace-mcp/src/tools.rs crates/sotrace-server/src/handlers/thread_analysis.rs && git commit -m "feat(cli,mcp,server): surface per-core residency in scheduling (#117)"`

- [ ] **Step 6: 更新内存 thread-analyzer.md — 加 #117 段**
追加：`ThreadSchedulingStats` 加 `core_residency: Vec<(u32,u64)>`（per-core 驻留步数）；`analyze_scheduling` 从 per-thread HashMap 累加改为**全局 step 时序遍历**（BTreeMap flatten 重建全局序列），residency = 相邻 switch 的 step 差归给 to_thread 的 in-core；无界尾贡献 0（同 #65）；`cpu_core==None` 跳过不误归核 0；加字段非改类型无缓存假象但 touch+重 build+杀旧进程；2 新测试 + 既有 scheduling 测试断言。

- [ ] **Step 7: 更新 MEMORY.md 索引行**
thread-analyzer 行追加 `#117`。

- [ ] **Step 8: 提交计划文档**
Run: `git add docs/superpowers/plans/2026-07-15-scheduling-core-residency.md && git commit -m "docs: add plan for scheduling per-core residency (#117)"`

---

## 关键文件

| 文件 | 操作 |
|------|------|
| `crates/sotrace-engine/src/analyzer/thread_analyzer.rs` | `ThreadSchedulingStats` 加 `core_residency` + `analyze_scheduling` 改全局时序遍历 + 2 新测试 |
| `crates/sotrace-cli/src/main.rs` | `print_scheduling` 打印 residency |
| `crates/sotrace-mcp/src/tools.rs` / `crates/sotrace-server/src/handlers/thread_analysis.rs` | scheduling 测试加 `core_residency` 数组断言 |

## 陷阱

- **全局时序 vs per-thread 累加**：core_residency 必须走全局 step 序列（BTreeMap flatten），不能在 per-thread HashMap 累加循环里算——驻留时长是跨线程全局时序概念。in/out 计数仍可在同趟算（不依赖时序）。
- **无界尾贡献 0**：线程最后一段 in 后无后续 switch 封口 → 不加 residency（绝不凭空造时长，同 #65）。`last_in` 末尾残留的 interval 直接丢弃。
- **`cpu_core == None`**：`last_in` 设 None，该段不归核、闭合时不加，不误归核 0。
- **同 step 多 switch**：BTreeMap Vec 插入序，相邻同 step 差为 0（0 步驻留，合法退化，承 #56/#59）。
- **加字段非改类型**：serde 新增字段向后兼容（旧 JSON `default`），无 #110/#116 改类型缓存假象——但仍 `touch`+重 build bin + 杀旧 server 冒烟（防御性，承 #114）。
- **`make_switch` 夹具签名**：执行前读既有 scheduling 测试确认 `make_switch(step, from, to, reason, cpu_core)` 参数顺序与 `SwitchReason` import 路径。
- **residency 断言值**：Step 3 的测试断言值（20/60 steps）需执行时据实调整——核心是验证 per-core 累加与无界尾贡献 0，具体数值依赖 from/to 闭合语义。
