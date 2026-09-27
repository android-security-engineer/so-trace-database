# Trace Storm Mock SO

该 fixture 生成可重复、高密度的 instruction trace JSONL 输入，用于验证 SO Trace Database 的导入、地址/线程索引、查询、持久化和吞吐路径。支持 Frida Stalker 和 Unidbg 两种输出 schema，共用同一个确定性指令生成核心，便于对两条 adapter 路径做对等的功能与性能验证。

它包含一个真实可加载的 C 共享库 `libtrace_storm.so`，以及调用该库并流式写出 trace 的 `mock-trace-capture`。每轮固定产生 32 条逻辑指令事件；PC 是稳定的 SO 相对 mock offset（`0x1000` 至 `0x107c`），线程 ID 按轮在配置的线程集合中轮转，分支事件也保持确定性。

## 构建与生成

```bash
make -C fixtures/trace-storm
./fixtures/trace-storm/build/mock-trace-capture /tmp/trace-storm.jsonl 10 2
```

上例生成 320 条 instruction JSONL 记录（默认 Frida Stalker schema）。第三个参数是
线程数，省略时默认为 2；每轮按 `1000..1000+THREADS-1` 轮转线程 ID。导入 Frida
adapter 后，每个首次出现的线程还会生成一个 Thread announcement；因此 10 轮、2 线程
的输入会持久化为 322 个规范化事件。生成一百万条 instruction 记录使用 31,250 轮：

```bash
./fixtures/trace-storm/build/mock-trace-capture /tmp/trace-storm-1m.jsonl 31250
```

第四个可选参数选择输出 schema，取值为 `frida`（默认）或 `unidbg`：

```bash
./fixtures/trace-storm/build/mock-trace-capture /tmp/trace-storm-unidbg.jsonl 10 2 unidbg
```

两种 schema 携带的信息等价（seq/tid/地址/分支标记），差异仅在字段命名和事件
`type` 取值，用于分别驱动 Frida adapter 和 Unidbg adapter 的 `parse()`/
`parse_reader()` 路径。

## 端到端自检

`verify` 会在临时目录中构建 fixture、生成 trace、通过 `trace-save` 写入
数据库，并从持久化 trace 重放地址和线程查询，以及生命周期分析。它会验证每轮的
32 条指令、`0x1000` 地址索引的命中数、配置的线程集合，以及分析器从指令流
推导出的对应线程生命周期；临时数据会自动删除。

```bash
make -C fixtures/trace-storm verify          # 默认 10 轮（320 条指令），Frida schema
make -C fixtures/trace-storm verify ROUNDS=31250  # 100 万条指令
make -C fixtures/trace-storm verify ROUNDS=100 THREADS=8  # 8 线程索引验证
make -C fixtures/trace-storm verify FORMAT=unidbg  # 同样的检查跑一遍 Unidbg schema
```

性能测量

`bench` 会在临时目录中执行同一条完整链路，并输出可重现的指标：生成和导入耗时、
JSONL 与压缩 blob 大小、压缩比、持久化事件数、replay 查询耗时、生命周期分析耗时，
以及 instruction/event 吞吐。默认规模是一百万条 instruction；快速试跑可以指定较小
的轮数：

```bash
make -C fixtures/trace-storm bench                  # 默认 31,250 轮，Frida schema
make -C fixtures/trace-storm bench ROUNDS=3125      # 100,000 条指令
make -C fixtures/trace-storm bench ROUNDS=3125 THREADS=8
make -C fixtures/trace-storm bench ROUNDS=3125 FORMAT=unidbg  # 对比 Unidbg adapter 路径
SOTRACE_BIN=target/release/sotrace \
  make -C fixtures/trace-storm bench ROUNDS=31250
```

benchmark 的时间用于同一环境内的版本对比，不代表 Android 设备上的真实采集成本。

默认使用仓库中的 `target/debug/sotrace`；若尚未构建，脚本会自动构建。可以通过
`SOTRACE_BIN=/path/to/sotrace` 指向特定版本的 CLI，例如 release 二进制，以便在
同一套确定性数据上做性能对比。

输出是裸 event JSONL，可直接导入。Frida schema 用 `--format frida-stalker`，
Unidbg schema（第四个参数传 `unidbg` 生成）用 `--format unidbg`：

```bash
cargo run -p sotrace-cli -- --data-dir /tmp/sotrace-trace-storm \
  trace-save /tmp/trace-storm.jsonl \
  --format frida-stalker \
  --so fixtures/trace-storm/build/libtrace_storm.so

cargo run -p sotrace-cli -- --data-dir /tmp/sotrace-trace-storm trace-list
cargo run -p sotrace-cli -- --data-dir /tmp/sotrace-trace-storm \
  query --trace-id 1 instruction 0
```

实际使用时请将 `1` 替换为 `trace-save` 输出的 trace ID。

请将全局 `--data-dir` 放在命令名前。构建产物位于 `build/`，已被 Git 忽略。

## 边界

这是确定性的逻辑 instruction trace Mock，不会替代 Android 设备上的真实 CPU 指令采集。真实采集仍应通过 Frida、Pin、DynamoRIO 等工具及其 adapter 完成；本 fixture 的作用是提供轻量、可规模化、无需设备的回归与性能输入。
