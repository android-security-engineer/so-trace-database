# SO Trace Database — 接入指南

本文档整理了 sotrace-database 对接各主流 Android trace 工具的方式。
每个工具提供一个「推送侧插件」：运行在 trace 工具内部，自动将采集到的数据发送给 sotrace-server。

---

## 快速对比

| 工具 | 插件目录 | 接入方式 | 最低要求 |
|---|---|---|---|
| [unidbg](#unidbg) | `plugins/sotrace-unidbg/` | Maven JAR | Java 11, unidbg ≥ 0.9.7 |
| [Frida](#frida) | `plugins/sotrace-frida/` | Python 脚本 + JS Agent | Python 3.8+, Frida ≥ 16 |
| [Qiling](#qiling) | `plugins/sotrace-qiling/` | Python 包 | Python 3.8+, Qiling ≥ 1.4 |
| [GDB](#gdb) | `plugins/sotrace-gdb/` | GDB Python 脚本 | GDB 9+, Python 3.6+ |
| [QEMU](#qemu) | `plugins/sotrace-qemu/` | Python 脚本 (qemu-user) | Python 3.8+, qemu-user |
| [angr](#angr) | `plugins/sotrace-angr/` | Python 包 | Python 3.8+, angr ≥ 9.2 |
| [LLDB](#lldb) | `plugins/sotrace-lldb/` | LLDB Python 脚本 | LLDB 12+, Python 3.6+ |
| [radare2](#radare2) | `plugins/sotrace-r2/` | Python 脚本 (r2pipe) | Python 3.8+, r2 ≥ 5.0 |
| [Triton](#triton) | `plugins/sotrace-triton/` | Python 包 | Python 3.8+, Triton |
| [DynamoRIO](#dynamorio) | `plugins/sotrace-dynamorio/` | C 客户端 + Python 封装 | DynamoRIO SDK, cmake |
| [Intel Pin](#intel-pin) | `plugins/sotrace-pin/` | C++ Pintool + Python 封装 | Intel Pin SDK, g++ |
| [Binary Ninja](#binary-ninja) | `plugins/sotrace-binja/` | Binary Ninja Python 插件 | Binary Ninja ≥ 3.0 |
| [Ghidra](#ghidra) | `plugins/sotrace-ghidra/` | Java/Python GhidraScript + PyGhidra | Ghidra ≥ 10.0, Java 17 |
| [Valgrind](#valgrind) | `plugins/sotrace-valgrind/` | Python 脚本 (lackey/callgrind) | Python 3.8+, Valgrind ≥ 3.19 |
| [IDA Pro](#ida-pro) | `plugins/sotrace-ida/` | IDAPython 插件 + 无头模式 | IDA Pro 7.x/8.x, Python 3.8+ |
| [JADX](#jadx) | `plugins/sotrace-jadx/` | Python 脚本 (APK JNI 边界) | Python 3.8+, jadx CLI |
| [strace](#strace) | `plugins/sotrace-strace/` | Python 脚本 (系统调用解析) | Python 3.8+, strace |
| [ltrace](#ltrace) | `plugins/sotrace-ltrace/` | Python 脚本 (库函数调用解析) | Python 3.8+, ltrace |
| [ThreadSanitizer (TSan)](#threadsanitizer-tsan) | `plugins/sotrace-tsan/` | Python 脚本 (TSan 报告解析) | Python 3.8+, TSan (LLVM/NDK) |
| [perf/simpleperf](#perfsimpleperf) | `plugins/sotrace-perf/` | Python 脚本 (call graph 解析) | Python 3.8+, perf 或 simpleperf |
| [objdump](#objdump) | `plugins/sotrace-objdump/` | Python 脚本 (静态反汇编) | Python 3.8+, GNU binutils |
| [apktool](#apktool) | `plugins/sotrace-apktool/` | Python 脚本 (APK/smali 分析) | Python 3.8+, apktool |
| [Capstone](#capstone) | `plugins/sotrace-capstone/` | Python 包 (静态反汇编) | Python 3.8+, capstone + pyelftools |
| [dexdump](#dexdump) | `plugins/sotrace-dexdump/` | Python 脚本 (DEX 字节码分析) | Python 3.8+, Android SDK dexdump |

> **parse adapter only**：Rust 端已有解析适配器（`crates/sotrace-core/src/adapters/`），但尚无对应的推送侧插件；欢迎贡献。

---

## sotrace-server 接口速查

```
POST /api/v1/traces/import          # 导入 trace 数据（返回 trace_id）
GET  /api/v1/traces/:id/analyze/threads/races
GET  /api/v1/traces/:id/analyze/threads/deadlocks
GET  /api/v1/traces/:id/analyze/threads/contentions
GET  /api/v1/traces/:id/analyze/threads/critical-sections
GET  /api/v1/traces/:id/analyze/threads/jni-boundary
GET  /api/v1/traces/:id/analyze/threads/scheduling
GET  /api/v1/traces/:id/analyze/threads/lifecycle
GET  /api/v1/traces/:id/analyze/threads/states
POST /api/v1/traces/:id/analyze/threads   # 全量分析（12 维度）
```

---

## unidbg

插件目录：`plugins/sotrace-unidbg/`

### 安装

```bash
cd plugins/sotrace-unidbg
mvn install   # 安装到本地 Maven 仓库
```

在用户项目的 `pom.xml` 中添加：

```xml
<dependency>
    <groupId>io.sotrace</groupId>
    <artifactId>sotrace-unidbg</artifactId>
    <version>0.1.0</version>
</dependency>
```

### 快速接入（两行）

```java
import io.sotrace.unidbg.SoTracePlugin;

SoTracePlugin plugin = SoTracePlugin.attach(emulator, "http://192.168.1.83:3000");

// ... 运行模拟 ...

long traceId = plugin.flush();   // 上传数据，返回 trace_id
plugin.detach();
```

### Builder 模式（精细控制）

```java
SoTracePlugin plugin = SoTracePlugin.builder()
    .serverUrl("http://192.168.1.83:3000")
    .soBase(0x40000000L)          // SO 加载基址（用于偏移量计算）
    .enableSync(true)             // pthread 同步事件（默认 true）
    .enableMemory(true)           // 内存写入（默认 true）
    .enableCalls(true)            // 调用栈（默认 true）
    .build();
plugin.attach(emulator);
```

### 注入到 unidbg McpServer

若用户已启动 unidbg 内置 McpServer，sotrace 分析工具会自动注册：

```java
import io.sotrace.unidbg.mcp.McpToolBridge;

McpToolBridge.install(emulator, plugin::getTraceId, plugin.getClient());
// → 注册 sotrace_analyze_races / sotrace_detect_deadlocks 等 5 个工具
```

---

## Frida

插件目录：`plugins/sotrace-frida/`

### 安装

```bash
pip install -r plugins/sotrace-frida/requirements.txt
# frida>=16.0.0  requests>=2.31.0
```

### 快速接入

```bash
# Spawn 并实时上传
python sotrace-frida.py -U -f com.example.app \
    --server http://192.168.1.83:3000 \
    --so-name libtarget.so

# Attach 到运行中进程
python sotrace-frida.py -U com.example.app \
    --server http://192.168.1.83:3000

# 保存到文件（离线分析）
python sotrace-frida.py -U -f com.example.app \
    --output trace.jsonl
```

### 常用选项

| 选项 | 说明 |
|---|---|
| `-U` / `-R` / `-D <id>` | USB / 远程 / 指定设备 |
| `-f <app>` | Spawn 模式 |
| `--server <url>` | sotrace-server 地址 |
| `--output <file>` | 保存到 JSONL 文件 |
| `--so-base <hex>` | SO 基址（手动） |
| `--so-name <name>` | SO 名称（自动解析基址） |
| `--enable-instructions` | 指令级 tracing（高开销） |
| `--no-sync` | 关闭 pthread 同步 hook |
| `--no-calls` | 关闭调用栈 hook |

### Agent 脚本直接使用

```js
// 在自己的 Frida 脚本中引入
const agent = require('./sotrace-agent.js');   // 或直接 load

// 通过 rpc.exports 配置
script.exports.configure({
    soBase: 0x71000000,
    enableInstructions: false,
    enableSync: true,
});
```

---

## Qiling

插件目录：`plugins/sotrace-qiling/`

### 安装

```bash
pip install plugins/sotrace-qiling/
# 或开发模式：pip install -e plugins/sotrace-qiling/
```

### 快速接入

```python
from qiling import Qiling
from sotrace_qiling import SoTracePlugin

ql = Qiling(["./target_binary"], rootfs="./rootfs")

plugin = SoTracePlugin(
    ql,
    server_url="http://192.168.1.83:3000",
    so_name="libtarget.so",        # 自动解析基址
)
plugin.attach()

ql.run()

trace_id = plugin.flush()          # 上传并获取 trace_id
plugin.detach()
print(f"trace_id={trace_id}")
```

### Builder 模式

```python
plugin = (
    SoTracePlugin.builder(ql)
    .server_url("http://192.168.1.83:3000")
    .so_base(0x555555400000)
    .enable_memory(True)
    .enable_sync(True)
    .enable_calls(True)
    .batch_size(500)
    .build()
)
```

### Context Manager

```python
with SoTracePlugin(ql, server_url="http://...") as plugin:
    ql.run()
# 退出时自动 flush + detach
```

---

## angr

插件目录：`plugins/sotrace-angr/`

angr 是 Python 符号执行框架，支持 ARM64/ARM32/x86_64 等架构，适合对 SO 进行路径探索和漏洞分析。
sotrace-angr 采集 angr `inspect` 断点产生的指令/内存/调用事件。

### 安装

```bash
pip install plugins/sotrace-angr/
# 含 angr：pip install 'plugins/sotrace-angr/[angr]'
```

### 快速接入

```python
import angr
from sotrace_angr import SoTracePlugin

proj = angr.Project("libfoo.so", load_options={'auto_load_libs': False})
base = proj.loader.main_object.min_addr

state = proj.factory.blank_state(addr=base + 0x1234)

plugin = SoTracePlugin(proj, server_url="http://192.168.1.83:3000")
plugin.attach(state)    # 在 state 上注册 inspect 断点（自动传播到派生 state）

simgr = proj.factory.simgr(state)
simgr.run(n=1000)

trace_id = plugin.flush()
result = plugin.analyze("deadlocks")
```

### 符号执行路径探索

```python
# 让 angr 探索所有路径，找到目标地址
state.regs.x0 = state.solver.BVS('arg0', 64)   # 符号化输入
simgr.explore(find=base + 0x5678)

if simgr.found:
    trace_id = plugin.flush()
    print(plugin.analyze("races"))
```

### 保存到文件

```python
plugin = SoTracePlugin(proj, output_file="trace.jsonl")
plugin.attach(state)
simgr.run(n=500)
plugin.save("trace.jsonl")
# 离线导入：sotrace-cli trace-import --file trace.jsonl
```

### 常用选项

| 参数 | 说明 |
|---|---|
| `server_url` | sotrace-server 地址 |
| `max_events` | 自动 flush 阈值（防止内存爆增，默认 50000） |
| `output_file` | JSONL 输出路径（与 server_url 可同时使用） |

> **注意**：符号执行会产生大量路径分叉，`max_events` 建议根据内存情况调整。

---

## GDB

插件目录：`plugins/sotrace-gdb/`

适用场景：通过 `gdbserver` 调试 Android 进程，或本地调试 ARM 二进制（qemu-user + gdbstub）。

### 加载插件

```bash
# 在 GDB 会话中
(gdb) source /path/to/plugins/sotrace-gdb/sotrace-gdb.py
```

### 快速使用

```bash
# 上报到 sotrace-server
(gdb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo.so --steps 5000

# 保存到文件（后续用 CLI 导入）
(gdb) sotrace-trace --output /tmp/trace.jsonl --so libfoo.so --steps 5000
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `--server URL` | sotrace-server 地址 |
| `--output FILE` | 保存 JSONL 文件路径 |
| `--so NAME` | 目标 SO 名（用于自动定位基址） |
| `--steps N` | 最多采集步数（默认 10000） |

### 典型工作流（Android gdbserver）

```bash
# 设备侧
$ adb shell gdbserver :5039 --attach $(pidof com.example.app)

# 宿主侧
$ aarch64-linux-gnu-gdb /path/to/libfoo.so
(gdb) target remote :5039
(gdb) source plugins/sotrace-gdb/sotrace-gdb.py
(gdb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo.so --steps 2000
```

---

## QEMU

插件目录：`plugins/sotrace-qemu/`

使用 `qemu-user` 在宿主机上直接运行 ARM/AArch64 SO 测试程序，自动解析 `qemu -d in_asm` 输出并上报。

### 快速使用

```bash
# 上报到 server
python plugins/sotrace-qemu/sotrace-qemu.py \
    --server http://192.168.1.83:3000 \
    --so libfoo.so --arch aarch64 \
    -- ./libfoo_harness

# 保存到文件
python plugins/sotrace-qemu/sotrace-qemu.py \
    --output trace.jsonl --so libfoo.so \
    -- ./libfoo_harness

# 动态执行序列（需要 exec 日志）
python plugins/sotrace-qemu/sotrace-qemu.py \
    --dynamic --server http://192.168.1.83:3000 --so libfoo.so \
    -- ./libfoo_harness
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `--server URL` | sotrace-server 地址 |
| `--output FILE` | 保存 JSONL 文件路径 |
| `--so NAME` | SO 名（用于地址范围过滤） |
| `--arch ARCH` | `aarch64`/`arm`/`x86_64`/`x86`（默认 aarch64） |
| `--qemu PATH` | 指定 qemu-user 路径（默认自动查找） |
| `--dynamic` | 同时捕获 `-d exec`，还原动态执行顺序 |
| `--keep-log` | 保留原始 QEMU log 文件供调试 |

---

## Triton

插件目录：`plugins/sotrace-triton/`

[Triton](https://github.com/JonathanSalwan/Triton) 是 C++/Python 动态二进制分析框架，专注于污点分析与符号执行，支持 AArch64/ARM32/x86/x86_64。与 angr 的主要区别在于 Triton 直接操作真实机器码（无 IR 抽象层），适合 crackme、反混淆、密钥恢复等场景。

### 安装

```bash
pip install triton          # 或从源码编译
pip install lief pyelftools  # ELF 加载（二选一即可）
pip install -e plugins/sotrace-triton/
```

### 快速接入（具体执行）

```python
from sotrace_triton import SoTracePlugin

plugin = SoTracePlugin(
    arch="aarch64",
    server_url="http://192.168.1.83:3000",
    so_path="libfoo.so",
    entry_offset=0x1000,   # 函数入口相对 SO 基址的偏移
    max_steps=5000,
)

# 设置寄存器/内存初始状态
plugin.ctx.setConcreteRegisterValue(plugin.ctx.registers.x0, 0x42)

plugin.run()
trace_id = plugin.flush()
print(f"trace_id={trace_id}")
print(plugin.analyze("races"))
```

### 污点分析

```python
from triton import MemoryAccess, CPUSIZE

# 标记输入缓冲区为污点
INPUT_ADDR = 0x200000
plugin.ctx.setConcreteMemoryAreaValue(INPUT_ADDR, b"secret\x00")
for i in range(6):
    plugin.ctx.taintMemory(MemoryAccess(INPUT_ADDR + i, CPUSIZE.BYTE))

plugin.run()
```

### 符号执行（路径探索）

```python
# 符号化输入，让 Triton 推断哪些输入值使代码走不同分支
plugin.ctx.symbolizeMemory(MemoryAccess(INPUT_ADDR, CPUSIZE.DWORD), "key")
plugin.run()

# 获取路径约束，求解满足条件的输入
constraints = plugin.ctx.getPathConstraints()
```

### 参数说明

| 参数 | 默认值 | 说明 |
|---|---|---|
| `arch` | `"aarch64"` | 目标架构 |
| `server_url` | `None` | sotrace-server URL |
| `so_path` | `None` | SO 文件路径（自动加载） |
| `entry_offset` | `0` | 入口偏移（相对 so_base） |
| `so_base` | `0x400000` | SO 加载基址 |
| `max_steps` | `10000` | 最大执行步数 |
| `output_file` | `None` | JSONL 输出路径 |

---

## LLDB

插件目录：`plugins/sotrace-lldb/`

适用场景：macOS/iOS 开发环境，或使用 Android NDK 提供的 `lldb-server` 远程调试 Android 进程。

### 加载插件

```bash
# 在 LLDB 会话中
(lldb) command script import /path/to/plugins/sotrace-lldb/sotrace-lldb.py
```

### 快速使用

```bash
# 上报到 sotrace-server
(lldb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo.so --steps 5000

# 保存到文件（后续用 CLI 导入）
(lldb) sotrace-trace --output /tmp/trace.jsonl --so libfoo.so --steps 5000
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `--server URL` | sotrace-server 地址 |
| `--output FILE` | 保存 JSONL 文件路径 |
| `--so NAME` | 目标 SO 名（用于自动定位基址） |
| `--steps N` | 最多采集步数（默认 10000） |
| `--thread TID` | 只追踪指定线程 ID |

### 典型工作流（Android lldb-server）

```bash
# 设备侧（NDK lldb-server）
$ adb shell /data/local/tmp/lldb-server platform --listen "*:1234" --server

# 宿主侧
$ lldb
(lldb) platform select remote-android
(lldb) platform connect connect://localhost:1234
(lldb) attach --pid $(adb shell pidof com.example.app)
(lldb) command script import plugins/sotrace-lldb/sotrace-lldb.py
(lldb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo.so --steps 2000
```

---

## radare2

插件目录：`plugins/sotrace-r2/`

支持**静态分析**（无需运行，分析所有函数）和**动态调试**（attach 进程步进采集）两种模式。

### 快速使用

```bash
# 静态分析模式（离线，无需 root）
python plugins/sotrace-r2/sotrace-r2.py \
    --mode static --server http://192.168.1.83:3000 libfoo.so

# 动态调试模式（attach 到进程）
python plugins/sotrace-r2/sotrace-r2.py \
    --mode dynamic --pid 1234 --steps 5000 \
    --server http://192.168.1.83:3000

# 保存到文件
python plugins/sotrace-r2/sotrace-r2.py \
    --mode static --output trace.jsonl libfoo.so
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `--mode static\|dynamic` | 分析模式（默认 static） |
| `--server URL` | sotrace-server 地址 |
| `--output FILE` | 保存 JSONL 文件路径 |
| `--pid PID` | 动态模式：attach 到指定进程 |
| `--steps N` | 动态模式：最多步数（默认 5000） |

### 在 r2 会话内使用

```python
# r2 内部 Python（!python3 -c "..."）
import r2pipe
from sotrace_r2 import R2Tracer, SoTraceClient, EventBatcher

r2 = r2pipe.open()            # 复用当前 r2 会话
tracer = R2Tracer(r2, so_base=0)
instructions, calls = tracer.trace_static()
```

---

## 分析结果示例

导入后，调用分析 API 或使用 sotrace-cli：

```bash
# 竞态检测
sotrace-cli analyze --trace-id 42 --dimension races

# 死锁分析
sotrace-cli analyze --trace-id 42 --dimension deadlocks

# 全量分析（12 维度）
curl -X POST http://localhost:3000/api/v1/traces/42/analyze/threads
```

---

## DynamoRIO

插件目录：`plugins/sotrace-dynamorio/`

DynamoRIO C 客户端 + Python 封装。编译为 `.so`，通过 `drrun -c` 加载，输出 JSONL 后自动上报。

### 构建

```bash
cd plugins/sotrace-dynamorio
cmake -B build -DDynamoRIO_DIR=/path/to/DynamoRIO/cmake
cmake --build build
# 可选：启用内存 trace（性能开销高）
cmake -B build -DDynamoRIO_DIR=... -DSOTRACE_ENABLE_MEMORY=ON
```

### 快速使用

```bash
# 运行并上报
python sotrace-dynamorio.py run \
    --dynamorio-dir /path/to/DynamoRIO \
    --client build/libsotrace_client.so \
    --server http://192.168.1.83:3000 \
    --so libfoo.so \
    -- ./target_binary

# 保存到文件
python sotrace-dynamorio.py run \
    --client build/libsotrace_client.so \
    --output trace.jsonl --so libfoo.so \
    -- ./target_binary

# 保留原始 JSONL 日志
python sotrace-dynamorio.py run ... --keep-log
```

---

## Intel Pin

插件目录：`plugins/sotrace-pin/`

C++ Pintool + Python 封装。支持多线程程序（mutex 序列化输出），内存 trace 默认关闭。

### 构建

```bash
cd plugins/sotrace-pin
make PIN_ROOT=/path/to/pin
```

### 快速使用

```bash
# 运行并上报
python sotrace-pin.py run \
    --pin-root /path/to/pin \
    --pintool libsotrace_pintool.so \
    --server http://192.168.1.83:3000 \
    --so libfoo.so \
    -- ./target_binary

# 启用内存 trace
python sotrace-pin.py run ... --enable-memory

# 保存到文件
python sotrace-pin.py run ... --output trace.jsonl -- ./target_binary
```

---

## Binary Ninja

插件目录：`plugins/sotrace-binja/`

Binary Ninja Python 插件，支持 UI 和 headless 两种模式。通过 LLIL 采集指令，通过 MLIL 采集调用图。

### 安装（UI 模式）

```bash
# 将插件目录复制到 Binja 插件目录
cp -r plugins/sotrace-binja ~/.binaryninja/plugins/sotrace-binja
# 重启 Binary Ninja，插件自动加载
```

### UI 使用

Binary Ninja 加载 SO 后，在 **Plugins → sotrace** 菜单中：
- **Upload All Functions** — 分析所有函数并上报（弹窗输入 server URL）
- **Upload This Function** — 右键函数 → 只分析当前函数
- **Save Trace to File** — 保存 JSONL 文件供 CLI 导入

### Headless 模式

```python
import binaryninja as bn
from sotrace_binja.analyzer import SoTraceAnalyzer
from sotrace_binja.client import SoTraceClient

bv = bn.load("libcrackme.so")
bv.update_analysis_and_wait()

analyzer = SoTraceAnalyzer(bv)
envelope = analyzer.analyze_static()

client = SoTraceClient("http://192.168.1.83:3000")
trace_id = client.import_trace(envelope)
print(f"trace_id={trace_id}")
```

---

## Ghidra

插件目录：`plugins/sotrace-ghidra/`

Ghidra 静态分析插件，支持三种接入方式：
- **Java GhidraScript**（推荐）：Script Manager 运行，无外部依赖
- **Python GhidraScript**（Jython 2.7）：Script Manager 备选，兼容 Ghidra 自带 Jython
- **PyGhidra 无头模式**：Python 3 + Jpype，适合 CI / 批量分析

### Java Script Manager 模式（推荐）

1. 复制 `SoTraceScript.java` 到 Ghidra 脚本搜索路径：
   ```bash
   cp plugins/sotrace-ghidra/SoTraceScript.java ~/.ghidra/.ghidra_*/scripts/
   ```

2. Ghidra 打开 SO → 等待分析完成

3. **Window → Script Manager** → 搜索 `SoTraceScript` → 双击运行

4. 弹窗输入 sotrace-server URL（如 `http://192.168.1.83:3000`），留空则保存为 JSONL

### Python Script Manager 模式（Jython）

```bash
cp plugins/sotrace-ghidra/sotrace_script.py ~/.ghidra/.ghidra_*/scripts/
# Script Manager 搜索 sotrace_script，双击运行
```

### PyGhidra 无头模式

```bash
pip install pyghidra

python plugins/sotrace-ghidra/sotrace-ghidra.py \
    --ghidra-home /opt/ghidra \
    --server http://192.168.1.83:3000 \
    /path/to/libnative.so
```

输出：
```
[sotrace] Starting Ghidra JVM from /opt/ghidra …
[sotrace] Collected 12345 instructions, 876 calls
[sotrace] trace_id=42
[sotrace] Races: http://192.168.1.83:3000/api/v1/traces/42/analyze/threads/races
```

### 数据说明

Ghidra 为静态分析工具，不产生真实执行轨迹：
- `address` = 函数内指令 VA - `program.getImageBase()`（SO 偏移）
- `is_branch` 由 `FlowType.isBranch() | isCall() | isTerminal()` 推断
- `thread_id` 固定为 1（静态分析无线程概念）
- 适合用 **races/deadlocks** 以外的静态维度分析（`contentions`, `critical-sections`, `jni-boundary`）

---

## Valgrind

插件目录：`plugins/sotrace-valgrind/`

使用 Valgrind **lackey** 工具（指令 + 内存 trace）或 **callgrind** 工具（调用图），解析输出后自动上报 sotrace-server。

> **注意**：Valgrind 仅支持 Linux x86/x86_64；Android ARM SO 建议使用 sotrace-qemu 替代，或搭配 qemu-user 先运行 harness。

### 安装

```bash
sudo apt-get install valgrind    # 或对应发行版包管理器
```

无额外 Python 依赖（使用 stdlib urllib.request）。

### 快速使用

```bash
# lackey 模式 — 指令 + 内存 trace，上报到 server
python plugins/sotrace-valgrind/sotrace-valgrind.py \
    --tool lackey \
    --so libfoo.so \
    --server http://192.168.1.83:3000 \
    -- ./libfoo_harness

# callgrind 模式 — 调用图，开销更低
python plugins/sotrace-valgrind/sotrace-valgrind.py \
    --tool callgrind \
    --server http://192.168.1.83:3000 \
    -- ./libfoo_harness

# 保存到文件（后续用 CLI 导入）
python plugins/sotrace-valgrind/sotrace-valgrind.py \
    --tool lackey \
    --so libfoo.so \
    --output trace.jsonl \
    -- ./libfoo_harness
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `--tool lackey\|callgrind` | Valgrind 工具选择（默认 lackey） |
| `--server URL` | sotrace-server 地址 |
| `--output FILE` | 保存 JSONL 文件路径（与 server 可同时使用） |
| `--so NAME` | SO 名称（用于地址范围过滤） |

### 两种模式对比

| 模式 | 信息量 | 性能开销 | 适合场景 |
|---|---|---|---|
| lackey | 指令序列 + 内存读写地址 | 高（~20×） | 竞态/数据流分析 |
| callgrind | 调用图 + 函数执行次数 | 中（~5×） | function-safety / producer-consumer |

---

## IDA Pro

插件目录：`plugins/sotrace-ida/`

IDAPython 插件，支持 GUI 快捷键上传和 idat64 无头批量分析两种模式。使用 `idaapi`/`idautils` 采集所有函数指令和调用图，通过 stdlib urllib.request 上报，无需额外 pip 依赖。

### 安装

```bash
# 复制到 IDA 用户插件目录
cp -r plugins/sotrace-ida ~/.idapro/plugins/sotrace_ida
# 重启 IDA Pro，看到：[sotrace] loaded — press Ctrl+Shift+T to upload
```

### GUI 使用

1. 打开 SO 文件，等待 Auto Analysis 完成
2. 按 **Ctrl+Shift+T**（或 Edit → Plugins → Upload to sotrace-server）
3. 输入 server URL，留空则弹出文件保存对话框
4. 弹窗显示 `trace_id` 和快捷分析链接

### IDAPython 脚本内使用

```python
import sys
sys.path.insert(0, "/path/to/plugins/sotrace-ida")

from sotrace_ida.analyzer import analyze_static
from sotrace_ida.client import SoTraceClient

envelope = analyze_static()
client = SoTraceClient("http://192.168.1.83:3000")
trace_id = client.import_trace(envelope)
print(f"trace_id={trace_id}")
result = client.get_analysis(trace_id, "contentions")
```

### 无头模式（idat64 批量）

```bash
python plugins/sotrace-ida/examples/headless_analysis.py \
    --idat /opt/ida/idat64 \
    --server http://192.168.1.83:3000 \
    /path/to/libnative.so
```

### 数据说明

IDA 为静态分析工具，不产生真实执行轨迹：
- `address` = 指令 VA - `idaapi.get_imagebase()`（SO 偏移）
- `is_branch` 由 `insn.get_canon_feature() & (CF_CALL|CF_JUMP|CF_STOP)` 推断
- `thread_id` 固定为 1
- 竞态/死锁检测（races/deadlocks）需配合 Frida/GDB/unidbg 的运行时数据

---

## JADX

插件目录：`plugins/sotrace-jadx/`

JADX 是 Android APK/DEX 反编译工具。`sotrace-jadx` 扫描反编译出的 Java 源码，提取 `native` 方法声明和 `System.loadLibrary` 调用，生成 JNI 边界 trace 上报到 sotrace-server。适合在拿到 APK 后快速建立 JNI 接口图谱。

### 安装

```bash
# 需要 jadx CLI 在 PATH 中，或设置 JADX_PATH 环境变量
# 下载 jadx: https://github.com/skylot/jadx/releases
export JADX_PATH=/opt/jadx/bin/jadx   # 可选

# 无额外 Python 依赖（stdlib only）
```

### 快速使用

```bash
# 从 APK 提取 JNI 方法并上报
python plugins/sotrace-jadx/sotrace-jadx.py jadx \
    --apk target.apk \
    --server http://192.168.1.83:3000

# 过滤指定 SO
python plugins/sotrace-jadx/sotrace-jadx.py jadx \
    --apk target.apk \
    --so libnative \
    --server http://192.168.1.83:3000

# 保存为 JSONL
python plugins/sotrace-jadx/sotrace-jadx.py jadx \
    --apk target.apk \
    --output jni_methods.jsonl
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `--apk FILE` | APK / DEX / JAR 文件路径 |
| `--server URL` | sotrace-server 地址 |
| `--output FILE` | 保存 JSONL 路径（与 server 可同时使用） |
| `--so NAME` | 只保留指定 SO 的 native 方法 |
| `-v` | Debug 日志 |

### 工作原理

1. 调用 `jadx --output-dir <tmp>` 反编译 APK
2. 递归扫描所有 `.java` 源文件，提取 `native` 方法声明
3. 关联 `System.loadLibrary("xxx")` 推断每个 native 方法属于哪个 SO
4. 构建 JNI 边界 envelope（`sync_events` 里 `sync_type=JniEnter/JniExit`）并上报

### 典型用途

- 快速了解 APK 有哪些 JNI 接口，作为 Frida hook 点参考
- 搭配 `GET /api/v1/traces/:id/analyze/threads/jni-boundary` 分析 JNI 调用模式
- 在没有设备/运行时的情况下建立静态 JNI 图谱

---

## strace

插件目录：`plugins/sotrace-strace/`

Linux `strace` 系统调用追踪包装器。解析 `futex`/`clone` 等 syscall，提取同步原语和线程创建事件，转换为 sotrace sync_events 上报。

> **Android 说明**：Android 进程需 root + ptrace 权限。建议在 adb shell 或 QEMU/GDB 环境下使用。

### 快速使用

```bash
sudo apt-get install strace

# 运行并追踪 sync 事件
python plugins/sotrace-strace/sotrace-strace.py \
    --run -- ./libfoo_harness arg1 \
    --server http://192.168.1.83:3000

# 解析已有 strace 日志
python plugins/sotrace-strace/sotrace-strace.py \
    --input /tmp/strace.log \
    --server http://192.168.1.83:3000

# 保存为 JSONL
python plugins/sotrace-strace/sotrace-strace.py \
    --run --output trace.jsonl -- ./libfoo_harness
```

---

## ThreadSanitizer (TSan)

插件目录：`plugins/sotrace-tsan/`

解析 LLVM ThreadSanitizer (TSan) 报告，将竞态条件、互斥锁操作序列转换为 sotrace sync_events 上报。TSan 已集成在 Android NDK (clang -fsanitize=thread) 中，是发现 SO 并发 bug 的最直接工具。

### 使用 Android NDK TSan

```bash
# 1. 编译时启用 TSan（CMakeLists.txt）
# target_compile_options(libfoo PRIVATE -fsanitize=thread)
# target_link_options(libfoo PRIVATE -fsanitize=thread)

# 2. adb 运行，捕获 TSan 报告
adb shell TSAN_OPTIONS="log_path=/data/local/tmp/tsan" \
    /data/local/tmp/libfoo_harness

# 3. 拉取并解析报告
adb pull /data/local/tmp/tsan.$(adb shell pgrep libfoo_harness) /tmp/tsan.log
python plugins/sotrace-tsan/sotrace-tsan.py \
    --log /tmp/tsan.log \
    --server http://192.168.1.83:3000

# 4. 从 stdin 实时解析
TSAN_OPTIONS="verbosity=1" ./libfoo_harness 2>&1 | \
    python plugins/sotrace-tsan/sotrace-tsan.py --stdin \
    --server http://192.168.1.83:3000
```

### 分析建议

TSan 报告本身已包含竞态信息，上报到 sotrace 后可以：
- 对比 `GET /analyze/threads/races` 与 TSan 发现的竞态，交叉验证
- 使用 `GET /analyze/threads/contentions` 了解锁争用热点
- 与 Frida/unidbg 运行时 trace 合并（同一 SO，不同 trace_id）

---

## ltrace

插件目录：`plugins/sotrace-ltrace/`

专注于 `ltrace` 库函数调用的独立解析器（比 sotrace-strace 更专注 pthread/dlopen 等库调用语义）。解析 `-e 'pthread_*+dlopen+dlsym'` 过滤后的 ltrace 输出，提取同步原语调用序列。

### 快速使用

```bash
# 运行并追踪
python plugins/sotrace-ltrace/sotrace-ltrace.py --run \
    --server http://192.168.1.83:3000 \
    -- ./libfoo_harness arg1

# 解析已有日志
python plugins/sotrace-ltrace/sotrace-ltrace.py \
    --input trace.log \
    --server http://192.168.1.83:3000

# 保存到文件
python plugins/sotrace-ltrace/sotrace-ltrace.py --run \
    --output trace.jsonl \
    -- ./libfoo_harness
```

---

## APKTool

插件目录：`plugins/sotrace-apktool/`

使用 APKTool 反编译 APK，扫描 `smali` 文件提取 JNI 调用点和 `loadLibrary` 声明，构建 JNI 边界 trace。与 JADX 类似但解析 smali 字节码而非 Java 源码，适合混淆代码分析。

### 快速使用

```bash
# 需要 apktool 在 PATH 中: https://apktool.org/
python plugins/sotrace-apktool/sotrace-apktool.py \
    --apk target.apk \
    --server http://192.168.1.83:3000

# 过滤指定 SO
python plugins/sotrace-apktool/sotrace-apktool.py \
    --apk target.apk \
    --so libnative \
    --server http://192.168.1.83:3000
```

---

## Capstone

插件目录：`plugins/sotrace-capstone/`

基于 [Capstone](http://www.capstone-engine.org/) 反汇编引擎的静态分析插件。支持 ARM64/ARM32/x86_64/MIPS，读取 ELF SO 的 `.text` 段直接反汇编，无需外部工具。适合嵌入式分析脚本和 CI 场景。

### 安装

```bash
pip install capstone
```

### 快速使用

```python
from sotrace_capstone import CapstoneAnalyzer
from sotrace_capstone.client import SoTraceClient

analyzer = CapstoneAnalyzer("libnative.so", arch="arm64")
envelope = analyzer.analyze()

client = SoTraceClient("http://192.168.1.83:3000")
trace_id = client.import_trace(envelope)
print(f"trace_id={trace_id}")
```

```bash
# CLI 方式
python plugins/sotrace-capstone/sotrace-capstone.py \
    --so libnative.so \
    --arch arm64 \
    --server http://192.168.1.83:3000
```

---

## dexdump

插件目录：`plugins/sotrace-dexdump/`

解析 Android SDK `dexdump -d` 的 Dalvik 字节码反汇编输出，提取方法调用图和指令序列，上报到 sotrace-server。适合分析 DEX/APK 中的 Java 代码如何调用 native SO 方法（与 JNI 边界分析配合）。

### 安装

```bash
# dexdump 来自 Android SDK Build-Tools
# $ANDROID_SDK/build-tools/<version>/dexdump
export PATH="$ANDROID_SDK/build-tools/34.0.0:$PATH"
```

### 快速使用

```bash
# 分析 DEX 文件
python plugins/sotrace-dexdump/sotrace-dexdump.py classes.dex \
    --server http://192.168.1.83:3000

# 分析 APK
python plugins/sotrace-dexdump/sotrace-dexdump.py target.apk \
    --server http://192.168.1.83:3000

# 保存到文件
python plugins/sotrace-dexdump/sotrace-dexdump.py classes.dex \
    --output dex_trace.jsonl
```

---

## perf/simpleperf

插件目录：`plugins/sotrace-perf/`

解析 `perf script` 或 `simpleperf report` 输出的调用图（call graph），上报调用链事件到 sotrace-server。Linux 上使用 `perf record -g`，Android 上使用 NDK 的 `simpleperf`，两者输出格式兼容同一 parser。

### 快速使用

```bash
# 直接运行程序并采集（Linux）
python plugins/sotrace-perf/sotrace-perf.py \
    --run -- ./libfoo_harness \
    --server http://192.168.1.83:3000 \
    --so libfoo.so

# 解析已有的 perf.data 文件
python plugins/sotrace-perf/sotrace-perf.py \
    --perf-data perf.data \
    --server http://192.168.1.83:3000

# 解析 perf script 文本文件
python plugins/sotrace-perf/sotrace-perf.py \
    --input perf.script \
    --output trace.jsonl

# Android — 使用 simpleperf（NDK）
adb shell simpleperf record -g -o /data/local/tmp/perf.data ./harness
adb pull /data/local/tmp/perf.data .
simpleperf report-sample --show-callchain -i perf.data -o perf.script
python plugins/sotrace-perf/sotrace-perf.py \
    --input perf.script \
    --server http://192.168.1.83:3000 --so libfoo.so
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `--run` | 自动运行 `perf record -g`，剩余参数传给目标命令 |
| `--perf-data FILE` | 对已有 perf.data 运行 `perf script` |
| `--input FILE` | 直接解析 perf script 文本 |
| `--server URL` | sotrace-server 地址 |
| `--output FILE` | 保存 JSONL |
| `--so NAME` | 只保留属于指定 SO 的帧 |
| `--perf PATH` | 指定 perf 二进制路径 |

### 设计说明

- **so_base 自动推断**：取同一 SO 在所有 sample 中出现的最小虚拟地址作为基址，`frame.offset = VA - so_base`
- **调用链重建**：perf 输出顺序是 top→bottom（最近执行帧在前），mapper 反转为 caller→callee 逐对生成 Call 事件
- **指令去重**：按 `(pid, address)` 去重，避免同地址在多 sample 中重复上传

---

## objdump

插件目录：`plugins/sotrace-objdump/`

使用 GNU binutils `objdump -d` 静态反汇编 SO 文件，解析指令和调用图后上报。比 r2/Capstone 更轻量，适合只安装了 binutils 的 CI 环境。

### 快速使用

```bash
# 安装 ARM64 cross binutils
sudo apt-get install binutils-aarch64-linux-gnu

# 上报到 server
python plugins/sotrace-objdump/sotrace-objdump.py libfoo.so \
    --objdump aarch64-linux-gnu-objdump \
    --server http://192.168.1.83:3000

# 保存到文件
python plugins/sotrace-objdump/sotrace-objdump.py libfoo.so \
    --output trace.jsonl

# 只反汇编 .text section
python plugins/sotrace-objdump/sotrace-objdump.py libfoo.so \
    --section .text --server http://192.168.1.83:3000
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `binary` | SO / ELF 文件路径 |
| `--server URL` | sotrace-server 地址 |
| `--output FILE` | 保存 JSONL |
| `--arch ARCH` | 目标架构（默认从 ELF 自动检测） |
| `--objdump PATH` | objdump 路径（默认自动查找） |
| `--section NAME` | 只反汇编指定节（默认所有可执行节） |

---

## 贡献新插件

新插件需满足：
1. 目录放在 `plugins/sotrace-<toolname>/`
2. 实现 HTTP POST 到 `/api/v1/traces/import`，body 字段见 `docs/SPEC.md`
3. 提供 `README` 或在本文档中补充使用说明
4. 不依赖 sotrace Rust 代码（纯 push-side，与 server 以 HTTP 解耦）
