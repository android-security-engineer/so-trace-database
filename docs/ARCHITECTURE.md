# SO Trace Database — 架构设计

## 1. 系统定位

SO Trace Database 是一个**面向 Android SO 逆向分析的 trace 存储与查询数据库**，提供两种使用模式：

1. **嵌入式模式**：作为 Rust 库直接集成到逆向工具链中，零部署成本
2. **服务化模式**：作为 HTTP API Server 运行，提供 REST/gRPC/MCP 接口，支持 Web 前端和 AI Agent 接入

> 完整的系统架构设计见 [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md)

### 设计原则

1. **核心优先**：存储引擎和查询能力是核心，HTTP/前端/MCP 是接入层
2. **写入优化**：trace 场景是典型的"一次写入、多次查询"模式，写入性能是第一优先级
3. **列式存储**：trace 记录具有高度结构化和高重复性，列式存储天然适合压缩和批量扫描
4. **时序感知**：trace 数据本质是时序数据，存储和索引设计需充分利用时序特征
5. **可扩展的输入源**：通过插件式 adapter 支持多种 trace 采集工具的输出格式
6. **AI 原生**：通过 MCP 协议原生支持 AI Agent 接入，让 AI 能直接查询和分析 trace

## 2. 功能边界

### 核心功能（MVP 必须实现）

| 功能 | 描述 | 优先级 |
|------|------|--------|
| Trace 数据写入 | 批量写入指令级/函数级 trace 记录 | P0 |
| Trace 数据存储 | 列式存储 + 专用压缩，支持 10 亿+ 记录 | P0 |
| 基础查询 | 按地址、函数名、时间范围查询 | P0 |
| 调用链查询 | 查询函数调用/返回序列，支持调用栈重建 | P0 |
| Frida trace 导入 | 解析 Frida 脚本输出的 trace 数据 | P0 |
| SO 元数据关联 | 存储 SO 文件的段信息、符号表、导入导出表 | P1 |

### 增强功能（后续版本）

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 内存访问 trace | 存储和查询内存读写记录 | P1 |
| JNI 调用 trace | 跨 Java/Native 边界的调用链追踪 | P1 |
| 数据流追踪 | 从指定地址/寄存器追踪数据传播路径 | P1 |
| DynamoRIO/Pin 导入 | 支持指令级 trace 的导入 | P2 |
| strace 导入 | 系统调用 trace 的导入和查询 | P2 |
| 污点分析支持 | 基于内存 trace 的污点传播查询 | P2 |
| 反编译结果关联 | 与 IDA/Ghidra 反编译结果关联 | P3 |
| 查询语言 | 领域特定查询语言（类似 SQL 但面向 trace） | P3 |

### 明确不做

- Trace 数据采集（由 Frida/Pin 等工具负责）
- 符号执行引擎
- 自动漏洞检测

## 3. 数据模型

### 3.1 核心实体

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  SOFile      │────<│  SOFunction   │────<│  InstructionTrace│
│  (SO文件)    │     │  (函数)       │     │  (指令轨迹)      │
└─────────────┘     └──────────────┘     └─────────────────┘
       │                   │                     │
       │                   │                     │
       ▼                   ▼                     ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  SOSegment   │     │  CallTrace    │     │  MemoryAccess   │
│  (段信息)    │     │  (调用轨迹)   │     │  (内存访问)      │
└─────────────┘     └──────────────┘     └─────────────────┘
       │
       ▼
┌─────────────┐     ┌──────────────┐
│  SOSymbol    │     │  JNICall      │
│  (符号)      │     │  (JNI调用)    │
└─────────────┘     └──────────────┘
```

### 3.2 数据表设计

#### SOFile — SO 文件元数据

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| path | string | SO 文件路径 |
| build_id | bytes | Build ID（唯一标识） |
| arch | enum | 架构（arm64/arm/x86） |
| file_size | uint64 | 文件大小 |
| md5 | bytes | MD5 哈希 |
| sha256 | bytes | SHA256 哈希 |
| created_at | timestamp | 导入时间 |

#### SOFunction — SO 中的函数

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| so_file_id | uint64 | 外键 → SOFile |
| name | string | 函数名（可能为空） |
| offset | uint64 | 在 SO 文件中的偏移 |
| size | uint32 | 函数大小 |
| is_jni | bool | 是否为 JNI 函数 |
| is_imported | bool | 是否为导入函数 |
| is_exported | bool | 是否为导出函数 |

#### InstructionTrace — 指令级执行轨迹

| 字段 | 类型 | 描述 |
|------|------|------|
| seq | uint64 | 全局时序号（主键） |
| thread_id | uint32 | 线程 ID |
| so_file_id | uint32 | SO 文件 ID（字典编码） |
| address | uint64 | 指令地址 |
| opcode | bytes | 指令机器码（可选） |
| disasm | string | 反汇编文本（可选） |
| timestamp | uint64 | 时间戳（纳秒） |
| is_branch | bool | 是否为分支指令 |
| branch_taken | bool | 分支是否跳转 |

#### CallTrace — 函数调用轨迹

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| thread_id | uint32 | 线程 ID |
| caller_address | uint64 | 调用者地址 |
| callee_func_id | uint64 | 外键 → SOFunction |
| call_seq | uint64 | 调用发生时的指令时序号 |
| return_seq | uint64 | 返回时的指令时序号（可能为空） |
| depth | uint32 | 调用栈深度 |
| timestamp | uint64 | 时间戳 |

#### MemoryAccess — 内存访问记录

| 字段 | 类型 | 描述 |
|------|------|------|
| seq | uint64 | 对应的指令时序号 |
| thread_id | uint32 | 线程 ID |
| access_type | enum | 读/写/执行 |
| address | uint64 | 访问的内存地址 |
| size | uint8 | 访问大小（字节） |
| value | bytes | 读/写的值（可选） |

#### JNICall — JNI 调用记录

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| thread_id | uint32 | 线程 ID |
| call_seq | uint64 | 调用时的指令时序号 |
| direction | enum | Java→Native / Native→Java |
| java_class | string | Java 类名 |
| java_method | string | Java 方法名 |
| native_func_id | uint64 | 外键 → SOFunction |
| native_address | uint64 | Native 函数地址 |

### 3.3 存储格式设计

#### 列式存储 + 压缩

每张 trace 表按列存储，每列独立压缩：

| 列类型 | 压缩策略 |
|--------|----------|
| uint64 地址列 | Delta 编码 + Varint + Zstd |
| uint32 ID 列 | 字典编码 + Varint |
| bool 标志列 | 位图压缩 |
| string 文本列 | 字典编码 + LZ4/Zstd |
| bytes 列 | LZ4/Zstd |
| timestamp 列 | Delta 编码 + Zstd |

#### 分段存储（Segment）

trace 数据按时间/序列分段存储，每段包含固定数量的记录（如 100 万条）：

```
segment_000000/
  ├── metadata.bin          # 段元数据
  ├── instruction_trace/
  │   ├── seq.col           # 时序号列（delta+varint+zstd）
  │   ├── thread_id.col     # 线程ID列（dict+varint）
  │   ├── address.col       # 地址列（delta+varint+zstd）
  │   ├── opcode.col        # 机器码列（zstd）
  │   ├── disasm.col        # 反汇编列（dict+zstd）
  │   ├── flags.col         # 标志位列（bitmap）
  │   └── timestamp.col     # 时间戳列（delta+zstd）
  ├── call_trace/
  │   └── ...
  └── index/
      ├── address_index.idx  # 地址索引（B+树或跳表）
      ├── func_id_index.idx  # 函数ID索引
      └── time_index.idx     # 时间索引
```

#### 索引设计

| 索引 | 类型 | 用途 |
|------|------|------|
| 主键索引（seq） | 有序列本身 | 范围扫描 |
| 地址索引 | B+树 / 跳表 | 按地址查询指令 |
| 函数 ID 索引 | B+树 | 按函数查询 trace |
| 时间索引 | B+树 | 按时间窗口查询 |
| 调用链索引 | 嵌套集合模型 | 调用栈重建 |

## 4. 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                     上层应用 / 工具链                          │
│  (IDA 插件 / Ghidra 插件 / 自定义分析脚本 / CLI 工具)          │
└──────────────────────┬───────────────────────────────────────┘
                       │ Query API / Write API
┌──────────────────────▼───────────────────────────────────────┐
│                   SO Trace Database Core                      │
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐   │
│  │  Write Path  │  │  Query Engine │  │  Metadata Manager │   │
│  │             │  │              │  │                   │   │
│  │ - Batch     │  │ - Point      │  │ - SO File Info    │   │
│  │   Writer    │  │   Query      │  │ - Symbol Table    │   │
│  │ - Stream    │  │ - Range      │  │ - Segment Info    │   │
│  │   Writer    │  │   Query      │  │ - Function Info   │   │
│  │ - WAL       │  │ - Call Chain │  │                   │   │
│  │             │  │   Query      │  │                   │   │
│  └──────┬──────┘  └──────┬───────┘  └─────────┬─────────┘   │
│         │                │                     │              │
│  ┌──────▼────────────────▼─────────────────────▼─────────┐   │
│  │                  Storage Engine                        │   │
│  │                                                        │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐  │   │
│  │  │  Column    │  │  Segment   │  │  Index Engine   │  │   │
│  │  │  Store     │  │  Manager   │  │                │  │   │
│  │  │            │  │            │  │  - B+ Tree     │  │   │
│  │  │  - Encode  │  │  - Create  │  │  - Skip List   │  │   │
│  │  │  - Compress│  │  - Merge   │  │  - Bitmap      │  │   │
│  │  │  - Read    │  │  - Delete  │  │  - Bloom Filter│  │   │
│  │  └────────────┘  └────────────┘  └────────────────┘  │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐   │
│  │                  Input Adapters                        │   │
│  │  ┌──────┐  ┌──────────┐  ┌───────┐  ┌─────────────┐ │   │
│  │  │Frida │  │ Unidbg  │  │DynamoRIO│ │strace/Custom│ │   │
│  │  └──────┘  └──────────┘  └───────┘  └─────────────┘ │   │
│  └───────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  File System    │
              │  (数据文件)      │
              └─────────────────┘
```

### 4.1 Write Path（写入路径）

```
采集工具 → Adapter → BatchWriter → WAL → MemTable → Flush → Segment (列式文件)
```

1. **Adapter**：将不同采集工具的输出转换为统一的内部数据模型
2. **BatchWriter**：批量写入接口，支持单条和批量写入
3. **WAL（Write-Ahead Log）**：保证写入持久性，崩溃后可恢复
4. **MemTable**：内存中的有序数据结构，累积到阈值后刷盘
5. **Flush**：将 MemTable 按列式格式写入 Segment 文件

### 4.2 Input Adapter 实现边界

当前 adapter 位于 `crates/sotrace-core/src/adapters/`，输出统一的 `TraceEvent`，由 CLI 或其他调用方喂入引擎。除 Frida 外，Unidbg 已支持两种输入路径：推荐的 callback JSONL，以及对 `AssemblyCodeDumper` / `TraceMemoryHook` 常见文本的 best-effort fallback。

Unidbg callback 没有稳定的官方文件格式，JSONL 是本项目定义的 normalization contract，而不是声称兼容某个固定版本的 Unidbg dump。JSONL 可表达指令、内存、调用、线程、JNI、同步、上下文切换、状态和寄存器变化，并支持基址到 SO-relative offset 的转换。文本 fallback 只能从可读行中推断事件；没有显式线程字段时使用 tid 1，因此不能保证 OS 线程、JNI 或同步信息的准确性。需要可回放、线程精确的采集时，应在 Unidbg callback 中写 JSONL。

CLI 对应格式为 `--format unidbg`（JSONL）和 `--format unidbg-text`（文本 fallback），两者都可用于 `analyze`、`query` 和 `trace-save`。

### 4.3 Query Engine（查询引擎）

支持以下查询模式：

| 查询类型 | 描述 | 示例 |
|----------|------|------|
| 点查询 | 按精确地址/函数名查询 | "地址 0x1234 处执行了哪些指令？" |
| 范围查询 | 按时间/地址范围查询 | "10ms-20ms 之间执行了哪些指令？" |
| 调用链查询 | 查询函数调用/返回序列 | "谁调用了 decrypt 函数？" |
| 调用栈重建 | 重建某时刻的完整调用栈 | "时序号 500000 处的调用栈是什么？" |
| 内存访问查询 | 查询对特定地址的读写 | "哪些指令读写了地址 0xABCD？" |
| 过滤查询 | 按条件过滤 trace | "所有分支跳转指令" |

### 4.4 Storage Engine（存储引擎）

- **列式存储**：每列独立存储和压缩，最大化压缩比和查询效率
- **分段管理**：trace 数据按段组织，支持段级别的创建、合并、删除
- **索引引擎**：为常用查询维度建立索引，支持 B+树、跳表、位图索引等

## 5. 技术选型

### 5.1 实现语言

**Rust**

理由：
- 性能接近 C/C++，满足高吞吐写入需求
- 内存安全，避免 C/C++ 的缓冲区溢出等安全问题
- 丰富的生态系统（zstd、rocksdb bindings、serde 等）
- 跨平台编译，支持 Android 目标平台
- 零成本抽象，列式编解码可高效实现

### 5.2 核心依赖

| 组件 | 候选方案 | 说明 |
|------|----------|------|
| 压缩 | zstd / lz4 | zstd 压缩比好，lz4 速度快 |
| 序列化 | serde + bincode / flatbuffers | bincode 紧凑，flatbuffers 零拷贝 |
| 索引 | 自实现 B+树 / crossbeam-skiplist | 根据需求选择 |
| 内存分配 | jemalloc / mimalloc | 高性能内存分配器 |
| 测试 | proptest | 属性测试，验证编解码正确性 |

### 5.3 API 设计方向

```rust
// 写入 API（概念示例）
let mut db = SoTraceDB::open("/path/to/db")?;

// 导入 SO 文件元数据
let so_id = db.import_so_file("/path/to/libtest.so")?;

// 批量写入指令 trace
let mut writer = db.instruction_writer(so_id)?;
writer.batch_write(&[
    InstructionRecord { seq: 1, thread_id: 0, address: 0x1234, ... },
    InstructionRecord { seq: 2, thread_id: 0, address: 0x1238, ... },
    ...
])?;
writer.finish()?;

// 查询 API
// 按地址查询
let traces = db.query_by_address(so_id, 0x1234)?;

// 按函数名查询
let traces = db.query_by_function(so_id, "decrypt")?;

// 按时间范围查询
let traces = db.query_by_time_range(so_id, 1000..5000)?;

// 调用链查询
let call_chain = db.query_call_chain(so_id, "decrypt")?;

// 调用栈重建
let stack = db.rebuild_call_stack(so_id, seq: 500000)?;
```

## 6. 开发路线图

### Phase 1：MVP（核心存储 + 基础查询）

- [ ] 存储引擎核心：列式存储 + 压缩
- [ ] 数据模型定义和序列化
- [ ] 批量写入接口
- [ ] 基础查询：按地址、函数名、时间范围
- [x] Frida trace 导入 adapter（stalker / interceptor / jnitrace 三格式，sotrace-core/src/adapters/）
- [ ] SO 文件元数据导入（ELF 解析）
- [ ] CLI 工具：导入、查询

### Phase 2：增强查询 + 调用链

- [ ] 调用链查询和调用栈重建
- [ ] 内存访问 trace 存储
- [ ] JNI 调用 trace 支持
- [ ] 索引优化（B+树、位图索引）
- [ ] 段合并和压缩优化
- [ ] DynamoRIO/Pin 导入 adapter

### Phase 3：高级分析

- [ ] 数据流追踪查询
- [ ] 污点分析支持
- [ ] strace 导入
- [ ] 查询语言设计
- [ ] IDA/Ghidra 插件接口

### Phase 4：生态与优化

- [ ] Python binding
- [ ] 性能优化和基准测试
- [ ] 文档和示例
- [ ] 社区建设

## 7. 竞品分析

### 7.1 现有开源项目对比

| 项目 | 开源协议 | 语言 | Stars | 存储方式 | 查询能力 | Android 支持 | 适用性评价 |
|------|----------|------|-------|----------|----------|-------------|-----------|
| QIRA | MIT | C/C++/Python | 4.0k | 内存 mmap + 自定义 C++ 数据库 | 按地址/时间查询，Web UI 实时浏览 | ❌ 仅 x86/ARM Linux | ⭐⭐ 通用 trace 可视化，非 Android 专用 |
| PANDA | GPL-2.0 | C/C++ | 2.7k | 纯文本文件输出（trace.txt） | 无结构化查询，依赖外部工具 | ✅ 支持 ARM | ⭐⭐ 记录回放平台，trace 存储极其原始 |
| Triton | Apache-2.0 | C++/Python | 4.2k | 内存 AST + Pin/DBI 绑定 | 符号/污点查询，非通用 trace 查询 | ❌ 无 | ⭐ 分析框架，不是 trace 数据库 |
| AndroGuard | Apache-2.0 | Python | 6.1k | 纯文件/内存 | 静态分析查询，无 trace 支持 | ✅ 专为 Android | ⭐ 静态分析工具，不涉及 trace |
| Frida | 开源（非标准） | C/Vala/JS | 741 (core) | 标准输出/文件/Socket | 无结构化查询 | ✅ Android 原生支持 | ⭐ 采集工具，trace 无存储优化 |
| DynamoRIO | BSD | C | 3.1k | 纯文本文件输出 | 无结构化查询 | ❌ | ⭐ 采集工具，无存储方案 |
| jnitrace | MIT | TypeScript | 1.8k | 终端输出/文件 | 无结构化查询 | ✅ Android JNI 专用 | ⭐ 仅 JNI 层 trace |
| Intel libipt | BSD-3 | C | 730 | 解码库，不涉及存储 | 无 | ❌ | ⭐ 解码库，非存储方案 |
| REVEN | ❌ 商业 | N/A | N/A | 全系统 trace + 商业数据库 | 完整的 trace 查询回放 | ⚠️ 有限 | ⭐⭐⭐ 唯一完整方案，但闭源且昂贵 |

### 7.2 各项目详细分析

#### QIRA — 最接近的竞品

QIRA（QEMU Interactive Runtime Analyser）是 geohot 开发的实时 trace 分析工具，是**现有最接近我们产品定位的项目**。

**核心数据结构**（来自 `Trace.h`）：

```cpp
struct change {
  Address address;    // 指令/数据地址
  uint64_t data;      // 数据值
  Clnum clnum;        // 变更号（时序）
  uint32_t flags;     // 标志位（读/写/指令/系统调用等）
};
```

**存储架构**：
- 使用 mmap 将 QEMU 产出的二进制 trace 文件映射到内存
- C++ 数据库层维护以下索引：
  - `addresstype_to_clnums_`：地址+类型 → 时序号集合（`unordered_map<pair<Address,char>, set<Clnum>>`）
  - `clnum_to_entry_number_`：时序号 → 条目号
  - `registers_`：寄存器状态向量
  - `memory_`：内存状态映射
  - `pages_`：页面映射
- 读写锁保护并发访问

**查询能力**：
- `FetchClnumsByAddressAndType`：按地址+类型查询时序号
- `FetchChangesByClnum`：按时序号查询变更
- `FetchMemory`：查询某时刻的内存状态
- `FetchRegisters`：查询某时刻的寄存器状态

**关键局限**：
- ❌ 全部数据驻留内存，无法处理大规模 trace（>GB）
- ❌ 无压缩，原始二进制 mmap
- ❌ 无持久化索引，每次重启重建
- ❌ 仅支持 QEMU 后端
- ❌ 无 Android SO 特有支持
- ✅ 实时 trace 流式写入做得好
- ✅ 变更号（clnum）模型设计合理

**对我们的启发**：
- `change` 结构的 flags 设计简洁有效（IS_VALID/IS_WRITE/IS_MEM/IS_SYSCALL + SIZE_MASK）
- 地址到时序号的索引是核心查询需求
- 内存/寄存器状态的版本化存储思路值得借鉴

#### PANDA — 功能最全但存储最原始

PANDA 基于 QEMU，提供记录/回放 + 插件化的动态分析框架。

**trace 插件存储方式**：
- 纯文本文件输出（`trace.txt`），格式如：
  ```
  rip=0x4005a0,rax=0x1,mw=0x7fff:0102,
  rip=0x4005a7,mr=0x600:ff,
  ```
- 每行记录：PC + 寄存器 delta + 内存读写
- 寄存器只记录变化（delta），而非全量
- 内存访问记录地址 + 大小 + 值

**关键局限**：
- ❌ 纯文本无压缩，存储效率极低
- ❌ 无结构化查询，只能 grep
- ❌ 仅支持 x86/x86_64（trace 插件不兼容 ARM）
- ❌ 性能差，全指令 trace 时慢 10-100x
- ✅ 污点分析（taint2）生态成熟
- ✅ 记录/回放机制是核心优势

**对我们的启发**：
- 寄存器 delta 记录是好思路，减少存储量
- 但文本格式完全不可接受，必须二进制 + 压缩

#### Triton — 分析引擎而非存储

Triton 是动态符号执行和污点分析库，**不是 trace 数据库**。

- trace 数据以 AST 形式驻留内存，用于符号执行
- 无持久化存储方案
- 但其指令语义表示和污点传播模型值得关注

#### Frida — 最重要的 trace 数据来源

Frida 是 Android 逆向最常用的动态插桩工具，是我们的**主要数据来源**而非竞品。

- trace 输出：标准输出/文件/Socket，纯文本格式
- 无任何存储优化
- jnitrace 是 Frida 上的 JNI 专用 trace 插件，1852★，输出到终端
- Frida 的 Stalker API 可产生指令级 trace，但输出极快且无缓冲

**关键洞察**：Frida 生态缺乏一个高性能的 trace 存储后端，这正是我们的机会。

### 7.3 市场空白分析

```
                    查询能力
                    低 ←───────→ 高
              ┌─────────────────────────┐
          低  │ Frida trace             │
              │ jnitrace                │
   存        │ DynamoRIO/Pin           │
   储        │ PANDA trace             │
   效        ├─────────────────────────┤
   率        │ QIRA                    │
              │                         │
          高  │                         │
              │           ★ SO Trace DB │
              │             (我们的定位) │
              └─────────────────────────┘
```

**核心发现**：目前不存在一个同时具备高存储效率和高查询能力的开源 trace 数据库。

- QIRA 有查询能力但存储效率低（全内存、无压缩）
- 其他工具存储效率低且无查询能力
- REVEN 是唯一完整方案但闭源且昂贵（许可证数万美元/年）

### 7.4 我们的差异化

1. **专注 Android SO 场景**：现有工具多为通用 trace 平台，缺乏 Android SO 特有的 JNI 感知、ELF 关联等能力
2. **嵌入式数据库定位**：不是 trace 采集工具，不是分析框架，而是专注的存储和查询层
3. **列式 + 压缩**：针对 trace 数据特征优化的存储格式，相比 QIRA 的全内存方案可实现 10x+ 压缩
4. **多源统一**：通过 adapter 层统一不同采集工具的输出（Frida、DynamoRIO、strace 等）
5. **磁盘持久化**：支持 10 亿+ 级别的 trace 记录，不受内存限制
6. **JNI 感知**：原生理解 Android JNI 调用边界，支持 Java ↔ Native 跨边界 trace 查询
7. **开源免费**：Apache 2.0 协议，对比 REVEN 的商业方案
