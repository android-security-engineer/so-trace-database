# SO Trace Database

专为 Android 平台 SO（共享库）逆向分析场景设计的执行轨迹存储与查询数据库。

## 项目定位

- **不是** trace 采集工具（复用 Frida/Pin/DynamoRIO 等）
- **不是** 分析框架（不做符号执行、自动漏洞检测）
- **是** 一个 trace 数据库，提供嵌入式库 + HTTP API Server + MCP 接入三种使用模式

## 核心文档

- [产品愿景](docs/VISION.md) — 问题背景、价值主张、成功标准
- [架构设计](docs/ARCHITECTURE.md) — 数据模型、存储引擎、技术选型、竞品分析
- [系统架构](docs/SYSTEM_ARCHITECTURE.md) — 完整系统架构：后端、前端、微服务、MCP
- [产品功能规格书](docs/SPEC.md) — 完整功能列表、数据格式、API 设计、MVP 范围

## 核心模块

- **通用增量存储引擎（delta_store）**：所有存储的通用基础，支持 FullValue/ByteLevel/NumericDelta/BinaryDiff/DictionaryRef 5 种编码
- **时间线（Timeline）**：核心抽象，trace = timeline，所有 store 共享统一时间线索引
- **内存状态增量存储**：Checkpoint + Delta + Page-Granularity + byte-level delta
- **指令 Trace 存储**：NumericDelta 地址编码，AddressIndex 加速查询
- **调用 Trace 存储**：嵌套集合模型（Nested Set），支持 O(log N) 调用栈重建
- **寄存器 Delta 存储**：bitmask + 变长编码，register_index 加速单寄存器查询
- **线程状态存储**：dictionary 编码，ThreadIndex/SyncObjectIndex/ThreadSyncIndex 加速查询
- **线程分析器**：竞态检测、死锁检测、锁争用分析、线程-函数关联、数据流分析
- **TraceEngine**：统一引擎，协调所有 store 和 Timeline，支持跨 store 查询
- **MMap 存储引擎**：基于 memmap2 的零拷贝存储，支持大页、异步刷盘
- **增量查询加速**：SkipListIndex/AddressIndex/ThreadIndex/FunctionIndex，存储是为了更快的查询

## 技术栈

### 后端（Rust）
- **Web 框架**: Axum + Tokio
- **gRPC**: tonic + prost
- **MCP**: rmcp / 自定义
- **压缩**: zstd / lz4
- **序列化**: serde + bincode
- **mmap**: memmap2
- **ELF 解析**: object crate

### 前端（TypeScript）
- React 18+ + TypeScript 5+
- Ant Design 5+
- Vite 5+ 构建
- Zustand 状态管理

## 项目结构

```
so-trace-database/
├── crates/
│   ├── sotrace-core/       # 纯类型/模型层（库）
│   ├── sotrace-engine/     # 核心引擎层（库）— delta_store, trace_store, timeline, query, engine, analyzer
│   ├── sotrace-server/     # API Server 层（Axum，二进制）— 依赖 sotrace-engine
│   ├── sotrace-cli/        # CLI 工具（二进制）
│   └── sotrace-mcp/        # MCP Server（二进制）
├── frontend/               # React 前端
└── docs/                   # 文档
```

### sotrace-engine 核心模块

```
sotrace-engine/src/
├── delta_store/            # 通用增量存储引擎（最核心）
│   ├── types.rs            # DeltaRecord, DeltaPayload, DeltaEncoding, Snapshot
│   ├── snapshot.rs         # SnapshotManager: 周期性全状态快照 + CAS 去重
│   ├── delta_log.rs        # DeltaLog: 追加写入的增量日志
│   ├── delta_index.rs      # SkipListIndex, AddressIndex, ThreadIndex, FunctionIndex
│   └── encoding.rs         # byte-level, bitmask, numeric delta, binary diff 编码策略
├── trace_store/            # 基于 delta_store 的领域存储
│   ├── instruction_store.rs  # NumericDelta 地址编码
│   ├── register_store.rs     # bitmask delta 编码 + register_index
│   ├── memory_store.rs       # byte-level delta + page-granularity
│   ├── call_store.rs         # nested set model 调用链
│   ├── thread_store.rs       # dictionary 编码
│   └── jni_store.rs          # JNI 边界调用
├── timeline/               # 时间线（核心抽象，所有 store 共享）
├── query/                  # 查询引擎（增量索引加速）
├── storage/                # 底层存储（mmap, column store, compression, WAL）
└── elf/                    # ELF/SO 文件解析（object crate）
```

## 开发约定

- 所有文档使用简体中文
- 代码注释使用英文
- Commit message 使用英文
- 遵循 Rust 标准项目结构（Cargo Workspace）
- 前端代码使用 ESLint + Prettier
