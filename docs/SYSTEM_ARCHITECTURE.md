# SO Trace Database — 系统架构设计

> 本文档定义 SO Trace Database 的完整系统架构，包括存储引擎、HTTP API Server、前端、微服务和 AI Agent 接入层。
> 与 [ARCHITECTURE.md](ARCHITECTURE.md)（核心存储引擎设计）和 [SPEC.md](SPEC.md)（功能规格）互补。

---

## 1. 整体架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              客户端层                                       │
│                                                                             │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────────┐   │
│  │   Web Frontend    │  │   CLI Tool        │  │   AI Agent Client     │   │
│  │   (React+AntD)   │  │   (Rust Binary)   │  │   (MCP/Skills Client) │   │
│  └────────┬──────────┘  └────────┬──────────┘  └───────────┬───────────┘   │
│           │ HTTP/WS              │ gRPC/HTTP               │ MCP Protocol  │
└───────────┼──────────────────────┼─────────────────────────┼───────────────┘
            │                      │                         │
┌───────────▼──────────────────────▼─────────────────────────▼───────────────┐
│                           API Gateway / 接入层                              │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐    │
│  │  HTTP API Server │  │  gRPC Server    │  │  MCP Server              │    │
│  │  (Axum)         │  │  (tonic)        │  │  (rmcp / custom)         │    │
│  │                 │  │                 │  │                          │    │
│  │  - REST API     │  │  - 高性能批量   │  │  - Tools (查询/导入)     │    │
│  │  - WebSocket    │  │    写入接口     │  │  - Resources (SO/trace)  │    │
│  │  - 认证鉴权     │  │  - 流式导入     │  │  - Prompts (分析模板)    │    │
│  │  - OpenAPI      │  │                 │  │                          │    │
│  └────────┬────────┘  └────────┬────────┘  └────────────┬─────────────┘    │
│           │                    │                          │                  │
│           └────────────────────┼──────────────────────────┘                  │
│                                │                                             │
│  ┌─────────────────────────────▼──────────────────────────────────────────┐ │
│  │                     Service Layer (服务层)                              │ │
│  │                                                                        │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │ │
│  │  │ TraceService │  │ QueryService │  │ AuthService  │                 │ │
│  │  │ (导入/写入)   │  │ (查询/分析)  │  │ (认证/鉴权)  │                 │ │
│  │  └──────┬───────┘  └──────┬───────┘  └──────────────┘                 │ │
│  │         │                 │                                            │ │
│  │  ┌──────▼─────────────────▼────────────────────────────────────────┐  │ │
│  │  │              SO Trace Database Core (核心引擎)                   │  │ │
│  │  │                                                                  │  │ │
│  │  │  ┌──────────────────────────────────────────────────────────┐   │  │ │
│  │  │  │              Memory Delta Engine (内存增量引擎)           │   │  │ │
│  │  │  │  - Checkpoint Manager    - Page Content Store (CAS)      │   │  │ │
│  │  │  │  - Delta Encoder         - Snapshot Rebuilder           │   │  │ │
│  │  │  └──────────────────────────────────────────────────────────┘   │  │ │
│  │  │                                                                  │  │ │
│  │  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐     │  │ │
│  │  │  │ Column Store │  │ Index Engine │  │ Segment Manager    │     │  │ │
│  │  │  │ (列式存储)   │  │ (索引引擎)   │  │ (段管理器)         │     │  │ │
│  │  │  └─────────────┘  └──────────────┘  └────────────────────┘     │  │ │
│  │  │                                                                  │  │ │
│  │  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐     │  │ │
│  │  │  │ ELF Parser  │  │ Adapter Mgr  │  │ MMap Storage       │     │  │ │
│  │  │  │ (SO解析)    │  │ (输入适配)   │  │ (内存映射存储)      │     │  │ │
│  │  │  └─────────────┘  └──────────────┘  └────────────────────┘     │  │ │
│  │  └──────────────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
                                    │                                         │
                                    ▼                                         │
                           ┌─────────────────┐                                │
                           │  File System    │                                │
                           │  (mmap 数据文件) │                                │
                           └─────────────────┘                                │
```

---

## 2. 项目结构（Workspace）

```
so-trace-database/
├── Cargo.toml                    # Workspace 根配置
├── CLAUDE.md
├── LICENSE
├── docs/
│   ├── VISION.md
│   ├── ARCHITECTURE.md
│   ├── SPEC.md
│   └── SYSTEM_ARCHITECTURE.md   # 本文档
│
├── crates/
│   ├── sotrace-core/             # 核心存储引擎（库）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── db.rs             # SoTraceDB 主入口
│   │       ├── models/           # 数据模型
│   │       │   ├── mod.rs
│   │       │   ├── so_file.rs
│   │       │   ├── instruction_trace.rs
│   │       │   ├── call_trace.rs
│   │       │   ├── jni_call.rs
│   │       │   └── register_delta.rs
│   │       ├── storage/          # 存储引擎
│   │       │   ├── mod.rs
│   │       │   ├── column_store.rs    # 列式存储
│   │       │   ├── segment.rs         # 段管理
│   │       │   ├── mmap_store.rs      # 内存映射存储 ⭐
│   │       │   ├── compression.rs     # 压缩编解码
│   │       │   └── wal.rs             # Write-Ahead Log
│   │       ├── memory_delta/     # 内存增量引擎 ⭐ 独立模块
│   │       │   ├── mod.rs
│   │       │   ├── checkpoint.rs      # Checkpoint 管理
│   │       │   ├── delta_encoder.rs   # Delta 编码器
│   │       │   ├── page_store.rs      # 页面内容存储 (CAS)
│   │       │   ├── snapshot.rs        # 快照重建
│   │       │   └── types.rs           # 类型定义
│   │       ├── index/            # 索引引擎
│   │       │   ├── mod.rs
│   │       │   ├── btree.rs
│   │       │   └── bitmap.rs
│   │       ├── query/            # 查询引擎
│   │       │   ├── mod.rs
│   │       │   ├── instruction_query.rs
│   │       │   ├── call_chain_query.rs
│   │       │   ├── memory_query.rs
│   │       │   └── register_query.rs
│   │       ├── adapters/         # 输入适配器
│   │       │   ├── mod.rs
│   │       │   ├── frida.rs
│   │       │   ├── dynamorio.rs
│   │       │   └── strace.rs
│   │       └── elf/              # ELF 解析
│   │           ├── mod.rs
│   │           └── parser.rs
│   │
│   ├── sotrace-server/           # HTTP API Server（二进制）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── app.rs            # Axum App 配置
│   │       ├── router.rs         # 路由定义
│   │       ├── middleware/
│   │       │   ├── auth.rs       # 认证中间件
│   │       │   └── error.rs      # 错误处理中间件
│   │       ├── handlers/
│   │       │   ├── mod.rs
│   │       │   ├── trace.rs      # Trace 导入/查询 API
│   │       │   ├── so_file.rs    # SO 文件管理 API
│   │       │   ├── memory.rs     # 内存快照查询 API
│   │       │   ├── call_chain.rs # 调用链查询 API
│   │       │   └── auth.rs       # 认证 API
│   │       ├── grpc/             # gRPC 服务（可选）
│   │       │   └── mod.rs
│   │       └── mcp/              # MCP Server（AI Agent 接入）
│   │           ├── mod.rs
│   │           ├── tools.rs      # MCP Tools 定义
│   │           └── resources.rs  # MCP Resources 定义
│   │
│   ├── sotrace-cli/              # CLI 工具（二进制）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs
│   │
│   └── sotrace-mcp/              # MCP Server 独立进程（可选）
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
│
├── frontend/                     # React 前端
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── src/
│       ├── App.tsx
│       ├── main.tsx
│       ├── api/                  # API 客户端
│       │   ├── client.ts
│       │   ├── trace.ts
│       │   └── auth.ts
│       ├── pages/
│       │   ├── Login.tsx
│       │   ├── Dashboard.tsx
│       │   ├── TraceViewer.tsx
│       │   ├── MemoryInspector.tsx
│       │   ├── CallChainViewer.tsx
│       │   └── SOBrowser.tsx
│       ├── components/
│       │   ├── Layout.tsx
│       │   ├── TraceTable.tsx
│       │   ├── MemoryView.tsx
│       │   ├── CallStack.tsx
│       │   └── HexView.tsx
│       └── auth/
│           ├── AuthProvider.tsx
│           └── useAuth.ts
│
└── proto/                        # gRPC proto 定义（可选）
    └── sotrace.proto
```

---

## 3. 后端架构详细设计

### 3.1 HTTP API Server — Axum

**选型理由**：
- Axum 由 Tokio 团队维护，与 Tokio 生态无缝集成
- 性能优秀（TechEmpower 排名前列）
- Tower 中间件生态丰富
- 支持 WebSocket（实时 trace 流式导入/查询推送）
- 支持 OpenAPI 文档生成（utoipa）

**核心依赖**：

| crate | 用途 |
|-------|------|
| axum | Web 框架 |
| tokio | 异步运行时 |
| tower | 中间件抽象 |
| tower-http | CORS、Compression、Trace 等中间件 |
| utoipa + utoipa-swagger-ui | OpenAPI 文档自动生成 |
| serde + serde_json | JSON 序列化 |
| tokio-tungstenite | WebSocket |
| tonic + prost | gRPC（可选） |

**API 路由设计**：

```
POST   /api/v1/auth/setup              # 首次安装配置用户名密码
POST   /api/v1/auth/login              # 登录获取 JWT
POST   /api/v1/auth/refresh            # 刷新 Token
GET    /api/v1/auth/status             # 检查是否已初始化

POST   /api/v1/so-files                # 导入 SO 文件
GET    /api/v1/so-files                 # 列出 SO 文件
GET    /api/v1/so-files/:id            # 获取 SO 文件详情
GET    /api/v1/so-files/:id/functions  # 获取 SO 函数列表
GET    /api/v1/so-files/:id/symbols    # 获取 SO 符号表
GET    /api/v1/so-files/:id/segments   # 获取 SO 段信息

POST   /api/v1/traces/import           # 导入 trace 数据（multipart）
POST   /api/v1/traces/import/stream    # 流式导入 trace（WebSocket）
GET    /api/v1/traces                   # 查询 trace 列表
GET    /api/v1/traces/:id              # 获取 trace 详情

GET    /api/v1/traces/:id/instructions           # 查询指令 trace
GET    /api/v1/traces/:id/instructions/:address   # 按地址查询
GET    /api/v1/traces/:id/call-chain              # 查询调用链
GET    /api/v1/traces/:id/call-stack/:seq         # 调用栈重建
GET    /api/v1/traces/:id/memory/:seq             # 内存快照查询
GET    /api/v1/traces/:id/memory/:seq/:address    # 单地址内存值
GET    /api/v1/traces/:id/registers/:seq          # 寄存器状态
GET    /api/v1/traces/:id/jni-calls               # JNI 调用查询

GET    /api/v1/stats                   # 数据库统计信息
GET    /api/v1/health                  # 健康检查
```

### 3.2 认证方案

**首次安装认证**：

1. 首次启动时检查是否已配置管理员账户
2. 未配置时，访问任何 API 返回 `401` + `X-Setup-Required: true` 头
3. 前端引导用户到 `/setup` 页面配置用户名和密码
4. 密码使用 bcrypt/argon2 哈希后存储到本地配置文件
5. 配置完成后返回 JWT Token
6. 后续所有 API 请求需携带 `Authorization: Bearer <token>` 头

**认证流程**：

```
┌──────────┐     ┌──────────┐     ┌──────────────────┐
│  Client  │────→│  Axum    │────→│  Auth Middleware  │
│          │     │  Router  │     │                  │
│          │     │          │     │  1. 提取 Token   │
│          │     │          │     │  2. 验证签名      │
│          │     │          │     │  3. 检查过期      │
│          │     │          │     │  4. 注入用户信息  │
│          │     │          │     └──────────────────┘
└──────────┘     └──────────┘
```

**Token 存储**：
- JWT Secret 存储在本地配置文件（`~/.sotrace/config.toml`）
- Token 有效期：Access Token 24h, Refresh Token 7d
- 支持同时在线多个客户端

### 3.3 内存映射存储模块（MMap Storage）

**模块定位**：`crates/sotrace-core/src/storage/mmap_store.rs`

这是整个存储引擎的底层组件，负责将数据文件通过 mmap 映射到进程地址空间，实现零拷贝读写。

**Rust mmap 可行性分析**：

| 方面 | 评估 | 说明 |
|------|------|------|
| mmap 支持 | ✅ 完全可行 | `memmap2` crate 是成熟稳定的 mmap 绑定 |
| 性能 | ✅ 等同 C | 本质是 POSIX 系统调用，Rust 无额外开销 |
| 内存安全 | ✅ 优于 C | Rust 的借用检查器可防止 mmap 区域的 UAF |
| 零拷贝 | ✅ 支持 | 直接从 mmap 区域反序列化，无需额外拷贝 |
| 跨平台 | ✅ Linux/macOS/Windows | memmap2 支持主流平台 |
| 大文件 | ✅ 支持 | 64-bit 系统下 mmap 可映射 TB 级文件 |

**核心设计**：

```rust
// mmap_store.rs — 内存映射存储

use memmap2::MmapMut;
use std::fs::OpenOptions;
use std::path::Path;

/// 内存映射存储区域
pub struct MmapRegion {
    mmap: MmapMut,        // 可写 mmap 映射
    file: std::fs::File,  // 底层文件句柄
    offset: u64,          // 映射起始偏移
    len: u64,             // 映射长度
}

/// mmap 存储管理器
pub struct MmapStore {
    base_dir: PathBuf,              // 数据目录
    active_regions: Vec<MmapRegion>, // 活跃映射区域
    region_size: u64,               // 单个映射区域大小（默认 256MB）
}

impl MmapStore {
    /// 打开或创建 mmap 存储
    pub fn open(base_dir: &Path) -> Result<Self>;

    /// 分配新的写入区域
    pub fn allocate_region(&mut self, size: u64) -> Result<RegionHandle>;

    /// 获取只读映射（用于查询）
    pub fn get_readonly(&self, file_id: u64, offset: u64, len: u64) -> Result<&[u8]>;

    /// 刷盘（msync）
    pub fn sync(&self) -> Result<()>;

    /// 关闭并释放映射
    pub fn close(&mut self) -> Result<()>;
}
```

**性能优化策略**：

| 优化 | 描述 | 预期收益 |
|------|------|----------|
| 预分配区域 | 预先分配 256MB 映射区域，避免频繁 mmap/munmap | 减少系统调用 |
| 异步刷盘 | 后台线程定期 msync，不阻塞写入路径 | 写入延迟降低 90% |
| 大页支持 | 使用 MAP_HUGETLB 大页映射（2MB/1GB） | TLB miss 减少 50% |
| 顺序写优化 | 新数据追加写入，利用 OS 预读 | 写入吞吐 2x |
| MADV_DONTNEED | 已完成段的数据主动释放 | 减少内存占用 |
| NUMA 感知 | 多 NUMA 节点绑核分配 | 大内存服务器场景 |

**稳定性保障**：

| 措施 | 描述 |
|------|------|
| WAL 先写 | 所有写入先记 WAL，崩溃后可恢复 |
| 校验和 | 每个 Segment 文件包含 CRC32 校验和 |
| 原子切换 | 段文件写入完成后原子重命名，避免读到半写数据 |
| mmap 错误处理 | 捕获 SIGBUS/SIGSEGV，优雅降级 |
| 文件锁 | 使用 fcntl F_LOCK 防止多进程写冲突 |
| 定期 fsync | 每秒 fsync 一次 WAL，最多丢失 1 秒数据 |

### 3.4 gRPC 服务（可选，Phase 2）

**选型**：tonic + prost

**适用场景**：
- 高吞吐的流式 trace 写入（gRPC streaming）
- 微服务间的高性能内部调用
- Python/Go 等其他语言的客户端 SDK

**Proto 定义**（示例）：

```protobuf
service SoTraceService {
  // 批量写入 trace
  rpc WriteInstructions(stream InstructionBatch) returns (WriteAck);

  // 流式导入
  rpc StreamImport(stream TraceChunk) returns (ImportAck);

  // 查询
  rpc QueryInstructions(InstructionQuery) returns (stream InstructionRecord);
  rpc QueryMemory(MemoryQuery) returns (MemorySnapshot);
  rpc QueryCallChain(CallChainQuery) returns (CallChain);
}
```

### 3.5 MCP Server — AI Agent 接入

**MCP (Model Context Protocol)** 是 Anthropic 定义的 AI Agent 与外部工具交互的协议。

**选型**：自定义实现（JSON-RPC 2.0 over stdio）。位于 `crates/sotrace-mcp/`，已实现并覆盖 33 个单元测试 + stdio 端到端冒烟测试。

**实现状态**：✅ 已完成。MCP Server 暴露 `tools` + `resources` 双 capability，支持 `initialize` / `notifications/initialized` / `tools/list` / `tools/call` / `resources/list` / `resources/read` / `ping` 方法。TraceEngine 池（`trace_id → Arc<Mutex<TraceEngine>>`）跨请求复用。

#### Tools（AI 可调用的操作）

聚焦 SO 逆向中的线程追踪与分析，已全部实现：

| Tool Name | 描述 | 参数 |
|-----------|------|------|
| `import_trace` | 批量导入 trace 事件（线程/指令/内存写/同步/上下文切换/状态变更），原子插入 | `{ trace_id, threads?, instructions?, memory_writes?, sync_events?, context_switches?, state_changes? }` |
| `list_traces` | 列出所有已导入 trace ID | `{}` |
| `list_threads` | 列出 trace 内线程及元数据 | `{ trace_id }` |
| `query_instructions` | 按线程/地址/步骤范围查询指令 trace | `{ trace_id, start_step?, end_step?, thread_id?, address?, limit? }` |
| `query_sync_events` | 查询同步事件（mutex/futex/condvar），可按锁地址或线程过滤 | `{ trace_id, thread_id?, sync_object_addr?, start_step?, end_step? }` |
| `query_context_switches` | 查询上下文切换记录，可按线程参与过滤 | `{ trace_id, thread_id?, start_step?, end_step? }` |
| `analyze_threads` | 完整线程分析（竞态/死锁/争用/线程-函数关联/线程安全分类/数据流/生产者-消费者） | `{ trace_id }` |
| `detect_races` | 仅检测竞态条件（跨线程内存访问无同步） | `{ trace_id }` |
| `detect_deadlocks` | 仅检测死锁风险（锁顺序环检测） | `{ trace_id }` |
| `analyze_contentions` | 仅分析锁争用（获取次数/争用比/等待时间） | `{ trace_id }` |
| `classify_function_safety` | 分类函数线程安全性（ThreadSafe/PotentiallyUnsafe/Unsafe/Unknown） | `{ trace_id }` |

#### Resources（AI 可读取的数据）

只读快照，已全部实现：

| Resource URI | 描述 |
|-------------|------|
| `sotrace://traces` | 所有已导入 trace 列表 |
| `sotrace://traces/{id}/summary` | Trace 摘要（步骤数、线程数、上下文切换总数等） |
| `sotrace://traces/{id}/threads` | Trace 内线程列表（含 name/stack/TLS 元数据） |
| `sotrace://traces/{id}/stats` | 每线程统计（执行步骤、切换次数、同步事件数、锁获取/争用次数、平均等待时长） |

#### Prompts（预定义分析模板）

| Prompt Name | 描述 |
|-------------|------|
| `analyze_decryption` | 分析解密函数的执行流程 |
| `trace_data_flow` | 追踪数据从输入到输出的传播路径 |
| `find_sensitive_api` | 查找敏感 API 调用及其调用链 |
| `analyze_jni_boundary` | 分析 JNI 边界的数据交互 |

> 注：Prompts 为规划能力，当前未实现；现有 tools 已覆盖核心分析场景。

**Skills 接入**（Phase 3 延后）：
- Skills 是更高级的 AI Agent 能力组合
- 可以在 MCP tools 基础上编排多步分析流程
- 暂不实现，预留接口

---

## 4. 前端架构设计

### 4.1 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| React | 18+ | UI 框架 |
| TypeScript | 5+ | 类型安全 |
| Ant Design | 5+ | 组件库 |
| Vite | 5+ | 构建工具 |
| Axios | 1+ | HTTP 客户端 |
| React Router | 6+ | 路由 |
| Zustand | 4+ | 状态管理 |
| @ant-design/charts | 3+ | 图表 |

### 4.2 页面设计

```
/                       → 重定向到 /dashboard 或 /setup
/setup                  → 首次安装配置
/login                  → 登录
/dashboard              → 仪表盘（概览统计）
/so-files               → SO 文件管理
/so-files/:id           → SO 文件详情（函数、符号、段）
/traces                 → Trace 会话管理
/traces/:id             → Trace 分析主界面
  ├── instructions      → 指令 Trace 查看器
  ├── call-chain        → 调用链可视化
  ├── memory            → 内存检查器（Hex View）
  ├── registers         → 寄存器状态查看器
  └── jni               → JNI 调用查看器
/traces/:id/timeline    → 时间线视图（全局 trace 概览）
```

### 4.3 核心页面功能

#### Trace 分析主界面

```
┌─────────────────────────────────────────────────────────────────┐
│  SO Trace DB  │ SO Files │ Traces │ Dashboard │      user ▼    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Trace: libtest.so #3  │ Instructions │ Call Chain │ Memory │   │
│                                                                 │
│  ┌─────────────────────┬───────────────────────────────────┐   │
│  │   Function List     │    Instruction Trace Viewer       │   │
│  │                     │                                   │   │
│  │  ▸ decrypt()        │  seq=500001  BL decrypt           │   │
│  │  ▸ encrypt()        │  seq=500002  LDR X0, [SP,#0x10]  │   │
│  │  ▸ JNI_OnLoad()    │  seq=500003  STR X0, [X1]        │   │
│  │  ▸ sub_3A4C()      │  seq=500004  CBZ X0, 0x3A80      │   │
│  │  ▸ ...             │  seq=500005  ...                  │   │
│  │                     │                                   │   │
│  │  [Filter ▼]        │  [◄ Prev] Page 1/1000 [Next ►]   │   │
│  ├─────────────────────┴───────────────────────────────────┤   │
│  │   Detail Panel                                          │   │
│  │   Address: 0x3A4C  │ Registers │ Memory │ Call Stack   │   │
│  │                                                          │   │
│  │   X0=0x00007000  X1=0x7FF00010  SP=0x7FF00000          │   │
│  │   Memory at 0x7FF00010: 48 65 6C 6C 6F 00 00 00       │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

#### 内存检查器（Hex View）

```
┌──────────────────────────────────────────────────────────────┐
│  Memory Inspector   │  Seq: [500000]  │  Jump to: [0x7FF00] │
├──────────────────────────────────────────────────────────────┤
│  Address       00 01 02 03 04 05 06 07  08 09 0A 0B 0C ... │
│  0x7FF00000    48 65 6C 6C 6F 20 57 6F  72 6C 64 00 FF ... │
│  0x7FF00010    01 00 00 00 02 00 00 00  03 00 00 00 04 ... │
│  0x7FF00020    ...                                           │
│                                                              │
│  [Changed bytes highlighted in yellow]                      │
│  [Click byte to see write history]                          │
│                                                              │
│  Write history for 0x7FF00010:                              │
│    seq=499998  WRITE  01→00   (STR X0, [X1])              │
│    seq=499950  WRITE  00→01   (STR X0, [X1,#8])           │
└──────────────────────────────────────────────────────────────┘
```

---

## 5. 微服务部署方案

### 5.1 单体模式（MVP）

MVP 阶段采用单体部署，所有组件在一个进程中：

```bash
# 启动服务（包含 HTTP API + 嵌入式存储引擎）
sotrace-server --config config.toml

# 配置文件示例
[server]
bind = "0.0.0.0:8080"
data_dir = "/data/sotrace"

[auth]
jwt_secret = "auto-generated"  # 首次启动自动生成

[storage]
checkpoint_interval = 100000
segment_size = 1000000
compression = "zstd"
```

### 5.2 微服务模式（Phase 3+）

后续可拆分为微服务：

```
                    ┌───────────────┐
                    │   Nginx /     │
                    │   API Gateway │
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
    ┌─────────▼───┐  ┌─────▼─────┐  ┌───▼──────────┐
    │  Trace      │  │  Query    │  │  MCP Server  │
    │  Import     │  │  Service  │  │  (AI Agent)  │
    │  Service    │  │           │  │              │
    └──────┬──────┘  └─────┬─────┘  └──────┬───────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                  ┌────────▼────────┐
                  │  Storage Engine │
                  │  (共享数据卷)    │
                  └─────────────────┘
```

**拆分策略**：
- Trace Import Service：负责 trace 数据的接收、解析和写入
- Query Service：负责查询请求的处理
- MCP Server：独立的 AI Agent 接入服务
- Storage Engine：核心存储引擎，通过共享数据卷访问

### 5.3 Docker 部署

```dockerfile
# Dockerfile (多阶段构建)
FROM rust:1.77 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin sotrace-server

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/sotrace-server /usr/local/bin/
COPY frontend/dist/ /app/frontend/

EXPOSE 8080
ENTRYPOINT ["sotrace-server"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  sotrace:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - sotrace-data:/data/sotrace
    environment:
      - SOTRACE_BIND=0.0.0.0:8080
      - SOTRACE_DATA_DIR=/data/sotrace

volumes:
  sotrace-data:
```

---

## 6. 技术选型总览

| 层次 | 技术 | 选型 | 理由 |
|------|------|------|------|
| 存储引擎 | 语言 | Rust | 性能 + 内存安全 + mmap 支持 |
| 存储引擎 | mmap | memmap2 | 社区标准，稳定可靠 |
| 存储引擎 | 压缩 | zstd + lz4 | zstd 压缩比，lz4 速度 |
| 存储引擎 | 序列化 | serde + bincode | 紧凑二进制，Rust 原生 |
| 存储引擎 | ELF 解析 | object crate | 纯 Rust ELF 解析 |
| HTTP Server | 框架 | Axum | Tokio 生态，性能优秀 |
| HTTP Server | 运行时 | Tokio | 事实标准 |
| HTTP Server | 中间件 | Tower | Axum 原生支持 |
| HTTP Server | OpenAPI | utoipa | 自动生成 API 文档 |
| HTTP Server | 认证 | JWT (jsonwebtoken) | 轻量，无外部依赖 |
| HTTP Server | 密码哈希 | argon2 | 安全性最好的哈希 |
| gRPC | 框架 | tonic + prost | Rust gRPC 事实标准 |
| MCP | 框架 | rmcp / 自定义 | 基于 MCP 协议规范 |
| 前端 | UI | React + Ant Design | 用户指定 |
| 前端 | 构建 | Vite | 快速，现代 |
| 前端 | 状态 | Zustand | 轻量，简洁 |
| 前端 | 图表 | @ant-design/charts | 与 AntD 一体 |
| 部署 | 容器 | Docker + Compose | 简单可靠 |
