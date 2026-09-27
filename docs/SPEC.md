# SO Trace Database — 产品功能规格书

> 本文档定义 SO Trace Database 的完整功能列表、每个功能的详细边界和实现规格。
> 所有开发工作以本文档为基准。

---

## 1. 功能总览

SO Trace Database 的功能按层次组织：

```
┌─────────────────────────────────────────────────────┐
│                  查询接口层                           │
│  (Query API / CLI / Python Binding)                 │
├─────────────────────────────────────────────────────┤
│                  分析功能层                           │
│  (调用链重建 / 数据流追踪 / 污点分析支持)              │
├─────────────────────────────────────────────────────┤
│                  核心存储层                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │ 指令Trace │ │ 调用Trace │ │ 内存状态  │ │ JNI    │ │
│  │ 存储     │ │ 存储     │ │ 增量存储  │ │ Trace  │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────┘ │
├─────────────────────────────────────────────────────┤
│                  元数据层                            │
│  (SO文件 / 符号表 / 段信息 / 导入导出表)              │
├─────────────────────────────────────────────────────┤
│                  输入适配层                          │
│  (Frida / Unidbg / DynamoRIO / Pin / strace / 自定义)│
└─────────────────────────────────────────────────────┘
```

---

## 2. 核心存储层 — 详细功能规格

### 2.1 指令 Trace 存储

#### 功能描述

存储程序执行过程中每条指令的执行记录，包括执行地址、线程、时间戳、分支行为等。

#### 数据记录格式

| 字段 | 类型 | 大小 | 必选 | 描述 |
|------|------|------|------|------|
| seq | uint64 | 8B | ✅ | 全局单调递增时序号，作为主键 |
| thread_id | uint32 | 4B | ✅ | 线程 ID |
| address | uint64 | 8B | ✅ | 指令在 SO 中的虚拟地址 |
| timestamp | uint64 | 8B | ⬜ | 纳秒级时间戳（采集工具提供时） |
| is_branch | bool | 1bit | ⬜ | 是否为分支指令 |
| branch_taken | bool | 1bit | ⬜ | 分支是否跳转（仅 is_branch=true 时有效） |
| opcode_size | uint8 | 1B | ⬜ | 机器码长度（0 表示不存储机器码） |
| opcode | bytes | 变长 | ⬜ | 指令机器码（可选，受 opcode_size 控制） |

#### 功能边界

| 范围 | 说明 |
|------|------|
| ✅ 做 | 批量写入指令 trace 记录，支持百万级/秒吞吐 |
| ✅ 做 | 按地址、时序号范围、线程 ID 查询 |
| ✅ 做 | 列式压缩存储（delta + varint + zstd） |
| ✅ 做 | 分段存储，每段 100 万条记录 |
| ❌ 不做 | 不存储反汇编文本（查询时实时反汇编或关联 SO 元数据） |
| ❌ 不做 | 不存储寄存器值（由内存状态模块负责） |
| ❌ 不做 | 不存储操作数值（由内存访问模块负责） |

#### 压缩策略

| 列 | 编码方式 | 预期压缩比 |
|----|----------|-----------|
| seq | Delta 编码 + Varint | ~2B/条（vs 8B 原始） |
| thread_id | 字典编码 + Varint | ~0.5B/条（线程数少） |
| address | Delta 编码 + Varint + Zstd | ~3B/条（局部性强） |
| timestamp | Delta 编码 + Zstd | ~4B/条（单调递增） |
| is_branch + branch_taken | 位图打包 | ~0.25B/条 |
| opcode | Zstd | ~2-4B/条（指令集有限） |

**预期综合压缩**：~12B/条（vs 原始 ~30B/条），10 亿条约 12GB。

---

### 2.2 调用 Trace 存储

#### 功能描述

存储函数调用和返回事件，支持调用链重建和调用栈回溯。

#### 数据记录格式

| 字段 | 类型 | 大小 | 必选 | 描述 |
|------|------|------|------|------|
| id | uint64 | 8B | ✅ | 主键 |
| thread_id | uint32 | 4B | ✅ | 线程 ID |
| event_type | enum | 1B | ✅ | CALL / RETURN / TAIL_CALL |
| caller_address | uint64 | 8B | ✅ | 调用者指令地址 |
| callee_address | uint64 | 8B | ✅ | 被调用函数入口地址 |
| callee_func_id | uint32 | 4B | ⬜ | 外键 → SOFunction（已知时） |
| seq | uint64 | 8B | ✅ | 事件发生时的指令时序号 |
| depth | uint16 | 2B | ✅ | 调用栈深度（CALL 时 +1，RETURN 时 -1） |
| return_seq | uint64 | 8B | ⬜ | 返回时的时序号（RETURN 事件时填充） |

#### 功能边界

| 范围 | 说明 |
|------|------|
| ✅ 做 | 记录 CALL/RETURN 事件 |
| ✅ 做 | 调用栈深度追踪 |
| ✅ 做 | 调用链查询（谁调用了函数 X？函数 X 调用了谁？） |
| ✅ 做 | 任意时刻调用栈重建 |
| ✅ 做 | 递归调用检测和标记 |
| ⬜ 延后 | TAIL_CALL 优化识别（需反汇编配合） |
| ❌ 不做 | 不做函数参数/返回值追踪（由内存状态模块负责） |

#### 调用栈重建算法

使用**嵌套集合模型（Nested Set Model）**：

```
函数 A 调用 B 调用 C：
  A [1──────────────────────12]
      B [2──────────7]
          C [3──4]
      B [5──6]  (C 返回后 B 继续)
  A [8──────────11]
     (B 返回后 A 继续)

每个 CALL 事件分配 left 值，对应 RETURN 分配 right 值。
查询"时序号 N 处的调用栈" = 查找 left ≤ N ≤ right 的所有记录。
```

---

### 2.3 内存状态增量存储 ⭐ 核心模块

#### 功能描述

存储程序运行过程中内存状态的变化，支持在任意时序号处重建完整的内存快照。这是整个产品技术难度最高、也最有价值的模块。

#### 2.3.1 核心问题

程序运行时内存状态持续变化：
- 每条指令可能读写多个内存地址
- 全量存储每个时序号的内存状态不可行（一个进程可能有数百 MB 内存，每步都存 = 爆炸）
- 但逆向分析需要回答："时序号 N 时，地址 0xABCD 的值是什么？"

**核心矛盾**：存储量 vs 随机访问任意时刻内存状态的能力。

#### 2.3.2 设计方案：Checkpoint + Delta + Page-Granularity

采用**定期全量快照 + 增量变化**的混合方案，以**内存页**为粒度追踪变化。

##### 整体架构

```
时间轴 ──────────────────────────────────────────────→
         │          │          │          │
      Checkpoint₀  Checkpoint₁  Checkpoint₂  Checkpoint₃
         │    Δ₀    │    Δ₁    │    Δ₂    │    Δ₃
         ├──────────┤──────────┤──────────┤──────────┤
         │ 脏页记录 │ 脏页记录 │ 脏页记录 │ 脏页记录 │
         │ + 值变化 │ + 值变化 │ + 值变化 │ + 值变化 │
```

##### 三层存储结构

**第一层：Checkpoint（全量快照）**

- 每隔 N 条指令（默认 N = 100,000，可配置）存储一次全量内存快照
- 快照不是真的"全量复制"，而是**存储当前所有已映射页面的内容**
- 快照内部也做去重：相同内容的页面只存一份（内容寻址）

**第二层：Delta（增量变化）**

- 两个 Checkpoint 之间，只记录**发生了变化的内存区域**
- 以**内存页（4KB）**为最小追踪粒度
- 当一个页内的任何字节发生变化时，记录该页的变化

**第三层：Page Delta（页内增量）**

- 对于同一页面在多次变化之间，存储**页内二进制差分**而非全量页面
- 使用 bsdiff/VCDIFF 算法计算页内 delta
- 当 delta 大小超过页面原始大小的 50% 时，退化为存储全量页面

##### 数据记录格式

**MemoryCheckpoint（全量快照）**

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 快照 ID |
| seq | uint64 | 快照时刻的指令时序号 |
| page_count | uint32 | 已映射页面数 |
| pages | [PageRef] | 页面引用列表（内容寻址） |

**PageRef（页面引用）**

| 字段 | 类型 | 描述 |
|------|------|------|
| virtual_address | uint64 | 页面虚拟地址（页对齐） |
| content_hash | bytes[32] | 页面内容的 SHA-256 哈希（用于去重） |
| storage_ref | uint64 | 指向实际页面内容的存储引用 |

**MemoryDelta（增量变化记录）**

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| seq | uint64 | 变化发生时的指令时序号 |
| thread_id | uint32 | 线程 ID |
| page_address | uint64 | 发生变化的页面虚拟地址 |
| delta_type | enum | FULL_PAGE / PAGE_DELTA / BYTE_LEVEL |
| delta_data | bytes | 变化数据（格式由 delta_type 决定） |
| prev_content_hash | bytes[32] | 变化前的页面内容哈希（用于验证和回溯） |

**delta_type 编码规则**：

| delta_type | delta_data 格式 | 适用场景 |
|------------|----------------|----------|
| FULL_PAGE | 完整 4KB 页面内容 | 页面首次写入或 delta 过大 |
| PAGE_DELTA | bsdiff/VCDIFF 格式的二进制差分 | 同一页面多次修改，delta < 页面 50% |
| BYTE_LEVEL | `[(offset, size, value), ...]` 变长编码 | 页面内少量字节变化（< 64 字节） |

##### BYTE_LEVEL 编码细节

当页面内变化字节数 ≤ 64 时，使用最紧凑的字节级编码：

```
┌──────────┬──────────┬─────────────┬──────────┬─────────────┐
│ count:u8 │ off:u16  │  size:u8    │  value   │   ...       │
│ 变化数   │ 偏移1    │  大小1      │  值1     │  下一组...  │
└──────────┴──────────┴─────────────┴──────────┴─────────────┘
```

- count：变化的连续区域数量（1 字节，最多 255 个区域）
- 每个区域：offset（2 字节，页内偏移 0-4095）+ size（1 字节，0-255）+ value（size 字节）
- 典型场景：一条 STR 指令写 4/8 字节 → count=1, 总共 7-11 字节

##### 2.3.3 内存快照重建算法

**目标**：给定任意时序号 N，重建该时刻的完整内存状态。

**算法**：

```
function reconstruct_memory(target_seq):
    // 1. 找到 target_seq 之前最近的 checkpoint
    checkpoint = find_checkpoint_before(target_seq)
    
    // 2. 从 checkpoint 恢复基础内存状态
    memory = load_checkpoint(checkpoint)
    
    // 3. 从 checkpoint 到 target_seq 之间，正向应用所有 delta
    deltas = query_deltas_range(checkpoint.seq, target_seq)
    for delta in deltas:
        apply_delta(memory, delta)
    
    return memory
```

**优化：单地址查询**

如果只需要查询某个地址在时序号 N 时的值，不需要重建全部内存：

```
function query_memory_at(address, target_seq):
    // 1. 找到 target_seq 之前最近的 checkpoint
    checkpoint = find_checkpoint_before(target_seq)
    
    // 2. 检查该地址所在页面在 checkpoint 中是否存在
    page_addr = align_to_page(address)
    page = checkpoint.get_page(page_addr)
    
    // 3. 查找该页面在 [checkpoint.seq, target_seq] 之间的最后一次 delta
    last_delta = find_last_delta_for_page(page_addr, checkpoint.seq, target_seq)
    
    if last_delta == null:
        // 该页面在此区间内未变化，直接返回 checkpoint 中的值
        return page[address % PAGE_SIZE]
    else:
        // 应用 delta 得到最新页面内容
        current_page = apply_delta(page, last_delta)
        return current_page[address % PAGE_SIZE]
```

**复杂度**：
- 全量重建：O(checkpoint_size + delta_count)，取决于 checkpoint 间隔
- 单地址查询：O(log D)，D 为该页面的 delta 数量（有索引）

##### 2.3.4 Checkpoint 间隔策略

| 策略 | 描述 | 适用场景 |
|------|------|----------|
| 固定间隔 | 每 N 条指令一个 checkpoint | 简单可靠，默认方案 |
| 自适应间隔 | 根据脏页率动态调整：脏页多时缩短间隔，脏页少时延长 | 内存变化密集的程序 |
| 手动标记 | 用户在关键点手动插入 checkpoint | 调试特定代码段 |

**默认配置**：
- 固定间隔：100,000 条指令
- 预期效果：单地址查询需回溯最多 100,000 条指令的 delta
- 内存开销：每个 checkpoint 约 1-10MB（取决于进程内存占用，去重后）

##### 2.3.5 页面内容去重（Content-Addressable Storage）

同一页面内容可能在不同时刻、不同地址出现（如 .rodata 段、零页等）。

**去重策略**：
- 每个页面内容计算 SHA-256 哈希
- 使用哈希作为 key，页面内容作为 value 的 KV 存储
- 相同哈希的页面只存一份
- Checkpoint 中的 PageRef 通过哈希引用页面内容

**预期收益**：
- 零页（全零页面）只存一份，节省大量空间
- .rodata/.text 段内容不变，跨 checkpoint 去重
- 典型场景下去重率 30-60%

##### 2.3.6 存储空间估算

**场景假设**：
- 进程内存占用：50MB（12,800 个 4KB 页面）
- Trace 长度：1 亿条指令
- Checkpoint 间隔：100,000 条 → 1,000 个 checkpoint
- 每条指令平均修改 0.3 个页面中的 8 字节

**存储量计算**：

| 组件 | 计算 | 大小 |
|------|------|------|
| Checkpoint 页面内容（去重后） | 假设 50% 去重，6,400 页 × 4KB × 1 份 | ~25MB |
| Checkpoint 元数据 | 1,000 × 12,800 × 12B（地址+哈希+引用） | ~15MB |
| Delta 记录（BYTE_LEVEL 为主） | 1 亿 × 0.3 × 11B（平均） | ~330MB |
| Delta 索引 | 页面地址 + 时序号 B+树 | ~50MB |
| **总计** | | **~420MB** |

**对比全量存储**：1 亿 × 50MB = 5,000,000 TB（完全不可行）
**对比无去重 Delta**：~1.5GB
**压缩比**：相比无优化 Delta 约 3.5x，相比全量存储天文数字级

##### 2.3.7 功能边界

| 范围 | 说明 |
|------|------|
| ✅ 做 | Checkpoint + Delta 增量存储 |
| ✅ 做 | 页面粒度脏页追踪 |
| ✅ 做 | 页内 BYTE_LEVEL / PAGE_DELTA / FULL_PAGE 三级编码 |
| ✅ 做 | 页面内容去重（CAS） |
| ✅ 做 | 任意时序号处的单地址内存值查询 |
| ✅ 做 | 任意时序号处的完整内存快照重建 |
| ✅ 做 | Checkpoint 间隔可配置 |
| ⬜ 延后 | 自适应 checkpoint 间隔 |
| ⬜ 延后 | bsdiff/VCDIFF 页内差分（MVP 先用 BYTE_LEVEL + FULL_PAGE） |
| ❌ 不做 | 不做内存分配器追踪（malloc/free 追踪由上层工具负责） |
| ❌ 不做 | 不做堆对象语义识别 |
| ❌ 不做 | 不存储每条指令的完整寄存器集（只存变化，见 2.4） |

---

### 2.4 寄存器状态增量存储

#### 功能描述

存储程序运行过程中寄存器值的变化，采用与内存类似的增量策略。

#### 设计方案

寄存器数量有限（ARM64: 31 个通用寄存器 + SP + PC + 状态寄存器），但每条指令都可能改变寄存器。

**策略：只存变化（Delta）**

- 不存储每条指令的完整寄存器集
- 只记录**哪些寄存器发生了变化**以及**新值是什么**
- 类似 PANDA 的做法，但用二进制编码而非文本

#### 数据记录格式

**RegisterDelta（寄存器变化记录）**

| 字段 | 类型 | 描述 |
|------|------|------|
| seq | uint64 | 指令时序号 |
| change_mask | uint32 | 位掩码，标记哪些寄存器发生了变化（1 bit/寄存器） |
| values | 变长 | 变化寄存器的新值，按 mask 顺序排列 |

**change_mask 编码**（ARM64 示例）：

```
bit 0-30:  x0-x30 通用寄存器
bit 31:    SP
bit 32:    PC（通常总是变化）
bit 33:    CPSR/NZCV 标志寄存器
```

**values 编码**：

```
┌──────────────────────────────────────────────┐
│  reg0_value:u64  │  reg3_value:u64  │  ...   │
│  (mask bit 0=1)  │  (mask bit 3=1)  │        │
└──────────────────────────────────────────────┘
```

只存储 mask 中 bit=1 的寄存器值，顺序排列。

#### 压缩策略

| 场景 | 平均变化寄存器数 | 编码大小 |
|------|----------------|----------|
| 普通指令 | 1-2 个 | 4B(mask) + 8-16B(values) = 12-20B |
| 函数调用 | 3-5 个 | 4B + 24-40B = 28-44B |
| 系统调用 | 5-10 个 | 4B + 40-80B = 44-84B |

**列式存储优化**：
- change_mask 列：位图压缩（大量指令只改 1-2 个寄存器，mask 稀疏）
- values 列：按寄存器拆分为独立列，每列 delta 编码 + zstd

#### 功能边界

| 范围 | 说明 |
|------|------|
| ✅ 做 | 寄存器变化 delta 存储 |
| ✅ 做 | 任意时序号处的寄存器值查询 |
| ✅ 做 | 寄存器值历史变化查询 |
| ❌ 不做 | 不存储浮点/SIMD 寄存器（MVP 阶段） |
| ❌ 不做 | 不做寄存器值语义解释 |

---

### 2.5 JNI 调用 Trace 存储

#### 功能描述

存储 Java ↔ Native 边界的 JNI 调用记录，这是 Android SO 逆向的特有需求。

#### 数据记录格式

| 字段 | 类型 | 必选 | 描述 |
|------|------|------|------|
| id | uint64 | ✅ | 主键 |
| seq | uint64 | ✅ | 调用发生时的指令时序号 |
| thread_id | uint32 | ✅ | 线程 ID |
| direction | enum | ✅ | JAVA_TO_NATIVE / NATIVE_TO_JAVA |
| java_class | string | ✅ | Java 类的完整限定名 |
| java_method | string | ✅ | Java 方法名 |
| java_signature | string | ✅ | Java 方法签名（参数和返回值类型） |
| native_func_id | uint32 | ⬜ | 外键 → SOFunction |
| native_address | uint64 | ✅ | Native 函数地址 |
| jni_env_address | uint64 | ⬜ | JNIEnv 指针值 |
| args_count | uint8 | ⬜ | 参数数量 |
| args_data | bytes | ⬜ | 参数值序列化（可选） |

#### 功能边界

| 范围 | 说明 |
|------|------|
| ✅ 做 | JNI 调用方向记录（Java→Native / Native→Java） |
| ✅ 做 | Java 类/方法/签名记录 |
| ✅ 做 | Native 函数地址关联 |
| ✅ 做 | JNI 调用链查询 |
| ⬜ 延后 | JNI 参数/返回值捕获（需 Frida 脚本配合） |
| ❌ 不做 | 不做 Java 层 trace（由其他工具负责） |

---

## 3. 元数据层 — 详细功能规格

### 3.1 SO 文件元数据

#### 功能描述

存储 SO 文件（ELF 格式）的静态信息，为 trace 数据提供上下文。

#### 数据记录

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| path | string | SO 文件路径 |
| build_id | bytes | ELF Build ID |
| arch | enum | arm / arm64 / x86 / x86_64 |
| file_size | uint64 | 文件大小 |
| md5 | bytes[16] | MD5 哈希 |
| sha256 | bytes[32] | SHA-256 哈希 |
| loaded_base_address | uint64 | 运行时加载基地址 |
| created_at | timestamp | 导入时间 |

### 3.2 SO 段信息

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| so_file_id | uint64 | 外键 → SOFile |
| name | string | 段名（.text, .data, .rodata 等） |
| type | enum | 段类型 |
| offset | uint64 | 文件内偏移 |
| vaddr | uint64 | 虚拟地址 |
| size | uint64 | 段大小 |
| flags | uint32 | 段标志（可读/可写/可执行） |

### 3.3 SO 符号表

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| so_file_id | uint64 | 外键 → SOFile |
| name | string | 符号名 |
| value | uint64 | 符号值/地址 |
| size | uint64 | 符号大小 |
| type | enum | 符号类型（FUNC/OBJECT/NOTYPE 等） |
| bind | enum | 绑定类型（LOCAL/GLOBAL/WEAK） |
| is_imported | bool | 是否为导入符号 |
| is_exported | bool | 是否为导出符号 |

### 3.4 SO 函数信息

| 字段 | 类型 | 描述 |
|------|------|------|
| id | uint64 | 主键 |
| so_file_id | uint64 | 外键 → SOFile |
| symbol_id | uint64 | ⬜ 外键 → SOSymbol（有符号时） |
| name | string | 函数名（可能为 sub_XXXX 格式） |
| offset | uint64 | 在 SO 中的偏移 |
| size | uint32 | 函数大小 |
| is_jni | bool | 是否为 JNI 函数（RegisterNatives 或导出名含 Java_） |
| is_thunk | bool | 是否为跳转桩函数 |

#### 功能边界

| 范围 | 说明 |
|------|------|
| ✅ 做 | ELF 解析：段、符号表、导入导出表 |
| ✅ 做 | JNI 函数自动识别（Java_ 前缀 + RegisterNatives） |
| ✅ 做 | 函数与 trace 数据的关联查询 |
| ❌ 不做 | 不做反汇编（由 IDA/Ghidra 负责） |
| ❌ 不做 | 不做控制流图生成 |
| ❌ 不做 | 不做函数边界自动识别（使用符号表信息） |

---

## 4. 输入适配层 — 详细功能规格

### 4.1 通用 Adapter 接口

**实现状态**：✅ 已实现（`crates/sotrace-core/src/adapters/`）。

Adapter 层位于 `sotrace-core`，刻意不依赖 `sotrace-engine`：它把工具原生格式解析为统一的 `TraceEvent` 流，由调用方（CLI / MCP / HTTP server）喂给 `TraceEngine`。

```rust
/// 统一中间事件（adapter 产出，消费方喂入引擎）
pub enum TraceEvent {
    Thread(ThreadInfo),
    Instruction(InstructionTrace),
    Call(CallTrace),
    JniCall(JNICall),
    MemoryWrite { step, thread_id, address, data },
    MemoryRead { step, thread_id, address, size },
    Sync(ThreadSyncEvent),
    ContextSwitch(ContextSwitch),
    StateChange(ThreadStateChange),
}

pub trait TraceAdapter {
    fn name(&self) -> &str;
    fn supported_trace_types(&self) -> &[&str];
    /// 解析 trace 文本为归一化事件流。so_base_addr 用于把绝对地址转 SO 偏移。
    fn parse(&self, trace_type: &str, input: &str, so_base_addr: u64)
        -> Result<(Vec<TraceEvent>, ImportStats), ParseError>;
}
```

> 与早期规划的 `import(&mut SoTraceDB)` 不同，当前设计不耦合 DB 抽象（持久化层未就绪），改为产出事件流，由消费方决定如何写入。

### 4.2 Frida Trace Adapter

**实现状态**：✅ 已实现（`FridaAdapter`，stalker / interceptor / jnitrace 三种格式，20 个单元测试）。

#### 支持的输入格式

| 格式 | 描述 | 优先级 | 状态 |
|------|------|--------|------|
| Frida Stalker 输出 | 指令级 trace，send() 输出的 JSON 行格式 | P0 | ✅ |
| Frida Interceptor 输出 | 函数级 trace，onEnter/onLeave 回调 | P0 | ✅ |
| jnitrace 输出 | JNI API 调用 trace（`async` payload 包装） | P1 | ✅ |
| Frida 脚本自定义输出 | 用户自定义格式的 trace | P2 | ⏳ |

#### 输入格式

Adapter 接受两种 JSON 行包装：
1. Frida `send()` host 端格式：`{"type":"send","payload":{...事件...}}`
2. 裸事件对象（每行一个）：`{"type":"inst","tid":100,"pc":"0x7fff1000"}`

按内层 `type` 派发：`inst`→Instruction、`call`/`return`→Call、`memwrite`/`memread`→Memory、`sync`→Sync、`switch`→ContextSwitch、`thread`→Thread、`async`→jnitrace 记录。

地址解析支持数字、负 i64（高位地址的符号 reinterpretation）、`0x` 十六进制字符串。`so_base_addr` 非零时把绝对地址转为 SO 相对偏移。

#### CLI 用法

```bash
# Frida Stalker trace，SO 加载基址 0x7fff0000（地址自动转偏移）
sotrace analyze stalker.jsonl --format frida-stalker --base-addr 0x7fff0000

# jnitrace 输出
sotrace analyze jni.jsonl --format jnitrace
```

#### Frida Stalker 输出解析

Frida Stalker 典型输出格式：

```javascript
// Frida 脚本示例
Stalker.follow(tid, {
    transform: function(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            iterator.putCallout(function(context) {
                send({
                    type: 'inst',
                    tid: tid,
                    pc: context.pc,
                    sp: context.sp,
                    // 可选：寄存器、内存访问
                });
            });
        }
    }
});
```

**Adapter 需要处理的问题**：
- Frida send() 输出是 JSON 行格式，需要流式解析
- 地址是运行时绝对地址，需要减去 SO 加载基地址转换为 SO 偏移
- 线程 ID 需要映射
- 时间戳精度取决于 Frida 版本

### 4.3 Unidbg Trace Adapter

**实现状态**：✅ 已实现（`UnidbgAdapter`，`jsonl` 与 `text` 两种输入模式）。

Unidbg 的 tracing 能力主要通过 Java callback 暴露，官方没有一个稳定、版本化的 trace 文件格式。因此项目推荐在 callback 中输出“每行一个 JSON 事件”的归一化协议，再使用 `--format unidbg` 导入。`AssemblyCodeDumper`、`TraceMemoryHook` 以及自定义 listener 的常见人类可读输出则可使用 `--format unidbg-text` 做最佳努力解析。

#### 推荐 JSONL 协议

每行是一个事件对象，也接受 Frida 风格的 `send`/`message` 包装：

```json
{"type":"instruction","seq":1,"tid":7,"address":"0x71001000","opcode":[210,128,0,0]}
{"type":"memory_read","seq":2,"tid":7,"address":"0x71002000","size":4}
{"type":"memory_write","seq":3,"tid":7,"address":"0x71002004","size":2,"value":"0x1234"}
{"type":"jni_call","seq":4,"tid":7,"direction":"j2n","java_class":"com.example.Native","java_method":"run","signature":"()V","native_address":"0x71001100"}
{"type":"sync","seq":5,"tid":7,"op":"mutex_lock","addr":"0x72001000","result":"ok"}
```

支持的事件包括 instruction、memory read/write、call/return、thread、JNI、同步、context switch、thread state change 和 register delta。事件字段可使用 `tid` 或 `thread_id`，地址支持十进制及 `0x` 十六进制字符串；传入 `--base-addr` 后，SO 内地址会统一转换为相对偏移。例如 `0x71001000 - 0x71000000 = 0x1000`。内存写入的整数值按小端序编码。

```bash
# Unidbg callback JSONL，运行时 SO 基址转换为 SO-relative offset
sotrace analyze unidbg.jsonl --format unidbg --base-addr 0x71000000
sotrace trace-save unidbg.jsonl --format unidbg --base-addr 0x71000000

# 兼容 AssemblyCodeDumper / TraceMemoryHook 文本输出
sotrace query unidbg.txt --format unidbg-text threads
```

#### 文本 fallback 的边界

文本模式可识别带地址的反汇编行（例如 `0x71001000: mov x0, x1`）、常见 memory read/write 行，以及简单的 `call`/`return` 行。由于这类输出通常没有稳定的 OS tid、统一序号、JNI 元数据或同步结构，缺少显式 `tid`/`thread_id` 时默认归入线程 1，JNI/同步等结构化信息也无法保证完整。需要线程精确分析、可靠 JNI 关联或完整事件回放时，应由 callback 生成 JSONL。

### 4.4 DynamoRIO Trace Adapter（P2）

- 支持 DynamoRIO 的 drcov2 和自定义 trace 输出
- 支持 basic block trace 和指令级 trace

### 4.5 strace Adapter（P2）

- 解析 strace 输出的系统调用记录
- 关联系统调用号与名称

---

## 5. 查询接口层 — 详细功能规格

### 5.1 核心 Query API

```rust
impl SoTraceDB {
    // === 指令 Trace 查询 ===
    
    /// 按地址查询指令执行记录
    fn query_instructions_by_address(
        &self, so_id: u64, address: u64
    ) -> Result<Vec<InstructionRecord>>;
    
    /// 按地址范围查询
    fn query_instructions_by_address_range(
        &self, so_id: u64, start: u64, end: u64
    ) -> Result<Vec<InstructionRecord>>;
    
    /// 按时序号范围查询
    fn query_instructions_by_seq_range(
        &self, so_id: u64, start_seq: u64, end_seq: u64
    ) -> Result<Vec<InstructionRecord>>;
    
    /// 按函数查询
    fn query_instructions_by_function(
        &self, so_id: u64, func_id: u64
    ) -> Result<Vec<InstructionRecord>>;
    
    // === 调用链查询 ===
    
    /// 查询谁调用了指定函数
    fn query_callers(
        &self, so_id: u64, func_id: u64
    ) -> Result<Vec<CallRecord>>;
    
    /// 查询指定函数调用了谁
    fn query_callees(
        &self, so_id: u64, func_id: u64
    ) -> Result<Vec<CallRecord>>;
    
    /// 重建指定时序号处的调用栈
    fn rebuild_call_stack(
        &self, so_id: u64, seq: u64
    ) -> Result<Vec<StackFrame>>;
    
    /// 查询函数的完整调用链
    fn query_call_chain(
        &self, so_id: u64, func_id: u64
    ) -> Result<CallTree>;
    
    // === 内存状态查询 ===
    
    /// 查询指定地址在指定时序号处的值
    fn query_memory_value(
        &self, so_id: u64, address: u64, seq: u64
    ) -> Result<Vec<u8>>;
    
    /// 重建指定时序号处的完整内存快照
    fn rebuild_memory_snapshot(
        &self, so_id: u64, seq: u64
    ) -> Result<MemorySnapshot>;
    
    /// 查询指定地址范围的内存变化历史
    fn query_memory_history(
        &self, so_id: u64, address: u64, start_seq: u64, end_seq: u64
    ) -> Result<Vec<MemoryChangeRecord>>;
    
    /// 查询哪些指令读写了指定地址
    fn query_memory_accessors(
        &self, so_id: u64, address: u64
    ) -> Result<Vec<MemoryAccessRecord>>;
    
    // === 寄存器查询 ===
    
    /// 查询指定时序号处的寄存器值
    fn query_registers(
        &self, so_id: u64, seq: u64
    ) -> Result<RegisterState>;
    
    /// 查询指定寄存器的变化历史
    fn query_register_history(
        &self, so_id: u64, reg_index: u32, start_seq: u64, end_seq: u64
    ) -> Result<Vec<RegisterChange>>;
    
    // === JNI 查询 ===
    
    /// 查询指定 Java 方法的 JNI 调用
    fn query_jni_calls_by_java_method(
        &self, so_id: u64, class: &str, method: &str
    ) -> Result<Vec<JNICallRecord>>;
    
    /// 查询指定 Native 函数被哪些 Java 方法调用
    fn query_jni_callers(
        &self, so_id: u64, native_func_id: u64
    ) -> Result<Vec<JNICallRecord>>;
}
```

### 5.2 CLI 工具

> **当前实现**：
> - `sotrace analyze <trace.json>` 已实现（内存态导入 + 线程分析），支持 `--format native|frida-stalker|frida-interceptor|jnitrace|unidbg|unidbg-text`、`--base-addr 0x...`、`--only races|deadlocks|contentions|safety`、`--json` 输出。
> - `sotrace analyze` 新增 `--so <libtest.so>` 选项：解析 ELF 并把函数地址→名称映射注册进引擎，使分析结果（ThreadFunctionAssoc / FunctionThreadSafety）带上函数名而非裸地址。stripped SO 会自动 fallback 到 `.dynsym`（obj.exports()/imports()）恢复导出函数表。
> - `sotrace import-so <libtest.so>` 已实现（内存态）：打印架构、build_id、sha256、段/符号/函数数量、JNI/导出计数、样本函数。**尚未持久化**——SO 元数据只在进程内，依赖持久化层落地。
> - 下方 `import-frida` / `query *` 仍依赖持久化层，待 Phase 2 落地。

```bash
# 导入 SO 文件
sotrace import-so /path/to/libtest.so --base-addr 0x7f000000

# 导入 Frida trace
sotrace import-frida trace.jsonl --so libtest.so

# 分析 Frida Stalker / jnitrace / Unidbg trace（已实现，无需持久化）
sotrace analyze stalker.jsonl --format frida-stalker --base-addr 0x7fff0000
sotrace analyze jni.jsonl --format jnitrace --only races --json
sotrace analyze unidbg.jsonl --format unidbg --base-addr 0x71000000

# 查询指令
sotrace query instructions --so libtest.so --address 0x1234
sotrace query instructions --so libtest.so --function decrypt --range 1000..5000

# 查询调用链
sotrace query callers --so libtest.so --function decrypt
sotrace query call-stack --so libtest.so --seq 500000

# 查询内存
sotrace query memory --so libtest.so --address 0xABCD --seq 500000
sotrace query memory-history --so libtest.so --address 0xABCD --range 1000..5000

# 查询寄存器
sotrace query registers --so libtest.so --seq 500000

# 查询 JNI
sotrace query jni-calls --so libtest.so --java-class com.example.App --method nativeFunc

# 统计信息
sotrace stats --so libtest.so
```

---

## 6. 性能指标与约束

### 6.1 写入性能

| 指标 | 目标 | 测量方式 |
|------|------|----------|
| 指令 trace 写入 | ≥ 100 万条/秒 | 批量写入，batch_size=10000 |
| 调用 trace 写入 | ≥ 50 万条/秒 | 批量写入 |
| 内存 delta 写入 | ≥ 30 万条/秒 | 含编码和压缩 |
| 寄存器 delta 写入 | ≥ 100 万条/秒 | 批量写入 |

### 6.2 查询性能

| 指标 | 目标 | 条件 |
|------|------|------|
| 按地址查询指令 | < 10ms | 有索引 |
| 按函数查询指令 | < 50ms | 有索引 |
| 时序号范围查询 | < 100ms / 10万条 | 顺序扫描 |
| 调用栈重建 | < 50ms | 嵌套集合索引 |
| 单地址内存值查询 | < 100ms | checkpoint + delta 回溯 |
| 完整内存快照重建 | < 5s | 50MB 进程内存 |
| 寄存器值查询 | < 10ms | 有索引 |

### 6.3 存储规模

| 指标 | 目标 |
|------|------|
| 单次 trace 最大记录数 | ≥ 10 亿条 |
| 单个数据库最大大小 | ≥ 100GB |
| 单次 trace 压缩后大小 | ≤ 原始文本的 1/10 |

---

## 7. MVP 功能范围确认

### MVP 必须交付（Phase 1）

| # | 功能 | 优先级 |
|---|------|--------|
| 1 | SO 文件 ELF 解析和元数据存储 | P0 |
| 2 | 指令 trace 列式存储 + 压缩 | P0 |
| 3 | 调用 trace 存储 | P0 |
| 4 | 内存状态增量存储（Checkpoint + BYTE_LEVEL Delta） | P0 |
| 5 | 寄存器 delta 存储 | P0 |
| 6 | 基础查询 API（按地址/函数/时序号） | P0 |
| 7 | 内存值查询（单地址 + 快照重建） | P0 |
| 8 | Frida trace 导入 adapter | P0 |
| 9 | Unidbg trace 导入 adapter（JSONL + text fallback） | P1 |
| 10 | CLI 工具 | P0 |

### MVP 明确不做

| # | 不做 | 原因 |
|---|------|------|
| 1 | bsdiff/VCDIFF 页内差分 | 复杂度高，BYTE_LEVEL 已满足基本需求 |
| 2 | JNI trace 存储 | 非核心，Phase 2 |
| 3 | DynamoRIO/Pin adapter | 非核心，Phase 2 |
| 4 | 查询语言 | 非核心，Phase 3 |
| 5 | Python binding | 非核心，Phase 4 |
| 6 | IDA/Ghidra 插件 | 非核心，Phase 3 |
| 7 | 自适应 checkpoint 间隔 | 优化项，Phase 2 |
| 8 | 浮点/SIMD 寄存器 | 非核心需求 |
