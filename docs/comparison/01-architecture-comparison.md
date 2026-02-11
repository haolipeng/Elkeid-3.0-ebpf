# Elkeid eBPF 驱动 - 新旧版本架构对比

> 本文档对比 Elkeid 3.0 eBPF 驱动与旧版本的整体架构差异

---

## 1. 版本信息

| 项目 | 旧版本 | 新版本 |
|-----|-------|-------|
| 版本号 | 1.7.x / 1.8.x / 1.9.x | **3.0.0.7** |
| 代码位置 | `/home/work/Elkeid/driver` | `/home/work/Elkeid-3.0-ebpf/driver` |
| 主要语言 | C | **C + Rust** |
| 构建系统 | Makefile | Makefile + Cargo |

---

## 2. 目录结构对比

### 2.1 旧版本目录结构

```
/home/work/Elkeid/driver/
├── BPF/                          # eBPF 程序
│   ├── hids.bpf.c               # 主 eBPF 程序 (3187行)
│   ├── driver.bpf.c             # 备用 eBPF 程序 (278行)
│   ├── driver.btf.c             # BTF 信息 (11738行)
│   ├── consume.c                # 用户态消费 (2916行)
│   ├── xfer.c                   # 事件反序列化 (12309行)
│   ├── hids/                    # 头文件
│   │   ├── hids.h
│   │   ├── vmlinux.h
│   │   ├── kprobe_print.h       # 事件格式定义
│   │   ├── xfer.h               # 序列化定义
│   │   └── anti_rootkit_print.h
│   ├── helper/                  # 辅助函数库
│   │   ├── trace_helpers.c/h
│   │   ├── syscall_helpers.c/h
│   │   ├── btf_helpers.c/h
│   │   ├── map_helpers.c/h
│   │   ├── uprobe_helpers.c/h
│   │   └── errno_helpers.c/h
│   └── kernel/                  # 内核头文件
│       ├── x86/vmlinux-*.h
│       ├── arm64/vmlinux-*.h
│       └── libbpf/include/
├── LKM/                         # 内核模块 (Kprobe)
├── DOC/                         # 文档
├── dockerfiles/                 # Docker 构建
└── batch_compile*.sh            # 批量编译脚本
```

### 2.2 新版本目录结构

```
/home/work/Elkeid-3.0-ebpf/driver/
├── BPF/                          # eBPF 程序
│   ├── hids.c                   # 主 eBPF 程序 (3591行) ★ 重构
│   └── inc/
│       ├── bpf/                 # libbpf 头文件
│       └── hids/                # HIDS 头文件
│           ├── vmlinux.h
│           ├── kprobe_print.h   # 事件格式定义
│           └── anti_rootkit_print.h
├── ebpf/                        # ★ 新增: 用户态 eBPF 管理
│   ├── load.c                   # eBPF 加载器 (8239行)
│   ├── consume.c                # 事件消费 (17437行)
│   ├── helper/                  # 辅助函数
│   └── hids/                    # 头文件
├── rust/                        # ★ 新增: Rust FFI 层
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs               # 主入口 (851行)
│       ├── bindings.rs          # C 绑定
│       └── build.rs             # 构建脚本
├── ring/                        # ★ 新增: 环形缓冲区抽象
│   ├── core.c                   # 版本兼容层 (236行)
│   ├── kmod.c                   # LKM 对接 (1619行)
│   └── safeboot.c               # 安全启动 (179行)
├── zua/                         # ★ 新增: JSON 解析器
│   ├── zua_parser.c/h           # 语法解析 (1775行)
│   ├── zua_scanner.c/h          # 词法扫描 (732行)
│   ├── zua_type.c/h             # 类型系统 (594行)
│   └── hashmap.h                # 哈希表实现
├── xfer/                        # ★ 重构: 事件序列化
│   ├── xfer.c                   # 反序列化实现 (479行)
│   ├── xfer.h                   # 格式定义 (751行)
│   └── ring.h                   # Ring API 定义
├── libbpf/                      # libbpf 库
├── LKM/                         # 内核模块
├── test/                        # 测试程序
├── debian/                      # Debian 打包
├── Makefile                     # 主构建文件
└── VERSION                      # 版本文件: 3.0.0.7
```

---

## 3. 架构演进图

### 3.1 旧版本架构

```
┌──────────────────────────────────────────────────────────��──┐
│                      用户态应用                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    consume.c (C 语言)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ libbpf 加载 │  │ perf_buffer │  │ xfer.c 反序列化     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                    perf_event_output
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  内核态 eBPF 程序                            │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              hids.bpf.c (单文件)                     │   │
│  │  ├─ Kprobe hooks                                    │   │
│  │  ├─ Raw Tracepoint hooks                            │   │
│  │  ├─ BPF Maps (PERF_EVENT_ARRAY)                     │   │
│  │  └─ 事件序列化 (内联宏)                               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 新版本架构

```
┌─────────────────────────────────────────────────────────────┐
│                      用户态应用                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Rust FFI 层 (rust/lib.rs)                  │
│  ┌───────────────┐  ┌────────────────┐  ┌───────────────┐  │
│  │ RingSlot      │  │ SmithControl   │  │ EBPFConsumer  │  │
│  │ (数据采集)    │  │ (访问控制)      │  │ (eBPF消费)    │  │
│  └───────┬───────┘  └───────┬────────┘  └───────┬───────┘  │
└──────────┼──────────────────┼───────────────────┼───────────┘
           │                  │                   │
           ▼                  ▼                   ▼
┌─────────────────────────────────────────────────────────────┐
│              Ring 抽象层 (ring/core.c)                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ struct tb_ring_operations *g_ring_ops                 │  │
│  │  ├─ v1.7 ops   (历史兼容)                             │  │
│  │  ├─ v1.8 ops   (历史兼容)                             │  │
│  │  ├─ v1.9 ops   (LKM 主版本)                           │  │
│  │  └─ eBPF ops   (新 eBPF 版本)                         │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
           │                  │                   │
           ▼                  ▼                   ▼
┌──────────────────┐ ┌─────────────────┐ ┌────────────────────┐
│ ring/kmod.c      │ │ zua/ 解析器     │ │ ebpf/load.c        │
│ (LKM 数据采集)   │ │ (JSON 规则解析) │ │ (eBPF 加载)        │
└──────────────────┘ └─────────────────┘ └────────────────────┘
           │                                      │
           │              xfer/xfer.c             │
           │         (事件反序列化)                │
           ▼                                      ▼
┌─────────────────────────────────────────────────────────────┐
│                        内核态                                │
│  ┌─────────────────────┐    ┌─────────────────────────┐    │
│  │  LKM 内核模块       │    │   eBPF 程序             │    │
│  │  (ring buffer)      │    │   (BPF/hids.c)          │    │
│  └─────────────────────┘    └─────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. 核心改进点

### 4.1 模块化设计

| 改进点 | 旧版本 | 新版本 |
|-------|-------|-------|
| **代码组织** | 单一 BPF/ 目录 | 按功能拆分 (BPF/, ebpf/, ring/, xfer/, zua/, rust/) |
| **语言选择** | 纯 C | C (内核/底层) + Rust (用户态接口) |
| **配置解析** | 简单字符串处理 | ZUA JSON5 解析器 |
| **版本兼容** | 每版本单独维护 | Ring 抽象层统一管理 |

### 4.2 Rust FFI 层优势

```rust
// 类型安全的访问控制
pub struct SmithControl {
    ring_type: i32,
    trace_path: String,
}

impl SmithControl {
    // 白名单管理
    pub fn ac_add_allow_exe(&self, path: &str) -> Result<()>;
    pub fn ac_add_allow_argv(&self, argv: &str) -> Result<()>;

    // 黑名单管理
    pub fn ac_set_block_md5(&self, json_path: &str) -> Result<()>;
    pub fn ac_set_block_dns(&self, json_path: &str) -> Result<()>;

    // PSAD 防护
    pub fn psad_enable(&self) -> Result<()>;
    pub fn psad_add_allowlist_ipv4(&self, ip: u32, mask: u32) -> Result<()>;
}
```

### 4.3 版本兼容抽象

```c
// ring/core.c - 版本魔数定义
#define RING_KMOD_V1_7  (0x5254174B)  // hids_driver/ash
#define RING_KMOD_V1_8  (0x5254184B)  // smith
#define RING_KMOD_V1_9  (0x5254194B)  // elkeid
#define RING_EBPF       (0x52540045)  // ebpf

// 运行时版本选择
struct tb_ring_operations {
    int type;
    int (*ring_init)(int type, char *trace);
    int (*ring_fini)(int type);
    int (*ring_read)(char *msg, int len, int (*cb)(int *), int *ctx);
    // ... 访问控制函数指针
};
```

---

## 5. 代码规模对比

### 5.1 核心代码行数

| 模块 | 旧版本 | 新版本 | 变化 |
|-----|-------|-------|-----|
| **eBPF 主程序** | 3,187 行 | 3,591 行 | +12.7% |
| **用户态消费** | 2,916 行 | 17,437 行 | +498% |
| **事件序列化** | 12,309 行 | 1,230 行 | -90% (重构优化) |
| **eBPF 加载** | (含消费中) | 8,239 行 | 独立模块 |

### 5.2 新增模块代码量

| 新增模块 | 代码行数 | 说明 |
|---------|---------|------|
| **rust/** | 851 行 | Rust FFI 层 |
| **zua/** | 3,101 行 | JSON 解析器 |
| **ring/** | 2,034 行 | 环形缓冲区抽象 |
| **xfer/** (重构) | 1,230 行 | 事件序列化 |
| **合计** | **7,216 行** | 新增基础设施 |

### 5.3 总代码量对比

```
旧版本 BPF 相关代码：约 30,000 行
新版本 Driver 代码：约 45,000 行

增长原因：
1. Rust FFI 层 (+851 行) - 类型安全接口
2. ZUA 解析器 (+3,101 行) - 灵活配置支持
3. Ring 抽象层 (+2,034 行) - 多版本兼容
4. 用户态重构 (+14,000 行) - 功能增强
```

---

## 6. 数据流对比

### 6.1 旧版本数据流

```
内核事件
    │
    ▼
┌─────────────────┐
│ hids.bpf.c      │  Kprobe/Tracepoint 触发
│ 事件序列化      │  SD_XFER_* 宏展开
└────────┬────────┘
         │ bpf_perf_event_output()
         ▼
┌─────────────────┐
│ PERF_EVENT_ARRAY│  Per-CPU 环形缓冲
└────────┬────────┘
         │ perf_buffer__poll()
         ▼
┌─────────────────┐
│ consume.c       │  事件回调
│ xfer.c          │  反序列化
└────────┬────────┘
         │
         ▼
    用户态处理
```

### 6.2 新版本数据流

```
内核事件
    │
    ▼
┌─────────────────┐
│ BPF/hids.c      │  Raw Tracepoint 优先
│ 事件序列化      │  SD_XFER_* 宏展开
└────────┬────────┘
         │ bpf_perf_event_output()
         ▼
┌─────────────────┐
│ PERF_EVENT_ARRAY│  Per-CPU 环形缓冲
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ ebpf/consume.c  │  事件消费
│ xfer/xfer.c     │  反序列化
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ ring/core.c     │  版本抽象层
│ 统一接口        │  tb_read_ebpf() / tb_read_kmod()
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ rust/lib.rs     │  Rust FFI
│ RingSlot        │  类型安全封装
│ EBPFConsumer    │
└────────┬────────┘
         │
         ▼
    用户态应用 (Rust/Go/Python)
```

---

## 7. 构建系统对比

### 7.1 旧版本构建

```makefile
# 单一 Makefile
make -C BPF/
# 输出: hids.bpf.o, consume 可执行文件
```

### 7.2 新版本构建

```makefile
# 主 Makefile 协调多模块
make           # 编译所有 C 模块

# Cargo 构建 Rust 模块
cargo build --release

# 依赖关系:
# rust/build.rs 聚合编译:
#   - ring/*.c
#   - zua/*.c
#   - xfer/*.c
#   - ebpf/*.c
# 生成 libringslot.a 静态库
```

---

## 8. 总结

### 8.1 架构改进亮点

1. **模块化分层**：将单一代码库拆分为功能明确的模块
2. **语言混合**：C 用于底层性能，Rust 用于用户态安全
3. **版本兼容**：Ring 抽象层支持 v1.7 到 v1.9 及 eBPF
4. **配置灵活**：ZUA JSON 解析器支持复杂规则配置
5. **可维护性**：代码职责清晰，易于测试和扩展

### 8.2 技术栈演进

```
旧版本:  C (全栈) + libbpf
         │
         ▼
新版本:  Rust (用户接口)
         ├─ C (ring/zua/xfer 基础层)
         ├─ C (ebpf 用户态管理)
         ├─ C (BPF 内核态程序)
         └─ libbpf (eBPF 工具链)
```

### 8.3 向后兼容策略

新版本通过 Ring 抽象层保持对旧版 LKM 驱动的兼容：

- **v1.7 兼容**：hids_driver / ash 格式
- **v1.8 兼容**：smith 格式
- **v1.9 兼容**：elkeid LKM 格式
- **eBPF 新增**：纯 eBPF 数据通道

---

*下一篇: [02-new-modules-analysis.md](./02-new-modules-analysis.md) - 新增模块详解*
