# Elkeid 3.0 新增模块详解

> 本文档详细解读 Elkeid 3.0 eBPF 驱动新增的四个核心模块

---

## 模块概览

| 模块 | 代码行数 | 主要文件 | 设计目的 |
|------|---------|---------|---------|
| **rust/** | 851 行 | lib.rs, bindings.rs, build.rs | Rust 语言绑定与 FFI 包装 |
| **zua/** | 3,101 行 | zua_parser.c, zua_scanner.c, zua_type.c | JSON/JSON5 解析引�� |
| **ring/** | 2,034 行 | core.c, kmod.c, safeboot.c | 环形缓冲区与多版本兼容 |
| **xfer/** | 1,230 行 | xfer.c, xfer.h, ring.h | 事件数据序列化/反序列化 |
| **总计** | **7,216 行** | | 完整的数据采集与控制框架 |

---

## 1. Rust 模块 (`rust/`)

### 1.1 模块定位

Rust 模块是新版本的**用户态 API 入口**，为上层应用提供类型安全、内存安全的接口封装。

### 1.2 文件结构

```
rust/
├── Cargo.toml           # 项目配置
└── src/
    ├── lib.rs           # 主入口 (851行)
    ├── bindings.rs      # C 绑定定义
    └── build.rs         # 构建脚本
```

### 1.3 核心结构体

#### RingSlot - LKM 数据采集器

```rust
/// LKM 数据采集接口
pub struct RingSlot {
    control: Arc<AtomicBool>,    // 原子控制标志
    buf: [u8; 64 * 1024],        // 64KB 接收缓冲区
}

impl RingSlot {
    /// 初始化 LKM 驱动连接
    /// 支持 v1.7/v1.8/v1.9 版本自动检测
    pub fn new(ring_type: i32, trace_path: &str) -> Result<(Self, DropGuard)>;

    /// 读取单条记录（阻塞）
    pub fn read_record(&mut self) -> Result<&[u8]>;

    /// 检查是否已取消
    pub fn canceled(&self) -> bool;
}
```

**使用示例**：
```rust
let (mut ring, _guard) = RingSlot::new(
    RING_KMOD_V1_9,
    "/sys/module/elkeid/parameters/control_trace"
)?;

loop {
    match ring.read_record() {
        Ok(data) => process_event(data),
        Err(e) => break,
    }
}
```

#### SmithControl - 访问控制管理器

```rust
/// 访问控制接口
pub struct SmithControl {
    ring_type: i32,
    trace_path: String,
}

impl SmithControl {
    // ========== 白名单管理 ==========

    /// 添加可执行文件白名单
    pub fn ac_add_allow_exe(&self, exe_path: &str) -> Result<()>;

    /// 添加命令行白名单
    pub fn ac_add_allow_argv(&self, argv: &str) -> Result<()>;

    /// 删除可执行文件白名单
    pub fn ac_del_allow_exe(&self, exe_path: &str) -> Result<()>;

    /// 删除命令行白名单
    pub fn ac_del_allow_argv(&self, argv: &str) -> Result<()>;

    /// 查询可执行文件白名单
    pub fn ac_query_allow_exe(&self) -> Result<Vec<String>>;

    /// 查询命令行白名单
    pub fn ac_query_allow_argv(&self) -> Result<Vec<String>>;

    // ========== 黑名单管理 ==========

    /// 设置 MD5 黑名单（从 JSON 文件加载）
    pub fn ac_set_block_md5(&self, json_path: &str) -> Result<()>;

    /// 设置执行阻止规则（支持通配符）
    pub fn ac_set_block_exe_argv(&self, json_path: &str) -> Result<()>;

    /// 设置 DNS 黑名单
    pub fn ac_set_block_dns(&self, json_path: &str) -> Result<()>;

    // ========== PSAD 端口扫描防护 ==========

    /// 启用 PSAD
    pub fn psad_enable(&self) -> Result<()>;

    /// 禁用 PSAD
    pub fn psad_disable(&self) -> Result<()>;

    /// 设置 PSAD 标志
    pub fn psad_set_flag(&self, flags: u32) -> Result<()>;

    /// 添加 IPv4 白名单
    pub fn psad_add_allowlist_ipv4(&self, ip: u32, mask: u32) -> Result<()>;

    /// 添加 IPv6 白名单
    pub fn psad_add_allowlist_ipv6(&self, ip: &[u8; 16], prefix: u32) -> Result<()>;

    // ========== 自保护 ==========

    /// 启用自保护
    pub fn self_protection_enable(&self) -> Result<()>;

    /// 禁用自保护
    pub fn self_protection_disable(&self) -> Result<()>;
}
```

#### EBPFConsumer - eBPF 数据消费者

```rust
/// eBPF 程序数据消费
pub struct EBPFConsumer {
    // 内部状态
}

impl EBPFConsumer {
    /// 初始化 eBPF 消费者
    pub fn new() -> Result<Self>;

    /// 读取事件记录
    pub fn read_record(&mut self) -> Result<&[u8]>;
}
```

#### EBPFLoader - eBPF 程序加载器

```rust
/// eBPF 程序加载
pub struct EBPFLoader {
    // 内部状态
}

impl EBPFLoader {
    /// 加载 eBPF 程序
    pub fn load(obj_path: &str) -> Result<Self>;

    /// 查询版本
    pub fn version(&self) -> &str;
}
```

### 1.4 构建脚本 (build.rs)

```rust
// 聚合编译所有 C 模块
fn main() {
    cc::Build::new()
        // Ring 模块
        .file("../ring/core.c")
        .file("../ring/kmod.c")
        .file("../ring/safeboot.c")
        // ZUA 模块
        .file("../zua/zua_parser.c")
        .file("../zua/zua_scanner.c")
        .file("../zua/zua_type.c")
        // XFER 模块
        .file("../xfer/xfer.c")
        // eBPF 模块
        .file("../ebpf/load.c")
        .file("../ebpf/consume.c")
        // 编译选项
        .include("../xfer")
        .include("../ring")
        .include("../zua")
        .compile("ringslot");
}
```

### 1.5 关键依赖

```toml
[dependencies]
libbpf-sys = "1.3.0"     # libbpf 底层绑定
libc = "0.2"             # C 标准库绑定
anyhow = "1"             # 错误处理
```

---

## 2. ZUA 模块 (`zua/`) - JSON 解析引擎

### 2.1 模块定位

ZUA 是一个轻量级、高性能的 **JSON/JSON5 解析器**，用于解析访问控制规则配置。

### 2.2 文件结构

```
zua/
├── zua_parser.c         # Bison 生成的语法解析器 (1,775行)
├── zua_parser.h         # 解析器头文件
├── zua_parser_defs.h    # 解析器定义
├── zua_scanner.c        # 词法扫描器 (732行)
├── zua_scanner.h        # 扫描器头文件
├── zua_scanner_defs.h   # 扫描器定义
├── zua_type.c           # 值类型系统 (594行)
├── zua_type.h           # 类型定义头文件
├── hashmap.h            # 哈希表实现
└── Makefile             # 构建脚本
```

### 2.3 核心组件

#### 词法扫描器 (Scanner)

```c
// 扫描器状态结构
typedef struct _zua_json_scanner {
    zua_json_ctype *cursor;     // 当前扫描位置
    zua_json_ctype *token;      // 当前 token 起始
    zua_json_ctype *str_start;  // 字符串起始位置
    zval value;                 // 解析出的值
    int state;                  // 当前状态
    int errcode;                // 错误码
} zua_json_scanner;

// Token 类型枚举
enum {
    ZUA_TK_NUL,                 // null
    ZUA_TK_NAN,                 // NaN (JSON5)
    ZUA_TK_INFINITY,            // Infinity (JSON5)
    ZUA_TK_NEGATIVE_INFINITY,   // -Infinity (JSON5)
    ZUA_TK_TRUE,                // true
    ZUA_TK_FALSE,               // false
    ZUA_TK_INT,                 // 整数
    ZUA_TK_DOUBLE,              // 浮点数
    ZUA_TK_STRING,              // 字符串
    ZUA_TK_ETRING,              // 转义字符串
    ZUA_TK_EOI,                 // 输入结束
    ZUA_TK_ERROR                // 错误
};
```

#### 语法解析器 (Parser)

```c
// Bison/Yacc 生成的 LALR(1) 解析器
// 支持标准 JSON 和 JSON5 扩展语法

// 主要 API
int json_decode(const char *json_str, zval *result);
```

**支持的语法特性**：
- 标准 JSON（RFC 8259）
- JSON5 扩展：
  - `NaN`、`Infinity`、`-Infinity`
  - 单行/多行注释
  - 尾随逗号
  - 单引号字符串

#### 值类型系统 (Type System)

```c
// 值类型枚举
enum {
    IS_NULL,                    // null
    IS_FALSE,                   // false
    IS_TRUE,                    // true
    IS_LONG,                    // 64位整数
    IS_DOUBLE,                  // 双精度浮点
    IS_STRING,                  // 字符串
    IS_ARRAY,                   // 数组
    IS_OBJECT,                  // 对象
    IS_NAN,                     // NaN
    IS_INFINITY,                // Infinity
    IS_NEGATIVE_INFINITY        // -Infinity
};

// 值联合体
union _zua_value {
    long lval;                  // 整数值
    double dval;                // 浮点值
    zua_string *str;            // 字符串指针
    zua_array *arr;             // 数组（hashmap）
    zua_object *obj;            // 对象（hashmap）
};

// 完整值结构
typedef struct _zval {
    union _zua_value value;
    int type;
} zval;
```

### 2.4 主要 API

```c
// 初始化扫描器
void zua_json_scanner_init(zua_json_scanner *s, const char *str, size_t len);

// 获取下一个 token
int zua_json_scan(zua_json_scanner *s);

// 解析 JSON 字符串
int json_decode(const char *json_str, zval *result);

// 编码为 JSON 字符串
char *json_encode(zval *val);
char *json_encode_pretty(zval *val);  // 格式化输出

// 路径查询（如 "data.items[0].name"）
zval *zua_get_value_by_path(zval *root, const char *path);

// 内存管理
void zval_free(zval *val);
```

### 2.5 使用场景

```c
// 解析 MD5 黑名单配置
const char *json = R"({
    "md5_list": [
        "d41d8cd98f00b204e9800998ecf8427e",
        "098f6bcd4621d373cade4e832627b4f6"
    ],
    "enabled": true
})";

zval result;
if (json_decode(json, &result) == 0) {
    zval *md5_list = zua_get_value_by_path(&result, "md5_list");
    // 处理 MD5 列表...
    zval_free(&result);
}
```

---

## 3. Ring 模块 (`ring/`) - 环形缓冲区抽象层

### 3.1 模块定位

Ring 模块是**版本兼容层**，为不同版本的 LKM 驱动和 eBPF 程序提供统一的数据采集接口。

### 3.2 文件结构

```
ring/
├── core.c               # 版本兼容层 (236行)
├── kmod.c               # LKM 驱动对接 (1,619行)
└── safeboot.c           # 安全启动功能 (179行)
```

### 3.3 核心设计：版本兼容

#### 版本魔数定义

```c
// ring/core.c
#define RING_KMOD_V1_7  (0x5254174B)  // hids_driver / ash 格式
#define RING_KMOD_V1_8  (0x5254184B)  // smith 格式
#define RING_KMOD_V1_9  (0x5254194B)  // elkeid 格式（当前主版本）
#define RING_EBPF       (0x52540045)  // eBPF 格式（新增）

// 版本类型宏
#define RING_TYPE(x) ((x) & 0xFFFF0000)
#define IS_RING_KMOD(x) (RING_TYPE(x) == 0x52540000)
#define IS_RING_EBPF(x) ((x) == RING_EBPF)
```

#### 操作函数表

```c
// 抽象接口定义
struct tb_ring_operations {
    int type;                                           // 版本类型

    // 数据采集
    int (*ring_init)(int type, char *trace);           // 初始化
    int (*ring_fini)(int type);                        // 清理
    int (*ring_read)(char *msg, int len,               // 读取数据
                     int (*cb)(int *), int *ctx);

    // 访问控制
    int (*ac_init)(int type);                          // AC 初始化
    int (*ac_fini)(int type);                          // AC 清理
    int (*ac_setup)(int type, int op, ...);            // 设置规则
    int (*ac_clear)(int type, int op);                 // 清除规则
    int (*ac_check)(int type, int op, ...);            // 检查规则
    int (*ac_erase)(int type, int op, ...);            // 删除规则
    int (*ac_query)(int type, int op, char *buf, int len); // 查询规则

    // 状态统计
    int (*ring_stat)(int type, ...);                   // 获取统计
    int (*ring_show)(int type, char *buf, int len);    // 显示统计
};

// 版本实现
static struct tb_ring_operations g_ring_v1_7;  // v1.7 实现
static struct tb_ring_operations g_ring_v1_8;  // v1.8 实现
static struct tb_ring_operations g_ring_v1_9;  // v1.9 实现
static struct tb_ring_operations g_ring_ebpf;  // eBPF 实现

// 当前活动版本
static struct tb_ring_operations *g_ring_ops = NULL;
```

### 3.4 统一 API

#### 数据采集接口

```c
// LKM 数据采集
int tb_init_kmod(int type, char *trace);
int tb_fini_kmod(int type);
int tb_read_kmod(char *msg, int len, int (*cb)(int *), int *ctx);
int tb_stat_kmod(int type, uint64_t *produced, uint64_t *consumed, uint64_t *dropped);
int tb_show_kmod(int type, char *buf, int len);

// eBPF 数据采集
int tb_init_ebpf(void);
int tb_fini_ebpf(void);
int tb_read_ebpf(char *msg, int len, int (*cb)(int *), int *ctx);
int tb_load_ebpf(const char *obj_path);
```

#### 访问控制类型

```c
// 白名单类型
#define AL_TYPE_ARGV    (0xA1)  // 命令行白名单
#define AL_TYPE_EXE     (0xA2)  // 可执行文件白名单
#define AL_TYPE_PSAD    (0xA3)  // PSAD IP 白名单
#define AL_EBPF_ARGV    (0xAA)  // eBPF 命令行白名单
#define AL_EBPF_EXE     (0xAE)  // eBPF 可执行文件白名单

// 黑名单类型
#define BL_JSON_DNS     (0xB0)  // DNS 域名黑名单
#define BL_JSON_EXE     (0xB1)  // 执行阻止（支持通配符）
#define BL_JSON_MD5     (0xB2)  // MD5 哈希黑名单
```

#### 访问控制接口

```c
// 初始化/清理
int ac_init(int type);
int ac_fini(int type);

// 规则设置（支持 list 或 JSON 格式）
int ac_setup(int type, int op, ...);
// op = AL_TYPE_*: 添加白名单
// op = BL_JSON_*: 设置黑名单（JSON 文件）

// 规则清除
int ac_clear(int type, int op);

// 规则检查
int ac_check(int type, int op, ...);

// 规则删除
int ac_erase(int type, int op, ...);

// 规则查询
int ac_query(int type, int op, char *buf, int len);
```

### 3.5 LKM 实现细节 (kmod.c)

#### 控制路径

```c
// 不同版本的控制路径
// v1.7: /proc/elkeid-endpoint 或 /proc/smith
// v1.8: /proc/elkeid-endpoint
// v1.9: /sys/module/elkeid/parameters/control_trace (推荐)

// sysfs 参数路径
#define SYSFS_PSAD_SWITCH    "/sys/module/elkeid/parameters/psad_switch"
#define SYSFS_PSAD_FLAGS     "/sys/module/elkeid/parameters/psad_flags"
#define SYSFS_PROTECTOR      "/sys/module/elkeid/parameters/protector_switch"
```

#### 特殊功能

```c
// 二进制格式处理器注册（用于执行监控）
int tb_register_binfmt(void);
int tb_unregister_binfmt(void);

// 卸载前清理
int tb_pre_unload(void);

// 统计信息
typedef struct {
    uint64_t produced;   // 生产的消息数
    uint64_t consumed;   // 消费的消息数
    uint64_t dropped;    // 丢弃的消息数
} tb_ring_stats;
```

### 3.6 安全启动 (safeboot.c)

```c
// 检查安全启动状态
int safeboot_check(void);

// 清除安全启动标志
int safeboot_clear(void);
```

---

## 4. XFER 模块 (`xfer/`) - 事件序列化层

### 4.1 模块定位

XFER 模块定义**事件数据格式**和**序列化/反序列化协议**，是内核态与用户态通信的核心。

### 4.2 文件结构

```
xfer/
├── xfer.h               # 核心数据结构与宏定义 (751行)
├── xfer.c               # 反序列化实现 (479行)
└── ring.h               # Ring API 定义 (150+行)
```

### 4.3 事件格式定义

#### 事件头结构

```c
// 事件格式描述
struct sd_event_format {
    uint32_t size;          // 格式描述总大小
    uint32_t nids;          // 事件类型数量
    /* struct sd_item_ent eids[0]; */  // 事件项数组
};

// 事件项描述
struct sd_item_ent {
    union {
        uint32_t size;      // 数据长度（字节）
        uint32_t meta;      // 元数据头大小
        uint32_t item;      // 元素类型
    };
    union {
        uint32_t xid;       // 事件类型 ID
        uint32_t eid;       // 动态事件序号
        uint32_t len;       // 元素长度
    };
};
```

#### 基本数据类型

```c
// 类型编码（占 4-6 bits）
#define SD_TYPE_U8      (1)     // 无符号 8 位
#define SD_TYPE_S8      (0x41)  // 有符号 8 位 (0x40 | 1)
#define SD_TYPE_U16     (2)     // 无符号 16 位
#define SD_TYPE_S16     (0x42)  // 有符号 16 位
#define SD_TYPE_U32     (3)     // 无符号 32 位
#define SD_TYPE_S32     (0x43)  // 有符号 32 位
#define SD_TYPE_U64     (4)     // 无符号 64 位
#define SD_TYPE_S64     (0x44)  // 有符号 64 位
#define SD_TYPE_IP4     (5)     // IPv4 地址 (4字节)
#define SD_TYPE_IP6     (6)     // IPv6 地址 (16字节)
#define SD_TYPE_IPU     (7)     // 统一 IP 地址结构
#define SD_TYPE_XIDS    (8)     // 凭证集合 (8×u32)
#define SD_TYPE_STR     (9)     // 可变长度字符串
```

### 4.4 IP 地址结构

```c
// IPv4 地址
struct ipaddr_v4 {
    uint32_t addr;
};

// IPv6 地址
struct ipaddr_v6 {
    union {
        uint8_t  v6_addr8[16];
        uint16_t v6_addr16[8];
        uint32_t v6_addr32[4];
    };
};

// 统一 IP 地址描述符
struct ipaddr_ud {
    uint16_t port;          // 端口号
    uint8_t family;         // 地址族 (AF_INET/AF_INET6)
    uint8_t size;           // 地址大小: 0=无, 4=v4, 16=v6
    union {
        struct ipaddr_v4 v4;
        struct ipaddr_v6 v6;
    };
};
```

### 4.5 序列化宏系统

#### 参数计数宏

```c
// 计算变长参数数量（最多支持 69 个）
#define SD_N_ARGS(...)  SD_ARGS_C(__VA_ARGS__, SD_ARGS_S())

// 展开后的序列
#define SD_ARGS_S() \
    69,68,67,66,65,64,63,62,61,60, \
    59,58,57,56,55,54,53,52,51,50, \
    ...
    9,8,7,6,5,4,3,2,1,0
```

#### 事件定义宏

```c
// 定义事件结构
#define SD_XFER_DEFINE(NAME_SPEC, PROT_SPEC, XFER_SPEC) \
    /* 生成事件结构体 */ \
    struct SD_XFER_EVENT_##name { \
        struct sd_item_ent e_head;  /* 事件头 */ \
        uint32_t e_meta;            /* 元数据大小 */ \
        /* 字段数据 */ \
    }; \
    /* 生成序列化函数 */ \
    static __always_inline int SD_XFER_##name(PROT_ARGS) { \
        /* 序列化逻辑 */ \
    }
```

#### 字段打包宏

```c
// 打包事件数据
#define SD_ENTS_PACK_XFER(...) \
    SD_ENTS_PACK_N(SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)

// 字段入口宏
#define ENTRY_COMMON(event_id)  // 通用字段（uid, pid, exe_path 等）
#define ENTRY_INT(name, value)  // 整数字段
#define ENTRY_STR(name, str)    // 字符串字段
#define ENTRY_STL(name, str, len)  // 带长度的字符串
#define ENTRY_IPU(name, ipu)    // IP 地址字段
#define ENTRY_XIDS(name, xids)  // 凭证集合
```

### 4.6 字符串处理模式

```c
// 三种字符串复制模式
#define SD_STR_USR  (0)     // 用户空间字符串（bpf_probe_read_user_str）
#define SD_STR_KSL  (1)     // 内核空间字符串，已知长度
#define SD_STR_USL  (2)     // 用户空间字符串，已知长度
```

### 4.7 反序列化实现 (xfer.c)

#### 核心函数

```c
// 反序列化事件
int sd_unpack(void *de, int sde,    // 目标缓冲区
              void *se, int *rec);   // 源事件数据

// 显示事件（调试）
void sd_show_msg(char *str, int len);

// 十六进制转储
void sd_hexdump(const void *data, size_t size);
```

#### 类型转换函数

```c
// 高性能数值转字符串
int sd_u32toa(uint32_t value, char *buf);  // 比 snprintf 快 3 倍
int sd_u64toa(uint64_t value, char *buf);
int sd_s32toa(int32_t value, char *buf);
int sd_s64toa(int64_t value, char *buf);

// IP 地址转换
int sd_ip4toa(uint32_t ip, char *buf);     // → "192.168.1.1"
int sd_ip6toa(const uint8_t *ip6, char *buf); // → "2001:db8::1"
```

#### 性能优化：预计算查找表

```c
// 2 位十进制数查找表（200 字节）
static const char digit_pairs[200] = {
    '0','0', '0','1', '0','2', '0','3', '0','4',
    '0','5', '0','6', '0','7', '0','8', '0','9',
    '1','0', '1','1', '1','2', // ...
    '9','8', '9','9'
};

// 使用示例
int sd_u32toa(uint32_t value, char *buf) {
    // 每次处理 2 位数字
    while (value >= 100) {
        int idx = (value % 100) * 2;
        *--p = digit_pairs[idx + 1];
        *--p = digit_pairs[idx];
        value /= 100;
    }
    // ...
}
```

---

## 5. 模块间依赖关系

```
┌─────────────────────────────────────────────────────────────┐
│                 用户态应用 (Rust/Go/Python)                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────��───────────────────────────────────────┐
│                    Rust FFI 层 (rust/)                      │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │  RingSlot       │  │ SmithControl │  │ EBPFConsumer   │ │
│  │ (LKM 数据采集)  │  │ (访问控制)   │  │ (eBPF 数据采集)│ │
│  └────────┬────────┘  └──────┬───────┘  └───────┬────────┘ │
└───────────┼──────────────────┼──────────────────┼───────────┘
            │                  │                  │
            ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│              Ring 抽象层 (ring/core.c)                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ struct tb_ring_operations *g_ring_ops                 │  │
│  │  ├─ &g_ring_v1_7  (v1.7 版本)                        │  │
│  │  ├─ &g_ring_v1_8  (v1.8 版本)                        │  │
│  │  ├─ &g_ring_v1_9  (v1.9 版本)  ◄── LKM 主版本       │  │
│  │  └─ &g_ring_ebpf  (eBPF 版本)  ◄── 新增             │  │
│  └───────────────────────────────────────────────────────┘  │
│             │ 数据采集                   │ 规则管理          │
│             ├─ tb_init/read/fini         ├─ ac_setup/clear   │
│             └─ tb_load_ebpf              └─ ac_query/check   │
└──────┬──────────────────────────────┬───────────────────────┘
       │                              │
       ▼ (从 ringbuffer/procfs)       ▼ (JSON 规则解析)
┌──────────────────┐          ┌─────────────────────────────┐
│  XFER 模块       │          │  ZUA 模块                    │
│ (xfer/)          │          │ (zua/)                       │
│                  │          │                              │
│ ├─ sd_unpack()   │          │ ├─ json_decode()            │
│ │  (反序列化)    │          │ │  (解析 JSON)              │
│ ├─ sd_u32toa()   │          │ ├─ json_encode()            │
│ │  (数值转换)    │          │ │  (生成 JSON)              │
│ └─ sd_hexdump()  │          │ └─ zua_get_value_by_path()  │
│    (调试输出)    │          │    (路径查询)               │
└──────────────────┘          └─────────────────────────────┘
       │                              │
       └──────────────┬───────────────┘
                      ▼
            二进制事件流 / JSON 规则
```

---

## 6. 总结

### 6.1 设计亮点

| 模块 | 设计亮点 |
|-----|---------|
| **rust/** | 类型安全、内存安全、自动资源管理 |
| **zua/** | 轻量级、支持 JSON5、零外部依赖 |
| **ring/** | 多版本兼容、运行时版本选择、统一 API |
| **xfer/** | 高性能序列化、预计算查找表、位级打包 |

### 6.2 与旧版本对比

| 方面 | 旧版本 | 新版本 |
|-----|-------|-------|
| **配置解析** | 简单字符串处理 | ZUA JSON5 解析器 |
| **版本兼容** | 每版本独立代码 | Ring 抽象层统一管理 |
| **用户接口** | 直接 C 调用 | Rust FFI + 类型安全 |
| **序列化** | 12,000+ 行 | 1,200 行（重构优化） |
| **可维护性** | 单一文件 | 模块化分层 |

### 6.3 关键文件快速索引

```
rust/src/lib.rs          # Rust 用户态 API 入口
ring/core.c              # 版本兼容策略核心
zua/zua_type.h           # JSON 值类型系统
xfer/xfer.h              # 事件格式定义
```

---

*上一篇: [01-architecture-comparison.md](./01-architecture-comparison.md) - 总体架构对比*
*下一篇: [03-ebpf-improvements.md](./03-ebpf-improvements.md) - eBPF 程序改进*
