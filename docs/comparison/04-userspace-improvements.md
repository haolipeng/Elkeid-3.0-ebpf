# Elkeid 3.0 用户态改进分析

> 本文档对比新旧版本用户态程序的差异，包括加载器和消费者

---

## 1. 文件规模对比

| 组件 | 旧版本 | 新版本 | 变化 |
|-----|-------|-------|-----|
| **消费程序** | `BPF/consume.c` (2,916行) | `ebpf/consume.c` (17,437行) | **+498%** |
| **加载程序** | (内含于 consume.c) | `ebpf/load.c` (8,239行) | **独立模块** |
| **反序列化** | `BPF/xfer.c` (12,309行) | `xfer/xfer.c` (479行) | **-96%** |
| **辅助函数** | `BPF/helper/*.c` | `ebpf/helper/*.c` | 重组 |

---

## 2. 架构改进

### 2.1 旧版本架构

```
┌─────────────────────────────────────────┐
│           consume.c (单文件)             │
│  ┌─────────────────────────────────┐    │
│  │ main()                          │    │
│  │ ├─ libbpf 初始化                │    │
│  │ ├─ eBPF 程序加载                │    │
│  │ ├─ Hook 附加                    │    │
│  │ ├─ perf_buffer 创建             │    │
│  │ └─ 事件循环                     │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │ xfer.c (内联)                   │    │
│  │ └─ sd_unpack() 反序列化         │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

### 2.2 新版本架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Rust FFI 层 (rust/)                      │
│  ├─ RingSlot      (LKM 数据采集)                           │
│  ├─ SmithControl  (访问控制)                               │
│  └─ EBPFConsumer  (eBPF 数据采集)                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Ring 抽象层 (ring/core.c)                       │
│  ├─ tb_init_ebpf() / tb_init_kmod()                        │
│  ├─ tb_read_ebpf() / tb_read_kmod()                        │
│  └─ ac_setup() / ac_query() / ac_check()                   │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───���───────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────────┐
│  ebpf/load.c (加载器)    │     │  ebpf/consume.c (消费者)    │
│  ├─ tb_load_ebpf()       │     │  ├─ tb_init_ebpf()          │
│  ├─ ensure_core_btf()    │     │  ├─ perf_buffer 管理        │
│  └─ pin_maps()           │     │  └─ 事件回调                │
└─────────────────────────┘     └─────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  xfer/xfer.c (反序列化)                      │
│  ├─ sd_unpack()                                             │
│  ├─ sd_u32toa() / sd_ip4toa()                              │
│  └─ sd_hexdump()                                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. 加载器改进 (load.c)

### 3.1 新版本加载流程

```c
// ebpf/load.c 主要函数

/**
 * 加载带 BTF 支持的 eBPF 程序
 */
int tb_load_ebpf_with_btf(const char *obj_path)
{
    // 1. libbpf 初始化
    ensure_core_btf();                    // 加载 BTF 信息
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // 2. 打开 eBPF 对象
    struct hids_bpf *obj = hids_bpf__open_opts(&open_opts);

    // 3. 动态设置 Map 大小
    int pid_max = get_pid_max();          // 从 /proc/sys/kernel/pid_max
    bpf_map__set_max_entries(obj->maps.tid_cache, pid_max);

    // 4. 加载 eBPF 程序
    hids_bpf__load(obj);

    // 5. 附加 Hook 点
    hids_bpf__attach(obj);

    // 6. 固定 Maps 到 bpffs
    pin_maps(obj);

    return 0;
}
```

### 3.2 BTF 支持

```c
/**
 * 确保 BTF 信息可用
 */
static int ensure_core_btf(void)
{
    // 检查系统 BTF
    if (access("/sys/kernel/btf/vmlinux", F_OK) == 0) {
        // 系统提供 BTF
        return 0;
    }

    // 尝试从 BTF 归档加载
    // 支持旧内核通过外部 BTF 文件
    return load_btf_from_archive();
}
```

### 3.3 Map 固定

```c
/**
 * 固定 Maps 到 bpffs
 */
static int pin_maps(struct hids_bpf *obj)
{
    // 固定路径: /sys/fs/bpf/elkeid/map/
    const char *pin_path = "/sys/fs/bpf/elkeid/map";

    // 创建目录
    mkdir_p(pin_path, 0755);

    // 固定各个 Map
    bpf_map__pin(obj->maps.rodata, join_path(pin_path, "rodata"));
    bpf_map__pin(obj->maps.events, join_path(pin_path, "events"));
    bpf_map__pin(obj->maps.trusted_cmds, join_path(pin_path, "trusted_cmds"));
    bpf_map__pin(obj->maps.trusted_exes, join_path(pin_path, "trusted_exes"));

    return 0;
}
```

### 3.4 与旧版本对比

| 功能 | 旧版本 | 新版本 |
|-----|-------|-------|
| **BTF 支持** | 基础 | 完善（含归档加载） |
| **Map 固定** | 无 | 支持 bpffs 固定 |
| **动态 Map 大小** | 固定 10240 | 根据 pid_max 动态 |
| **错误处理** | 简单 | 详细日志 |
| **独立性** | 与消费合并 | 独立模块 |

---

## 4. 消费者改进 (consume.c)

### 4.1 初始化流程

```c
// ebpf/consume.c 初始化

int tb_init_ebpf(void)
{
    // 1. 打开已固定的 Maps
    int events_fd = open_pinned_map("/sys/fs/bpf/elkeid/map/events");
    int rodata_fd = open_pinned_map("/sys/fs/bpf/elkeid/map/rodata");

    // 2. 获取 Map 信息
    struct bpf_map_info info;
    bpf_obj_get_info_by_fd(events_fd, &info, &info_len);

    // 3. 初始化事件格式
    se_init_format(rodata_fd);            // 从 rodata 读取格式定义

    // 4. 创建 perf_buffer
    g_pb = perf_buffer__new(events_fd, PERF_BUFFER_PAGES,
                           event_handling,     // 数据到达回调
                           event_missing,      // 数据丢失回调
                           NULL, NULL);

    return 0;
}
```

### 4.2 事件格式初始化

```c
/**
 * 初始化事件格式表
 */
static int se_init_format(int rodata_fd)
{
    // 从 rodata Map 读取事件格式定义
    void *rodata = mmap_map(rodata_fd);

    // 定位 magic section
    char *magic = find_magic(rodata, SD_EVENT_POINT_MAGIC);
    if (!magic) {
        return -EINVAL;
    }

    // 解析版本号
    char *version = magic + strlen(SD_EVENT_POINT_MAGIC);
    if (strcmp(version, EXPECTED_VERSION) != 0) {
        // 版本不匹配警告
        log_warn("Version mismatch: %s vs %s", version, EXPECTED_VERSION);
    }

    // 构建事件格式表
    struct sd_event_point *events = (void *)(magic + 32);
    for (int i = 0; events[i].eid != 0; i++) {
        g_event_formats[events[i].eid] = &events[i];
    }

    return 0;
}
```

### 4.3 事件处理回调

```c
/**
 * 事件到达回调
 */
static void event_handling(void *ctx, int cpu, void *data, __u32 size)
{
    struct sd_item_ent *head = data;

    // 检查事件有效性
    if (size < sizeof(*head) || head->size != size) {
        return;
    }

    // 查找事件格式
    struct sd_event_point *fmt = g_event_formats[head->eid];
    if (!fmt) {
        return;
    }

    // 反序列化
    char output[SD_OUTPUT_MAX];
    int len = sd_unpack(output, sizeof(output), data, &rec);
    if (len > 0) {
        // 输出事件
        write_event(output, len);
    }
}

/**
 * 事件丢失回调
 */
static void event_missing(void *ctx, int cpu, __u64 cnt)
{
    log_warn("Lost %llu events on CPU %d", cnt, cpu);
    g_stats.lost += cnt;
}
```

### 4.4 主循环

```c
/**
 * 事件消费主循环
 */
int tb_read_ebpf(char *msg, int len, int (*cb)(int *), int *ctx)
{
    while (!g_exiting) {
        // 轮询 perf_buffer
        int ret = perf_buffer__poll(g_pb, 100);  // 100ms 超时

        if (ret < 0) {
            if (ret == -EINTR)
                continue;
            return ret;
        }

        // 检查回调
        if (cb && cb(ctx) != 0) {
            break;
        }
    }

    return 0;
}
```

---

## 5. 反序列化改进 (xfer.c)

### 5.1 代码精简

| 方面 | 旧版本 | 新版本 |
|-----|-------|-------|
| **代码行数** | 12,309 行 | 479 行 |
| **减少比例** | - | **-96%** |

### 5.2 核心函数

```c
// xfer/xfer.c

/**
 * 反序列化事件数据
 */
int sd_unpack(void *de, int sde, void *se, int *rec)
{
    struct sd_item_ent *head = se;
    char *dst = de;
    char *src = (char *)se + head->meta;  // 跳过元数据
    int dst_len = 0;

    // 获取事件格式
    struct sd_event_format *fmt = get_format(head->eid);
    if (!fmt)
        return -EINVAL;

    // 遍历字段
    struct sd_item_ent *items = fmt->items;
    for (int i = 0; i < fmt->nids; i++) {
        int type = items[i].item;
        int len = items[i].len;

        switch (type) {
        case SD_TYPE_U32:
            dst_len += sd_u32toa(*(uint32_t *)src, dst + dst_len);
            break;
        case SD_TYPE_U64:
            dst_len += sd_u64toa(*(uint64_t *)src, dst + dst_len);
            break;
        case SD_TYPE_IP4:
            dst_len += sd_ip4toa(*(uint32_t *)src, dst + dst_len);
            break;
        case SD_TYPE_IP6:
            dst_len += sd_ip6toa(src, dst + dst_len);
            break;
        case SD_TYPE_STR:
            dst_len += sd_strtoa(src, dst + dst_len);
            break;
        // ... 其他类型
        }

        // 添加分隔符
        dst[dst_len++] = SD_FIELD_SEP;  // 0x1e

        src += len;
    }

    *rec = 1;
    return dst_len;
}
```

### 5.3 高性能转换函数

```c
// 预计算的 2 位数字查找表
static const char digit_pairs[200] = {
    '0','0', '0','1', '0','2', '0','3', '0','4',
    '0','5', '0','6', '0','7', '0','8', '0','9',
    '1','0', '1','1', '1','2', '1','3', '1','4',
    // ... 到 '9','9'
};

/**
 * uint32 转字符串（比 snprintf 快 3 倍）
 */
int sd_u32toa(uint32_t value, char *buf)
{
    char *p = buf + 10;  // 最大 10 位
    *p = '\0';

    // 每次处理 2 位
    while (value >= 100) {
        int idx = (value % 100) * 2;
        *--p = digit_pairs[idx + 1];
        *--p = digit_pairs[idx];
        value /= 100;
    }

    // 处理剩余位
    if (value >= 10) {
        int idx = value * 2;
        *--p = digit_pairs[idx + 1];
        *--p = digit_pairs[idx];
    } else {
        *--p = '0' + value;
    }

    // 移动到缓冲区开头
    int len = buf + 10 - p;
    memmove(buf, p, len + 1);
    return len;
}

/**
 * IPv4 转字符串
 */
int sd_ip4toa(uint32_t ip, char *buf)
{
    uint8_t *bytes = (uint8_t *)&ip;
    int len = 0;

    for (int i = 0; i < 4; i++) {
        if (i > 0)
            buf[len++] = '.';
        len += sd_u8toa(bytes[i], buf + len);
    }

    buf[len] = '\0';
    return len;
}
```

---

## 6. 访问控制改进

### 6.1 新版本访问控制架构

```
┌─────────────────────────────────────────────────────────────┐
│                   SmithControl (Rust)                       │
│  ├─ ac_add_allow_exe()    添加可执行文件白名单              │
│  ├─ ac_add_allow_argv()   添加命令行白名单                  │
│  ├─ ac_set_block_md5()    设置 MD5 黑名单                   │
│  ├─ ac_set_block_dns()    设置 DNS 黑名单                   │
│  └─ psad_enable()         启用 PSAD 防护                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│               ring/core.c (C 抽象层)                         │
│  ├─ ac_setup(type, op, ...)     设置规则                    │
│  ├─ ac_clear(type, op)          清除规则                    │
│  ├─ ac_check(type, op, ...)     检查规则                    │
│  ├─ ac_erase(type, op, ...)     删除规则                    │
│  └─ ac_query(type, op, buf, len) 查询规则                   │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────��────────────┐ ┌─────────────────┐ ┌──────────────────┐
│  LKM 控制接口    │ │ ZUA JSON 解析   │ │  eBPF Map 更新   │
│  (sysfs/procfs)  │ │ (规则文件)      │ │  (bpf_map_update)│
└──────────────────┘ └─────────────────┘ └──────────────────┘
```

### 6.2 规则类型

```c
// 白名��类型
#define AL_TYPE_ARGV    (0xA1)  // 命令行白名单
#define AL_TYPE_EXE     (0xA2)  // 可执���文件白名单
#define AL_TYPE_PSAD    (0xA3)  // PSAD IP 白名单
#define AL_EBPF_ARGV    (0xAA)  // eBPF 命令行白名单
#define AL_EBPF_EXE     (0xAE)  // eBPF 可执行文件白名单

// 黑名单类型
#define BL_JSON_DNS     (0xB0)  // DNS 域名黑名单
#define BL_JSON_EXE     (0xB1)  // 执行阻止（支持通配符）
#define BL_JSON_MD5     (0xB2)  // MD5 哈希黑名单
```

### 6.3 JSON 规则示例

```json
// MD5 黑名单 (BL_JSON_MD5)
{
    "md5_list": [
        "d41d8cd98f00b204e9800998ecf8427e",
        "098f6bcd4621d373cade4e832627b4f6"
    ]
}

// DNS 黑名单 (BL_JSON_DNS)
{
    "dns_list": [
        "*.malware.com",
        "evil.example.org"
    ]
}

// 执行阻止 (BL_JSON_EXE)
{
    "block_list": [
        {
            "exe": "/tmp/*",
            "argv": "*.sh"
        }
    ]
}
```

---

## 7. 数据流对比

### 7.1 旧版本数据流

```
eBPF 程序
    │ bpf_perf_event_output()
    ▼
PERF_EVENT_ARRAY
    │ perf_buffer__poll()
    ▼
consume.c
    │ event_handling()
    │ sd_unpack()
    ▼
stdout / 日志
```

### 7.2 新版本数据流

```
eBPF 程序                    LKM 驱动
    │                           │
    │ bpf_perf_event_output()   │ ring_buffer
    ▼                           ▼
PERF_EVENT_ARRAY         /sys/module/elkeid/
    │                           │
    └─────────┬─────────────────┘
              │
              ▼
    ring/core.c (版本抽象)
              │
              ├─ tb_read_ebpf()
              └─ tb_read_kmod()
              │
              ▼
    xfer/xfer.c (反序列化)
              │
              ▼
    rust/lib.rs (Rust FFI)
              │
              ▼
    用户态应用 (Rust/Go/Python)
```

---

## 8. 统计与监控

### 8.1 新版本统计接口

```c
// ring/core.c

/**
 * 获取 LKM 统计信息
 */
int tb_stat_kmod(int type, uint64_t *produced, uint64_t *consumed, uint64_t *dropped)
{
    // 从 sysfs 读取统计
    // /sys/module/elkeid/parameters/stats
}

/**
 * 格式化显示统计
 */
int tb_show_kmod(int type, char *buf, int len)
{
    uint64_t produced, consumed, dropped;
    tb_stat_kmod(type, &produced, &consumed, &dropped);

    return snprintf(buf, len,
        "produced: %lu\n"
        "consumed: %lu\n"
        "dropped: %lu\n",
        produced, consumed, dropped);
}
```

### 8.2 Rust 层统计

```rust
impl RingSlot {
    /// 获取统计信息
    pub fn stats(&self) -> Result<RingStats> {
        // 调用 C 层 tb_stat_kmod()
    }
}

pub struct RingStats {
    pub produced: u64,
    pub consumed: u64,
    pub dropped: u64,
}
```

---

## 9. 错误处理改进

### 9.1 旧版本错误处理

```c
// 简单的错误返回
if (error)
    return -1;
```

### 9.2 新版本错误处理

```c
// 详细的错误码和日志
if (error) {
    log_error("Failed to load eBPF: %s (errno=%d)", strerror(errno), errno);
    return -errno;
}

// Rust 层使用 Result 类型
pub fn load(obj_path: &str) -> Result<Self> {
    // 自动错误传播和上下文
}
```

---

## 10. 总结

### 10.1 主要改进

| 方面 | 旧版本 | 新版本 |
|-----|-------|-------|
| **架构** | 单文件 | 模块化 (load/consume/xfer) |
| **语言** | 纯 C | C + Rust FFI |
| **版本兼容** | 单版本 | 多版本抽象 (v1.7-v1.9+eBPF) |
| **反序列化** | 12,000+ 行 | 479 行 |
| **访问控制** | 基础 | JSON 规则 + 多种类型 |
| **错误处理** | 简单 | 详细日志 + Result 类型 |

### 10.2 代码质量提升

```
旧版本:
├─ 单文件设计，难以维护
├─ C 语言直接操作，易出错
└─ 有限的错误处理

新版本:
├─ 模块化设计，职责清晰
├─ Rust FFI 提供类型安全
├─ 完善的错误处理和日志
└─ 支持多种数据源统一接口
```

### 10.3 性能优化

```
旧版本:
├─ 基础的数值转换
└─ 内联反序列化

新版本:
├─ 查找表加速数值转换（3x 提升）
├─ 精简的反序列化代码（96% 减少）
└─ 零拷贝设计
```

---

*上一篇: [03-ebpf-improvements.md](./03-ebpf-improvements.md) - eBPF 程序改进*
*下一篇: [05-code-examples.md](./05-code-examples.md) - 关键代码示例对比*
