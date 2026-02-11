# Elkeid 3.0 eBPF 程序改进分析

> 本文档详细对比新旧版本 eBPF 程序的差异，重点分析改进内容

---

## 1. 文件对比概览

| 项目 | 旧版本 | 新版本 |
|-----|-------|-------|
| **主程序文件** | `BPF/hids.bpf.c` (3,187行) | `BPF/hids.c` (3,591行) |
| **头文件位置** | `BPF/hids/` | `BPF/inc/hids/` |
| **xfer 引用** | `hids/xfer.h` | `xfer/xfer.h` |
| **版本标识** | 无明确版本 | `3.0.0.7` |
| **Map 命名** | `g_tid_cache` | `tid_cache` (简化) |

---

## 2. BPF Map 设计对比

### 2.1 Map 定义对比

#### 旧版本 Map 定义

```c
// 旧版本: BPF/hids.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_N_TRUSTED_APPS);
    __type(key, u64);
    __type(value, struct exe_item);
} trusted_exes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct proc_tid);
} g_tid_cache SEC(".maps");  // 带 g_ 前缀
```

#### 新版本 Map 定义

```c
// 新版本: BPF/hids.c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_N_TRUSTED_APPS);
    __type(key, u64);
    __type(value, struct exe_item);
} trusted_exes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct proc_tid);
} tid_cache SEC(".maps");  // 移除 g_ 前缀，更简洁
```

### 2.2 Map 类型统计

| Map 名称 | 类型 | 旧版本 | 新版本 | 变化 |
|---------|------|-------|-------|-----|
| `trusted_exes` | LRU_HASH | ✓ | ✓ | 无变化 |
| `trusted_cmds` | LRU_HASH | ✓ | ✓ | 无变化 |
| `tid_cache` | LRU_HASH | `g_tid_cache` | `tid_cache` | 重命名 |
| `events` | PERF_EVENT_ARRAY | ✓ | ✓ | 无变化 |
| `g_percpu_data` | PERCPU_ARRAY | ✓ | ✓ | 无变化 |

### 2.3 Ring Buffer 预留设计

```c
// 新旧版本都预留了 Ring Buffer 支持（注释状态）
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 256 * 1024 /* 256 KB */);
// } g_trace_ring SEC(".maps");
```

**注释说明**：Ring Buffer 在内核 5.8+ 可用，但由于其不可覆写特性，暂未启用：
```c
// bpf ringbuf is not overwritable !!!!!
// https://lore.kernel.org/bpf/20220906195656.33021-3-flaniel@linux.microsoft.com/T/
```

---

## 3. Hook 点设计对比

### 3.1 Raw Tracepoint Hooks

两个版本都采用 Raw Tracepoint 作为主要 Hook 方式：

| Hook 点 | 事件类型 | 用途 |
|--------|---------|------|
| `raw_tracepoint/sched_process_exec` | 进程执行 | 捕获 execve |
| `raw_tracepoint/sched_process_fork` | 进程创建 | 捕获 fork |
| `raw_tracepoint/sched_process_exit` | 进程退出 | 清理缓存 |
| `raw_tracepoint/sys_exit` | 系统调用返回 | 捕获系统调用结果 |

### 3.2 Kprobe Hooks

| Hook 函数 | 事件 ID | 用途 |
|----------|--------|------|
| `security_inode_create` | 602 | 文件创建 |
| `security_inode_rename` | 82 | 文件重命名 |
| `security_inode_link` | 86 | 创建硬链接 |
| `security_task_prctl` | 157 | PR_SET_NAME |
| `call_usermodehelper_exec` | 607 | 用户模式 helper |
| `do_init_module` | 603 | 模块初始化 |
| `commit_creds` | 604 | 权限变更 |
| `filp_close` | - | 文件关闭 |

### 3.3 性能优先级

```
Raw Tracepoint > Kprobe > Tracepoint

性能对比（相对开销）：
- Raw Tracepoint: 1x (基准)
- Kprobe: 3-5x
- Tracepoint: 2-3x
```

---

## 4. CO-RE 支持改进

### 4.1 编译选项

```c
// BTF/CORE 支持开关
#ifdef  BPF_NO_PRESERVE_ACCESS_INDEX
#undef  HAVE_CORE_SUPPORT
#else
#define HAVE_CORE_SUPPORT
#endif
```

### 4.2 内存访问宏对比

#### 有 CO-RE 支持时

```c
#ifdef HAVE_CORE_SUPPORT
// 使用 BPF_CORE_READ 自动处理字段偏移
#define READ_KERN(...) BPF_CORE_READ(__VA_ARGS__)
#define READ_USER(...) BPF_CORE_READ(__VA_ARGS__)

// 系统调用参数 - CO-RE 版本
#define SC_REGS_PARM1(regs) PT_REGS_PARM1_CORE_SYSCALL(regs)
#define SC_REGS_PARM2(regs) PT_REGS_PARM2_CORE_SYSCALL(regs)
#define SC_REGS_PARM3(regs) PT_REGS_PARM3_CORE_SYSCALL(regs)
#define SC_REGS_PARM4(regs) PT_REGS_PARM4_CORE_SYSCALL(regs)
#define SC_REGS_PARM5(regs) PT_REGS_PARM5_CORE_SYSCALL(regs)

// 函数调用参数 - CO-RE 版本
#define FC_REGS_PARM1(regs) PT_REGS_PARM1_CORE(regs)
#define FC_REGS_PARM2(regs) PT_REGS_PARM2_CORE(regs)
#define FC_REGS_PARM3(regs) PT_REGS_PARM3_CORE(regs)
#define FC_REGS_PARM4(regs) PT_REGS_PARM4_CORE(regs)
#define FC_REGS_PARM5(regs) PT_REGS_PARM5_CORE(regs)

// 返回值
#define RC_REGS(regs) PT_REGS_RC_CORE(regs)
#endif
```

#### 无 CO-RE 支持时（兼容旧内核）

```c
#else
// 手工实现的内存读取宏链
#define READ_OPo(mode, n, s, e, ...)                                    \
    ({                                                                  \
        typeof((s)->e) _p_##e##_##n = LOAD_##mode((s)->e);              \
        READ_##mode##_##n(mode, n, _p_##e##_##n, ##__VA_ARGS__);        \
    })

#define READ_KERN_7(mode, n, ...)  READ_OPo(mode, 6, ## __VA_ARGS__)
#define READ_KERN_6(mode, n, ...)  READ_OPe(mode, 5, ## __VA_ARGS__)
#define READ_KERN_5(mode, n, ...)  READ_OPo(mode, 4, ## __VA_ARGS__)
#define READ_KERN_4(mode, n, ...)  READ_OPe(mode, 3, ## __VA_ARGS__)
#define READ_KERN_3(mode, n, ...)  READ_OPo(mode, 2, ## __VA_ARGS__)
#define READ_KERN_2(mode, n, s, e) LOAD_KERN((s)->e)
#define READ_KERN_1(mode, n, e)    LOAD_KERN(e)

// 系统调用参数 - 非 CO-RE 版本
#define SC_REGS_PARM1(regs) LOAD_KERN(PT_REGS_PARM1_SYSCALL(regs))
#define SC_REGS_PARM2(regs) LOAD_KERN(PT_REGS_PARM2_SYSCALL(regs))
// ...
#endif
```

### 4.3 CO-RE 使用示例

```c
// 读取多级指针链
// 有 CO-RE: 一行代码
inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);

// 无 CO-RE: 需要逐级展开
struct nsproxy *nsp = LOAD_KERN(task->nsproxy);
struct mnt_namespace *mnt_ns = LOAD_KERN(nsp->mnt_ns);
unsigned int inum = LOAD_KERN(mnt_ns->ns.inum);
```

---

## 5. 事件格式系统改进

### 5.1 版本标识

```c
// 新版本增加了明确的版本标识
char sd_event_point_start[32] SEC(".rodata")= {
    SD_EVENT_POINT_MAGIC "3.0.0.7"  // 版本号嵌入
};
```

### 5.2 事件序列化宏

```c
// 事件序列化函数生成宏
#define SD_XFER_DEFINE_N(n, p, x)                                       \
    static __always_inline int SD_XFER(n, SD_DECL_##p)                  \
    {                                                                   \
        struct proc_tid *__tid = find_current_tid();                    \
                                                                        \
        if (likely(__tid)) {                                            \
            struct SD_XFER_EVENT_##n *__ev;                             \
            SD_ENTS_STRP_##x    /* 字符串指针准备 */                    \
            SD_ENTS_STRS_##x    /* 字符串长度计算 */                    \
            uint32_t __tr_used = 0;                                     \
            uint32_t __tr_size = SD_DATA_##x;                           \
                                                                        \
            /* 对齐到 4 字节边界 */                                     \
            __tr_size = ALIGN(sizeof(*__ev) + __tr_size, 4);            \
            if (__tr_size > SD_EVENT_MAX)                               \
                return -7 /* E2BIG */;                                  \
                                                                        \
            /* 分配 per-CPU 缓冲 */                                     \
            __ev = sd_get_percpu_data(__tr_size, 0);                    \
            if (likely(__ev)) {                                         \
                __ev->e_timestamp = bpf_ktime_get_ns();  /* 时间戳 */   \
                __ev->e_head.size = __tr_size;                          \
                __ev->e_head.eid = SD_XFER_TYPEID_##n;                  \
                __ev->e_meta = sizeof(*__ev);                           \
                SD_ENTS_PACK_##x    /* 打包字段 */                      \
                                                                        \
                /* 输出到 perf buffer */                                \
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,  \
                                      __ev, __tr_size & SD_EVENT_MASK); \
                sd_put_percpu_data(__ev);                               \
                return __tr_size;                                       \
            }                                                           \
            return 0;                                                   \
        }                                                               \
        return -2; /* -ENOENT */                                        \
    }
```

### 5.3 事件 ID 定义

```c
// 系统调用事件
#define PRCTL           157     // PR_SET_NAME
#define EXECVE          59      // 进程执行
#define CONNECT         42      // 网络连接
#define BIND            49      // 套接字绑定
#define ACCEPT          43      // 接受连接
#define RENAME          82      // 文件重命名
#define LINK            86      // 创建链接
#define CHMOD           90      // 修改权限
#define PTRACE          101     // 进程跟踪
#define SETSID          112     // 设置会话ID
#define MEMFD_CREATE    356     // 内存文件创建

// 自定义事件
#define DNS_QUERY       601     // DNS 查询
#define FILE_CREATE     602     // 文件创建
#define INIT_MODULE     603     // 模块初始化
#define COMMIT_CREDS    604     // 权限变更
#define UNLINK          605     // 删除文件
#define RMDIR           606     // 删除目录
#define UMH_EXEC        607     // 用户模式 helper
#define PRIVILEGE_ESCALATION 611 // 权限提升

// Anti-Rootkit 事件
#define PROC_FILE_HOOK  700     // /proc 文件 hook
#define SYSCALL_HOOK    701     // 系统调用表 hook
#define LKM_HIDDEN      702     // 隐藏的内核模块
#define INTERRUPTS_HOOK 703     // 中断表 hook
```

---

## 6. 数据结构改进

### 6.1 进程缓存结构 (proc_tid)

```c
struct proc_tid {
    // 身份信息
    struct cred_xids xids;      // UID/GID/EUID/EGID 等 8 个值

    // Namespace 信息
    __u64 mntns_id;             // Mount namespace ID
    __u64 root_mntns_id;        // Root mount namespace ID

    // 哈希值（用于快速比对）
    __u64 cmd_hash;             // 命令行 Murmur 哈希
    __u64 exe_hash;             // 执行路径 Murmur 哈希

    // 进程 ID 信息
    pid_t pid, tgid, ppid, pgid;
    __u32 sid, epoch;           // Session ID 和 Epoch 时间戳

    // 字符串长度
    __u16 node_len, pidtree_len, exe_len, cmd_len;

    // 字符串数据
    char comm[16];              // 进程名 (TASK_COMM_LEN)
    char node[64];              // 节点名（主机名/容器名）
    char pidtree[256];          // 进程树（PID 链）
    char exe[1024];             // 执行文件路径
    char cmd[1024];             // 完整命令行
};
```

### 6.2 可信应用结构 (exe_item)

```c
struct exe_item {
    int len;                    // 字符串长度
    __u32 sid;                  // String ID（插件扩展点）
    __u64 hash;                 // Murmur 哈希值
    char name[1024];            // 完整路径或命令行
};

// 最大支持 2048 个可信应用
#define MAX_N_TRUSTED_APPS 2048
```

### 6.3 网络地址结构

```c
// 统一 IP 地址结构
struct ipaddr_ud {
    union {
        __u32 ip4;              // IPv4 地址
        __u8 ip6[16];           // IPv6 地址
    };
    __u16 port;                 // 端口号
    __u16 family;               // 地址族 (AF_INET/AF_INET6)
    __u8 size;                  // 地址长度: 0=无, 4=v4, 16=v6
};

// 源/目标地址对
struct smith_ipu {
    struct ipaddr_ud sip;       // 源地址
    struct ipaddr_ud dip;       // 目标地址
};
```

---

## 7. 内核版本兼容

### 7.1 循环展开策略

```c
// 内核 5.2+ 支持有界循环
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 2, 0)
#define LOOPS_UNROLL    (1)     // 5.2 以下需要手动展开
#else
#define LOOPS_UNROLL    (0)     // 5.2+ 支持有界循环
#endif
```

### 7.2 辅助函数实现

```c
// 文件描述符查找
#define FD_MAX (65536)
static __noinline struct file *fget_raw(struct task_struct *task, int nr)
{
    if (nr < 0 || nr >= FD_MAX)
        return NULL;

    struct files_struct *files = (void *)READ_KERN(task, files);
    if (files == NULL)
        return NULL;
    struct fdtable *fdt = (struct fdtable *)READ_KERN(files, fdt);
    if (fdt == NULL)
        return NULL;
    if (nr >= (int)READ_KERN(fdt, max_fds))
        return NULL;
    struct file **fds = (struct file **)READ_KERN(fdt, fd);
    if (fds == NULL)
        return NULL;
    struct file *file = (struct file *)LOAD_KERN(fds[nr]);

    return file;
}

// Socket 从文件获取
static __noinline struct socket *socket_from_file(struct file *file)
{
    struct inode *inode;
    struct socket *sock = NULL;
    umode_t mode;

    inode = (struct inode *)READ_KERN(file, f_inode);
    if (!inode)
        goto errorout;

    mode = (umode_t)READ_KERN(inode, i_mode);
    if (((mode) & S_IFMT) == S_IFSOCK)
        sock = SOCKET_I(inode);

errorout:
    return sock;
}
```

---

## 8. 性能优化改进

### 8.1 Per-CPU 缓冲

```c
// 每 CPU 数据缓冲结构
struct sd_percpu_data {
    __u8 data[SD_EVENT_MAX];    // 16KB per CPU
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct sd_percpu_data);
    __uint(max_entries, 2);     // 2 个条目（主/备）
} g_percpu_data SEC(".maps");

// 获取缓冲
static void *sd_get_percpu_data(uint32_t size, int id)
{
    if (size > SD_EVENT_MAX)
        return NULL;
    return bpf_map_lookup_elem(&g_percpu_data, &id);
}
```

### 8.2 LRU 缓存策略

```c
// 进程缓存使用 LRU_HASH
// 自动淘汰最少使用的条目
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);           // pid/tgid
    __type(value, struct proc_tid);
} tid_cache SEC(".maps");

// 优势：
// 1. 自动内存管理，无需手动清理
// 2. 避免僵尸进程无限占用
// 3. 热点进程保持在缓存中
```

### 8.3 内联优化

```c
// 关键函数强制内联
static __always_inline void *sd_get_local(uint32_t size)
{
    return sd_get_percpu_data(size, 1);
}

// 序列化函数强制内联（支持 >5 参数）
#define SD_XFER_DEFINE_N(n, p, x)                                       \
    static __always_inline int SD_XFER(n, SD_DECL_##p)                  \
    // ...
```

---

## 9. 新增功能对比

### 9.1 新版本独有功能

| 功能 | 描述 |
|-----|------|
| **版本标识** | 内嵌 `3.0.0.7` 版本号 |
| **xfer 模块化** | 独立 xfer 目录，便于维护 |
| **增强的 IPU 类型** | `SD_TYPE_IPU` 统一 IP 处理 |
| **事件格式描述** | `sd_event_point` 结构 |

### 9.2 改进的事件处理

```c
// 新版本增加了事件格式自描述
struct sd_event_point g_sd_events[] SEC(".rodata") = {
#include "hids/kprobe_print.h"
#include "hids/anti_rootkit_print.h"
    {.fmt = 0, .eid = 0, .ent = 0,}  // 终止标记
};

// 计算事件类型数量
#define N_SD_TYPES (sizeof(g_sd_events)/sizeof(struct sd_event_point) - 1)
```

---

## 10. 总结

### 10.1 主要改进点

| 方面 | 改进内容 |
|-----|---------|
| **代码组织** | xfer 独立模块，头文件重组 |
| **命名规范** | 移除 `g_` 前缀，更简洁 |
| **版本管理** | 内嵌版本号，便于兼容性检查 |
| **CO-RE 支持** | 完善的有/无 CO-RE 双路径 |
| **事件系统** | 自描述格式，版本化协议 |

### 10.2 保持不变的设计

| 方面 | 说明 |
|-----|------|
| **Map 类型** | LRU_HASH + PERF_EVENT_ARRAY |
| **Hook 策略** | Raw Tracepoint 优先 |
| **Per-CPU 缓冲** | 16KB × 2 条目 |
| **事件 ID** | 与旧版本兼容 |

### 10.3 架构演进方向

```
旧版本设计:
├─ 单文件 eBPF 程序
├─ 内联 xfer 定义
└─ 隐式版本

新版本设计:
├─ 模块化 eBPF 程序
├─ 独立 xfer 模块
├─ 显式版本标识
└─ 自描述事件格式
```

---

*上一篇: [02-new-modules-analysis.md](./02-new-modules-analysis.md) - 新增模块详解*
*下一篇: [04-userspace-improvements.md](./04-userspace-improvements.md) - 用户态改进*
