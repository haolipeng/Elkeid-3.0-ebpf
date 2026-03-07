# Elkeid 3.0 eBPF 事件体系调研报告

> 版本：EBPF_PROG_VERSION "3.0.0.7"
> 源码路径：`/home/work/openSource/Elkeid-3.0-ebpf/`
> 调研日期：2026-02-23

---

## 目录

- [第一章：架构概览](#第一章架构概览)
- [第二章：事件传输机制](#第二章事件传输机制)
- [第三章：公共字段定义（ENTRY_COMMON）](#第三章公共字段定义entry_common)
- [第四章：已启用事件详细清单（19种）](#第四章已启用事件详细清单19种)
- [第五章：反 Rootkit 检测事件（4种）](#第五章反-rootkit-检测事件4种)
- [第六章：已禁用事件清单（14种）](#第六章已禁用事件清单14种)
- [第七章：用户态 Agent 事件消费架构](#第七章用户态-agent-事件消费架构)
- [第八章：安全能力评估总结](#第八章安全能力评估总结)

---

## 第一章：架构概览

### 1.1 eBPF 事件采集整体架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Linux Kernel Space                                 │
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │  raw_tracepoint   │  │     kprobe        │  │   Anti-Rootkit Scanner   │  │
│  │                    │  │                    │  │                          │  │
│  │ sched_process_exec│  │ security_inode_*   │  │ proc file_operations     │  │
│  │ sched_process_fork│  │ call_usermodehelper│  │ sys_call_table           │  │
│  │ sched_process_exit│  │ do_init_module     │  │ module list              │  │
│  │ sys_exit          │  │ commit_creds       │  │ IDT (x86 only)          │  │
│  │                    │  │ filp_close         │  │                          │  │
│  │                    │  │ security_task_prctl│  │                          │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────────┬─────────────┘  │
│           │                      │                          │                │
│           └──────────┬───────────┘                          │                │
│                      ▼                                      ▼                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │              SD_XFER 序列化框架                                       │   │
│  │  SD_XFER_DEFINE → 事件结构体 + 序列化函数 + 元数据                    │   │
│  │  per-CPU buffer (16KB) → bpf_perf_event_output()                     │   │
│  └──────────────────────────────┬───────────────────────────────────────┘   │
│                                  │                                           │
│  ┌──────────────────────────────┴───────────────────────────────────────┐   │
│  │         BPF_MAP_TYPE_PERF_EVENT_ARRAY ("events")                      │   │
│  └──────────────────────────────┬───────────────────────────────────────┘   │
│                                  │                                           │
└──────────────────────────────────┼───────────────────────────────────────────┘
                                   │ perf_event ring buffer
                                   ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                          User Space                                          │
│                                                                              │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │              Plugin 子进程 (eBPF Driver)              │                    │
│  │  perf buffer 读取 → 编码为: 4B长度+varint字段+载荷    │                    │
│  └──────────────────────┬──────────────────────────────┘                    │
│                          │ pipe (stdout)                                     │
│                          ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │              Elkeid Agent 主进程                      │                    │
│  │                                                       │                    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  │                    │
│  │  │ 事件接收解析  │→│ Ring Buffer   │→│ gRPC 上报    │  │                    │
���  │  │ (3 goroutine │  │ (2048 slots)  │  │ 100ms 批量   │  │                    │
│  │  │  per plugin) │  │ 4级对象池     │  │ Snappy 压缩  │  │                    │
│  │  └─────────────┘  └──────────────┘  │ TLS/mTLS     │  │                    │
│  │                                      └──────┬─────┘  │                    │
│  └─────────────────────────────────────────────┼────────┘                    │
│                                                 │ gRPC 双向流                 │
│                                                 ▼                             │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │              Elkeid Server (控制端)                    │                    │
│  │  接收事件 ← Transfer(stream) → 下发命令/配置           │                    │
│  └─────────────────────────────────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 关键组件说明

| 组件 | 源文件 | 说明 |
|------|--------|------|
| eBPF 主程序 | `driver/BPF/hids.c` (3591行) | 所有 Hook 实现，事件采集入口 |
| 事件字段定义 | `driver/BPF/inc/hids/kprobe_print.h` | `SD_XFER_DEFINE` 宏定义每个事件的字段 |
| 反 Rootkit 事件 | `driver/BPF/inc/hids/anti_rootkit_print.h` | 4种反 Rootkit 检测事件定义 |
| 序列化框架 | `driver/xfer/xfer.h` (752行) | `SD_XFER_DEFINE` 宏展开框架 |
| Hook 辅助函数 | `driver/BPF/inc/hids/kprobe.h` | 进程信息采集、��径解析、过滤 |
| 常量与数据结构 | `driver/ebpf/hids/hids.h` | `proc_tid`、`cred_xids`、常量定义 |
| Agent 事件接收 | `agent/plugin/plugin.go` | 从 Plugin 管道读取并解析事件 |
| Agent 子进程管理 | `agent/plugin/plugin_linux.go` | Plugin 生命周期管理 |
| Agent 事件缓冲 | `agent/buffer/buffer.go` | 2048 槽位 Ring Buffer |
| Agent gRPC 上报 | `agent/transport/transfer.go` | 批量发送、命令接收 |
| gRPC 协议定义 | `agent/proto/grpc.proto` | `Transfer` 服务、消息格式 |

### 1.3 BPF Maps 定义

| Map 名称 | 类型 | 容量 | 用途 |
|----------|------|------|------|
| `tid_cache` | `BPF_MAP_TYPE_LRU_HASH` | 10,240 | 进程/线程信息缓存（`struct proc_tid`） |
| `trusted_exes` | `BPF_MAP_TYPE_LRU_HASH` | 2,048 | 可信可执行文件白名单（按路径哈希） |
| `trusted_cmds` | `BPF_MAP_TYPE_LRU_HASH` | 2,048 | 可信命令行白名单（按命令行哈希） |
| `events` | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | per-CPU | 事件输出到用户态的 perf 通道 |
| `g_percpu_data` | `BPF_MAP_TYPE_PERCPU_ARRAY` | 2 | per-CPU 临时事件构建缓冲区（每个 16KB） |

---

## 第二章：事件传输机制

### 2.1 内核态事件序列化与输出

#### 2.1.1 SD_XFER_DEFINE 宏体系

`SD_XFER_DEFINE` 是一个三阶段编译时代码生成宏，通过 C 预处理器递归展开：

**阶段一：枚举生成**
```c
// 为每个事件生成唯一的类型 ID 枚举值
#define SD_XFER_DEFINE(n, p, x)     SD_XFER_TYPEID_##n,
// 示例：SD_XFER_TYPEID_execve, SD_XFER_TYPEID_connect, ...
```

**阶段二：结构体与元数据生成**
```c
// 生成事件结构体定义和元数据数组
struct SD_XFER_EVENT_execve {
    uint64_t e_timestamp;           // 8 字节，纳秒时间戳
    struct sd_item_ent e_head;      // 8 字节（size + eid）
    uint32_t e_meta;                // 4 字节，元数据大小
    /* 固定字段区域 */
    char p_data[0];                 // 变长数据区域
} __attribute__((packed));
```

**阶段三：序列化函数生成**
```c
// 生成类型安全的序列化函数
static __always_inline int SD_XFER_execve(void *ctx, char *cwd, ...) {
    // 1. 分配 per-CPU 缓冲区
    __ev = sd_get_percpu_data(__tr_size, 0);
    // 2. 填充事件头
    __ev->e_timestamp = bpf_ktime_get_ns();
    __ev->e_head.size = __tr_size;
    __ev->e_head.eid = SD_XFER_TYPEID_execve;
    // 3. 打包所有字段（SD_ENTS_PACK_*）
    // 4. 输出到 perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          __ev, __tr_size & SD_EVENT_MASK);
}
```

**代码位置**：`driver/BPF/hids.c:187-280`，`driver/xfer/xfer.h`

#### 2.1.2 字段类型宏

| 宏 | 含义 | 示例 |
|----|------|------|
| `ENTRY_XID(id)` | 事件类型 ID | `ENTRY_XID(59)` |
| `ENTRY_U32(name, val)` | 32位无符号整数 | `ENTRY_U32(uid, __tid->xids.uid)` |
| `ENTRY_U64(name, val)` | 64位无符号整数 | `ENTRY_U64(mntns_id, __tid->mntns_id)` |
| `ENTRY_S32(name, val)` | 32位有符号整数 | `ENTRY_S32(socket_pid, socket_pid)` |
| `ENTRY_INT(name, val)` | int 类型 | `ENTRY_INT(retval, retval)` |
| `ENTRY_ULONG(name, val)` | unsigned long | `ENTRY_ULONG(addr, (unsigned long)addr)` |
| `ENTRY_STL(name, src, len)` | 变长字符串（带长度） | `ENTRY_STL(exe_path, __tid->exe, __tid->exe_len)` |
| `ENTRY_STR(name, src)` | 固定字符串 | `ENTRY_STR(filename, filename)` |
| `ENTRY_IPU(name, val)` | IP 地址（IPv4/IPv6 联合体） | `ENTRY_IPU(dip, dip)` |
| `ENTRY_XIDS(name, val)` | 凭证结构（8个 u32） | `ENTRY_XIDS(p_cred, p_cred)` |

#### 2.1.3 事件大小限制

```c
#define SD_EVENT_MAX    (16384)      // 单个事件最大 16KB
#define SD_EVENT_MASK   (SD_EVENT_MAX - 1)
#define SD_STR_MAX      (1024)       // 单个字符串最大 1KB
```

#### 2.1.4 变长字符串存储编码

字符串字段在事件结构中存储为一个 `uint32_t` 编码值：
- **高 16 位**：字符串长度
- **低 16 位**：在 `p_data` 变长区域中的偏移量

```c
__ev->s_##name = ((uint32_t)(__rc - 1)) << 16 | __tr_used;
```

#### 2.1.5 事件输出流水线

```
Hook 函数触发
    ↓
检查白名单（exe_is_allowed / cmd_is_allowed）
    ↓ 命中则跳过
分配 per-CPU 缓冲: sd_get_percpu_data(__tr_size, 0)
    ↓
获取进程上下文: find_current_tid() → 从 tid_cache 查询
    ↓
构建事件: SD_XFER_EVENT_xxx + SD_ENTS_PACK_xxx
    ↓
提交事件: bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ...)
    ↓
释放缓冲: sd_put_percpu_data()
```

### 2.2 用户态事件传输协议

#### 2.2.1 Plugin → Agent 管道协议

Plugin 子进程通过 stdout 管道将事件编码后发送给 Agent 主进程：

```
┌──────────┬───────────┬──────────┬───────────┬──────────┬─────────────┐
│ 4B Length │ Separator │ DataType │ Separator │Timestamp │   Payload   │
│ (LE u32) │   (1B)    │ (varint) │   (1B)    │ (varint) │  (bytes)    │
└──────────┴───────────┴──────────┴───────────┴──────────┴─────────────┘
```

- **4B Length**：小端序 uint32，表示后续数据总长度
- **Separator**：1 字节分隔符
- **DataType**：protobuf 风格 varint 编码的事件类型 ID
- **Timestamp**：varint 编码的 Unix 秒时间戳
- **Payload**：原始二进制载荷

**代码位置**：`agent/plugin/plugin.go:74-131`，`agent/plugin/protocol.go:14-32`

#### 2.2.2 Agent Ring Buffer

```
┌─────────────────────────────────────────────┐
│          Ring Buffer (2048 slots)             │
│                                               │
│  slot[0] slot[1] slot[2] ... slot[2047]      │
│    ↑                           ↑              │
│   读取起点                    写入位置         │
│                                               │
│  WriteEncodedRecord(): offset < 2048 ? 写入   │
│  ReadEncodedRecords(): 原子读取全部，重置 offset│
└─────────────────────────────────────────────┘
```

- 固定 2048 个槽位，mutex 保护
- 满时丢弃新事件（回收到对象池）
- `ReadEncodedRecords()` 原子读取全部已缓冲记录并重置

**代码位置**：`agent/buffer/buffer.go:9-64`

#### 2.2.3 四级对象池

| 级别 | 容量范围 | 底层数组大小 |
|------|----------|-------------|
| 0 | 1-1024 字节 | 1024 字节 |
| 1 | 1025-2048 字节 | 2048 字节 |
| 2 | 2049-3072 字节 | 3072 字节 |
| 3 | 3073-4096 字节 | 4096 字节 |

分配逻辑：`index = (size - 1) >> 10`（除以 1024 向下取整）

**代码位置**：`agent/buffer/pool.go:9-63`

#### 2.2.4 gRPC 上报机制

- **批量发送**：100ms 定时器触发（`time.NewTicker(100 * time.Millisecond)`）
- **压缩算法**：Snappy（`grpc.UseCompressor("snappy")`）
- **传输协议**：gRPC 双向流（`Transfer(stream PackagedData) returns (stream Command)`）
- **安全传输**：TLS/mTLS 加密
- **重试策略**：连接失败重试 6 次，每次间隔 5 秒
- **发送内容**：每批次包含 `AgentId`、IP 地址、`Hostname`、`Version`、`Product`

**代码位置**：`agent/transport/transfer.go:39-127`

---

## 第三章：公共字段定义（ENTRY_COMMON）

大部分事件（除 `call_usermodehelper_exec` 外）都包含 `ENTRY_COMMON` 宏定义的 13 个公共字段。

**代码位置**：`driver/BPF/inc/hids/kprobe_print.h:3-17`

```c
#define ENTRY_COMMON(xid)                                                       \
                     ENTRY_XID(xid),                                            \
                     ENTRY_U32(uid, __tid->xids.uid),                           \
                     ENTRY_STL(exe_path, __tid->exe, __tid->exe_len),           \
                     ENTRY_U32(pid, (pid_t)bpf_get_current_pid_tgid()),         \
                     ENTRY_U32(ppid, __tid->ppid),                              \
                     ENTRY_U32(pgid, __tid->pgid),                              \
                     ENTRY_U32(tgid, (pid_t)(bpf_get_current_pid_tgid() >> 32)),\
                     ENTRY_U32(sid, __tid->sid),                                \
                     ENTRY_U32(epoch, __tid->epoch),                            \
                     ENTRY_STL(comm, __tid->comm, TASK_COMM_LEN),               \
                     ENTRY_STL(nodename, __tid->node, __tid->node_len),         \
                     ENTRY_U64(mntns_id, __tid->mntns_id),                      \
                     ENTRY_U64(root_mntns_id, __tid->root_mntns_id)
```

### 3.1 公共字段详细说明

| 序号 | 字段名 | 类型 | 内核数据来源 | 说明 |
|------|--------|------|-------------|------|
| 1 | `xid` | u32 | 参数传入（如 59, 42） | 事件类型 ID，对应 syscall 编号或自定义 ID |
| 2 | `uid` | u32 | `__tid->xids.uid` | 当前用户 ID，来自 `proc_tid` 缓存的凭证 |
| 3 | `exe_path` | string | `__tid->exe`（长度 `__tid->exe_len`） | 可执行文件完整路径，缓存于 `proc_tid` |
| 4 | `pid` | u32 | `(pid_t)bpf_get_current_pid_tgid()` | 当前线程 ID（低 32 位），实时获取 |
| 5 | `ppid` | u32 | `__tid->ppid` | 父进程 ID，缓存于 `proc_tid` |
| 6 | `pgid` | u32 | `__tid->pgid` | 进程组 ID，缓存于 `proc_tid` |
| 7 | `tgid` | u32 | `(pid_t)(bpf_get_current_pid_tgid() >> 32)` | 线程组 ID（高 32 位），即主进程 PID |
| 8 | `sid` | u32 | `__tid->sid` | 会话 ID，缓存于 `proc_tid` |
| 9 | `epoch` | u32 | `__tid->epoch` | 时间戳纪元计数器 |
| 10 | `comm` | string | `__tid->comm`（最大 TASK_COMM_LEN=16） | 进程名（`task_struct->comm`） |
| 11 | `nodename` | string | `__tid->node`（长度 `__tid->node_len`，最大 64） | 主机名（UTS namespace） |
| 12 | `mntns_id` | u64 | `__tid->mntns_id` | 挂载命名空间 ID（容器标识） |
| 13 | `root_mntns_id` | u64 | `__tid->root_mntns_id` | 根挂载命名空间 ID（宿主机标识） |

### 3.2 proc_tid 缓存结构

公共字段的数据源主要来自 `struct proc_tid`（缓存在 `tid_cache` BPF Map 中）：

```c
struct proc_tid {
    struct cred_xids xids;      // 32 字节 - 凭证 ID（uid/gid/euid/egid/...）
    __u64 mntns_id;             // 挂载命名空间 ID
    __u64 root_mntns_id;        // 根挂载命名空间 ID
    __u64 cmd_hash;             // 命令行哈希（MurmurHash）
    __u64 exe_hash;             // 可执行文件路径哈希

    pid_t pid, tgid, ppid, pgid;
    __u32 sid;                  // 会话 ID
    __u32 epoch;                // 纪元计数器

    __u16 node_len, pidtree_len, exe_len, cmd_len;

    char comm[16];              // 进程名
    char node[64];              // 主机名
    char pidtree[256];          // PID 树
    char exe[1024];             // 可执行文件路径
    char cmd[1024];             // 命令行参数
};
```

**缓存更新时机**：
- `tp__proc_fork()`：fork 时创建新条目（`construct_tid()`）
- `tp__proc_exec()`：execve 时刷新条目（`refresh_tid()`）
- `tp__proc_exit()`：exit 时删除条目

**代码位置**：`driver/ebpf/hids/hids.h`

### 3.3 cred_xids 凭证结构

```c
struct cred_xids {
    union {
        uint32_t xids[8];
        struct {
            uint32_t uid, gid, suid, sgid, euid, egid, fsuid, fsgid;
        };
    };
};
```

用于 `ENTRY_COMMON` 中的 `uid` 字段提取，以及 `privilege_escalation` 事件的完整凭证对比。

---

## 第四章：已启用事件详细清单（19种）

> 以下事件均在 `kprobe_print.h` 中通过 `SD_XFER_DEFINE` 定义，且未被 `#if 0` 包裹。
> 每个事件的字段表格中，**公共字段**（ENTRY_COMMON 的 13 个字段）不再重复列出，仅列出事件特有字段。

### 4.1 execve — 进程执行

| 属性 | 值 |
|------|-----|
| **事件名称** | `execve` |
| **类型 ID** | 59（对应 `__NR_execve`） |
| **���载点** | `raw_tracepoint/sched_process_exec` → `tp__proc_exec()` + `raw_tracepoint/sys_exit` |
| **代码位置** | `kprobe_print.h:34-77`，`hids.c` tp__proc_exec / tp__sys_exit |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `args` | string | `__tid->cmd`（`__tid->cmd_len`） | 完整命令行参数，最大 1024 字节 |
| `cwd` | string | 参数传入（`cwd_len`） | 当前工作目录 |
| `tmp_stdin` | string | 参数传入（最大 256 字节） | 标准输入重定向目标 |
| `tmp_stdout` | string | 参数传入 | 标准输出重定向目标 |
| `dip` | IPU | `struct ipaddr_ud *dip` | 目标 IP 地址（关联 socket） |
| `sip` | IPU | `struct ipaddr_ud *sip` | 源 IP 地址（关联 socket） |
| `sa_family` | u32 | `dip->family` | 地址族（AF_INET/AF_INET6） |
| `pidtree` | string | `__tid->pidtree`（`__tid->pidtree_len`） | 进程树信息，最大 256 字节 |
| `tty_name` | string | 参数传入（最大 64 字节） | TTY 终端名称 |
| `socket_pid` | s32 | 参数传入 | 关联 socket 的进程 PID |
| `ssh_conn` | string | 参数传入 | SSH 连接信息（`SSH_CONNECTION` 环境变量） |
| `ld_preload` | string | 参数传入 | `LD_PRELOAD` 环境变量值 |
| `ld_lib_path` | string | 参数传入 | `LD_LIBRARY_PATH` 环境变量值 |
| `retval` | int | 参数传入 | syscall 返回值 |
| `size` | u64 | 参数传入 | 可执行文件大小 |
| `md5` | string | 参数传入（32 字节） | 可执行文件 MD5 哈希 |

**安全场景**：
- 恶意命令执行检测（反弹 shell、挖矿程序启动）
- 进程启动链审计（通过 pidtree 追溯父进程链）
- 动态链接库注入检测（LD_PRELOAD / LD_LIBRARY_PATH 异常）
- SSH 会话关联（通过 ssh_conn 关联远程登录来源）
- 可疑文件执行（通过 md5 比对恶意样本库）

---

### 4.2 connect — 网络连接

| 属性 | 值 |
|------|-----|
| **事件名称** | `connect` |
| **类型 ID** | 42（对应 `__NR_connect`） |
| **挂载点** | `raw_tracepoint/sys_exit`（syscall 42 返回时） |
| **代码位置** | `kprobe_print.h:79-94` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `sa_family` | u32 | `dip->family` | 地址族 |
| `dip` | IPU | 内核 socket 结构 | 目标 IP 地址 |
| `sip` | IPU | 内核 socket 结构 | 源 IP 地址 |
| `retval` | int | syscall 返回值 | 连接结果（0=成功） |
| `pidtree` | string | `__tid->pidtree` | 进程树 |

**安全场景**：
- C2 回连检测（异常外连地址/端口）
- 横向移动检测（内网扫描行为）
- 数据外泄通道识别

---

### 4.3 dns — DNS 查询

| 属性 | 值 |
|------|-----|
| **事件名称** | `dns` |
| **类型 ID** | 601（自定义 ID） |
| **挂载点** | `raw_tracepoint/sys_exit`（UDP 端口 53/5353 的数据包） |
| **代码位置** | `kprobe_print.h:96-118` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `dom` | string | DNS 报文解析 | 查询域名 |
| `sa_family` | u32 | `dip->family` | 地址族 |
| `dip` | IPU | socket 目标地址 | DNS 服务器 IP |
| `sip` | IPU | socket 源地址 | 本地 IP |
| `opcode` | int | DNS 头部 | 操作码（0=标准查询） |
| `rcode` | int | DNS 头部 | 响应码（0=无错误） |
| `type` | int | DNS 查询类型 | 记录类型（A=1, AAAA=28 等） |
| `pidtree` | string | `__tid->pidtree` | 进程树 |

**安全场景**：
- DNS 隧道检测（异常长域名、高频查询）
- DGA 域名检测（算法生成的随机域名）
- C2 域名发现（恶意域名解析行为）

---

### 4.4 create — 文件创建（inode 级）

| 属性 | 值 |
|------|-----|
| **事件名称** | `create` |
| **类型 ID** | 602（自定义 ID） |
| **挂载点** | `kprobe/security_inode_create` → `kp__inode_create()` |
| **代码位置** | `kprobe_print.h:120-140` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `pathstr` | string | inode 路径解析 | 创建文件的完整路径 |
| `dip` | IPU | 关联 socket | 目标 IP（若有网络关联） |
| `sip` | IPU | 关联 socket | 源 IP |
| `sa_family` | u32 | `dip->family` | 地址族 |
| `socket_pid` | u32 | 关联 socket PID | socket 关联的进程 PID |
| `s_id` | string | 超级块 s_id（32 字节） | 文件系统标识符 |
| `pidtree` | string | `__tid->pidtree` | 进程树 |

**安全场景**：
- Webshell 文件落盘检测
- 恶意文件写入监控（/tmp、/dev/shm 等敏感路径）
- 远程文件下载关联（通过 socket 信息关联网络来源）

---

### 4.5 rename — 文件重命名

| 属性 | 值 |
|------|-----|
| **事件名称** | `rename` |
| **类型 ID** | 82（对应 `__NR_rename`） |
| **挂载点** | `kprobe/security_inode_rename` → `kp__inode_rename()` |
| **代码位置** | `kprobe_print.h:142-157` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `oldname` | string | 原文件路径 | 重命名前的文件路径 |
| `newname` | string | 新文件路径 | 重命名后的文件路径 |
| `s_id` | string | 超级块 s_id（32 字节） | 文件系统标识符 |

**安全场景**：
- 恶意文件伪装（重命名为系统文件名）
- 日志篡改检测（日志文件被重命名）
- 配置文件替换检测

---

### 4.6 link — 硬链接创建

| 属性 | 值 |
|------|-----|
| **事件名称** | `link` |
| **类型 ID** | 86（对应 `__NR_link`） |
| **挂载点** | `kprobe/security_inode_link` → `kp__inode_link()` |
| **代码位置** | `kprobe_print.h:159-174` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `oldname` | string | 原文件路径 | 链接源文件路径 |
| `newname` | string | 新链接路径 | 硬链接目标路径 |
| `s_id` | string | 超级块 s_id（32 字节） | 文件系统标识符 |

**安全场景**：
- SUID 文件硬链接提权（创建硬链接绕过权限检查）
- 敏感文件持久化（通过硬链接防止删除）

---

### 4.7 bind — 端口绑定

| 属性 | 值 |
|------|-----|
| **事件名称** | `bind` |
| **类型 ID** | 49（对应 `__NR_bind`） |
| **挂载点** | `raw_tracepoint/sys_exit`（syscall 49 返回时） |
| **代码位置** | `kprobe_print.h:176-189` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `sa_family` | u32 | `dip->family` | 地址族 |
| `dip` | IPU | socket bind 地址 | 绑定的 IP 地址 |
| `retval` | int | syscall 返回值 | 绑定结果 |
| `pidtree` | string | `__tid->pidtree` | 进程树 |

**安全场景**：
- 后门监听端口检测
- 未授权服务启动检测
- 端口劫持检测

---

### 4.8 accept — 连接接受

| 属性 | 值 |
|------|-----|
| **事件名称** | `accept` |
| **类型 ID** | 43（对应 `__NR_accept`） |
| **挂载点** | `raw_tracepoint/sys_exit`（syscall 43 返回时） |
| **代码位置** | `kprobe_print.h:191-205` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `sa_family` | u32 | `dip->family` | 地址族 |
| `dip` | IPU | 客户端地址 | 连接来源 IP |
| `sip` | IPU | 服务端地址 | 本地监听 IP |
| `retval` | int | syscall 返回值 | 新 socket fd 或错误 |

**安全场景**：
- 反弹 shell 连接建立检测
- 异常入站连接监控
- 蜜罐触发告警

---

### 4.9 call_usermodehelper_exec — 用户态辅助程序执行

| 属性 | 值 |
|------|-----|
| **事件名称** | `call_usermodehelper_exec` |
| **类型 ID** | 607（自定义 ID） |
| **挂载点** | `kprobe/call_usermodehelper_exec` → `kp__umh_exec()` |
| **代码位置** | `kprobe_print.h:207-222` |

> **注意**：此事件使用 `ENTRY_XID(607)` 而非 `ENTRY_COMMON`，不包含标准公共字段。

**字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `xid` | u64 | 607 | 事件类型 ID |
| `exe` | string | 内核 subprocess_info | 要执行的程序路径 |
| `argv` | string | 内核 subprocess_info | 命令行参数 |
| `wait` | int | 内核 subprocess_info | 等待模式（UMH_WAIT_EXEC/PROC） |

**安全场景**：
- 内核态恶意代码检测（Rootkit 通过内核模块调用用户态程序）
- 内核漏洞利用检测（内核 exploit 执行 payload）
- 这是高价值安全事件，正常情况下极少触发

---

### 4.10 init_module — 内核模块加载

| 属性 | 值 |
|------|-----|
| **事件名称** | `init_module` |
| **类型 ID** | 603（自定义 ID） |
| **挂载点** | `kprobe/do_init_module` → `kp__init_module()` |
| **代码位置** | `kprobe_print.h:224-238` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `mod` | string | 内核模块名 | 加载的内核模块名称 |
| `pidtree` | string | `__tid->pidtree` | 进程树 |
| `pwd` | string | 当前工作目录 | 加载操作的工作目录 |

**安全场景**：
- Rootkit 内核模块加载检测
- 未授权内核模块安装告警
- 内核模块来源审计（结合 pwd 和 pidtree）

---

### 4.11 mount — 文件系统挂载

| 属性 | 值 |
|------|-----|
| **事件名称** | `mount` |
| **类型 ID** | 165（对应 `__NR_mount`） |
| **挂载点** | `raw_tracepoint/sys_exit`（syscall 165 返回时） |
| **代码位置** | `kprobe_print.h:240-264` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `pidtree` | string | `__tid->pidtree` | 进程树 |
| `dev_name` | string | mount 参数 | 设备名称 |
| `file_path` | string | mount 参数 | 挂载点路径 |
| `fsid` | string | 超级块（32 字节） | 文件系统 ID |
| `fstype` | string | mount 参数 | 文件系统类型（ext4, nfs 等） |
| `flags` | int | mount 参数 | 挂载标志位 |
| `option` | string | mount 参数 | 挂载选项字符串 |

**安全场景**：
- 容器逃逸检测（挂载宿主机文件系统）
- 恶意文件系统挂载（如 overlay 覆盖系统文件）
- 特权容器风险评估

---

### 4.12 ptrace — 进程调试/注入

| 属性 | 值 |
|------|-----|
| **事件名称** | `ptrace` |
| **类型 ID** | 101（对应 `__NR_ptrace`） |
| **挂载点** | `raw_tracepoint/sys_exit`（syscall 101 返回时，仅 POKETEXT/POKEDATA） |
| **代码位置** | `kprobe_print.h:267-284` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `request` | int | ptrace 请求类型 | PTRACE_POKETEXT(4) / PTRACE_POKEDATA(5) |
| `owner_pid` | u32 | 目标进程 PID | 被注入的进程 PID |
| `addr` | ulong | ptrace 地址参数 | 目标内存地址 |
| `data_res` | string | ptrace 数据参数 | 写入的数据内容 |
| `pidtree` | string | `__tid->pidtree` | 进程树 |

**安全场景**：
- 进程注入检测（通过 POKETEXT/POKEDATA 修改目标进程内存）
- 调试器附加检测
- 代码注入攻击（shellcode 注入）

---

### 4.13 memfd_create — 内存文件创建

| 属性 | 值 |
|------|-----|
| **事件名称** | `memfd_create` |
| **类型 ID** | 356（对应 `__NR_memfd_create`） |
| **挂载点** | `raw_tracepoint/sys_exit`（syscall 356 返回时） |
| **代码位置** | `kprobe_print.h:286-298` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `fdname` | string | memfd 名称参数 | 内存文件描述名称 |
| `flags` | int | memfd 标志参数 | 创建标志（MFD_CLOEXEC 等） |

**安全场景**：
- 无文件攻击检测（恶意代码仅存在于内存，不落盘）
- 内存马检测（fileless malware 常用 memfd_create 加载 payload）
- ELF 内存加载检测

---

### 4.14 setsid — 会话创建

| 属性 | 值 |
|------|-----|
| **事件名称** | `setsid` |
| **类型 ID** | 112（对应 `__NR_setsid`） |
| **挂载点** | `raw_tracepoint/sys_exit`（syscall 112 返回时） |
| **代码位置** | `kprobe_print.h:300-310` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `newsid` | int | syscall 返回值 | 新会话 ID |
| `pidtree` | string | `__tid->pidtree` | 进程树 |

**安全场景**：
- 守护进程创建检测（恶意程序脱离终端控制）
- 反弹 shell 行为特征（fork + setsid 模式）

---

### 4.15 commit_creds — 凭证变更

| 属性 | 值 |
|------|-----|
| **事件名称** | `commit_creds` |
| **类型 ID** | 604（自定义 ID） |
| **挂载点** | `kprobe/commit_creds` → `kp__commit_creds()` |
| **代码位置** | `kprobe_print.h:312-324` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `pidtree` | string | `__tid->pidtree` | 进程树 |
| `v_uid` | u32 | 新凭证 uid | 变更后的用户 ID |
| `v_euid` | int | 新凭证 euid | 变更后的有效用户 ID |

**安全场景**：
- 权限提升检测（非 root → root 的凭证变更）
- sudo/su 操作审计
- 内核漏洞利用后的提权行为

---

### 4.16 privilege_escalation — 权限提升检测

| 属性 | 值 |
|------|-----|
| **事件名称** | `privilege_escalation` |
| **类型 ID** | 611（自定义 ID） |
| **挂载点** | `raw_tracepoint/sys_exit`（setuid/setgid 类 syscall 返回时） |
| **代码位置** | `kprobe_print.h:326-340` |

**触发的 syscall**：`setreuid`, `setregid`, `setresuid`, `setresgid`, `setuid`, `setgid`, `setfsuid`, `setfsgid`

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `task_pid` | int | 目标任务 PID | 发生提权的进程 PID |
| `pidtree` | string | `__tid->pidtree` | 进程树 |
| `p_cred` | XIDS | 变更前凭证 | 旧的 uid/gid/suid/sgid/euid/egid/fsuid/fsgid |
| `c_cred` | XIDS | 变更后凭证 | 新的 uid/gid/suid/sgid/euid/egid/fsuid/fsgid |

> `XIDS` 类型为 `struct cred_xids`，包含 8 个 u32 字段：uid, gid, suid, sgid, euid, egid, fsuid, fsgid

**安全场景**��
- 精准权限提升检测（对比变更前后完整凭证快照）
- 内核漏洞 exploit 提权（如 dirty pipe、dirty cow 利用后的凭证变更）
- 可疑 SUID 程序滥用

---

### 4.17 file_creation — 文件创建（close 触发）

| 属性 | 值 |
|------|-----|
| **事件名称** | `file_creation` |
| **类型 ID** | 613（自定义 ID） |
| **挂载点** | `kprobe/filp_close` → `kp__filp_close()`（检查 FMODE_CREATED 标志） |
| **代码位置** | `kprobe_print.h:342-352` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `file_path` | string | 文件路径解析 | 新创建文件的完整路径 |

**安全场景**：
- 文件落盘完成检测（与 create(602) 的区别：此事件在文件关闭时触发，确认文件已写入完毕）
- 恶意文件写入确认（文件内容已完整写入磁盘）
- 适合与文件内容扫描联动

---

### 4.18 chmod — 文件权限修改

| 属性 | 值 |
|------|-----|
| **事件名称** | `chmod` |
| **类型 ID** | 90（对应 `__NR_chmod`） |
| **挂载点** | `raw_tracepoint/sys_exit`（syscall chmod/fchmod 返回时） |
| **代码位置** | `kprobe_print.h:354-371` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `pidtree` | string | `__tid->pidtree` | 进程树 |
| `file_path` | string | 文件路径解析 | 被修改权限的文件路径 |
| `fsid` | string | 超级块（32 字节） | 文件系统标识符 |
| `mode` | int | chmod 参数 | 新的文件权限模式 |
| `retval` | int | syscall 返回值 | 操作结果 |

**安全场景**：
- SUID/SGID 位设置检测（chmod u+s）
- 敏感文件权限放宽告警（如 /etc/shadow 权限变更）
- 可执行权限添加检测（对新下载文件）

---

### 4.19 prctl — 进程控制

| 属性 | 值 |
|------|-----|
| **事件名称** | `prctl` |
| **类型 ID** | 157（对应 `__NR_prctl`） |
| **挂载点** | `kprobe/security_task_prctl` → `kp__task_prctl()` |
| **代码位置** | `kprobe_print.h:20-32` |

**特有字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `option` | int | prctl 选项参数 | 操作类型（如 PR_SET_NAME=15） |
| `newname` | string | prctl 参数 | 新进程名（仅 PR_SET_NAME 时有效） |

**安全场景**：
- 进程名伪装检测（PR_SET_NAME 修改 /proc/self/comm）
- 恶意程序隐藏行为（修改进程名模仿系统进程）

---

## 第五章：反 Rootkit 检测事件（4种）

> 反 Rootkit 事件定义在 `driver/BPF/inc/hids/anti_rootkit_print.h` 中。
> 这些事件不包含 `ENTRY_COMMON` 公共字段，仅使用 `ENTRY_XID` 加少量特定字段。
> 主要用于检测内核级别的恶意篡改行为。

### 5.1 fops / PROC_FILE_HOOK — /proc 文件操作钩子检测

| 属性 | 值 |
|------|-----|
| **事件名称** | `fops` |
| **类型 ID** | 700（`PROC_FILE_HOOK`） |
| **检测目标** | /proc 文件系统的 `file_operations` 结构被篡改 |
| **代码位置** | `anti_rootkit_print.h` |

**字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `name` | string | 模块名（最大 MODULE_NAME_LEN） | 篡改 /proc 文件操作的内核模块名称 |

**安全场景**：
- Rootkit 通过修改 /proc 文件操作隐藏进程、网络连接、内核模块
- 检测 `/proc/modules`、`/proc/net/tcp` 等关键 proc 文件的 handler 替换

---

### 5.2 syscall / SYSCALL_HOOK — 系统调用表钩子检测

| 属性 | 值 |
|------|-----|
| **事件名称** | `syscall` |
| **类型 ID** | 701（`SYSCALL_HOOK`） |
| **检测目标** | `sys_call_table` 被篡改 |
| **代码位置** | `anti_rootkit_print.h` |

**字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `name` | string | 模块名（最大 MODULE_NAME_LEN） | 篡改系统调用的内核模块名称 |
| `scid` | int | 系统调用号 | 被 hook 的系统调用 ID |

**安全场景**：
- 经典 Rootkit 技术：替换 sys_call_table 中的函数指针
- 检测 getdents/kill/read 等常被 hook 的系统调用

---

### 5.3 mod / LKM_HIDDEN — 隐藏内核模块检测

| 属性 | 值 |
|------|-----|
| **事件名称** | `mod` |
| **类型 ID** | 702（`LKM_HIDDEN`） |
| **检测目标** | 从 `modules` 链表中移除自身的内核模块 |
| **代码位置** | `anti_rootkit_print.h` |

**字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `name` | string | 模块名（最大 MODULE_NAME_LEN） | 隐藏的内核模块名称 |

**安全场景**：
- Rootkit 通过 `list_del()` 从内核模块链表中移除自身，使 `lsmod` 无法显示
- 结合 init_module(603) 事件，可追溯模块加载到隐藏的全过程

---

### 5.4 interrupts / INTERRUPTS_HOOK — 中断处理钩子检测（仅 x86）

| 属性 | 值 |
|------|-----|
| **事件名称** | `interrupts` |
| **类型 ID** | 703（`INTERRUPTS_HOOK`） |
| **检测目标** | IDT（中断描述符表）被篡改 |
| **条件编译** | `#if IS_ENABLED(CONFIG_X86)` — 仅 x86 架构 |
| **代码位置** | `anti_rootkit_print.h` |

**字段**：

| 字段名 | 类型 | 数据来源 | 说明 |
|--------|------|----------|------|
| `name` | string | 模块名（最大 MODULE_NAME_LEN） | 篡改中断处理的内核模块名称 |
| `intno` | int | 中断号 | 被 hook 的中断向量号 |

**安全场景**：
- 高级 Rootkit 通过修改 IDT 实现系统调用劫持
- 检测中断门（interrupt gate）的非法修改

---

## 第六章：已禁用事件清单（14种）

> 以下事件在 `kprobe_print.h` 中被 `#if 0 /* TODO for phase 3 */` 包裹，字段定义已完成但未启用。
> 另有 3 个事件（write、file_permission_write、file_permission_read）虽有定义但在 hids.c 中无对应 Hook 实现。

### 6.1 udev — USB 设备事件

| 属性 | 值 |
|------|-----|
| **类型 ID** | 610 |
| **代码位置** | `kprobe_print.h:375-393` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(610) | — | 公共字段 |
| `product` | string | USB 设备产品名 |
| `manufacturer` | string | 制造商 |
| `serial` | string | 序列号 |
| `action` | int | 设备动作（插入/移除） |

**禁用原因分析**：USB 设备事件需要额外的内核子系统 Hook（udev/USB 子系统），Phase 3 规划中，可能涉及 BadUSB 检测等场景。

---

### 6.2 mprotect — 内存保护变更

| 属性 | 值 |
|------|-----|
| **类型 ID** | 10（对应 `__NR_mprotect`） |
| **代码位置** | `kprobe_print.h:395-412` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(10) | — | 公共字段 |
| `prot` | u32 | 新保护标志（PROT_READ/WRITE/EXEC） |
| `owner_pid` | u32 | 目标进程 PID |
| `owner_file` | string | 关联文件 |
| `vm_file` | string | VMA 映射文件 |
| `pid_tree` | string | 进程树 |

**禁用原因分析**：`mprotect` 调用频率极高（几乎所有动态链接程序都会调用），启用会产生大量事件导致性能问题。安全价值主要在 RWX→RX 的内存保护变更（JIT spraying），需要精细的过滤策略。

---

### 6.3 open — 文件打开

| 属性 | 值 |
|------|-----|
| **类型 ID** | 2（对应 `__NR_open`） |
| **代码位置** | `kprobe_print.h:414-427` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(2) | — | 公共字段 |
| `flags` | int | 打开标志 |
| `mode` | int | 文件模式 |
| `filename` | string | 文件路径 |

**禁用原因分析**：文件打开是最高频 syscall 之一，无差别采集会产生海量事件。需要路径白名单过滤才能实际使用（如仅监控 /etc/passwd、/etc/shadow 等敏感文件）。

---

### 6.4 nanosleep — 休眠

| 属性 | 值 |
|------|-----|
| **类型 ID** | 35（对应 `__NR_nanosleep`） |
| **代码位置** | `kprobe_print.h:429-440` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(35) | — | 公共字段 |
| `sec` | int | 休眠秒数 |
| `nsec` | int | 休眠纳秒数 |

**禁用原因分析**：nanosleep 调用极其频繁，安全价值有限。潜在用途是检测恶意程序的定时行为模式（如 beacon 间隔），但信噪比太低。

---

### 6.5 kill — 信号发送

| 属性 | 值 |
|------|-----|
| **类型 ID** | 62（对应 `__NR_kill`） |
| **代码位置** | `kprobe_print.h:442-455` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(62) | — | 公共字段 |
| `killpid` | int | 目标进程 PID |
| `killsig` | int | 信号编号 |
| `killret` | int | 返回值 |

**禁用原因分析**：kill 信号发送频率中等，主要安全场景是检测进程间干扰（如杀死安全产品进程）。可能需要结合目标进程信息进行过滤，Phase 3 实现。

---

### 6.6 tkill — 线程信号发送

| 属性 | 值 |
|------|-----|
| **类型 ID** | 200（对应 `__NR_tkill`） |
| **代码位置** | `kprobe_print.h:457-470` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(200) | — | 公共字段 |
| `killtid` | int | 目标线程 ID |
| `killsig` | int | 信号编号 |
| `killret` | int | 返回值 |

**禁用原因分析**：与 kill 类似，tkill 针对线程级别。安全场景与 kill 重叠，Phase 3 统一实现。

---

### 6.7 tgkill — 线程组信号发送

| 属性 | 值 |
|------|-----|
| **类型 ID** | 201（对应 `__NR_tgkill`） |
| **代码位置** | `kprobe_print.h:472-487` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(201) | — | 公共字段 |
| `kiltgid` | int | 目标线程组 ID |
| `killtid` | int | 目标线程 ID |
| `killsig` | int | 信号编号 |
| `killret` | int | 返回值 |

**禁用原因分析**：tgkill 是 tkill 的增强版（增加 tgid 参数防误杀），与 kill/tkill 一起在 Phase 3 规划。

---

### 6.8 exit — 进程退出

| 属性 | 值 |
|------|-----|
| **类型 ID** | 60（对应 `__NR_exit`） |
| **代码位置** | `kprobe_print.h:489-498` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(60) | — | 公共字段 |
| `retval` | int | 退出码 |

**禁用原因分析**：进程退出事件通过 `raw_tracepoint/sched_process_exit` 已经在 `tp__proc_exit()` 中处理（用于清理 tid_cache），但不作为安全事件上报。安全价值有限，Phase 3 可选。

---

### 6.9 exit_group — 线程组退出

| 属性 | 值 |
|------|-----|
| **类型 ID** | 231（对应 `__NR_exit_group`） |
| **代码位置** | `kprobe_print.h:500-509` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(231) | — | 公共字段 |
| `retval` | int | 退出码 |

**禁用原因分析**：与 exit 类似，exit_group 终止整个线程组。已通过 tracepoint 处理缓存清理，安全事件上报延后。

---

### 6.10 security_path_rmdir — 目录删除

| 属性 | 值 |
|------|-----|
| **类型 ID** | 606 |
| **代码位置** | `kprobe_print.h:511-523` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(606) | — | 公共字段 |
| `file_path` | string | 被删除目录路径 |
| `s_id` | string | 文件系统标识 |

**禁用原因分析**：目录删除事件频率中等，主要安全场景是日志目录清除检测、取证痕迹清理。需要路径过滤策略，Phase 3 实现。

---

### 6.11 security_path_unlink — 文件删除

| 属性 | 值 |
|------|-----|
| **类型 ID** | 605 |
| **代码位置** | `kprobe_print.h:525-537` |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(605) | — | 公共字段 |
| `file_path` | string | 被删除文件路径 |
| `s_id` | string | 文件系统标识 |

**禁用原因分析**：与 rmdir 类似，文件删除频率高。安全场景包括恶意程序自删除、日志清理。需过滤策略。

---

### 6.12 write — 文件写入

| 属性 | 值 |
|------|-----|
| **类型 ID** | 1（对应 `__NR_write`） |

**字段定义**：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| ENTRY_COMMON(1) | — | 公共字段 |
| `file_path` | string | 写入的文件路径 |
| `fd` | int | 文件描述符 |
| `count` | int | 写入字节数 |

**禁用原因分析**：write 是系统中最高频的 syscall，无差别采集会导致严重性能下降。即使有过滤，事件量仍然巨大。安全场景需求（如 /etc/crontab 写入检测）可通过 inotify 或更精准的 LSM Hook 替代。

---

### 6.13 file_permission_write — 文件写入权限检查

| 属性 | 值 |
|------|-----|
| **类型 ID** | 608 |

**禁用原因分析**：通过 `security_file_permission` LSM Hook 实现，检查写权限时触发。频率极高，与 write 事件类似的性能问题。

---

### 6.14 file_permission_read — 文件读取权限检查

| 属性 | �� |
|------|-----|
| **类型 ID** | 609 |

**禁用原因分析**：与 file_permission_write 对称，检查读权限时触发。读操作频率更高，性能影响更大。

---

## 第七章：用户态 Agent 事件消费架构

### 7.1 Agent 整体架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        Elkeid Agent 主进程                                │
│                                                                          │
│  ┌────────────────────────────────────────────────────┐                  │
│  │              Plugin 管理层                           │                  │
│  │                                                      │                  │
│  │  ┌──���───────┐  ┌──────────┐  ┌──────────┐          │                  │
│  │  │ eBPF     │  │ Plugin B │  │ Plugin C │  ...     │                  │
│  │  │ Driver   │  │          │  │          │          │                  │
│  │  │ (子进程)  │  │ (子进程)  │  │ (子进程)  │          │                  │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘          │                  │
│  │       │pipe          │pipe         │pipe             │                  │
│  │       ▼              ▼             ▼                  │                  │
│  │  ┌──────────────────────────────────────────────┐   │                  │
│  │  │  事件接收层 (每 Plugin 3 个 goroutine)         │   │                  │
│  │  │  G1: 进程等待 + 管道清理                       │   │                  │
│  │  │  G2: ReceiveData() 循环读取事件               │   │                  │
│  │  │  G3: SendTask() 接收服务端命令并下发           │   │                  │
│  │  └──────────────────────┬───────────────────────┘   │                  │
│  └─────────────────────────┼──────────────────────────┘                  │
│                             │                                              │
│                             ▼                                              │
│  ┌──────────────────────────────────────────────────────┐                │
│  │            Ring Buffer (2048 slots)                    │                │
│  │                                                        │                │
│  │  ┌──────┬──────┬──────┬─────────────────┬──────┐     │                │
│  │  │ [0]  │ [1]  │ [2]  │      ...        │[2047]│     │                │
│  │  └──────┴──────┴──────┴─────────────────┴──────┘     │                │
│  │  ← mutex 保护，满时丢弃新事件                          │                │
│  │                                                        │                │
│  │  四级对象池: [1KB] [2KB] [3KB] [4KB]                  │                │
│  └──────────────────────┬─────────────────────────────┘                │
│                          │ 100ms 定时读取                                 │
│                          ▼                                                │
│  ┌──────────────────────────────────────────────────────┐                │
│  │            gRPC Transport 层                           │                │
│  │                                                        │                │
│  │  PackagedData {                                       │                │
│  │    records: [EncodedRecord, ...],                     │                │
│  │    agent_id, hostname, version,                       │                │
│  │    intranet_ipv4/ipv6, extranet_ipv4/ipv6            │                │
│  │  }                                                    │                │
│  │                                                        │                │
│  │  ← Snappy 压缩 → gRPC 双向流 → TLS/mTLS →           │                │
│  └──────────────────���───┬─────────────────────────────┘                │
│                          │                                                │
│  ┌──────────────────────┴─────────────────────────────┐                │
│  │            心跳 & 遥测                                │                │
│  │  DataType 1000: Agent 心跳 (60s)                     │                │
│  │  DataType 1001: Plugin 统计 (60s)                    │                │
│  │  DataType 1010: Agent 日志                            │                │
│  └────────────────────────────────────────────────────┘                │
└──────────────────────────────────────────────────────────────────────────┘
                          │
                          │ gRPC 双向流
                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     Elkeid Server                                         │
│                                                                          │
│  Transfer(stream PackagedData) returns (stream Command)                  │
│                                                                          │
│  下发命令:                                                               │
│  ├─ Plugin 配置同步 (add/remove/update)                                  │
│  ├─ DataType 1050: 文件上传请求                                           │
│  ├─ DataType 1051: 元数据设置 (idc/region)                               │
│  └─ DataType 1060: Agent 关闭命令                                        │
└──────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Plugin 子进程模型

**代码位置**：`agent/plugin/plugin_linux.go`

每个 Plugin 作为独立子进程运行：

| 特性 | 说明 |
|------|------|
| **启动方式** | Agent 下载 Plugin 二进制文件，校验签名后 fork/exec |
| **工作目录** | `{agent_wd}/plugin/{plugin_name}/` |
| **通信方式** | stdout 管道（Plugin→Agent）、stdin 管道（Agent→Plugin） |
| **进程组** | `Setpgid: true`，便于整组终止 |
| **优雅退出** | 关闭管道 → 等待 10 秒 → SIGKILL 强制终止 |
| **每 Plugin goroutine** | 3 个：进程等待、事件接收、命令下发 |

### 7.3 事件解析协议

**代码位置**：`agent/plugin/plugin.go:74-131`，`agent/plugin/protocol.go:14-32`

#### 解析流程

```
1. 从 buffered reader 读取 4 字节 → 小端序解码为 uint32 长度
2. 跳过 1 字节分隔符
3. 读取 varint → DataType（事件类型 ID）
4. 跳过 1 字节分隔符
5. 读取 varint → Timestamp（Unix 秒时间戳）
6. 跳过 1 字节分隔符
7. 如果还有剩余字节：
   a. 读取 varint → 载荷长度
   b. 从对象池分配 EncodedRecord
   c. 读取剩余字节到 EncodedRecord.Data
8. 设置 EncodedRecord.DataType 和 EncodedRecord.Timestamp
9. 写入 Ring Buffer
```

#### varint 编码（Protobuf 风格）

```
每字节：[1bit 继续标志][7bit 数据]
示例：值 300 = 0b100101100
  字节1: 10101100 (继续=1, 数据=0101100)
  字节2: 00000010 (继续=0, 数据=0000010)
  解码: 0101100 | (0000010 << 7) = 300
```

### 7.4 事件缓冲：Ring Buffer + 对象池

**代码位置**：`agent/buffer/buffer.go:9-64`，`agent/buffer/pool.go:9-63`

#### Ring Buffer 行为

```go
var buf = [2048]*proto.EncodedRecord{}  // 固定 2048 槽位
var offset = 0                           // 写入游标
var mu = &sync.Mutex{}                   // 互斥锁

WriteEncodedRecord(rec):
    lock(mu)
    if offset < 2048:
        buf[offset] = rec
        offset++
    else:
        PutEncodedRecord(rec)  // 满了，回收到对象池
    unlock(mu)

ReadEncodedRecords() → []*EncodedRecord:
    lock(mu)
    result = buf[0:offset]     // 取出所有
    offset = 0                 // 重置
    unlock(mu)
    return result
```

#### 四级对象池工作原理

```
分配请求 size=1500 字节：
  index = (1500 - 1) >> 10 = 1  → 使用 Pool[1]（2048 字节）
  从 sync.Pool 获取或新建 EncodedRecord

回收 EncodedRecord：
  if cap(rec.Data) == pool_capacity:
      放回对应 Pool
  else:
      丢弃（让 GC 回收）
```

### 7.5 gRPC 上报机制

**代码位置**：`agent/transport/transfer.go:39-127`

#### 发送流程

1. **定时触发**：`time.NewTicker(100 * time.Millisecond)` → 每 100ms 执行一次
2. **批量读取**：`buffer.ReadEncodedRecords()` → 获取所有缓冲事件
3. **构建消息**：打包为 `proto.PackagedData`
4. **压缩发送**：Snappy 压缩 → gRPC stream `Send()`
5. **资源回收**：发送完成后将 EncodedRecord 归还对象池

#### 连接管理

| 参数 | 值 |
|------|-----|
| 重试次数 | 6 次 |
| 重试间隔 | 5 秒 |
| 压缩算法 | Snappy |
| 安全传输 | TLS/mTLS |
| 流类型 | 双向流（Bidirectional Streaming） |

#### gRPC 协议定义

```protobuf
// agent/proto/grpc.proto

service Transfer {
  rpc Transfer(stream PackagedData) returns (stream Command) {}
}

message PackagedData {
  repeated EncodedRecord records = 1;
  string agent_id = 2;
  repeated string intranet_ipv4 = 3;
  repeated string extranet_ipv4 = 4;
  repeated string intranet_ipv6 = 5;
  repeated string extranet_ipv6 = 6;
  string hostname = 7;
  string version = 8;
  string product = 9;           // "elkeid-agent"
}

message EncodedRecord {
  int32 data_type = 1;
  int64 timestamp = 2;          // Unix 秒
  bytes data = 3;               // 二进制载荷
}

message Command {
  Task task = 2;
  repeated Config configs = 3;
}

message Task {
  int32 data_type = 1;
  string object_name = 2;      // "elkeid-agent" 或 plugin 名
  string data = 3;             // JSON 数据
  string token = 4;            // 追踪令牌
}

message Config {
  string name = 1;
  string type = 2;
  string version = 3;
  string sha256 = 4;
  string signature = 5;
  repeated string download_urls = 6;
  string detail = 7;           // 环境变量 DETAIL=...
}
```

### 7.6 Agent 自身事件

| DataType | 名称 | 频率 | 内容 |
|----------|------|------|------|
| **1000** | Agent 心跳 | 60 秒 | 系统信息、Agent 状态、资源使用、网络指标、负载均值 |
| **1001** | Plugin 统计 | 60 秒/插件 | 插件名、版本、CPU/内存、IO 速率、吞吐量 |
| **1010** | Agent 日志 | 实时 | 诊断日志，通过 `GrpcWriter` 实现 `io.Writer` 接口 |

#### DataType 1000 心跳详细字段

```
系统信息: kernel_version, arch, platform, platform_family, platform_version
Agent 状态: state (running/abnormal), state_detail (错误列表 JSON)
网络: idc, region, net_mode, rx_speed, tx_speed
资源: cpu%, rss(MB), read_speed, write_speed, pid, nfd, start_time
gRPC 指标: tx_tps, rx_tps
存储: du (目录占用), ngr (goroutine 数), nproc (CPU 核数), total_mem
负载: load_1, load_5, load_15
主机: host_serial, host_id, host_model, host_vendor, dns, gateway
CPU: cpu_name, boot_time, cpu_usage, mem_usage
```

### 7.7 服务端下发命令处理

**代码位置**：`agent/transport/transfer.go:129-245`

#### Agent 自身命令（ObjectName == "elkeid-agent"）

| DataType | 命令 | 说明 |
|----------|------|------|
| 1050 | 文件上传 | 上传指定文件到服务端（通过 FileExt gRPC 服务） |
| 1051 | 元数据设置 | 更新 idc/region，执行 `elkeidctl set` |
| 1060 | 关闭 Agent | 优雅停止 Agent 进程 |

#### Plugin 命令路由

- 服务端下发 `Command.Task`，`ObjectName` 指定目标 Plugin
- Agent 通过 Plugin 的 task channel 转发
- Plugin 通过 stdin 管道接收（4 字节长度前缀 + protobuf 编码）

#### Plugin 配置同步

- 服务端下发 `Command.Configs` 数组
- Agent 对比当前 Plugin 列表：
  - 新增 Plugin → 下载、校验签名、启动子进程
  - 版本变更 → 停止旧版本、启动新版本
  - 移除 Plugin → 停止子进程、清理工作目录
- 失败时 Agent 标记为 abnormal 状态

### 7.8 Agent 身份标识

**代码位置**：`agent/agent/id.go`

Agent ID 解析优先级：

1. 环境变量 `SPECIFIED_AGENT_ID`（允许手动覆盖）
2. Cloud-Init 实例 ID（`/var/lib/cloud/data/instance-id`）
3. DMI Product UUID + MAC 地址 + 实例 ID → SHA1 生成
4. Machine ID（`/etc/machine-id`）
5. 随机生成 UUID（兜底方案）

---

## 第八章：安全能力评估总结

### 8.1 已覆盖安全检测场景矩阵

| 安全场景 | 对应事件 | 覆盖程度 |
|----------|----------|----------|
| **进程执行审计** | execve(59) | ★★★★★ 完整命令行、环境变量、进程树 |
| **网络连接监控** | connect(42), accept(43), bind(49) | ★★★★★ 出入站连接+端口绑定 |
| **DNS 监控** | dns(601) | ★★★★☆ 覆盖 UDP 53/5353，不含 DoH/DoT |
| **文件创建监控** | create(602), file_creation(613) | ★★★★☆ inode 级+close 触发双重覆盖 |
| **文件操作审计** | rename(82), link(86), chmod(90) | ★★★☆☆ 覆盖关键操作，缺少 unlink/rmdir |
| **权限提升检测** | privilege_escalation(611), commit_creds(604) | ★★★★★ 凭证变更前后对比 |
| **进程注入检测** | ptrace(101) | ★★★☆☆ 仅覆盖 POKETEXT/POKEDATA |
| **无文件攻击** | memfd_create(356) | ★★★★☆ 覆盖内存文件创建 |
| **内核模块监控** | init_module(603) | ★★★★☆ 模块加载检测 |
| **Rootkit 检测** | fops(700), syscall(701), mod(702), interrupts(703) | ★★★★☆ 覆盖主要 Rootkit 技术 |
| **容器安全** | mount(165) + mntns_id 字段 | ★★★☆☆ 挂载操作+命名空间标识 |
| **会话管理** | setsid(112) | ★★☆☆☆ 基础会话创建检测 |
| **内核态攻击** | call_usermodehelper_exec(607) | ★★★★★ 高价值事件 |

### 8.2 未覆盖 / 待启用能力分析

| 能力缺口 | 影响 | 对应禁用事件 | 启用建议 |
|----------|------|-------------|----------|
| **文件删除监控** | 无法检测日志清理、痕迹擦除 | unlink(605), rmdir(606) | 建议优先启用，配合路径过滤 |
| **信号监控** | 无法检测杀死安全进程 | kill(62), tkill(200), tgkill(201) | 建议启用，仅监控特定目标进程 |
| **文件读写审计** | 无法检测敏感文件读取/篡改 | open(2), write(1) | 需精细过滤策略，可选启用 |
| **内存保护变更** | 无法检测 JIT spraying | mprotect(10) | 高性能开销，建议仅特定场景启用 |
| **USB 设备** | 无法检测 BadUSB | udev(610) | 需额外内核子系统支持 |
| **进程退出审计** | 无法追踪进程生命周期终结 | exit(60), exit_group(231) | 安全价值有限，可选 |
| **DoH/DoT** | DNS over HTTPS/TLS 绕过 | 无对应事件 | 需应用层 Hook 或网络层检测 |
| **eBPF 程序加载** | 恶意 eBPF 程序注入 | 无对应事件 | 建议新增 bpf() syscall 监控 |
| **容器逃逸** | 仅有 mount 事件 | — | 建议增加 setns/unshare 监控 |

### 8.3 ATT&CK 框架映射（粗粒度）

| ATT&CK 战术 | ATT&CK 技术 | Elkeid 对应事件 | 覆盖状态 |
|-------------|-------------|----------------|----------|
| **初始访问** | T1190 公共应用利用 | execve + connect | 部分覆盖 |
| **执行** | T1059 命令和脚本解释器 | execve(59) | ✅ 覆盖 |
| | T1106 原生 API | connect(42), bind(49) | ✅ 覆盖 |
| | T1204 用户执行 | execve(59) | ✅ 覆盖 |
| **持久化** | T1543 创建/修改系统服务 | file_creation(613), chmod(90) | 部分覆盖 |
| | T1547 启动项 | file_creation(613), create(602) | 部分覆盖 |
| | T1546 事件触发执行 | create(602), rename(82) | 部分覆盖 |
| **权限提升** | T1548 滥用提升控制机制 | privilege_escalation(611) | ✅ 覆盖 |
| | T1068 利用漏洞提权 | commit_creds(604), privilege_escalation(611) | ✅ 覆盖 |
| | T1574 劫持执行流 | execve(LD_PRELOAD 检测) | ✅ 覆盖 |
| **防御规避** | T1014 Rootkit | fops(700), syscall(701), mod(702) | ✅ 覆盖 |
| | T1055 进程注入 | ptrace(101) | 部分覆盖 |
| | T1070 指标移除 | rename(82) | 部分覆盖（缺少 unlink） |
| | T1140 反混淆/解码 | memfd_create(356) | 部分覆盖 |
| | T1620 反射代码加载 | memfd_create(356) | ✅ 覆盖 |
| **凭证访问** | T1003 OS 凭证转储 | — | ❌ 未覆盖（需 open 事件） |
| **发现** | T1082 系统信息发现 | execve(59) | 部分覆盖 |
| | T1049 网络连接发现 | execve(59) | 部分覆盖 |
| **横向移动** | T1021 远程服务 | connect(42), accept(43) | 部分覆盖 |
| **收集** | T1005 本地数据收集 | — | ❌ 未覆盖（需 open/read 事件） |
| **命令与控制** | T1071 应用层协议 | connect(42), dns(601) | ✅ 覆盖 |
| | T1572 协议隧道 | dns(601), connect(42) | 部分覆盖 |
| | T1573 加密通道 | connect(42) | 部分覆盖 |
| **数据外泄** | T1048 通过替代协议 | connect(42), dns(601) | 部分覆盖 |
| **影响** | T1485 数据销毁 | — | ❌ 未覆盖（需 unlink 事件） |

### 8.4 总体评估

**优势**：
- 事件覆盖面广：19 种安全事件 + 4 种反 Rootkit 事件，覆盖主要攻击面
- 字段信息丰富：execve 事件包含 16 个特有字段（含进程树、SSH 连接、LD_PRELOAD）
- 权限提升检测精细：通过凭证快照对比实现高精度提权检测
- 反 Rootkit 能力完备：覆盖 proc hook、syscall hook、隐藏模块、IDT hook 四大类
- 白名单机制高效：通过 MurmurHash + LRU Map 实现低开销的可信进程过滤
- 容器感知：所有事件携带 mntns_id/root_mntns_id 用于容器/宿主机区分

**待改进**：
- 文件删除事件未启用，影响痕迹清理检测
- 信号监控缺失，无法检测安全产品被杀
- DNS 仅覆盖明文 UDP，DoH/DoT 存在检测盲区
- 进程注入仅覆盖 ptrace POKETEXT/POKEDATA，缺少 process_vm_writev 等现代注入技术
- 缺少 eBPF 程序加载监控（bpf syscall）
- 缺少 namespace 操作监控（setns/unshare）用于容器逃逸检测

---

> **文档完毕**
>
> 本文档基于 Elkeid 3.0 eBPF Driver (EBPF_PROG_VERSION 3.0.0.7) 源码分析，覆盖内核态 eBPF 事件采集体系和用户态 Agent 事件消费架构的完整调研。
