# Elkeid eBPF HIDS 渐进式学习指南

本目录包含从 Elkeid 项目 `BPF/hids.c` 中提取的核心技术点，拆解为独立的、可运行的最小化学习 demo。

## 前置要求

- Linux 内核 >= 5.4（推荐 5.10+）
- clang >= 12（用于编译 eBPF C 代码）
- Go >= 1.19（用于编译用户态程序）
- bpftool（可选，用于检查 map/prog）
- root 权限（加载 eBPF 程序需要）

### 安装依赖（Ubuntu/Debian）

```bash
apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
```

### 生成 vmlinux.h

每个 demo 都依赖 `vmlinux.h`，需要从当前内核生成：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

将生成的 `vmlinux.h` 放到每个 demo 目录下，或者放到一个公共位置并在编译时通过 `-I` 指定。

## 学习路线

```
阶段1: 进程生命周期跟踪 (01-process-lifecycle)
  目标: 掌握 raw_tracepoint、BPF_MAP_TYPE_LRU_HASH、进程 fork/exec/exit 追踪
    │
阶段2: Per-CPU Buffer 事件输出 (02-percpu-buffer)
  目标: 掌握 PERCPU_ARRAY 突破栈限制、PERF_EVENT_ARRAY 输出、execve 数据采集
    │
阶段3: Kprobe 提权检测 (03-privesc-detection)
  目标: 掌握 kprobe 挂载内核函数、凭证对比、commit_creds 提权告警
    │
整合: Elkeid 完整 hids.c
  将上述技术组合: 进程缓存 + 大数据采集 + 多 hook 协同
```

## 各 demo 技术点与 Elkeid 源码对照

| Demo | 核心技术 | Elkeid 对应代码 |
|------|---------|----------------|
| 01-process-lifecycle | raw_tracepoint + LRU_HASH | `hids.c:3094-3167` (tp__proc_fork/exec/exit) + `hids.c:1568-1632` (construct_tid/find_current_tid) |
| 02-percpu-buffer | PERCPU_ARRAY + PERF_EVENT | `hids.c:66-103` (g_percpu_data/sd_get_percpu_data) + `hids.c:248-280` (SD_XFER_DEFINE_N 事件打包) |
| 03-privesc-detection | kprobe + cred 检测 | `hids.c:3471-3489` (kp__commit_creds) + `hids.c:1061-1109` (construct_xids/validate_xids/privilege_escalation) |

## 通用编译命令

```bash
# 编译 eBPF 内核态程序
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c xxx.bpf.c -o xxx.bpf.o

# 初始化 Go 模块（首次）
go mod init demo
go mod tidy

# 编译并运行（需要 root）
go build -o demo . && sudo ./demo
```
