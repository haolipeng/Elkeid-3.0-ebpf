// SPDX-License-Identifier: GPL-2.0
//
// 技术点 6: 条件 #pragma unroll 循环展开 —— 内核版本兼容性策略
//
// 核心技术:
//   - LOOPS_UNROLL 宏: 根据内核版本决定是否展开循环
//   - kernel <= 5.2: 验证器不理解循环，必须 #pragma unroll 完全展开
//   - kernel >= 5.3: 验证器可证明有界循环终止，无需展开
//   - 展开模式下减少迭代次数 (50 vs 75) 以控制指令数
//   - __noinline 减少展开后的指令膨胀
//
// 对应 Elkeid 源码:
//   - hids.c:294-298  (LOOPS_UNROLL 宏定义，基于 KERNEL_VERSION(5,2,0))
//   - hids.c:870-887  (DNS 解析循环: 展开模式 50 次 vs 有界模式 75 次)
//   - hids.c:575-585  (socket fd 遍历: #pragma unroll + 早期 break)
//   - 全文 13 处 #if LOOPS_UNROLL / #pragma unroll 使用
//
// 设计目标:
//   演示三种典型循环模式在展开/有界两种策略下的行为差异，
//   以及 Elkeid 如何通过条件编译同时支持新旧内核。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 循环展开策略宏
 *
 * 对应 Elkeid: hids.c:294-298
 *   #if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 2, 0)
 *   #define LOOPS_UNROLL    (1)
 *   #else
 *   #define LOOPS_UNROLL    (0)
 *   #endif
 *
 * 本 demo 默认为 0 (现代内核)，可通过编译参数覆盖:
 *   clang -DFORCE_UNROLL=1 ...
 *
 * 在旧内核 (<= 5.2) 上编译时必须开启展开，否则验证器
 * 会因为看到"后向跳转"(backward jump) 而拒绝程序。
 * ============================================================ */
#ifndef FORCE_UNROLL
#   define FORCE_UNROLL 0
#endif

#if FORCE_UNROLL
#   define LOOPS_UNROLL (1)
#else
#   define LOOPS_UNROLL (0)
#endif

/* ============================================================
 * 常量定义
 * ============================================================ */

/* Demo 1: 固定大小数组遍历 */
#define ARRAY_SIZE  16

/*
 * Demo 2: 字符串/域名解析循环
 *
 * 对应 Elkeid: hids.c:870-875
 *   #if LOOPS_UNROLL
 *   #   define DNS_N_LOOPS  (50)    // 展开模式: 减少迭代防止指令超限
 *   #   pragma unroll
 *   #else
 *   #   define DNS_N_LOOPS  (75)    // 有界模式: 可处理更长的域名
 *   #endif
 *
 * 为什么展开模式要减少迭代?
 *   展开后指令数 = 迭代次数 x 循环体指令数
 *   如果循环体有 200 条指令，75 次展开 = 15000 条
 *   加上其他代码可能超过 BPF_COMPLEXITY_LIMIT (1M 条指令)
 *   所以展开模式下将 75 降低为 50，牺牲功能换取通过验证
 */
#if LOOPS_UNROLL
#   define NAME_N_LOOPS  12     /* 展开模式: 减少迭代 */
#else
#   define NAME_N_LOOPS  20     /* 有界模式: 可处理更长字符串 */
#endif

/* Demo 3: 早期退出搜索 */
#define MAX_FDS     16

/* 缓冲区大小 */
#define BUF_MAX     4096
#define STR_MAX     256

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/* Per-CPU 缓冲区: 用于存放超过 512 字节栈限制的临时数据 */
struct percpu_buf {
    __u8 data[BUF_MAX];
};

/*
 * 输出事件结构体: 包含三个 demo 的处理结果
 *
 * 用户态可以对比展开模式和有界模式下:
 *   - array_sum: 应该相同 (固定计算)
 *   - name_len: 展开模式可能截断更多 (12 vs 20 次迭代)
 *   - found_idx: 应该相同 (早期退出逻辑不受影响)
 */
struct loop_event {
    __u32 pid;              /* 进程 ID */
    __u32 ppid;             /* 父进程 ID */
    char  comm[16];         /* 进程名 */
    __u32 array_sum;        /* Demo 1: 数组元素累加和 */
    __u32 name_len;         /* Demo 2: 解析后的字符串长度 */
    __u32 found_idx;        /* Demo 3: 找到的 fd 索引 (-1 表示未找到) */
    __u32 loops_unroll;     /* 当前编译模式: 1=展开, 0=有界 */
    __u32 name_max_iter;    /* Demo 2 的最大迭代次数 */
    char  parsed_name[STR_MAX]; /* Demo 2: 解析后的字符串内容 */
};

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

/*
 * Per-CPU 缓冲区 map: 用于循环处理时的临时存储
 *
 * 循环体中经常需要操作大缓冲区 (如 DNS 域名解析、路径拼接)，
 * 这些缓冲区远超 512 字节栈限制，必须放在 percpu array 中。
 *
 * 对应 Elkeid: hids.c:70-75 (g_percpu_data)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct percpu_buf);
    __uint(max_entries, 1);
} g_percpu_buf SEC(".maps");

/* 事件输出通道 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* ============================================================
 * Demo 1: 固定大小数组遍历 (Simple bounded loop)
 *
 * 最基本的循环模式: 遍历固定大小的数组并累加。
 *
 * 展开模式 (#pragma unroll):
 *   编译器将 for 循环展开为 16 条独立的加法指令:
 *     sum += arr[0]; sum += arr[1]; ... sum += arr[15];
 *   没有任何后向跳转，验证器看到的是顺序执行的指令流。
 *   指令数 = 16 x (load + add) ≈ 32 条
 *
 * 有界模式 (kernel >= 5.3):
 *   编译器生成正常的循环:
 *     loop_start: if (nr >= 16) goto loop_end;
 *                 sum += arr[nr]; nr++; goto loop_start;
 *     loop_end:
 *   验证器分析循环变量 nr 的范围，证明最多执行 16 次。
 *   指令数 ≈ (load + add + cmp + jmp) x 1 + 循环开销 ≈ 10 条
 *
 * 对应 Elkeid: hids.c:575-585 (遍历 fd 数组)
 *   以及 hids.c 中所有 "for (nr = 0; nr < 16; nr++)" 模式
 * ============================================================ */
static __noinline __u32 demo_array_sum(void)
{
    /* 模拟一个固定大小的数据数组 */
    __u32 arr[ARRAY_SIZE];
    __u32 sum = 0;
    int nr;

    /* 初始化数组: 使用简单的计算值 */
    /* 注意: 这个初始化循环也需要条件展开 */
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (nr = 0; nr < ARRAY_SIZE; nr++) {
        arr[nr] = nr * 2 + 1;  /* 1, 3, 5, 7, ..., 31 */
    }

    /*
     * 累加循环 —— 条件展开的典型用法
     *
     * 对应 Elkeid: hids.c 中 13 处 #if LOOPS_UNROLL 模式:
     *   #if LOOPS_UNROLL
     *   #   pragma unroll
     *   #endif
     *       for (nr = 0; nr < 16; nr++) { ... }
     */
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (nr = 0; nr < ARRAY_SIZE; nr++) {
        sum += arr[nr];
    }

    /* 预期结果: 1+3+5+...+31 = 16^2 = 256 */
    return sum;
}

/* ============================================================
 * Demo 2: 字符串/域名解析循环 (逐字符处理)
 *
 * 模拟 Elkeid 的 DNS 域名解析: query_dns_record (hids.c:870-887)
 *
 * DNS 域名格式: "\x03www\x06google\x03com\x00"
 * 每个标签前有一个长度字节，以 \0 结束。
 * 解析循环需要逐字节处理，遇到 \0 停止。
 *
 * 展开模式的挑战:
 *   逐字节处理循环的循环体较大 (读内存 + 条件判断 + 写缓冲区)，
 *   假设循环体有 ~30 条指令:
 *     展开 20 次 = 600 条指令 (可接受)
 *     展开 75 次 = 2250 条指令 (加上其他代码可能超限)
 *   所以 Elkeid 在展开模式下将迭代次数从 75 减少到 50。
 *
 * __noinline 的作用:
 *   如果 process_char 被内联，展开后每次迭代都包含函数的全部代码。
 *   使用 __noinline 可以让每次迭代只生成一条 call 指令，
 *   大幅减少展开后的总指令数。
 *
 *   对应 Elkeid: hids.c:830 process_domain_name 是 __noinline 的
 * ============================================================ */

/*
 * 逐字符处理函数 (模拟 Elkeid 的 process_domain_name)
 *
 * __noinline 确保不被内联:
 *   展开时: 每次迭代生成 1 条 call 指令 (而非整个函数体)
 *   不展开时: 正常函数调用，无影响
 *
 * 对应 Elkeid: hids.c:830-868
 *   static __noinline int process_domain_name(...)
 */
static __noinline int process_char(const char *src, char *dst,
                                    __u32 *out_len, int idx)
{
    /*
     * 边界检查: eBPF 验证器要求所有内存访问都有明确的边界
     * idx 必须在 [0, STR_MAX-1] 范围内，否则验证器拒绝
     */
    if (idx < 0 || idx >= STR_MAX)
        return 0;  /* 停止处理 */

    char c = 0;
    bpf_probe_read_kernel(&c, 1, src + idx);

    /* 遇到 \0 或不可打印字符则停止 */
    if (c == 0)
        return 0;

    /* DNS 域名中的长度字节 (< 0x20) 替换为 '.' */
    if (c > 0 && c < 0x20)
        c = '.';

    dst[idx] = c;
    *out_len = idx + 1;
    return 1;  /* 继续处理 */
}

static __noinline __u32 demo_name_parse(struct percpu_buf *buf,
                                         char *out_name)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    __u32 name_len = 0;
    int i;

    /*
     * 读取进程的 cmdline 作为待解析字符串
     *
     * 在 Elkeid 中这里是 DNS 数据包的域名字段:
     *   data = skb->data + dns_header_offset
     * 我们用 cmdline 作为替代，演示逐字符处理的模式。
     */
    const char *arg_start = BPF_CORE_READ(task, mm, arg_start);
    if (!arg_start)
        return 0;

    /* 先将原始数据读入 percpu buffer */
    bpf_probe_read_user(buf->data, STR_MAX, (void *)arg_start);

    /*
     * 逐字符处理循环 —— DNS 解析模式
     *
     * 对应 Elkeid: hids.c:876-886
     *   #if LOOPS_UNROLL
     *   #   define DNS_N_LOOPS  (50)
     *   #   pragma unroll
     *   #else
     *   #   define DNS_N_LOOPS  (75)
     *   #endif
     *       for (i = 1; i < DNS_N_LOOPS; i++) {
     *           if (!process_domain_name(data, name, &flag, i))
     *               break;
     *       }
     *
     * 注意迭代次数的差异:
     *   展开模式: NAME_N_LOOPS = 12 (减少展开量)
     *   有界模式: NAME_N_LOOPS = 20 (可处理更长字符串)
     *
     * 这意味着展开模式下最多解析 12 个字符，
     * 有界模式下最多解��� 20 个字符。
     * 较长的字符串在展开模式下会被截断。
     */
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (i = 0; i < NAME_N_LOOPS; i++) {
        if (!process_char((const char *)buf->data, out_name,
                          &name_len, i))
            break;
    }

    return name_len;
}

/* ============================================================
 * Demo 3: 早期退出搜索循环 (Early exit with break)
 *
 * 模拟 Elkeid 的 socket fd 遍历: find_sock_internal (hids.c:575-585)
 *
 * 场景: 遍历进程的 fd 表，找到第一个匹配的 socket。
 * 循环在找到匹配项后立即 break 退出。
 *
 * #pragma unroll + break 的行为:
 *   编译器展开整个循环为 N 个 if-else 块:
 *     if (match(0)) goto found;
 *     if (match(1)) goto found;
 *     ...
 *     if (match(15)) goto found;
 *     found: ...
 *   虽然展开了 N 份代码，但 break 编译为 goto，
 *   运行时遇到匹配项会直接跳到循环后的代码。
 *   代码膨胀但运行时不一定慢。
 *
 * 对应 Elkeid: hids.c:575-585
 *   #if LOOPS_UNROLL
 *   #   pragma unroll
 *   #endif
 *       for (nr = 0; nr < 16; nr++) {
 *           sk = find_sock_internal(fds, nr, max);
 *           if (sk)
 *               break;
 *       }
 * ============================================================ */

/*
 * 模拟 fd 匹配检查 (对应 Elkeid 的 find_sock_internal)
 *
 * 在真实场景中，这个函数会:
 *   1. 通过 fd 号查找 struct file
 *   2. 检查 file->f_op 是否为 socket_file_ops
 *   3. 从 file->private_data 获取 struct socket
 *   4. 返回 socket->sk
 *
 * 这里简化为: 查找 comm 中第一个匹配目标字符的位置。
 */
static __noinline int check_fd_match(const char *comm, int idx,
                                      char target)
{
    if (idx < 0 || idx >= 16)
        return 0;
    char c = 0;
    bpf_probe_read_kernel(&c, 1, comm + idx);
    return (c == target) ? 1 : 0;
}

static __noinline __u32 demo_early_exit(void)
{
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    int nr;
    __u32 found_idx = (__u32)-1;  /* -1 表示未找到 */

    /*
     * 早期退出搜索 —— 找到第一个 'a' 字符的位置
     *
     * 对应 Elkeid: hids.c:575-585
     *   #if LOOPS_UNROLL
     *   #   pragma unroll
     *   #endif
     *       for (nr = 0; nr < 16; nr++) {
     *           sk = find_sock_internal(fds, nr, max);
     *           if (sk)
     *               break;
     *       }
     *
     * 展开后的伪代码:
     *   if (check_fd_match(comm, 0, 'a')) { found_idx=0; goto done; }
     *   if (check_fd_match(comm, 1, 'a')) { found_idx=1; goto done; }
     *   ...
     *   if (check_fd_match(comm, 15, 'a')) { found_idx=15; goto done; }
     *   done:
     */
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (nr = 0; nr < MAX_FDS; nr++) {
        if (check_fd_match(comm, nr, 'a')) {
            found_idx = nr;
            break;
        }
    }

    return found_idx;
}

/* ============================================================
 * eBPF 入口函数
 *
 * 挂载到 raw_tracepoint/sched_process_exec，
 * 每次有进程 exec 时触发，运行三个循环 demo。
 *
 * 对应 Elkeid: hids.c:3094-3124 (tp__proc_exec)
 * ============================================================ */
SEC("raw_tracepoint/sched_process_exec")
int tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
    /* 过滤: 只处理主线程 */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid  = (__u32)pid_tgid;
    if (tgid != pid)
        return 0;

    /* 获取 percpu buffer 用于字符串处理 */
    __u32 zero = 0;
    struct percpu_buf *buf = bpf_map_lookup_elem(&g_percpu_buf, &zero);
    if (!buf)
        return 0;

    /* 构建输出事件 */
    struct loop_event ev = {};
    ev.pid = tgid;

    struct task_struct *task = (void *)bpf_get_current_task();
    ev.ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));

    /* 记录当前编译模式，方便用户态区分 */
    ev.loops_unroll = LOOPS_UNROLL;
    ev.name_max_iter = NAME_N_LOOPS;

    /*
     * 运行三个 Demo
     *
     * 每个 demo 展示一种典型的循环模式:
     *   Demo 1: 固定次数遍历 (数组求和)
     *   Demo 2: 逐字符处理 (域名/字符串解析)
     *   Demo 3: 早期退出搜索 (fd 查找)
     */
    ev.array_sum = demo_array_sum();
    ev.name_len  = demo_name_parse(buf, ev.parsed_name);
    ev.found_idx = demo_early_exit();

    /* 发送事件到用户态 */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &ev, sizeof(ev));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
