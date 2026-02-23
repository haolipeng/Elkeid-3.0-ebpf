// SPDX-License-Identifier: GPL-2.0
//
// 技术点 8: __noinline vs __always_inline —— 控制 eBPF 指令数与栈使用
//
// 核心技术:
//   - __noinline: 生成 BPF-to-BPF 子程序调用 (BPF subprogram call)
//     函数体只存在一份，多个调用点共享，节省指令数
//     每个函数拥有独立的 512 字节栈帧
//     约束: 最多 5 个寄存器参数 (R1-R5)，最大调用深度 8
//   - __always_inline: 在每个调用点展开函数体
//     无参数数量限制，无调用深度计数
//     代价: 代码重复，指令数膨胀
//
// 对应 Elkeid 源码:
//   - hids.c 中约 45 个 __noinline 函数，约 5 个 __always_inline 函数
//   - hids.c:244-247  (必须 inline 以支持 >5 个参数的注释)
//   - hids.c:248-280  (SD_XFER_DEFINE_N 宏生成 __always_inline 序列化函数)
//   - hids.c:837      ("marked as noinline to save 253 times of expansion")
//   - hids.c:921      ("mark as noinline to minimize codes generations")
//
// 设计目标:
//   演示三个关键场景:
//   1. __noinline 函数在多个 hook 点间共享代码，节省指令数
//   2. __always_inline 函数突破 5 参数限制
//   3. __noinline 函数的栈帧隔离——两个大栈函数独立工作

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

/* 事件类型标识: 区分不同 hook 点触发的事件 */
#define EVENT_TYPE_EXEC  1   /* sched_process_exec 触发 */
#define EVENT_TYPE_EXIT  2   /* sched_process_exit 触发 */

/* 字符串最大长度 */
#define STR_MAX  128

/* 函数调用计数器索引 */
#define CNT_READ_PROCESS_INFO  0   /* __noinline 共享函数调用次数 */
#define CNT_SERIALIZE_EVENT    1   /* __always_inline 函数调用次数 */
#define CNT_STACK_FUNC_A       2   /* 栈隔离演示函数 A 调用次数 */
#define CNT_STACK_FUNC_B       3   /* 栈隔离演示函数 B 调用次数 */
#define CNT_HOOK_EXEC          4   /* exec hook 触发次数 */
#define CNT_HOOK_EXIT          5   /* exit hook 触发次数 */
#define CNT_MAX                6

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/*
 * 进程信息结构体
 *
 * 由 __noinline 函数 read_process_info() 填充。
 * 这个函数被 exec 和 exit 两个 hook 共同调用，
 * 体现了 __noinline 的代码复用优势。
 */
struct process_info {
    u32  pid;           /* 进程 ID (tgid) */
    u32  tid;           /* 线程 ID (pid) */
    u32  ppid;          /* 父进程 ID */
    u32  uid;           /* 用户 ID */
    u64  timestamp;     /* 事件时间戳 */
    char comm[16];      /* 进程名 */
};

/*
 * 输出事件结构体
 *
 * 通过 perf event 发送到用户态。
 * 包含事件类型 + 进程信息 + 额外数据。
 */
struct output_event {
    u32  event_type;    /* EVENT_TYPE_EXEC 或 EVENT_TYPE_EXIT */
    u32  pid;
    u32  tid;
    u32  ppid;
    u32  uid;
    u32  exit_code;     /* 仅 exit 事件有效 */
    u64  timestamp;
    char comm[16];
    /* 栈隔离演示的结果 */
    u32  stack_a_sum;   /* 函数 A 的计算结果 */
    u32  stack_b_sum;   /* 函数 B 的计算结果 */
    u32  _pad;
};

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

/*
 * 事件输出通道 (perf event array)
 *
 * 对应 Elkeid: hids.c:37-41
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * 函数调用计数器
 *
 * 用于在用户态统计各函数的调用次数，验证:
 *   - read_process_info() 被 exec 和 exit 两个 hook 共同调用
 *   - serialize_event() 在每个调用点被内联展开（但逻辑上只调用一次）
 *   - 栈隔离函数被正确调用
 *
 * 使用 PERCPU_ARRAY 避免跨 CPU 原子操作，
 * 用户态需要对所有 CPU 的值求和。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CNT_MAX);
} call_counts SEC(".maps");

/* ============================================================
 * 辅助函数: 递增计数器
 * ============================================================ */
static __always_inline void bump_counter(u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&call_counts, &idx);
    if (val)
        (*val)++;
}

/* ============================================================
 * 场景 1: __noinline 共享函数 —— 多 hook 点代码复用
 *
 * read_process_info() 被 exec 和 exit 两个 hook 同时调用。
 *
 * 使用 __noinline 的好处:
 *   1. 函数体在 ELF 中只存在一份，两个 hook 通过 BPF call 指令调用
 *      节省了一倍的指令数（相当于 Elkeid 注释中的 "save N times of expansion"）
 *   2. 函数拥有独立的 512 字节栈帧，不占用调用者的栈空间
 *
 * 约束检查:
 *   参数数量 = 2 (ctx, info) ≤ 5 ✓
 *   满足 BPF-to-BPF 调用的寄存器限制
 *
 * 对应 Elkeid:
 *   - hids.c:837 "marked as noinline to save 253 times of expansion
 *     in query_dns_record()" —— 同样的代码复用模式
 *   - hids.c:921 "mark as noinline to minimize codes generations,
 *     to be called twice (by 2 different callers)"
 * ============================================================ */
static __noinline int read_process_info(void *ctx,
                                        struct process_info *info)
{
    /*
     * 参数说明:
     *   ctx  → R1 (BPF 上下文指针)
     *   info → R2 (输出指针)
     *   共 2 个参数，远低于 5 参数限制
     */

    bump_counter(CNT_READ_PROCESS_INFO);

    struct task_struct *task = (void *)bpf_get_current_task();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    info->pid  = (u32)(pid_tgid >> 32);   /* tgid = 用户态 PID */
    info->tid  = (u32)pid_tgid;           /* pid  = 内核线程 ID */
    info->ppid = BPF_CORE_READ(task, real_parent, tgid);
    info->uid  = (u32)bpf_get_current_uid_gid();
    info->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(info->comm, sizeof(info->comm));

    return 0;
}

/* ============================================================
 * 场景 2: __always_inline 函数 —— 突破 5 参数限制
 *
 * serialize_event() 接收 8 个参数，超过了 BPF-to-BPF 调用的
 * 5 寄存器限制 (R1-R5)，因此必须声明为 __always_inline。
 *
 * 如果将其声明为 __noinline，编译器/验证器会报错:
 *   "BPF program has too many args for BPF-to-BPF call"
 *
 * 对应 Elkeid:
 *   - hids.c:244-247 注释:
 *     "must be inline to support > 5 parameters; to save overall
 *      stack usage, could call these serializing functions in a
 *      __noinline function"
 *   - hids.c:248-280 SD_XFER_DEFINE_N 宏:
 *     生成的 xxx_print() 函数都是 __always_inline，
 *     因为它们的参数数量远超 5 个 (execve_print 有 ~20 个参数)
 *
 * 替代方案:
 *   如果不想内联，可以将多个参数打包到一个结构体中，
 *   通过结构体指针传递（只占 1 个寄存器）:
 *
 *   struct serialize_args {
 *       void *ctx;
 *       u32 event_type, pid, tid, ppid, uid, exit_code;
 *       u64 timestamp;
 *       const char *comm;
 *       u32 stack_a_sum, stack_b_sum;
 *   };
 *   static __noinline int serialize_event(struct serialize_args *args);
 *
 *   但 Elkeid 选择了 __always_inline，因为序列化函数本身较短，
 *   内联的代价可以接受。
 * ============================================================ */
static __always_inline int serialize_event(
    void *ctx,
    u32 event_type,     /* 参数 1: R1 已被 ctx 占用 → 实际从 R2 开始 */
    u32 pid,            /* 参数 2 */
    u32 tid,            /* 参数 3 */
    u32 ppid,           /* 参数 4 */
    u32 uid,            /* 参数 5 */
    u32 exit_code,      /* 参数 6 ← 超过 R5! __noinline 无法支持 */
    u64 timestamp,      /* 参数 7 */
    const char *comm,   /* 参数 8 */
    u32 stack_a_sum,    /* 参数 9 */
    u32 stack_b_sum)    /* 参数 10 */
{
    /*
     * 如果尝试将此函数声明为 __noinline，会发生什么？
     *
     * 取消注释下面的代码，将上面的 __always_inline 改为 __noinline:
     *
     * // static __noinline int serialize_event(
     * //     void *ctx, u32 event_type, u32 pid, u32 tid,
     * //     u32 ppid, u32 uid, u32 exit_code, u64 timestamp,
     * //     const char *comm, u32 stack_a_sum, u32 stack_b_sum)
     *
     * 编译时 clang 可能会报错或生成无效代码，
     * 因为 x86_64 BPF 调用约定只有 R1-R5 五个参数寄存器。
     * 第 6 个及之后的参数无法通过寄存器传递。
     *
     * 在传统 x86_64 C 调用约定中，多余参数通过栈传递，
     * 但 BPF-to-BPF 调用不支持栈传参。
     */

    bump_counter(CNT_SERIALIZE_EVENT);

    /* 构建输出事件 */
    struct output_event out = {};
    out.event_type  = event_type;
    out.pid         = pid;
    out.tid         = tid;
    out.ppid        = ppid;
    out.uid         = uid;
    out.exit_code   = exit_code;
    out.timestamp   = timestamp;
    out.stack_a_sum = stack_a_sum;
    out.stack_b_sum = stack_b_sum;

    /* 拷贝进程名 */
    bpf_probe_read_kernel(out.comm, sizeof(out.comm), comm);

    /* 通过 perf event 发送到用户态 */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &out, sizeof(out));

    return 0;
}

/* ============================================================
 * 场景 3: __noinline 栈帧隔离 —— 解决 512 字节栈限制
 *
 * eBPF 验证器要求每个函数的栈帧不超过 512 字节。
 * 如果两个函数各自需要 300 字节的局部变量:
 *
 *   __always_inline 场景 (内联到调用者):
 *     调用者栈帧 = 自身变量 + 函数A变量(300) + 函数B变量(300)
 *                = 可能超过 512 字节! → 验证器拒绝
 *
 *   __noinline 场景 (独立栈帧):
 *     调用者栈帧 = 自身变量 (远低于 512)
 *     函数A栈帧 = 300 字节 (< 512) ✓
 *     函数B栈帧 = 300 字节 (< 512) ✓
 *     总栈 = 当前调用路径上各帧之和 (而非所有函数之和)
 *
 * 注意: "总栈" 指的是从入口到最深调用的路径上的帧之和，
 * 而不是程序中所有函数帧的总和。如果 A 和 B 是顺序调用
 * 而非嵌套调用，它们的栈帧不会同时存在。
 *
 * 对应 Elkeid:
 *   Elkeid 中很多 __noinline 函数 (如 dentry_path, query_ipu 等)
 *   内部都有较大的局部变量。如果全部内联到 sysret_exec 中，
 *   单个函数的栈帧会远超 512 字节。
 * ============================================================ */

/*
 * 栈隔离演示函数 A: 使用较大的局部数组
 *
 * 独立栈帧约 260 字节 (64 * 4 + 少量临时变量)
 * 如果内联到调用者，会增加调用者的栈压力
 */
static __noinline u32 stack_heavy_func_a(u32 pid)
{
    bump_counter(CNT_STACK_FUNC_A);

    /*
     * 较大的局部数组: 64 * 4 = 256 字节
     * 这个数组在独立栈帧中是安全的 (256 < 512)
     * 但如果与 func_b 一起内联，256 + 256 = 512，接近极限
     */
    u32 buf[64];
    u32 sum = 0;

    /* 使用 pid 作为种子填充数组并计算哈希 */
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        buf[i] = pid + i;
        sum += buf[i];
    }

    return sum;
}

/*
 * 栈隔离演示函数 B: 同样使用较大的局部数组
 *
 * 与 func_a 类似的栈使用量。
 * 两个函数顺序调用时栈帧不会叠加 (A 返回后栈帧被回收，再调用 B)。
 * 但如果都内联到同一个调用者中，编译器可能同时分配两份局部变量。
 */
static __noinline u32 stack_heavy_func_b(u32 tid)
{
    bump_counter(CNT_STACK_FUNC_B);

    u32 buf[64];
    u32 sum = 0;

    /* 使用 tid 作为种子，计算方式与 func_a 不同 */
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        buf[i] = tid ^ (i * 7);
        sum ^= buf[i];
    }

    return sum;
}

/* ============================================================
 * Hook 1: sched_process_exec —— 进程执行时触发
 *
 * 演示要点:
 *   1. 调用 __noinline 的 read_process_info() 共享函数
 *   2. 调用 __noinline 的栈隔离函数 A 和 B
 *   3. 调用 __always_inline 的 serialize_event() (>5 参数)
 *
 * 调用图:
 *   tp_exec (入口, 深度 0)
 *     ├── read_process_info()   __noinline, 深度 1
 *     ├── stack_heavy_func_a()  __noinline, 深度 1
 *     ├── stack_heavy_func_b()  __noinline, 深度 1
 *     └── serialize_event()     __always_inline, 内联展开
 *
 * 注意 A, B 是顺序调用，不是嵌套调用，
 * 所以最大调用深度 = 2 (入口 + 1层)，远低于 8 的限制。
 * ============================================================ */
SEC("raw_tracepoint/sched_process_exec")
int tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
    bump_counter(CNT_HOOK_EXEC);

    /*
     * ① 调用 __noinline 共享函数读取进程信息
     *
     * 这个函数也被 tp_exit 调用 —— 代码只存在一份。
     * 如果是 __always_inline，编译器会在 tp_exec 和 tp_exit
     * 中各生成一份副本，指令数翻倍。
     */
    struct process_info info = {};
    read_process_info(ctx, &info);

    /*
     * ② 调用栈隔离演示函数
     *
     * func_a 和 func_b 各自有 256 字节的局部数组。
     * 由于是 __noinline，它们有独立的栈帧，不会撑爆调用者的 512 字节限制。
     *
     * 如果改为 __always_inline:
     *   tp_exec 的栈 = 自身变量 + info(~52B) + func_a 的 buf(256B)
     *                 + func_b 的 buf(256B) = 可能超过 512B
     */
    u32 sum_a = stack_heavy_func_a(info.pid);
    u32 sum_b = stack_heavy_func_b(info.tid);

    /*
     * ③ 调用 __always_inline 序列化函数 (10 个参数)
     *
     * 这个函数有 10 个参数，超过 BPF-to-BPF 的 5 寄存器限制。
     * 必须内联才能正常工作。
     *
     * 对应 Elkeid: hids.c:248-280
     *   SD_XFER_DEFINE_N 生成的序列化函数有 ~20 个参数，
     *   强制 __always_inline。
     */
    serialize_event(ctx,
                    EVENT_TYPE_EXEC,
                    info.pid,
                    info.tid,
                    info.ppid,
                    info.uid,
                    0,              /* exit_code = 0 (exec 无退出码) */
                    info.timestamp,
                    info.comm,
                    sum_a,
                    sum_b);

    return 0;
}

/* ============================================================
 * Hook 2: sched_process_exit —— 进程退出时触发
 *
 * 与 tp_exec 共享同一个 read_process_info() 函数。
 * 这就是 __noinline 代码复用的核心价值:
 *   - 在 ELF 二进制中，read_process_info 的机器码只有一份
 *   - tp_exec 和 tp_exit 都通过 BPF call 指令跳转到同一个地址
 *   - 如果 read_process_info 有 100 条指令，
 *     __noinline 省下了 100 条指令（只需 1 条 call 指令）
 *   - Elkeid 的 query_dns_record 被调用 253 次，
 *     __noinline 省下了 252 * N 条指令（N=函数体指令数）
 * ============================================================ */
SEC("raw_tracepoint/sched_process_exit")
int tp_exit(struct bpf_raw_tracepoint_args *ctx)
{
    bump_counter(CNT_HOOK_EXIT);

    /*
     * ① 复用同一个 __noinline 函数
     *
     * read_process_info 的代码不会因为多一个调用者而膨胀。
     * 这就是 hids.c:921 注释所说的:
     *   "mark as noinline to minimize codes generations,
     *    to be called twice (by 2 different callers)"
     */
    struct process_info info = {};
    read_process_info(ctx, &info);

    /*
     * ② 获取退出码
     *
     * task->exit_code 包含进程的退出状态。
     * exit_code >> 8 得到 exit(N) 中的 N 值。
     */
    struct task_struct *task = (void *)bpf_get_current_task();
    u32 exit_code = BPF_CORE_READ(task, exit_code) >> 8;

    /*
     * ③ 序列化并发送事件
     *
     * 同样使用 __always_inline 的 serialize_event (10 个参数)。
     * 内联意味着 tp_exec 和 tp_exit 中各有一份 serialize_event 的代码副本。
     * 这是 >5 参数函数不得不付出的代价。
     *
     * Elkeid 的策略: 将这种被迫内联的函数的调用放在 __noinline 函数中，
     * 从而将内联展开的代码限制在 __noinline 函数体内。
     * 参考 hids.c:244-247:
     *   "to save overall stack usage, could call these serializing
     *    functions in a __noinline function"
     */
    serialize_event(ctx,
                    EVENT_TYPE_EXIT,
                    info.pid,
                    info.tid,
                    info.ppid,
                    info.uid,
                    exit_code,
                    info.timestamp,
                    info.comm,
                    0,    /* exit 不演示栈隔离 */
                    0);

    return 0;
}

/* 许可证声明: eBPF 程序必须声明 GPL 兼容许可证 */
char LICENSE[] SEC("license") = "GPL";
