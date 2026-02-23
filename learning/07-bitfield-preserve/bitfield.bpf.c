// SPDX-License-Identifier: GPL-2.0
//
// 技术点 7: __builtin_preserve_field_info —— CO-RE 方式读取内核位域
//
// 核心技术:
//   - __builtin_preserve_field_info(field, kind): 编译器内建函数，
//     在编译时记录位域的布局信息，由 BPF loader 在加载时重定位
//   - 4 种 field info kind:
//     BPF_FIELD_BYTE_OFFSET (0): 位域所在字节的偏移量
//     BPF_FIELD_BYTE_SIZE   (1): 包含位域的最小字节数
//     BPF_FIELD_LSHIFT_U64  (2): 左移量 (清除高位无关 bit)
//     BPF_FIELD_RSHIFT_U64  (3): 右移量 (将值对齐到 bit 0)
//   - preserve_access_index 属性: 让编译器为结构体字段生成重定位记录
//   - BPF_CORE_READ_BITFIELD 宏: libbpf 提供的高层封装 (底层原理相同)
//
// 对应 Elkeid 源码:
//   - hids.c:667-676  (sock_prot 函数: 使用 __builtin_preserve_field_info)
//   - hids.c:631-664  (struct sock___v55 / sock___v56: 位域布局差异)
//   - hids.c:678-691  (旧方案: 版本相关的 #ifdef 位操作)
//
// 设计目标:
//   挂载 kprobe/tcp_connect，当 TCP 连接发起时，使用
//   __builtin_preserve_field_info 读取 struct sock 中的位域字段
//   sk_protocol，同时读取 sk_type 和 sk_family 等非位域字段作为对比，
//   展示位域读取的完整流程和必要性。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

/* 协议号 (对应 /etc/protocols) */
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/* socket 类型 */
#define SOCK_STREAM     1    /* TCP: 面向连接的流式 socket */
#define SOCK_DGRAM      2    /* UDP: 无连接的数据报 socket */

/* 地址族 */
#define AF_INET         2    /* IPv4 */
#define AF_INET6        10   /* IPv6 */

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/*
 * 发送到用户态的事件结构体
 *
 * 包含 socket 的协议信息和进程上下文，用于展示:
 *   - sk_protocol: 位域字段，需要 __builtin_preserve_field_info 读取
 *   - sk_type:     非位域字段 (>= 5.6)，但在旧内核中也是位域
 *   - sk_family:   普通 u16 字段，BPF_CORE_READ 即可
 */
struct event {
    u32  pid;          /* 进程 ID (tgid) */
    u32  tid;          /* 线程 ID */
    u32  uid;          /* 用户 ID */
    u32  protocol;     /* sk_protocol: TCP=6, UDP=17 (位域读取!) */
    u32  sock_type;    /* sk_type: STREAM=1, DGRAM=2 */
    u16  family;       /* sk_family: AF_INET=2, AF_INET6=10 */
    u16  sport;        /* 源端口 (网络字节序转主机字节序) */
    u16  dport;        /* 目标端口 */
    u16  _pad;         /* 对齐填充 */
    char comm[16];     /* 进程名 */
};

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/* ============================================================
 * 位域读取的核心问题: 为什么 BPF_CORE_READ 无法处理位域？
 *
 * struct sock 中 sk_protocol 的定义在不同内核版本中差异巨大:
 *
 * ---- 内核 < 5.6 (如 4.19, 5.4): 位域打包在 unsigned int 中 ----
 *
 *   struct sock {
 *       ...
 *       __u32 sk_txhash;
 *       unsigned int __sk_flags_offset[0];   // 占位标记
 *       unsigned int sk_padding    : 1;      // bit 0
 *       unsigned int sk_kern_sock  : 1;      // bit 1
 *       unsigned int sk_no_check_tx: 1;      // bit 2
 *       unsigned int sk_no_check_rx: 1;      // bit 3
 *       unsigned int sk_userlocks  : 4;      // bit 4-7
 *       unsigned int sk_protocol   : 8;      // bit 8-15  ← 位域!
 *       unsigned int sk_type       : 16;     // bit 16-31 ← 也是位域!
 *       u16 sk_gso_max_segs;
 *   };
 *
 * ---- 内核 >= 5.6: sk_protocol 变为独立的 u16 字段 ----
 *
 *   struct sock {
 *       ...
 *       __u32 sk_txhash;
 *       u8  sk_padding    : 1,
 *           sk_kern_sock  : 1,
 *           sk_no_check_tx: 1,
 *           sk_no_check_rx: 1,
 *           sk_userlocks  : 4;
 *       u8  sk_pacing_shift;
 *       u16 sk_type;                         // 不再是位域
 *       u16 sk_protocol;                     // 不再是位域!
 *       u16 sk_gso_max_segs;
 *   };
 *
 * 为什么 BPF_CORE_READ 失败:
 *   BPF_CORE_READ(sk, sk_protocol) 会生成:
 *     bpf_probe_read(&val, sizeof(sk->sk_protocol), &sk->sk_protocol)
 *
 *   问题 1: sizeof(位域) 在 C 中是不合法的
 *   问题 2: &(位域) 取地址也是不合法的
 *   问题 3: 即使读取了包含位域的整个 word，还需要位操作来提取
 *   问题 4: 位操作参数 (掩码/移位量) 在不同内核版本中不同
 *
 * 结论: 位域不是普通字段，不能用地址+大小来描述，
 *       需要额外的元信息 (偏移/大小/移位量) 来定位和提取。
 * ============================================================ */

/* ============================================================
 * 核心函数: 使用 __builtin_preserve_field_info 读取位域
 *
 * 完全对应 Elkeid 的 sock_prot 函数 (hids.c:667-676)。
 *
 * __builtin_preserve_field_info 是 Clang 编译器内建函数:
 *   编译时: 根据当前 vmlinux.h 中的定义计算字段布局信息
 *   加载时: BPF loader (libbpf) 根据目标内核的 BTF 重定位这些常量
 *
 * 4 个 kind 的含义:
 *
 *   BPF_FIELD_BYTE_OFFSET (0):
 *     位域所在字节相对于结构体起始的偏移量。
 *     例如 sk_protocol 在旧内核中偏移为 sk_txhash 之后的某个字节。
 *
 *   BPF_FIELD_BYTE_SIZE (1):
 *     需要读取的最小字节数以包含整个位域。
 *     旧内核: 4 (sk_protocol 在 32-bit unsigned int 中)
 *     新内核: 2 (sk_protocol 是独立的 u16)
 *
 *   BPF_FIELD_LSHIFT_U64 (2):
 *     将读取的值左移到 u64 高位，清除高位的无关 bit。
 *     如果 sk_protocol 占 bit 8-15，左移后它会被推到 u64 最高有效位。
 *
 *   BPF_FIELD_RSHIFT_U64 (3):
 *     将值右移回到 bit 0 位置，同时清除低位无关 bit。
 *     左移+右移的组合效果等同于掩码提取 (mask & shift)。
 *
 * 为什么用左移+右移而不是直接掩码？
 *   - 掩码值依赖字段的精确位宽和位置
 *   - 移位量更容易被 BPF loader 重定位 (只需要替换立即数)
 *   - 对有符号字段，算术右移可以正确做符号扩展
 *
 * 对应 Elkeid: hids.c:667-676
 * ============================================================ */
static __noinline int sock_prot(struct sock *sk)
{
    /*
     * 步骤 1: 获取位域在结构体中的字节偏移量
     *
     * 编译时: 编译器根据 vmlinux.h 中 struct sock 的定义计算偏移
     * 加载时: BPF loader 替换为目标内核 BTF 中的实际偏移
     *
     * 旧内核 (位域): offset = sk_txhash 之后的偏移
     * 新内核 (u16):   offset = sk_protocol 字段的字节偏移
     */
    unsigned int offset = __builtin_preserve_field_info(
        sk->sk_protocol, BPF_FIELD_BYTE_OFFSET);

    /*
     * 步骤 2: 获取需要读取的字节数
     *
     * 旧内核: size = 4 (位域打包在 32-bit word 中)
     * 新内核: size = 2 (独立的 u16 字段)
     *
     * & 0x0f 是防御性编程: 限制最大读取 15 字节，
     * 防止异常值导致越界读取。
     */
    unsigned int size = __builtin_preserve_field_info(
        sk->sk_protocol, BPF_FIELD_BYTE_SIZE);

    /*
     * 步骤 3: 使用 bpf_probe_read 读取包含位域的原始字节
     *
     * 不能用 BPF_CORE_READ，因为位域没有独立地址。
     * 这里手动计算地址: (void *)sk + offset
     *
     * prot 初始化为 0，确保未读取的高字节为 0。
     * 读取 size 个字节到 prot 的低位 (小端序)。
     *
     * 对应 Elkeid: hids.c:673
     */
    unsigned long long prot = 0;
    bpf_probe_read(&prot, size & 0x0f, (void *)sk + offset);

    /*
     * 步骤 4: 左移清除高位无关 bit
     *
     * 假设旧内核中 sk_protocol 占 bit 8-15 (8 个 bit):
     *   读取的 32-bit 值: [sk_type(16)] [sk_protocol(8)] [flags(8)]
     *   放入 u64 后:       0000_0000_TTTT_TTTT_PPPP_PPPP_FFFF_FFFF
     *   左移 40 位后:      PPPP_PPPP_FFFF_FFFF_0000_0000_0000_0000
     *
     * 左移量 = 64 - (bit_offset_in_word + bit_width)
     * 这个值由编译器+loader 自动计算。
     *
     * 对应 Elkeid: hids.c:674
     */
    prot <<= __builtin_preserve_field_info(
        sk->sk_protocol, BPF_FIELD_LSHIFT_U64);

    /*
     * 步骤 5: 右移将值对齐到 bit 0，同时清除左边推上来的低位垃圾
     *
     * 继续上面的例子:
     *   左移后:   PPPP_PPPP_FFFF_FFFF_0000_0000_0000_0000
     *   右移 56:  0000_0000_0000_0000_0000_0000_PPPP_PPPP
     *
     * 右移量 = 64 - bit_width = 64 - 8 = 56
     *
     * 左移+右移的净效果: 从 32-bit 中精确提取 bit 8-15。
     * 等价于: (raw_value >> 8) & 0xFF
     * 但左移+右移方式可以被 BPF loader 通过替换立即数来重定位。
     *
     * 对应 Elkeid: hids.c:675
     */
    prot >>= __builtin_preserve_field_info(
        sk->sk_protocol, BPF_FIELD_RSHIFT_U64);

    return (int)prot;

    /*
     * ============================================================
     * 旧方案对比: 版本相关的 #ifdef (已被 CO-RE 方案取代)
     *
     * 对应 Elkeid: hids.c:678-691
     *
     * 旧方案的问题:
     *   1. 需要为每个内核版本范围写不同的提取代码
     *   2. 掩码和移位量是硬编码的，版本判断错误就会读取垃圾数据
     *   3. 无法处理同一版本号内不同发行版的差异 (如 CentOS 反向移植)
     *   4. 新内核版本发布时需要更新代码和重新编译
     *
     *   #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
     *       int prot;
     *       prot = READ_KERN(sk, ...);
     *       return (prot & 0xFF00) >> 8;   // 硬编码: bit 8-15
     *   #elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
     *       int prot;
     *       prot = READ_KERN(sk, __sk_flags_offset[0]);
     *       return (prot & 0xFF00) >> 8;   // 硬编码: bit 8-15
     *   #else
     *       return READ_KERN(sk, sk_protocol);  // >= 5.6 不再是位域
     *   #endif
     *
     * CO-RE 方案优势:
     *   1. 一份代码适配所有内核版本
     *   2. BPF loader 在加载时自动重定位
     *   3. 正确处理发行版的特殊修改
     *   4. 不需要重新编译
     * ============================================================
     */
}

/* ============================================================
 * 辅助函数: 字节序转换
 *
 * 端口号在 struct sock 中以网络字节序 (大端) 存储，
 * 需要转换为主机字节序 (x86_64 为小端) 才能正确显示。
 *
 * 对应 Elkeid: hids.c:625-628 (swap16 函数)
 * ============================================================ */
static __always_inline u16 bpf_ntohs(u16 port)
{
    return ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
}

/* ============================================================
 * eBPF 入口函数
 *
 * 挂载到 kprobe/tcp_connect:
 *   tcp_connect(struct sock *sk)
 *
 * tcp_connect 是 TCP 主动连接的核心函数，在客户端调用
 * connect() 系统调用时被触发。第一个参数就是 struct sock *sk，
 * 包含了连接的所有网络信息。
 *
 * 这是使用 __builtin_preserve_field_info 的最佳演示场景:
 *   - sk->sk_protocol 在旧内核中是位域，需要特殊处理
 *   - sk->sk_family / sk->sk_num / sk->sk_dport 是普通字段
 *   - 可以对比位域读取和普通字段读取的差异
 * ============================================================ */
SEC("kprobe/tcp_connect")
int kp_tcp_connect(struct pt_regs *regs)
{
    /*
     * 获取 kprobe 的第一个参数: struct sock *sk
     *
     * tcp_connect 函数签名:
     *   int tcp_connect(struct sock *sk)
     *
     * x86_64 函数调用约定: 第一个参数在 RDI 寄存器中。
     * PT_REGS_PARM1_CORE 使用 CO-RE 方式读取寄存器值，
     * 跨内核版本兼容。
     */
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(regs);
    if (!sk)
        return 0;

    struct event e = {};

    /* ============================================================
     * 进程上下文信息
     * ============================================================ */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = (u32)(pid_tgid >> 32);
    e.tid = (u32)pid_tgid;
    e.uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    /* ============================================================
     * 读取普通字段: BPF_CORE_READ 即可
     *
     * sk_family 是一个普通的 u16 字段 (所有内核版本一致)，
     * BPF_CORE_READ 可以正常处理。
     * ============================================================ */
    e.family = BPF_CORE_READ(sk, __sk_common.skc_family);

    /* 只关注 IPv4 和 IPv6 连接 */
    if (e.family != AF_INET && e.family != AF_INET6)
        return 0;

    /* ============================================================
     * 读取端口号: 普通字段 + 字节序转换
     *
     * sk_num:  源端口，已经是主机字节序
     * sk_dport: 目标端口，网络字节序 (需要 ntohs)
     *
     * 这些字段在 __sk_common 中:
     *   struct sock_common {
     *       ...
     *       __be16 skc_dport;     // 目标端口 (网络字节序)
     *       unsigned short skc_num; // 源端口 (主机字节序)
     *   };
     * ============================================================ */
    e.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    /* ============================================================
     * 读取 sk_type: 在某些内核中也是位域
     *
     * 内核 < 5.6: sk_type 是 16-bit 位域 (unsigned int sk_type: 16)
     * 内核 >= 5.6: sk_type 是独立的 u16 字段
     *
     * 这里使用 BPF_CORE_READ_BITFIELD 宏:
     *   这是 libbpf 提供的高层封装，底层原理与
     *   __builtin_preserve_field_info 完全相同，
     *   但自动处理了读取+左移+右移的步骤。
     *
     * BPF_CORE_READ_BITFIELD 展开后大致等价于:
     *   unsigned long long val = 0;
     *   unsigned int offset = __builtin_preserve_field_info(sk->sk_type, 0);
     *   unsigned int size   = __builtin_preserve_field_info(sk->sk_type, 1);
     *   bpf_probe_read(&val, size, (void *)sk + offset);
     *   val <<= __builtin_preserve_field_info(sk->sk_type, 2);
     *   val >>= __builtin_preserve_field_info(sk->sk_type, 3);
     *   return val;
     *
     * 但宏封装让代码更简洁，推荐日常使用。
     * ============================================================ */
    e.sock_type = BPF_CORE_READ_BITFIELD(sk, sk_type);

    /* ============================================================
     * 读取 sk_protocol: 位域字段 —— 本 demo 的核心!
     *
     * 调用我们实现的 sock_prot 函数，该函数使用
     * __builtin_preserve_field_info 手动提取位域值。
     *
     * 为什么不直接用 BPF_CORE_READ_BITFIELD？
     *   1. 理解原理: sock_prot 展示了底层的完整流程
     *   2. 灵活性: 某些复杂场景需要手动控制读取过程
     *   3. 调试: 可以逐步检查 offset/size/shift 值
     *   4. Elkeid 原始代码: Elkeid 就是用手动方式实现的
     *
     * 注意: __noinline 修饰符让 sock_prot 有独立栈帧，
     * 这是 Elkeid 的设计选择 (见技术点 8: noinline 控制)。
     * ============================================================ */
    e.protocol = sock_prot(sk);

    /* 输出事件到用户态 */
    bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
