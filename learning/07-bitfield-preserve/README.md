# 技术点 7: `__builtin_preserve_field_info` —— CO-RE ��式读取内核位域

## 核心问题: 为什么 `BPF_CORE_READ` 无法处理位域？

在前面的模块中，我们使用 `BPF_CORE_READ(obj, field)` 读取内核结构体字段。这个宏本质上是：

```c
bpf_probe_read(&val, sizeof(obj->field), &obj->field)
```

它依赖两个 C 语言操作：`sizeof(field)` 和 `&field`。但 C 语言标准明确禁止对位域 (bitfield) 执行这两个操作：

```c
struct sock {
    unsigned int sk_protocol : 8;   // 位域: 只占 8 个 bit
    unsigned int sk_type     : 16;  // 位域: 只占 16 个 bit
};

// 编译错误!
sizeof(sk->sk_protocol);   // error: sizeof applied to a bit-field
&sk->sk_protocol;          // error: cannot take address of bit-field
```

位域没有独立的内存地址，它和其他位域共享同一个存储单元（通常是 `unsigned int` 或 `u8`）。因此，`BPF_CORE_READ` 完全无法工作。

## `sk_protocol` 的版本差异：问题的根源

`struct sock` 中的 `sk_protocol` 字段在不同内核版本中定义截然不同：

### 内核 < 5.6（如 4.19, 5.4）：位域打包

```c
struct sock {
    __u32 sk_txhash;
    unsigned int __sk_flags_offset[0];     // 零长数组占位标记
    unsigned int sk_padding    : 1;        // bit 0
    unsigned int sk_kern_sock  : 1;        // bit 1
    unsigned int sk_no_check_tx: 1;        // bit 2
    unsigned int sk_no_check_rx: 1;        // bit 3
    unsigned int sk_userlocks  : 4;        // bit 4-7
    unsigned int sk_protocol   : 8;        // bit 8-15  ← 8-bit 位域!
    unsigned int sk_type       : 16;       // bit 16-31 ← 16-bit 位域!
    u16 sk_gso_max_segs;
};
```

所有标志位被打包进一个 32-bit `unsigned int` 中。`sk_protocol` 占 bit 8-15，要读取它需要：
1. 读取整个 32-bit word
2. 右移 8 位
3. AND 掩码 0xFF

### 内核 >= 5.6：独立字段

```c
struct sock {
    __u32 sk_txhash;
    u8  sk_padding    : 1,
        sk_kern_sock  : 1,
        sk_no_check_tx: 1,
        sk_no_check_rx: 1,
        sk_userlocks  : 4;
    u8  sk_pacing_shift;
    u16 sk_type;                           // 不再是位域!
    u16 sk_protocol;                       // 独立的 u16 字段!
    u16 sk_gso_max_segs;
};
```

`sk_protocol` 变成了独立的 `u16` 字段。读取它只需要：
1. 计算字段偏移
2. 读取 2 个字节

**同一个字段，不同的读取方式。** 如果硬编码任何一种方式，就无法在另一种内核上正确工作。

## 旧方案：版本相关的 `#ifdef`

在 CO-RE 之前，Elkeid 使用编译时版本判断来处理这个差异：

```c
/* 对应 Elkeid: hids.c:678-691 (已被废弃的旧方案) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
    int prot;
    prot = READ_KERN(sk, ...);
    return (prot & 0xFF00) >> 8;             // 硬编码: bit 8-15
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
    int prot;
    prot = READ_KERN(sk, __sk_flags_offset[0]);
    return (prot & 0xFF00) >> 8;             // 硬编��: bit 8-15
#else
    return READ_KERN(sk, sk_protocol);       // >= 5.6 直接读
#endif
```

这种方案的问题：

1. **版本边界不精确**：CentOS/RHEL 经常反向移植补丁，内核版本号不能准确反映数据结构布局
2. **硬编码掩码**：`0xFF00` 和 `>> 8` 是根据特定版本的位域布局硬编码的
3. **维护负担**：每个新内核版本可能需要添加新的 `#elif` 分支
4. **需要重新编译**：针对不同内核版本需要不同的二进制文件

## CO-RE 方案：`__builtin_preserve_field_info`

`__builtin_preserve_field_info` 是 Clang 编译器的内建函数，专门解决位域的 CO-RE 问题。它接受两个参数：

```c
__builtin_preserve_field_info(field_access, info_kind)
```

- `field_access`：位域的访问表达式（如 `sk->sk_protocol`）
- `info_kind`：要获取的信息类型（0-3）

### 4 种 field info kind

| Kind | 常量 | 含义 | 示例值 (旧内核) | 示例值 (新内核) |
|------|------|------|:---:|:---:|
| 0 | `BPF_FIELD_BYTE_OFFSET` | 位域所在字节的偏移量 | `sk_txhash` 之后 | `sk_protocol` 偏移 |
| 1 | `BPF_FIELD_BYTE_SIZE` | 需要读取的字节数 | 4 (32-bit word) | 2 (u16) |
| 2 | `BPF_FIELD_LSHIFT_U64` | 左移量 (清除高位) | 40 | 48 |
| 3 | `BPF_FIELD_RSHIFT_U64` | 右移量 (对齐到 bit 0) | 56 | 48 |

编译时，Clang 根据 `vmlinux.h` 中的结构体定义计算这些值，并生成 BTF 重定位记录。加载时，BPF loader (libbpf) 根据目标内核的 BTF 信息替换这些常量。

### 提取过程详解

以旧内核中 `sk_protocol` (bit 8-15, 8 个 bit) 为例：

```
步骤 1: bpf_probe_read(&prot, 4, sk + offset)
  读取 32-bit word: [sk_type:16][sk_protocol:8][flags:8]
  prot (u64) = 0x0000_0000_TTTT_TTPP_PPPP_PPFF_FFFF_FF00

步骤 2: prot <<= LSHIFT (40)
  左移清除高位无关 bit:
  prot = 0xPPPP_PPFF_FFFF_FF00_0000_0000_0000_0000

步骤 3: prot >>= RSHIFT (56)
  右移到 bit 0:
  prot = 0x0000_0000_0000_00PP_PPPP_PP

  最终 prot 就是 sk_protocol 的值 (如 TCP=6, UDP=17)
```

**为什么用左移+右移而不���掩码？**

- 掩码值 (`0xFF00`) 依赖精确的位域位置和宽度，重定位复杂
- 移位量是简单的立即数，BPF loader 只需替换指令中的立即数操作数
- 对有符号位域，算术右移 (`>>`) 可以正确做符号扩展
- 移位方式在所有架构上行为一致，掩码方式需要考虑字节序

### Elkeid 源码解读 (hids.c:667-676)

```c
/* query protocol of user sock connection: udp (dgram) or tcp ? */
static __noinline int sock_prot(struct sock *sk)
{
    unsigned long long prot = 0;

    // ① 获取 sk_protocol 所在字节的偏移量
    unsigned int offset = __builtin_preserve_field_info(
        sk->sk_protocol, BPF_FIELD_BYTE_OFFSET);

    // ② 获取需要读取的字节数
    unsigned int size = __builtin_preserve_field_info(
        sk->sk_protocol, BPF_FIELD_BYTE_SIZE);

    // ③ 从 sk 的指定偏移处读取 size 个字节
    //    & 0x0f: 防御性编程，限制最大 15 字节
    bpf_probe_read(&prot, size & 0x0f, (void *)sk + offset);

    // ④ 左移清除高位无关 bit
    prot <<= __builtin_preserve_field_info(
        sk->sk_protocol, BPF_FIELD_LSHIFT_U64);

    // ⑤ 右移将值对齐到 bit 0
    prot >>= __builtin_preserve_field_info(
        sk->sk_protocol, BPF_FIELD_RSHIFT_U64);

    return (int)prot;
}
```

这 10 行代码替代了旧方案中 10+ 行的 `#ifdef` 分支，且能自动适配所有内核版本。

## `BPF_CORE_READ_BITFIELD` 宏：高层封装

libbpf 提供了 `BPF_CORE_READ_BITFIELD` 宏，它封装了上述 5 个步骤：

```c
// 一行代码完成位域读取
u32 sock_type = BPF_CORE_READ_BITFIELD(sk, sk_type);
```

宏展开后的逻辑与 `sock_prot` 函数完全等价：

```c
// BPF_CORE_READ_BITFIELD(sk, sk_type) 展开为:
({
    unsigned long long val = 0;
    unsigned int offset = __builtin_preserve_field_info(
        sk->sk_type, BPF_FIELD_BYTE_OFFSET);
    unsigned int size = __builtin_preserve_field_info(
        sk->sk_type, BPF_FIELD_BYTE_SIZE);
    bpf_probe_read_kernel(&val, size, (void *)sk + offset);
    val <<= __builtin_preserve_field_info(
        sk->sk_type, BPF_FIELD_LSHIFT_U64);
    val >>= __builtin_preserve_field_info(
        sk->sk_type, BPF_FIELD_RSHIFT_U64);
    val;
})
```

**何时用宏，何时手动？**

| 场景 | 推荐方式 |
|------|----------|
| 日常使用 | `BPF_CORE_READ_BITFIELD` 宏，简洁安全 |
| 学习原理 | 手动 `__builtin_preserve_field_info`，理解底层 |
| 调试问题 | 手动方式，可以逐步打印 offset/size/shift |
| 复杂提取 | 手动方式，如需要同时提取多个相邻位域 |

Elkeid 选择手动方式（`sock_prot` 函数），可能是因为开发时 `BPF_CORE_READ_BITFIELD` 宏尚未成熟或不支持所有场景。

## `preserve_access_index` 属性

`__builtin_preserve_field_info` 能工作的前提是结构体声明带有 `preserve_access_index` 属性：

```c
struct sock {
    ...
    unsigned int sk_protocol : 8;
    unsigned int sk_type     : 16;
    u16 sk_gso_max_segs;
} __attribute__((preserve_access_index));
```

这个属性告诉 Clang 编译器：

1. 为该结构体的每次字段访问生成 BTF 重定位记录
2. 记录字段名、类型、偏移量等元信息到 ELF 的 `.BTF` 和 `.BTF.ext` section
3. BPF loader 加载时将这些记录与目标内核的 BTF 匹配，更新指令中的立即数

当使用 `vmlinux.h`（由 `bpftool btf dump` 生成）时，所有结构体自动带有此属性。如果手动定义结构体（如 Elkeid 的 `struct sock___v55`），需要显式添加。

Elkeid hids.c 中的两个 sock 变体 (hids.c:632-663) 展示了同一结构体在不同内核中的不同定义，都带有 `preserve_access_index`：

```c
/* 旧内核: sk_protocol 是 8-bit 位域 */
struct sock___v55 {
    unsigned int sk_protocol: 8;
    unsigned int sk_type: 16;
} __attribute__((preserve_access_index));

/* 新内核: sk_protocol 是独立的 u16 */
struct sock___v56 {
    u16 sk_type;
    u16 sk_protocol;
} __attribute__((preserve_access_index));
```

## Demo 代码解读

### 整体架构

```
                      内核态                              用户态
┌──────────────────────────────────────┐    ┌──────────────────────┐
│  kprobe/tcp_connect                  │    │  main.go             │
│  │                                   │    │  │                   │
│  ├── 获取 struct sock *sk            │    │  ├── LoadCollection  │
│  │                                   │    │  ├── Kprobe attach   │
│  ├── sock_prot(sk) [位域读取]        │    │  ├── perf.NewReader  │
│  │   ├── preserve_field_info × 4     │    │  └── for { Read() }  │
│  │   ├── bpf_probe_read              │    │       ├── 解析事件    │
│  │   └── 左移 + 右移 → protocol      │    │       ├── 协议名翻译  │
│  │                                   │    │       └── 格式化输出  │
│  ├── BPF_CORE_READ_BITFIELD(sk_type) │    │                       │
│  ├── BPF_CORE_READ(sk_family, ports) │    └──────────────────────┘
│  │                                   │              ↑
│  └── perf_event_output ─────────────────────────────┘
│                                      │
└──────────────────────────────────────┘
```

### eBPF 端 (bitfield.bpf.c)

1. **`sock_prot()`** (`__noinline`): 完整复现 Elkeid 的位域读取逻辑，使用 4 次 `__builtin_preserve_field_info` 调用
2. **`kp_tcp_connect()`**: kprobe 入口函数，对比三种读取方式：
   - `sock_prot()`: 手动位域提取 → `protocol`
   - `BPF_CORE_READ_BITFIELD`: 宏封装位域提取 → `sock_type`
   - `BPF_CORE_READ`: 普通字段读取 → `family`, `sport`, `dport`

### Go 端 (main.go)

标准 cilium/ebpf 模式：加载 ELF、附加 kprobe、循环读取 perf event。重点在验证 `protocol` 字段是否正确读取为 TCP(6)。

## 编译与运行

```bash
# 1. 生成 vmlinux.h（如果还没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF 程序
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c bitfield.bpf.c -o bitfield.bpf.o

# 3. 初始化 Go 模块
go mod init bitfield_preserve
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/perf@latest
go mod tidy

# 4. 编译并运行（需要 root 权限）
go build -o bitfield_demo . && sudo ./bitfield_demo
```

## 测试方法

在另一个终端执行会发起 TCP 连接的命令：

```bash
# 触发 TCP 连接到外部
curl -s https://www.baidu.com > /dev/null

# 连接本地服务
ssh localhost

# 使用 wget
wget -q -O /dev/null http://example.com

# 使用 nc (netcat) 连接指定端口
nc -z -w1 127.0.0.1 22

# 批量触发
for i in $(seq 1 5); do curl -s http://127.0.0.1 > /dev/null 2>&1; done
```

## 预期输出

```
监控 TCP 连接 (kprobe/tcp_connect)... 按 Ctrl+C 停止

位域读取验证说明:
  PROTOCOL 列: 通过 __builtin_preserve_field_info 从位域中提取
  TYPE 列:     通过 BPF_CORE_READ_BITFIELD 宏读取
  FAMILY 列:   通过 BPF_CORE_READ 普通读取
  若 PROTOCOL 正确显示为 TCP(6)，说明位域 CO-RE 重定位成功

PID      COMM             UID    PROTO    TYPE     FAMILY  CONNECTION
-------- ---------------- ------ -------- -------- ------  --------------------
18201    curl             1000   TCP      STREAM   IPv4    :45678 -> :443
18202    ssh              0      TCP      STREAM   IPv4    :52100 -> :22
18203    wget             1000   TCP      STREAM   IPv6    :33210 -> :80

=== 位域读取验证统计 ===
总事件数:          3
协议正确 (TCP=6):  3/3
结论: __builtin_preserve_field_info 位域读取完全正确
      CO-RE 重定位成功，位域的 offset/size/shift 参数正确
```

关键验证点：
- **PROTO 列全部为 TCP**：因为 `tcp_connect` 只处理 TCP 连接
- **TYPE 列全部为 STREAM**：TCP 使用流式 socket
- **如果 PROTO 显示异常值**：说明位域重定位失败，需要检查 BTF 支持

## 核心概念索引

| 概念 | 说明 | 本 demo 位置 | Elkeid 对应 |
|------|------|-------------|-------------|
| `__builtin_preserve_field_info` | 编译器内建: 获取位域布局信息 | `bitfield.bpf.c:sock_prot` | `hids.c:670-675` |
| `BPF_FIELD_BYTE_OFFSET` | kind 0: 字节偏移量 | `sock_prot` 步骤 1 | `hids.c:670` |
| `BPF_FIELD_BYTE_SIZE` | kind 1: 读取字节数 | `sock_prot` 步骤 2 | `hids.c:671` |
| `BPF_FIELD_LSHIFT_U64` | kind 2: 左移量 | `sock_prot` 步骤 4 | `hids.c:674` |
| `BPF_FIELD_RSHIFT_U64` | kind 3: 右移量 | `sock_prot` 步骤 5 | `hids.c:675` |
| `BPF_CORE_READ_BITFIELD` | libbpf 位域读取宏 | `kp_tcp_connect: sk_type` | 可替代 sock_prot |
| `preserve_access_index` | 结构体属性: 启用 CO-RE 重定位 | vmlinux.h 自动包含 | `hids.c:632-663` |
| 位域版本差异 | sk_protocol: 8-bit 位域 vs u16 | README 说明 | `hids.c:631-664` |
| `__noinline` | 独立栈帧 | `sock_prot` 函数 | `hids.c:667` |
| 旧方案 `#ifdef` | 版本判断+硬编码掩码 | 注释对比 | `hids.c:678-691` |

## 进阶方向

1. **验证重定位记录**: 使用 `llvm-objdump -r bitfield.bpf.o` 或 `bpftool btf dump file bitfield.bpf.o` 查看编译器为 `__builtin_preserve_field_info` 生成的重定位条目，理解 BPF loader 如何在加载时替换立即数
2. **对比 `BPF_CORE_READ_BITFIELD_PROBED`**: 这个变体使用 `bpf_probe_read_kernel` 而非直接内存访问，适用于从其他结构体指针读取位域的场景
3. **有符号位域实验**: 构造一个带有有符号位域的结构体，验证算术右移是否正确做符号扩展
4. **多内核测试**: 在 5.4 (位域版) 和 5.10+ (独立字段版) 上分别运行同一个 `.o` 文件，验证 CO-RE 的"编译一次，到处运行"
5. **手动 BTF 分析**: 使用 `bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A 20 'sock'` 查看当前内核中 `struct sock` 的实际 BTF 定义，确认 `sk_protocol` 是位域还是独立字段
6. **位域与字节序**: 研究大端架构 (如 s390x) 上位域布局的差异，理解为什么 `LSHIFT/RSHIFT` 比掩码更具可移植性
