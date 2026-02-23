# 技术点 6: 条件 `#pragma unroll` 循环展开 —— 内核版本兼容性策略

## 核心问题: eBPF 验证器与循环

eBPF 程序在加载到内核前必须通过**验证器** (verifier) 的检查。验证器的核心职责之一是确保程序**一定会终止**，不会让内核陷入死循环。这就引出了 eBPF 中最经典的限制之一：**循环处理**。

### 内核 <= 5.2: 完全禁止循环

在 Linux 5.3 之前，验证器使用一种简单粗暴的策略：**拒绝所有包含后向跳转 (backward jump) 的程序**。

```
普通 for 循环的汇编结构:

    insn 0: r1 = 0              ; i = 0
    insn 1: if r1 >= 16 goto 4  ; if (i >= 16) break
    insn 2: ... 循环体 ...       ; loop body
    insn 3: r1 += 1             ; i++
    insn 4: goto 1              ; ← 后向跳转! 验证器直接拒绝!
    insn 5: ...                 ; loop end
```

验证器看到 `goto 1` 这条后向跳转指令时，**不会尝试分析循环是否有界**，而是直接报错：

```
back-edge from insn 4 to 1
```

这意味着在旧内核上，**任何形式的循环都无法通过验证**。唯一的解决方法是让编译器在编译阶段把循环完全展开，消除后向跳转。

### 内核 >= 5.3: 有界循环支持

Linux 5.3 引入了有界循环 (bounded loop) 支持（commit `2589726d12a1`）。验证器新增了以下能力：

1. **跟踪循环变量的值域**: 验证器记录循环计数器的最小值和最大值
2. **证明循环终止**: 如果验证器能证明循环计数器在有限步内达到退出条件，就接受该循环
3. **指令计数限制**: 循环的总执行路径仍然受 `BPF_COMPLEXITY_LIMIT_JMP_SEQ` (1M 条指令) 限制

```c
/* 内核 >= 5.3 验证器可以接受这种循环 */
for (int i = 0; i < 16; i++) {
    /* 验证器分析:
     *   i 初始值 = 0
     *   每次迭代 i += 1
     *   退出条件 i >= 16
     *   → 最多执行 16 次，循环一定终止
     *   → 接受!
     */
    sum += arr[i];
}
```

有界循环的要求：
- 循环变量的**上界必须是编译期常量**（不能是运行时变量）
- 循环体中不能修改循环变量（`i++` 只能出现在 for 语句的第三部分）
- 总指令执行路径不能超过 1M

## `#pragma unroll` 的工作原理

`#pragma unroll` 是 Clang 编译器指令，告诉编译器将循环**完全展开**为顺序指令：

```c
/* 源代码 */
#pragma unroll
for (int i = 0; i < 4; i++) {
    sum += arr[i];
}

/* 编译器展开后的等效代码 */
sum += arr[0];
sum += arr[1];
sum += arr[2];
sum += arr[3];
/* 没有任何跳转指令! 验证器无条件接受 */
```

### 展开的代价：指令膨胀

展开后的指令数 = **迭代次数 x 循环体指令数**。

以 Elkeid 的 DNS 域名解析为例（hids.c:870-887）：

```
循环体 (process_domain_name): 约 30 条 BPF 指令
  - bpf_probe_read_kernel: ~5 条
  - 条件判断 + 分支: ~10 条
  - 字符处理 + 写入: ~10 条
  - 函数调用开销: ~5 条

展开 75 次: 75 x 30 = 2250 条指令
展开 50 次: 50 x 30 = 1500 条指令
加上其他函数的展开... 可能超过 1M 限制!
```

因此 Elkeid 在展开模式下将 DNS 循环次数从 75 减少到 50：

```c
/* hids.c:870-875 */
#if LOOPS_UNROLL
#   define DNS_N_LOOPS  (50)    /* 展开模式: 减少迭代防止超限 */
#   pragma unroll
#else
#   define DNS_N_LOOPS  (75)    /* 有界模式: 可处理更长域名 */
#endif
```

### 有界循环的优势

有界循环不展开代码，只保留一份循环体：

```
指令数 ≈ 循环体指令数 + 循环控制开销 ≈ 30 + 5 = 35 条
```

无论循环 50 次还是 75 次，代码大小相同。区别在于**验证器需要追踪的执行路径变长**，但远未达到 1M 限制。因此有界模式可以支持更多的迭代次数。

## Elkeid 的条件编译策略

### LOOPS_UNROLL 宏 (hids.c:294-298)

```c
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 2, 0)
#define LOOPS_UNROLL    (1)     /* 旧内核: 必须展开 */
#else
#define LOOPS_UNROLL    (0)     /* 新内核: 验证器支持有界循环 */
#endif
```

这个宏是整个循环兼容策略的开关。Elkeid 在源码中共有 **13 处**使用了条件展开：

```c
/* 标准模式: 保护每个 for 循环 */
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (nr = 0; nr < 16; nr++) {
        /* ... */
    }
```

### 13 处使用汇总

| 位置 | 循环用途 | 迭代次数 |
|------|---------|---------|
| socket fd 遍历 | 查找进程的第一个 socket | 16 |
| cmdline 参数解析 | 遍历 exec 参数列表 | 16 |
| xids 循环 | 读取 supplementary group IDs | 8 |
| path 路径构建 | dentry 链遍历构建文件路径 | 可变 |
| pid tree 遍历 | 向上遍历父进程树 | 8 |
| DNS 域名解析 | 逐字节解析 DNS 域名 | 50/75 |
| 环境变量遍历 | 读取进程环境变量 | 16 |
| ... | 其他遍历场景 | 4-16 |

### DNS 解析循环详解 (hids.c:870-887)

这是最复杂的条件展开场景，因为它不仅展开/不展开循环，还调整了迭代次数：

```c
#if LOOPS_UNROLL
#   define DNS_N_LOOPS  (50)    /* workaround for ebpf insts limit */
#   pragma unroll
#else
#   define DNS_N_LOOPS  (75)
#endif
    for (i = 1; i < DNS_N_LOOPS; i++) {
        if (!process_domain_name(data, name, &flag, i))
            break;
    }
```

**为什么是 50 和 75?**

- DNS 域名最长 253 字节，但实际中大多数域名 < 75 字节
- 有界模式 75 次足以覆盖绝大多数域名
- 展开模式 75 次的指令量太大，降低到 50 次
- 50 次仍然可以处理 "www.very-long-subdomain.example.com" 这类域名
- 极少数超长域名会被截断，这是可接受的妥协

### Socket fd 遍历 (hids.c:575-585)

```c
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (nr = 0; nr < 16; nr++) {
        sk = find_sock_internal(fds, nr, max);
        if (sk)
            break;
    }
```

这是典型的**早期退出搜索**模式。展开后，`break` 被编译为 `goto` 跳转到循环后面的代码。虽然展开了 16 份代码，但运行时如果第 3 个 fd 就匹配了，后面 13 份代码不会执行（通过跳转跳过）。

### `__noinline` 减少指令膨胀

```c
/* hids.c:830 */
static __noinline int process_domain_name(...)
```

`process_domain_name` 被标记为 `__noinline`。如果它被内联：

```
展开 50 次 x (内联后的完整函数体 ~60 条) = 3000 条指令
```

使用 `__noinline`：

```
展开 50 次 x (call 指令 ~3 条) = 150 条指令
+ 函数体本身 60 条 = 210 条指令
```

从 3000 条减少到 210 条，效果显著。这是 Elkeid 在循环展开场景下控制指令数的关键技巧。

## 指令数分析

### 展开 vs 有界的指令对比

```
                    展开模式              有界模式
                    ─────────────         ─────────────
代码大小 (字节):    N x body_size         body_size + ~20
验证路径 (指令):    N x body_size         N x body_size
最大迭代次数:       受代码大小限制         受验证路径限制
DNS 示例:           50 x 30 = 1500       75 x 30 + 20 = 2270
                    (代码 1500 条)        (代码 ~50 条)
```

关键区别：
- **展开模式**: 代码大小和验证路径都是 N x body_size
- **有界模式**: 代码大小只有 body_size，验证路径才是 N x body_size
- 两者的验证路径长度相当，但有界模式的代码体积小得多
- 代码体积受限时（多个展开的函数共存），展开模式需要减少 N

### 为什么展开模式下 50 就够了?

```
假设程序中有 13 个展开的循环:
  - 5 个 x 16 次 x 20 条 = 1600 条
  - 3 个 x 8 次 x 25 条  = 600 条
  - 1 个 x 50 次 x 30 条 = 1500 条  (DNS)
  - 其他 4 个            ≈ 800 条
  总计 ≈ 4500 条展开指令

加上非循环代码: ~2000 条
总计: ~6500 条 (远未达 1M 限制)

但如果 DNS 用 75 次:
  1 个 x 75 次 x 30 条 = 2250 条 (多了 750 条)
  总计: ~7250 条

虽然仍未超限，但 Elkeid 保守设计，
为未来新增 hook 点预留空间。
```

## 常见循环模式

### 模式 1: 固定次数遍历

```c
/* 遍历固定大小的数组 */
#if LOOPS_UNROLL
#   pragma unroll
#endif
for (nr = 0; nr < 16; nr++) {
    total += arr[nr];
}
```

特点: 循环次数固定，没有 break，每次迭代独立。
展开后: 16 份独立的加法指令。
有界后: 一个循环，验证器追踪 nr 的范围 [0, 16)。

### 模式 2: 早期退出搜索

```c
/* 搜索匹配项，找到就退出 */
#if LOOPS_UNROLL
#   pragma unroll
#endif
for (nr = 0; nr < 16; nr++) {
    result = check(nr);
    if (result)
        break;
}
```

特点: 循环可能提前退出，实际执行次数 <= 上限。
展开后: 16 个 if-goto 块，break 变成 goto loop_end。
有界后: 正常循环 + break 跳转。

### 模式 3: 逐字符处理

```c
/* 逐字符/逐字节处理缓冲区 */
#if LOOPS_UNROLL
#   define N_LOOPS 50
#   pragma unroll
#else
#   define N_LOOPS 75
#endif
for (i = 0; i < N_LOOPS; i++) {
    if (!process_byte(buf, i))
        break;
}
```

特点: 迭代次数因展开模式而异，循环体调用外部函数。
关键: 被调函数用 `__noinline` 防止内联导致指令膨胀。
展开后: N_LOOPS 个 call 指令（不含函数体的内联）。

## Elkeid 源码逐行解读

### 1. LOOPS_UNROLL 宏 (hids.c:294-298)

```c
/*
 * 根据内核版本自动选择循环策略:
 *   <= 5.2: 验证器不支持有界循环，必须展开
 *   >= 5.3: 验证器支持有界循环，无需展开
 *
 * LINUX_VERSION_CODE 由内核头文件 linux/version.h 定义，
 * 在编译期就确定，不增加运行时开销。
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 2, 0)
#define LOOPS_UNROLL    (1)
#else
#define LOOPS_UNROLL    (0)
#endif
```

### 2. DNS 解析循环 (hids.c:870-887)

```c
/*
 * DNS 域名逐字节解析:
 *   数据来自网络包: skb->data + dns_offset
 *   格式: \x03www\x06google\x03com\x00
 *
 * process_domain_name 是 __noinline 的:
 *   展开时: 每次迭代一条 call，而非整个函数体
 *   关键的指令数控制手段
 */
#if LOOPS_UNROLL
#   define DNS_N_LOOPS  (50)
#   pragma unroll
#else
#   define DNS_N_LOOPS  (75)
#endif
    for (i = 1; i < DNS_N_LOOPS; i++) {
        if (!process_domain_name(data, name, &flag, i))
            break;
    }
```

### 3. Socket fd 遍历 (hids.c:575-585)

```c
/*
 * 遍历进程的前 16 个 fd，查找第一个 socket:
 *   find_sock_internal: 检查 fd 是否指向 socket
 *   找到后立即 break，不继续遍历
 *
 * 展开后: 16 个 if-call-break 块
 * 有界后: 一个 while 循环 + break
 */
#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (nr = 0; nr < 16; nr++) {
        sk = find_sock_internal(fds, nr, max);
        if (sk)
            break;
    }
```

## Demo 代码解读

### 整体架构

```
                      内核态                              用户态
┌──────────────────────────────────────┐    ┌──────────────────────┐
│  raw_tracepoint/sched_process_exec   │    │  main.go             │
│  │                                   │    │  │                   │
│  ├── demo_array_sum()                │    │  ├── LoadCollection  │
│  │   #pragma unroll (条件)           │    │  ├── AttachRawTP     │
│  │   for (0..16) sum += arr[nr]      │    │  ├── perf.NewReader  │
│  │                                   │    │  └── for { Read() }  │
│  ├── demo_name_parse()               │    │       ├── 解析事件    │
│  │   #pragma unroll (条件)           │    │       ├── 显示结果    │
│  │   for (0..12/20) process_char()   │    │       └── 对比模式    │
│  │                                   │    └──────────────────────┘
│  ├── demo_early_exit()               │              ↑
│  │   #pragma unroll (条件)           │              │
│  │   for (0..16) if match break      │              │
│  │                                   │              │
│  └── perf_event_output ─────────────────────────────┘
└──────────────────────────────────────┘
```

### eBPF 端 (loop_unroll.bpf.c)

三个 demo 函数演示三种典型循环模式：

1. **`demo_array_sum()`**: 固定次数遍历数组求和。展开/有界结果相同 (256)，因为迭代次数不变。
2. **`demo_name_parse()`**: 逐字符处理 cmdline。展开模式最多处理 12 字符，有界模式 20 字符。使用 `__noinline` 的 `process_char()` 减少展开膨胀。
3. **`demo_early_exit()`**: 搜索 comm 中第一个 'a' 字符。展开/有界结果相同，因为早期退出逻辑不受展开影响。

### Go 端 (main.go)

标准 cilium/ebpf 用户态程序：加载 ELF、附加 tracepoint、循环读取 perf event 并格式化输出。输出中包含 `UNROLL` 字段标识当前编译模式。

## 编译与运行

```bash
# 1. 生成 vmlinux.h（如果还没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF 程序 —— 默认模式（有界循环，适用于内核 >= 5.3）
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -c loop_unroll.bpf.c -o loop_unroll.bpf.o

# 2b. 编译 eBPF 程序 —— 展开模式（模拟旧内核 <= 5.2）
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -DFORCE_UNROLL=1 \
  -I. \
  -c loop_unroll.bpf.c -o loop_unroll.bpf.o

# 3. 初始化 Go 模块
go mod init loop_unroll
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/perf@latest
go mod tidy

# 4. 编译并运行（需要 root 权限）
go build -o loop_unroll_demo . && sudo ./loop_unroll_demo
```

### 对比两种模式

可以分别用两种模式编译，对比输出中 `UNROLL`、`ITER`、`NAME_LEN` 字段的差异：

```bash
# 模式 1: 有界循环
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. \
  -c loop_unroll.bpf.c -o loop_unroll.bpf.o
go build -o demo . && sudo ./demo

# 模式 2: 展开循环
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -DFORCE_UNROLL=1 -I. \
  -c loop_unroll.bpf.c -o loop_unroll.bpf.o
go build -o demo . && sudo ./demo
```

还可以用 `llvm-objdump` 对比两种模式的指令数差异：

```bash
# 查看展开后的指令数
llvm-objdump -d loop_unroll.bpf.o | wc -l
```

## 测试方法

在另一个终端执行各种命令，触发 exec 事件：

```bash
ls /tmp
cat /etc/hostname
echo hello
python3 -c "print('test')"
bash -c "echo test"
```

## 预期输出

### 有界模式 (UNROLL=0, ITER=20)

```
监控循环展开 demo... 按 Ctrl+C 停止

PID      PPID     COMM             UNROLL  ITER  SUM    NAME_LEN FD    PARSED_NAME
-------- -------- ---------------- ------- ----- ------ -------- ----- ----------
18201    18100    ls               0       20    256    2        N/A   ls
18202    18100    cat              0       20    256    3        1     cat
18203    18100    echo             0       20    256    4        N/A   echo
18204    18100    python3          0       20    256    7        N/A   python3
18205    18100    bash             0       20    256    4        1     bash
```

### 展开模式 (UNROLL=1, ITER=12)

```
PID      PPID     COMM             UNROLL  ITER  SUM    NAME_LEN FD    PARSED_NAME
-------- -------- ---------------- ------- ----- ------ -------- ----- ----------
18301    18100    ls               1       12    256    2        N/A   ls
18302    18100    cat              1       12    256    3        1     cat
18303    18100    echo             1       12    256    4        N/A   echo
18304    18100    python3          1       12    256    7        N/A   python3
18305    18100    bash             1       12    256    4        1     bash
```

输出对比：
- `SUM` 列: 两种模式相同 (256)，因为数组大小固定为 16
- `NAME_LEN` 列: 短字符串两种模式相同；超过 12 字符的名称在展开模式下被截断
- `FD` 列: 两种模式相同，早期退出搜索不受展开策略影响
- `UNROLL` 和 `ITER` 列: 反映当前编译模式

## 核心概念索引

| 概念 | 说明 | 本 demo 位置 | Elkeid 对应 |
|------|------|-------------|-------------|
| `LOOPS_UNROLL` 宏 | 内核版本检测开关 | `loop_unroll.bpf.c:FORCE_UNROLL` | `hids.c:294-298` |
| `#pragma unroll` | 编译器循环展开指令 | `loop_unroll.bpf.c:三个 demo` | `hids.c:全文 13 处` |
| 有界循环 | 验证器证明循环终止 | `loop_unroll.bpf.c:LOOPS_UNROLL=0` | `hids.c:内核>=5.3` |
| 可变迭代次数 | 展开模式减少迭代 | `loop_unroll.bpf.c:NAME_N_LOOPS` | `hids.c:870-875 DNS_N_LOOPS` |
| `__noinline` 控制膨胀 | 防止展开时内联函数体 | `loop_unroll.bpf.c:process_char` | `hids.c:830 process_domain_name` |
| 早期退出 | `break` + `#pragma unroll` | `loop_unroll.bpf.c:demo_early_exit` | `hids.c:575-585` |
| percpu 缓冲区 | 循环处理中的临时存储 | `loop_unroll.bpf.c:g_percpu_buf` | `hids.c:70-75` |
| 后向跳转 | 旧内核验证器拒绝的原因 | README 理论部分 | 内核 verifier.c |

## 进阶方向

1. **指令数对比实验**: 分别用 `-DFORCE_UNROLL=0` 和 `-DFORCE_UNROLL=1` 编译，用 `llvm-objdump -d` 对比两种模式的指令数差异，验证展开的指令膨胀效果
2. **增加迭代次数**: 尝试将 `NAME_N_LOOPS` 在展开模式下从 12 增加到 100，观察验证器是否因指令数过多而拒绝
3. **内联 vs 非内联**: 将 `process_char` 的 `__noinline` 去掉，在展开模式下对比指令数变化，体会 `__noinline` 对控制膨胀的重要性
4. **验证器日志分析**: 使用 `bpftool prog load loop_unroll.bpf.o /sys/fs/bpf/test log_level 2` 查看验证器处理有界循环的日志
5. **旧内核测试**: 在 5.2 或更早的内核上运行不展开的版本，观察验证器的具体错误信息
6. **复杂循环嵌套**: 尝试在一个展开的循环内部再嵌套一个展开的循环，观察指令数的二次方增长
