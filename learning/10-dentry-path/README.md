# 技术点 10: 反向 dentry 路径构建

## 从 Elkeid HIDS 学习 VFS 路径解析

> **对应 Elkeid 源码**: `BPF/hids.c:1111-1267`
> **Hook 点**: `kprobe/security_inode_create`, `raw_tracepoint/sched_process_exec`
> **核心难度**: 在 eBPF 受限环境中重建完整文件路径

---

## 目录

1. [为什么路径构建在 eBPF 中很难](#1-为什么路径构建在-ebpf-中很难)
2. [反向构建原理](#2-反向构建原理)
3. [核心函数逐行解析](#3-核心函数逐行解析)
4. [swap 缓冲区布局](#4-swap-缓冲区布局)
5. [挂载点穿越](#5-挂载点穿越)
6. [Elkeid 源码对照](#6-elkeid-源码对照)
7. [编译运行](#7-编译运行)
8. [预期输出](#8-预期输出)
9. [概念索引](#9-概念索引)
10. [进阶方向](#10-进阶方向)

---

## 1. 为什么路径构建在 eBPF 中很难

在用户态程序中，获取文件路径很简单 —— 调用 `realpath()` 或读取 `/proc/self/fd/N`。但在 eBPF 内核态，这是一个相当困难的任务。

### 1.1 没有内核的 d_path()

Linux 内核有一个 `d_path()` 函数可以将 dentry 转换为路径字符串。但 eBPF 程序不能直接调用它，原因包括：

- `d_path()` 内部需要获取 `rename_lock` (sequence lock)
- 它可能 sleep (等待锁)
- eBPF 程序必须是非阻塞的 (不能 sleep)
- 虽然 BPF 5.9+ 有 `bpf_d_path()` helper，但它不是在所有 hook 点都可用

### 1.2 没有动态内存分配

```
BPF 栈限制: 512 字节
路径最大长度: PATH_MAX = 4096 字节

问题: 路径缓冲区放不下栈
解决: 使用 per-CPU map 作为 "堆" 内存
```

### 1.3 dentry 只存储文件名

Linux VFS 的 dentry (directory entry) 只存储**单个**文件名（不是完整路径）：

```
dentry 结构体:
  struct dentry {
      struct dentry *d_parent;     // 父目录的 dentry
      struct qstr d_name;          // 此 dentry 的名字 (如 "ls")
      struct inode *d_inode;       // 关联的 inode
      ...
  };
```

要构建 `/usr/bin/ls`，需要遍历整个 dentry 链：

```
dentry("ls") → dentry("bin") → dentry("usr") → dentry("/")
  d_parent ------^  d_parent ------^  d_parent ----^
                                        d_parent == self (根)
```

### 1.4 循环有界限制

BPF 验证器要求所有循环必须有已知上界。我们不能写 `while (de != root)`，必须写 `for (i = 0; i < MAX; i++)`。Elkeid 选择 `MAX_PATH_ENTS = 16` 作为上界，覆盖绝大多数实际路径。

### 1.5 挂载点使问题更复杂

Linux 文件系统是多个挂载点组成的树。一个路径可能跨越多个文件系统：

```
/mnt/data/project/src/main.c

文件系统边界:
  rootfs:  / → mnt → data (挂载点)
  ext4:    data → project → src → main.c

dentry 链在挂载点处断开，需要穿越处理
```

---

## 2. 反向构建原理

### 2.1 为什么从右到左？

考虑路径 `/usr/bin/ls`。遍历 dentry 链的顺序是 **叶到根**：`ls → bin → usr → /`。

**如果从左到右构建**（不推荐）：

```
步骤 1: 遍历到 "ls"   → buf = "ls"
步骤 2: 遍历到 "bin"  → buf = "bin/ls"     ← 需要 memmove "ls" 后移!
步骤 3: 遍历到 "usr"  → buf = "usr/bin/ls" ← 再次 memmove!
步骤 4: 添加 "/"      → buf = "/usr/bin/ls"

每步都需要移动已有内容，O(n^2) 复���度
而且 eBPF 中没有 memmove!
```

**Elkeid 的从右到左构建**（推荐）：

```
缓冲区大小: 1024 字节 (PATH_BUF_SIZE)

步骤 1: 写入 "ls\0"
  索引: 0                                              1023
        [                                          ls\0    ]
                                                   ^
                                             len=3, pos=1021

步骤 2: 写入 "/bin"
  索引: 0                                              1023
        [                                     /bin/ls\0    ]
                                              ^
                                        len=7, pos=1017

步骤 3: 写入 "/usr"
  索引: 0                                              1023
        [                                /usr/bin/ls\0     ]
                                         ^
                                   len=11, pos=1013

步骤 4: 到达根 "/"，停止
  最终路径从 &buf[1013] 开始: "/usr/bin/ls\0"
```

### 2.2 关键公式

```c
// 写入位置计算
pos = (PATH_BUF_SIZE - len - num) & PATH_BUF_MASK

// 其中:
//   PATH_BUF_SIZE = 1024    (缓冲区总大小)
//   len           = 已使用长度 (从右端开始)
//   num           = 本次要写入的字节数
//   PATH_BUF_MASK = 1023    (0x3FF)

// & PATH_BUF_MASK 的作用:
//   1. 确保 pos 在 [0, 1023] 范围内
//   2. 满足 BPF 验证器的边界检查要求
//   3. 即使计算溢出也不会越界
```

### 2.3 最终路径获取

```c
// 路径从 buf[pos] 开始，到 buf[PATH_BUF_SIZE-1] 结束（含 null）
char *path = &buf[(PATH_BUF_SIZE - len) & PATH_BUF_MASK];

// 路径长度 = len (包含 null terminator)
```

---

## 3. 核心函数逐行解析

### 3.1 prepend_path() —— 右到左写入

**对应 Elkeid**: `hids.c:1111-1123`

```c
// 函数签名
static __noinline int prepend_path(
    struct path_buffer *pb,  // per-CPU 路径缓冲区
    int *len,                // [in/out] 已使用长度
    const char *src,         // 源数据
    int num                  // 源数据长度
);
```

**逐行解析**：

```c
// 1. 溢出检查
if (*len + num > PATH_BUF_SIZE)
    return -1;
// 如果已用空间 + 新数据超过缓冲区，拒绝写入
// 这保证不会覆盖缓冲区前面的未使用区域

// 2. 计算写入位置
int pos = (PATH_BUF_SIZE - *len - num) & PATH_BUF_MASK;
// 示例: BUF=1024, len=7("/bin/ls"), num=4("/usr")
//   pos = (1024 - 7 - 4) & 1023 = 1013

// 3. 写入数据
bpf_probe_read_kernel(&pb->buf[pos], num & PATH_BUF_MASK, src);
// num & PATH_BUF_MASK: 长度也做位与，防止验证器报错
// bpf_probe_read_kernel: BPF 中唯一的内存拷贝方式

// 4. 更新长度
*len += num;
```

**设计决策**：
- 使用 `__noinline` 而非 `__always_inline`：减小程序体积，避免验证器指令数限制
- 位与运算代替取模：`& 1023` 等价于 `% 1024`，但更快且验证器友好
- `bpf_probe_read_kernel` 代替 `memcpy`：BPF 不支持直接内存操作

### 3.2 prepend_entry() —— dentry 名提取

**对应 Elkeid**: `hids.c:1125-1144`

```c
static __noinline int prepend_entry(
    struct path_buffer *pb,  // per-CPU 缓冲区
    int *len,                // [in/out] 已使用长度
    struct dentry *de        // 要提取名字的 dentry
);
```

**核心技巧 —— swap 缓冲区**：

```c
// 步骤 1: 预置分隔符
pb->swap[3] = '/';

// 步骤 2: 读取文件名到 swap[4]
const unsigned char *name = BPF_CORE_READ(de, d_name.name);
int str_len = bpf_probe_read_kernel_str(&pb->swap[4], PATH_NAME_LEN, name);

// 步骤 3: 一次性 prepend "/" + 名字
return prepend_path(pb, len, &pb->swap[3], str_len);
```

**为什么用 swap 缓冲区？**

不使用 swap 的话，需要两次 prepend：
```c
prepend_path(pb, len, name, name_len);   // 先写名字
prepend_path(pb, len, "/", 1);           // 再写 '/'
```

使用 swap 后，只需一次 prepend：
```c
// swap[3] = '/'
// swap[4..] = 名字
prepend_path(pb, len, &swap[3], 1 + name_len);  // 一次写入
```

一次 prepend 意味着一次 `bpf_probe_read_kernel` 调用，性能更优。

### 3.3 get_parent_dentry() —— 父 dentry 获取

**对应 Elkeid**: `hids.c:1146-1152`

```c
static __noinline struct dentry *get_parent_dentry(struct dentry *de)
{
    struct dentry *parent = BPF_CORE_READ(de, d_parent);

    // 根节点检测: 根目录的 d_parent 指向自身
    if (de == parent)
        return NULL;  // 到达根，停止遍历

    return parent;
}
```

**VFS 的根节点约定**：

```
普通目录:
  dentry("bin") → d_parent → dentry("usr")  (不同对象)

根目录:
  dentry("/") → d_parent → dentry("/")  (指向自身!)
```

这是一个优雅的哨兵设计 —— 不需要额外标志位来标记根节点。

### 3.4 build_dentry_path() —— 简单 dentry 遍历

**对应 Elkeid**: `hids.c:1207-1225`

```c
static __noinline int build_dentry_path(
    struct path_buffer *pb,   // 缓冲区
    struct dentry *de,        // 起始 dentry (叶节点)
    __u32 *depth              // [out] 遍历深度
);
```

**完整流程**：

```
输入: dentry("ls")，dentry 链为 ls → bin → usr → /

迭代 1: prepend_entry(de="ls")
  swap = "xxx/ls\0"
  buf = [                                          /ls\0]
  len = 4, depth = 1

迭代 2: de = parent("bin"), prepend_entry(de="bin")
  swap = "xxx/bin\0"
  buf = [                                     /bin/ls\0]
  len = 8, depth = 2

迭代 3: de = parent("usr"), prepend_entry(de="usr")
  swap = "xxx/usr\0"
  buf = [                                /usr/bin/ls\0]
  len = 12, depth = 3

迭代 4: de = parent("/"), get_parent_dentry 返回 NULL
  循环结束

返回: pos = (1024 - 12) & 1023 = 1012
路径: &buf[1012] = "/usr/bin/ls\0"
```

**限制**：此函数不处理挂载点穿越，路径是相对于当前文件系统根的。

### 3.5 build_full_path() —— 完整路径 + 挂载穿越

**对应 Elkeid**: `hids.c:1160-1204`

```c
static __noinline int build_full_path(
    struct path_buffer *pb,   // 缓冲区
    struct dentry *de,        // 起始 dentry
    struct vfsmount *mnt,     // 起始 vfsmount
    __u32 *depth              // [out] 遍历深度
);
```

**与 build_dentry_path 的区别**：

| 特性 | build_dentry_path | build_full_path |
|------|------------------|-----------------|
| 挂载穿越 | 不支持 | 支持 |
| 输入参数 | dentry | dentry + vfsmount |
| 输出路径 | 文件系统内相对路径 | 全局绝对路径 |
| 对应 Elkeid | dentry_path() | d_path() |
| 使用场景 | 文件创建 | 进程执行 |

**挂载穿越逻辑**（详见下一节）：

```c
for (int i = 0; i < MAX_PATH_DEPTH; i++) {
    struct dentry *parent = BPF_CORE_READ(de, d_parent);

    if (de == mnt_root || de == parent) {
        // 到达文件系统根
        if (mnt_p == mnt_parent) break;     // 全局根，结束
        if (de == mnt_root) {               // 挂载边界，穿越
            de = BPF_CORE_READ(mnt_p, mnt_mountpoint);
            mnt_p = mnt_parent;
            // 更新 mnt_root, mnt_parent ...
            continue;
        }
        break;  // 异常情况
    }

    // 正常: prepend 当前 dentry 名字
    prepend_entry(pb, &len, de);
    de = parent;
}
```

---

## 4. swap 缓冲区布局

### 4.1 为什么需要 swap 缓冲区？

BPF 程序不能在栈上分配大数组（512 字节限制），也不能动态分配内存。swap 缓冲区是 per-CPU map 中的一块固定区域，用于临时存放 dentry 名字。

### 4.2 详细布局

```
swap buffer (260 字节 = SWAP_BUF_SIZE):

偏移:  [0] [1] [2] [3]  [4]  [5]  [6]  ... [259]
内容:   ?   ?   ?   '/'  'f'  'i'  'l'  ... '\0'
                 ^    ^    ^
                 |    |    |
                 |    |    bpf_probe_read_kernel_str 从这里开始写入
                 |    '/' 分隔符 (prepend 时的起始位置)
                 未使用 (留作对齐或未来扩展)

prepend_path 调用:
  src = &swap[3]       ← 从 '/' 开始
  num = str_len        ← bpf_probe_read_kernel_str 的返回值
                          (包含文件名 + null terminator)
```

### 4.3 为什么偏移从 [3] 开始？

```
Elkeid 的设计考量:

在 Elkeid 原始代码中:
  - offset [3] = '/' (PATH_NAME_LEN 对齐用)
  - offset [4] = 文件名开始

这个偏移量的选择可能与:
  1. 内存对齐有关 (4 字节对齐)
  2. Elkeid 内部 swap 缓冲区的复用有关

在我们的简化实现中，关键是理解:
  swap[某个偏移] = '/'
  swap[偏移+1]   = 文件名
  整体从 swap[偏移] 开始 prepend
```

### 4.4 数据流

```
dentry->d_name.name = "myfile.txt"

步骤 1: swap[3] = '/'
  swap: [?][?][?][/][?][?]...[?]

步骤 2: bpf_probe_read_kernel_str(&swap[4], 256, name)
        返回 11 (10 个字符 + 1 个 null)
  swap: [?][?][?][/][m][y][f][i][l][e][.][t][x][t][\0]...[?]

步骤 3: prepend_path(pb, len, &swap[3], 11)
        写入 11 字节: "/" + "myfile.txt" (不含 null)
  buf:  [                         /myfile.txt\0]
```

---

## 5. 挂载点穿越

### 5.1 Linux 挂载模型

Linux 文件系统是一棵树，由多个挂载点组成：

```
全局文件系统树:

    /  (rootfs, ext4)
    ├── usr/
    │   └── bin/
    ├── mnt/
    │   └── data/  ← 挂载点 (另一个 ext4 分区)
    │       ├── project/
    │       │   └── src/
    │       │       └── main.c
    │       └── docs/
    └── proc/  ← 挂载点 (procfs)
```

### 5.2 挂载相关数据结构

```c
struct vfsmount {
    struct dentry *mnt_root;    // 此文件系统的根 dentry
    struct super_block *mnt_sb; // 超级块
    int mnt_flags;              // 挂载标志
};

struct mount {
    struct mount *mnt_parent;       // 父挂载
    struct dentry *mnt_mountpoint;  // 在父文件系统中的挂载点 dentry
    struct vfsmount mnt;            // 嵌入的 vfsmount
    ...
};
```

### 5.3 穿越过程详解

以文件 `/mnt/data/project/src/main.c` 为例：

假设 `/mnt/data` 是单独的 ext4 分区挂载。

**dentry 链（在 ext4 分区内）**：

```
main.c → src → project → data (这是 ext4 分区的根!)
                          ^
                          dentry == mnt_root !
```

当 `dentry == mnt_root` 时，说明到达了当前文件系统的根。此时检查是否是全局根：

```
检查: mount == mnt_parent ?
  如果是 → 全局根，结束
  如果否 → 需要穿越到父挂载
```

**穿越步骤**：

```
穿越前:
  dentry = data (ext4 根 dentry)
  mount  = ext4_mount

穿越操作:
  dentry = mount->mnt_mountpoint  → data (rootfs 中的 dentry)
  mount  = mount->mnt_parent      → rootfs_mount

穿越后:
  继续在 rootfs 中遍历:
  data → mnt → / (d_parent == self, 全局根)
```

**完整路径构建过程**：

```
迭代 1: dentry="main.c"  → prepend "/main.c"
        buf: [                          /main.c\0]

迭代 2: dentry="src"     → prepend "/src"
        buf: [                     /src/main.c\0]

迭代 3: dentry="project" → prepend "/project"
        buf: [              /project/src/main.c\0]

迭代 4: dentry="data"    → dentry == mnt_root!
        穿越: dentry = mnt_mountpoint ("data" in rootfs)
              mount = rootfs_mount
        continue (不 prepend)

迭代 5: dentry="data"(rootfs) → prepend "/data"
        buf: [         /data/project/src/main.c\0]

迭代 6: dentry="mnt"    → prepend "/mnt"
        buf: [    /mnt/data/project/src/main.c\0]

迭代 7: dentry="/"      → d_parent == self
        mount == mnt_parent (全局根)
        break

最终路径: "/mnt/data/project/src/main.c"
```

### 5.4 三个终止条件

```
条件 1: dentry == d_parent
  含义: 到达文件系统根 (根目录 d_parent 指向自身)
  动作: 如果也是全局根 → break; 否则 → 异常

条件 2: dentry == mnt_root && mount == mnt_parent
  含义: 到达全局根 (根文件系统的 mount 指向自身)
  动作: break (路径构建完成)

条件 3: dentry == mnt_root && mount != mnt_parent
  含义: 到达挂载边界，需要穿越到父挂载
  动作: 切换 dentry 和 mount，continue
```

### 5.5 图解

```
文件: /mnt/data/project/main.c

层级视图:

                   rootfs
                  ┌───────────────────────┐
                  │ dentry: /             │
                  │   ├── mnt/            │
  mount 边界 ──→  │   │   └── data/ ←─────│──── mnt_mountpoint
                  │   ├── usr/            │
                  │   └── ...             │
                  └───────────────────────┘
                            │
                     挂载穿越 (mnt_parent)
                            │
                  ┌───────────────────────┐
                  │ ext4 分区             │
  mnt_root ──→   │ dentry: data/ (根)    │
                  │   └── project/        │
                  │       └── main.c      │ ← 起始点
                  └───────────────────────┘

遍历方向: main.c → project → data(穿越) → data → mnt → /
```

---

## 6. Elkeid 源码对照

### 6.1 函数对照表

| Demo 函数 | Elkeid 函数 | 源码位置 | 说明 |
|-----------|------------|---------|------|
| `prepend_path()` | `prepend_path()` | hids.c:1111-1123 | 右到左缓冲区写入 |
| `prepend_entry()` | `prepend_entry()` | hids.c:1125-1144 | dentry 名提取 + swap 技巧 |
| `get_parent_dentry()` | `d_parent()` | hids.c:1146-1152 | 父 dentry 获取 + 根检测 |
| `build_full_path()` | `d_path()` | hids.c:1160-1204 | 完整路径 + 挂载穿越 |
| `build_dentry_path()` | `dentry_path()` | hids.c:1207-1225 | 简单 dentry 遍历 |
| N/A | `d_tid_path()` | hids.c:1243-1267 | 获取进程 exe 路径 |

### 6.2 常量对照表

| Demo 常量 | Elkeid 常量 | 值 | 用途 |
|-----------|-----------|---|------|
| `PATH_BUF_SIZE` | `SD_STR_MAX` | 1024 | 路径缓冲区大小 |
| `PATH_BUF_MASK` | `SD_STR_MASK` | 1023 | 位与取模掩码 |
| `PATH_NAME_LEN` | `PATH_NAME_LEN` | 256 | 单个文件名最大长度 |
| `PATH_NAME_MASK` | `PATH_NAME_MASK` | 255 | 文件名长度掩码 |
| `MAX_PATH_DEPTH` | `MAX_PATH_ENTS` | 16 | 最大路径深度 |
| `SWAP_BUF_SIZE` | (内嵌在 sd) | 260 | swap 缓冲区大小 |

### 6.3 Elkeid 中路径函数的使用场景

Elkeid 在多个 hook 点使用 `d_path()` / `dentry_path()` 获取路径信息：

| Hook 点 | 使用函数 | 源码位置 | 获取的路径 |
|---------|---------|---------|-----------|
| `kp__inode_create` | `dentry_path()` | hids.c:3226-3264 | 新创建文件路径 |
| `tp__sched_process_exec` | `d_path()` | hids.c:2800+ | 可执行文件路径 |
| `kp__security_file_open` | `d_path()` | hids.c:3100+ | 打开的文件路径 |
| `kp__security_inode_rename` | `dentry_path()` | hids.c:3300+ | 重命名源/目标路径 |
| `kp__security_inode_link` | `dentry_path()` | hids.c:3350+ | 硬链接路径 |
| `kp__security_inode_unlink` | `dentry_path()` | hids.c:3400+ | 删除文件路径 |
| `kp__security_sb_mount` | `dentry_path()` | hids.c:3450+ | 挂载点路径 |
| `kp__security_socket_connect` | `d_tid_path()` | hids.c:3500+ | 进程 exe 路径 |
| `kp__security_ptrace_access` | `d_tid_path()` | hids.c:3550+ | 目标进程 exe 路径 |

### 6.4 Elkeid 的 per-CPU 缓冲区管理

Elkeid 使用一个更复杂的 per-CPU 缓冲区系统：

```c
// Elkeid 的 sd (shared data) 结构
struct sd {
    // [0] 和 [1] 用于通���缓冲区
    // [2] 用于字符串构建
    // [3] 用于 swap (存放 '/' + 文件名)
    // [4] 用于 swap (存放文件名)
    char buf[5][SD_STR_MAX];
};

// 我们简化为:
struct path_buffer {
    char buf[1024];     // 对应 sd.buf[2]
    char swap[260];     // 对应 sd.buf[3] 和 sd.buf[4] 的部分
};
```

---

## 7. 编译运行

### 7.1 前置条件

```bash
# 确保内核头文件和 BTF 信息可用
ls /sys/kernel/btf/vmlinux

# 确保安装了 clang 和 bpftool
clang --version
bpftool version
```

### 7.2 编译 eBPF 程序

```bash
cd /home/work/openSource/Elkeid-3.0-ebpf/driver/learning/10-dentry-path

# 编译 eBPF 字节码
# -O2: 优化级别 (必须, 否则验证器可能拒绝)
# -g:  生成调试信息 (包含 BTF)
# -target bpf: 指定目标为 BPF 架构
# -D__TARGET_ARCH_x86: 指定目标 CPU 架构
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I../../src/vmlinux/x86 \
    -c dentry_path.bpf.c -o dentry_path.bpf.o

# 可选: 查看编译后的 BPF 程序
llvm-objdump -d dentry_path.bpf.o
```

### 7.3 旧内核编译（需要循环展开）

```bash
# 内核版本 < 5.3 时，添加 -DLOOPS_UNROLL
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -DLOOPS_UNROLL \
    -I../../src/vmlinux/x86 \
    -c dentry_path.bpf.c -o dentry_path.bpf.o
```

### 7.4 编译运行用户态程序

```bash
# 初始化 Go 模块 (如果还没有)
go mod init dentry-path-demo
go mod tidy

# 编译并运行 (需要 root 权限)
go build -o dentry_path_demo main.go
sudo ./dentry_path_demo
```

### 7.5 触发事件

```bash
# 在另一个终端执行以下命令触发事件:

# 触发 CREATE 事件
touch /tmp/test_create.txt
echo "hello" > /tmp/test_write.txt
mkdir /tmp/test_dir

# 触发 EXEC 事件
ls /tmp
cat /etc/hostname
python3 --version
```

---

## 8. 预期输出

### 8.1 正常运行输出

```
2024/01/15 10:30:00 加载 eBPF 程序: dentry_path.bpf.o
2024/01/15 10:30:00 eBPF 程序加载成功
2024/01/15 10:30:00 附加 kprobe 到 security_inode_create
2024/01/15 10:30:00 kprobe 附加成功
2024/01/15 10:30:00 附加 raw_tracepoint 到 sched_process_exec
2024/01/15 10:30:00 raw_tracepoint 附加成功
2024/01/15 10:30:00 创建 perf event reader
2024/01/15 10:30:00 perf event reader 创建成功

====================================================================================================
TYPE       PID      PPID     COMM             DEPTH  PATH
----------------------------------------------------------------------------------------------------
[CREATE]   1234     1000     touch            3      /tmp/test_create.txt
[CREATE]   1235     1000     bash             3      /tmp/test_write.txt
[CREATE]   1236     1000     mkdir            2      /tmp/test_dir
[EXEC  ]   1237     1000     ls               4      /usr/bin/ls
[EXEC  ]   1238     1000     cat              4      /usr/bin/cat
[EXEC  ]   1239     1000     python3          4      /usr/bin/python3
[CREATE]   1240     1200     vim              5      /home/user/.file.swp
[EXEC  ]   1241     1200     gcc              4      /usr/bin/gcc
^C
2024/01/15 10:31:00
收到退出信号, 正在清理...
====================================================================================================
统计: CREATE=4  EXEC=4  TOTAL=8
程序已退出
```

### 8.2 挂载穿越示例

如果 `/mnt/data` 是独立挂载点：

```
# 创建测试文件
sudo mount /dev/sdb1 /mnt/data
touch /mnt/data/test.txt

# 预期输出 (穿越了挂载边界):
[CREATE]   2000     1000     touch            4      /mnt/data/test.txt
```

### 8.3 深路径示例

```
# 创建深层目录
mkdir -p /tmp/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o
touch /tmp/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/deep.txt

# 预期输出 (深度可能被截断到 MAX_PATH_DEPTH=16):
[CREATE]   3000     1000     touch            16     /a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/deep.txt
```

---

## 9. 概念索引

| 概念 | 说明 | 相关代码 |
|------|------|---------|
| **dentry** | 目录项, VFS 的核心数据结构, 表示路径中的一个组成部分 | `struct dentry` |
| **d_name** | dentry 中的文件名 (不含路径) | `BPF_CORE_READ(de, d_name.name)` |
| **d_parent** | 指向父目录的 dentry, 根目录指向自身 | `get_parent_dentry()` |
| **vfsmount** | 表示一个挂载实例, 包含挂载根和标志 | `struct vfsmount` |
| **mount** | 完整挂载结构, 包含 vfsmount + 父挂载信息 | `struct mount` |
| **mnt_root** | 挂载的根 dentry (此文件系统的根) | `BPF_CORE_READ(mnt, mnt_root)` |
| **mnt_mountpoint** | 挂载点在父文件系统中的 dentry | `BPF_CORE_READ(mnt_p, mnt_mountpoint)` |
| **mnt_parent** | 父挂载结构, 全局根指向自身 | `BPF_CORE_READ(mnt_p, mnt_parent)` |
| **container_of** | 从结构体成员指针获取结构体指针 | `container_of(mnt, struct mount, mnt)` |
| **per-CPU map** | 每 CPU 独立的 map, 避免并发冲突 | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| **右到左构建** | 从缓冲区末尾开始写入, 避免 memmove | `prepend_path()` |
| **swap 缓冲区** | 临时存放文件名 + 分隔符的区域 | `pb->swap[3] = '/'` |
| **PATH_BUF_MASK** | 位与掩码, 确保索引不越界 | `& PATH_BUF_MASK` |
| **CO-RE** | Compile Once Run Everywhere, BTF 重定位 | `BPF_CORE_READ` |
| **__noinline** | 阻止内联, 减小程序体积 | 所有核心函数 |
| **有界循环** | 循环必须有编译时已知的上界 | `MAX_PATH_DEPTH = 16` |
| **LSM hook** | Linux Security Module 钩子 | `security_inode_create` |
| **raw_tracepoint** | 原始跟踪点, 比 tracepoint 性能更好 | `sched_process_exec` |

---

## 10. 进阶方向

### 10.1 overlayfs 双层 dentry

容器环境 (Docker/Kubernetes) 广泛使用 overlayfs。overlayfs 有两层 dentry：

```
overlay 层:
  upper (可写层): /var/lib/docker/overlay2/xxx/diff/
  lower (只读层): /var/lib/docker/overlay2/yyy/diff/

问题:
  从 overlay dentry 看到的路径是 overlay 内部路径
  需要额外处理才能得到宿主机上的真实路径

Elkeid 的处理:
  检查 dentry->d_sb->s_type->name == "overlay"
  然后获取 upper/lower 的真实 dentry
```

### 10.2 /proc/self/exe 符号链接解析

`/proc/self/exe` 是一个特殊的符号链接，指向当前进程的可执行文件。但在 eBPF 中不能使用 `readlink`：

```
替代方案 (Elkeid 的做法):
  task->mm->exe_file->f_path.dentry
  直接从内核数据结构获取，不经过 /proc
```

### 10.3 长路径截断处理

当路径深度超过 `MAX_PATH_DEPTH = 16` 时，路径会被截断：

```
实际路径: /a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t.txt
截断后:   /e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t.txt (只有最后 16 层)
缺失:     /a/b/c/d/ 部分丢失

改进方案:
  1. 增大 MAX_PATH_DEPTH (会增加指令数)
  2. 在路径前添加 "..." 标记截断
  3. 使用 tail call 突破指令限制
  4. 分两次遍历: 先计数, 再构建
```

### 10.4 性能优化: 缓存常见路径前缀

频繁访问的路径前缀 (如 `/usr/bin/`, `/lib/x86_64-linux-gnu/`) 可以缓存：

```c
// 路径前缀缓存 (LRU hash map)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);       // dentry 地址
    __type(value, struct cached_path);
} path_cache SEC(".maps");

// 查找缓存:
//   如果某个中间 dentry 已经在缓存中,
//   直接拼接缓存的前缀 + 剩余的后缀
//   减少 dentry 遍历次数
```

### 10.5 与 bpf_d_path() helper 的对比

Linux 5.9+ 引入了 `bpf_d_path()` BPF helper：

```
优势:
  - 调用简单, 一个函数搞定
  - 内核实现, 性能最优
  - 处理所有边界情况

限制:
  - 只在特定 BPF 程序类型中可用 (fentry/fexit/LSM)
  - 不能在 kprobe/tracepoint 中使用
  - 需要内核 5.9+

Elkeid 选择手动实现的原因:
  1. 需要支持旧内核 (4.18+)
  2. 需要在 kprobe 中使用
  3. 需要更灵活的控制 (如自定义缓冲区)
```

### 10.6 相关学习资源

- Linux VFS 源码: `fs/dcache.c` (dentry 缓存)
- Linux 挂载系统: `fs/mount.h`, `fs/namespace.c`
- 内核 d_path 实现: `fs/d_path.c`
- BPF helper 文档: `include/uapi/linux/bpf.h`
- Elkeid 源码: `driver/BPF/hids.c`

---

## 总结

反向 dentry 路径构建是 eBPF 安全监控的核心技术之一。通过学习 Elkeid 的实现，我们掌握了：

1. **右到左缓冲区填充**: 避免 memmove，O(n) 复杂度一次完成
2. **swap 缓冲区技巧**: 将 '/' 和文件名合并为一次写入操作
3. **per-CPU 缓冲区**: 突破 BPF 512 字节栈限制
4. **挂载点穿越**: 正确处理跨文件系统边界的路径
5. **位与掩码**: 满足 BPF 验证器的边界检查要求
6. **条件循环展开**: 兼容不同内核版本的验证器

这些技巧不仅适用于路径构建，也是 eBPF 程序开发中处理变长数据、遍历内核数据结构的通用模式。
