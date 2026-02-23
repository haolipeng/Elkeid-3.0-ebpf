// SPDX-License-Identifier: GPL-2.0
//
// 技术点 10: 反向 dentry 路径构建 —— 从 Elkeid HIDS 学习 VFS 路径解析
//
// 核心技术:
//   - 反向遍历 dentry 链 (从叶到根)
//   - 右到左缓冲区填充 (避免 memmove)
//   - swap 缓冲区技巧 (offset [3] 放 '/', [4] 放名���)
//   - 挂载点穿越 (mnt_root → mnt_mountpoint → mnt_parent)
//   - 条件 #pragma unroll 兼容旧内核
//
// 对应 Elkeid 源码:
//   - hids.c:1111-1123  (prepend_path: 右到左写入)
//   - hids.c:1125-1144  (prepend_entry: dentry 名提取)
//   - hids.c:1146-1152  (d_parent: 父 dentry 获取)
//   - hids.c:1160-1204  (d_path: 完整路径 + 挂载穿越)
//   - hids.c:1207-1225  (dentry_path: 简单 dentry 遍历)
//   - hids.c:3226-3264  (kp__inode_create 使用 dentry_path)
//
// 编译:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//     -I../../src/vmlinux/x86 -c dentry_path.bpf.c -o dentry_path.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// ============================================================================
// 常量定义
// ============================================================================

// 路径缓冲区大小 (1024 字节，与 Elkeid SD_STR_MAX 对应)
// 使用 2 的幂次方，方便位运算取模
#define PATH_BUF_SIZE   1024
#define PATH_BUF_MASK   1023    // PATH_BUF_SIZE - 1, 用于 & 运算保证索引不越界

// 单个文件名最大长度 (Linux NAME_MAX = 255, +1 for null)
// 对应 Elkeid PATH_NAME_LEN=256, PATH_NAME_MASK=255
#define PATH_NAME_LEN   256
#define PATH_NAME_MASK  255

// 最大路径深度 (最多遍历 16 层 dentry)
// 对应 Elkeid MAX_PATH_ENTS=16
// 这个限制是 BPF 验证器要求的 —— 循环必须有上界
#define MAX_PATH_DEPTH  16

// swap 缓冲区大小: 4 字节前缀 + NAME_MAX + 1 (null terminator)
// [0-2] 未使用, [3] = '/', [4...259] = 文件名
#define SWAP_BUF_SIZE   260

// 事件类型
#define EVENT_CREATE    1       // 文件创建 (security_inode_create)
#define EVENT_EXEC      2       // 进程执行 (sched_process_exec)

// ============================================================================
// 条件展开宏 —— 与模块 09 相同的兼容性技巧
// ============================================================================
//
// 旧版内核 (< 5.3) 的 BPF 验证器不支持有界循环,
// 必须使用 #pragma unroll 将循环完全展开。
// 新版内核则支持有界循环，不需要展开。
//
// LOOPS_UNROLL 通过编译选项 -DLOOPS_UNROLL 控制:
//   旧内核: clang -DLOOPS_UNROLL ...  → 展开循环
//   新内核: 不加此选项             → 使用有界循环

// ============================================================================
// 数据结构
// ============================================================================

// 路径构建缓冲区 (存放在 per-CPU map 中，避免栈溢出)
//
// 为什么不用栈?
//   BPF 栈限制 512 字节, 而我们需要 1024 + 260 = 1284 字节
//   所以必须使用 map 作为 "堆" 内存
//
// 缓冲区布局 (右到左填充):
//   buf[0 ... PATH_BUF_SIZE-1]:
//     [    未使用空间    |/usr/bin/ls\0        ]
//                        ^                     ^
//                     start                 end (null)
//                  (BUF_SIZE - len)
//
// swap 缓冲区布局:
//   swap[0..2]: 未使用
//   swap[3]:    '/' (路径分隔符)
//   swap[4..259]: 文件名 (bpf_probe_read_str 写入)
struct path_buffer {
    char buf[PATH_BUF_SIZE];    // 主路径缓冲区 (右到左填充)
    char swap[SWAP_BUF_SIZE];   // swap 缓冲区 (读取 dentry 名用)
};

// 上报到用户态的事件结构
struct event {
    __u32 pid;                  // 进程 ID
    __u32 ppid;                 // 父进程 ID
    __u32 event_type;           // 事件类型: EVENT_CREATE 或 EVENT_EXEC
    __u32 path_len;             // 路径长度
    __u32 depth;                // 路径深度 (遍历了多少层 dentry)
    __u32 _pad;                 // 填充对齐到 8 字节边界
    char  comm[16];             // 进程名
    char  path[PATH_NAME_LEN];  // 路径 (截断到 256 字节)
};

// ============================================================================
// BPF Maps
// ============================================================================

// per-CPU 路径缓冲区 map
// 每个 CPU 有独立的缓冲区, 避免并发冲突
// key = 0 (只有一个条目), value = struct path_buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buffer);
} path_buf SEC(".maps");

// perf event 输出 map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// ============================================================================
// 辅助函数: 获取 per-CPU 缓冲区
// ============================================================================

// 从 per-CPU map 获取路径缓冲区
// 返回 NULL 表示获取失败 (不应发生)
static __always_inline struct path_buffer *get_path_buffer(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&path_buf, &zero);
}

// ============================================================================
// 核心函数 1: prepend_path() —— 右到左写入
// ============================================================================
//
// 对应 Elkeid hids.c:1111-1123
//
// 功能: 将 src 的 num 个字节写入缓冲区的右侧
//
// 右到左写入原理:
//   传统的从左到右构建路径需要在头部插入字符串，
//   每次插入都要 memmove 移动已有内容，O(n^2) 复杂度。
//
//   右到左则从缓冲区末尾开始写入:
//     1. 先写入叶节点名 (如 "ls")
//     2. 再写入父目录名 (如 "/bin")
//     3. 以此类推直到根 (如 "/usr")
//
//   只需要维护一个 len 变量，追踪已使用的字节数。
//   写入位置 = PATH_BUF_SIZE - len - num
//   最终路径从 &buf[PATH_BUF_SIZE - len] 开始。
//
// 参数:
//   pb   - 路径缓冲区指针
//   len  - 指向已使用长度的指针 (输入输出参数)
//   src  - 源字符串
//   num  - 要写入的字节数
//
// 返回值: 0 成功, -1 失败 (缓冲区溢出)
//
// 关键: & PATH_BUF_MASK 保证索引不越界
//   即使计算出的 pos 为负数或超大值，
//   位与运算后总是 [0, 1023] 范围内
static __noinline int prepend_path(struct path_buffer *pb,
                                   int *len, const char *src, int num)
{
    // 检查缓冲区是否有足够空间
    // 如果已用长度 + 新数据长度 > 缓冲区大小，则溢出
    if (*len + num > PATH_BUF_SIZE)
        return -1;

    // 计算写入起始位置
    // 公式: pos = PATH_BUF_SIZE - 当前已用长度 - 新数据长度
    //
    // 示例: buf_size=1024, len=3 ("ls\0"), num=4 ("/bin")
    //   pos = 1024 - 3 - 4 = 1017
    //   写入 "/bin" 到 buf[1017..1020]
    //   更新 len = 7
    //
    // & PATH_BUF_MASK: 位运算确保索引在 [0, 1023] 范围内
    // 这是 BPF 验证器要求的 —— 所有内存访问必须证明不越界
    int pos = (PATH_BUF_SIZE - *len - num) & PATH_BUF_MASK;

    // 使用 bpf_probe_read_kernel 写入数据
    // 虽然 src 已经在内核空间，但 BPF 不能直接 memcpy
    // 必须通过 helper 函数来访问内存
    int ret = bpf_probe_read_kernel(&pb->buf[pos], num & PATH_BUF_MASK, src);
    if (ret < 0)
        return -1;

    // 更新已使用长度
    *len += num;
    return 0;
}

// ============================================================================
// 核心函数 2: prepend_entry() —— dentry 名提取
// ============================================================================
//
// 对应 Elkeid hids.c:1125-1144
//
// 功能: 从 dentry 中提取文件名，写入路径缓冲区
//
// swap 缓冲区技巧:
//   直接从 dentry->d_name.name 读取文件名存在问题:
//     - 不知道文件名长度 (需要 bpf_probe_read_str 返回)
//     - 还需要在名字前面加 '/' 分隔符
//
//   Elkeid 的巧妙解决方案:
//     1. 在 swap[3] 预置 '/' 字符
//     2. 在 swap[4] 开始写入文件名 (bpf_probe_read_str)
//     3. 然后从 swap[3] 开始 prepend (包含 '/' + 名字)
//
//   这样只需要一次 prepend_path 调用就同时写入 '/' 和名字
//
// 参数:
//   pb    - 路径缓冲区
//   len   - 已使用长度指针
//   de    - dentry 指针
//
// 返回值: 0 成功, 负值失败
static __noinline int prepend_entry(struct path_buffer *pb,
                                    int *len, struct dentry *de)
{
    // 步骤 1: 在 swap[3] 放置 '/' 分隔符
    // swap 缓冲区布局:
    //   [0] [1] [2] [3]  [4] [5] [6] ... [259]
    //                '/'  'l' 's' '\0'
    //                 ^    ^
    //                 |    bpf_probe_read_str 写入位置
    //                 prepend 时从这里开始
    pb->swap[3] = '/';

    // 步骤 2: 读取 dentry 文件名到 swap[4]
    // BPF_CORE_READ 处理内核版本差异:
    //   de->d_name.name 是一个 const char* 指针
    //   不同内核版本中 d_name 的偏移可能不同
    //   CO-RE (Compile Once, Run Everywhere) 在加载时重定位
    const unsigned char *name = BPF_CORE_READ(de, d_name.name);

    // bpf_probe_read_str: 读取以 null 结尾的字符串
    // 返回值: 读取的字节数 (包含 null terminator)
    // 写入位置: swap[4] 开始
    // 最大长度: PATH_NAME_LEN (256)
    int str_len = bpf_probe_read_kernel_str(&pb->swap[4],
                                            PATH_NAME_LEN, name);
    if (str_len <= 0)
        return -1;

    // 步骤 3: 计算要 prepend 的总长度
    // total = 1 (斜杠 '/') + str_len - 1 (不包含 null terminator)
    // 因为 bpf_probe_read_str 返回值包含 '\0'，但我们不需要它
    // (下一次 prepend 会覆盖它，或者最后会手动加 '\0')
    //
    // 但第一次调用 (叶节点) 时需要包含 '\0'
    // 所以 Elkeid 的做法是: 第一次调用时 len 从 0 开始，
    // 最终路径的 '\0' 已经在 buf 中了
    int total = str_len;    // str_len 包含 null, +1 for '/', -1 for null = str_len

    // 步骤 4: 将 "/" + 名字 写入主缓冲区
    // 从 swap[3] 开始, 长度为 total (包含 '/' 和名字，不含 null)
    return prepend_path(pb, len, &pb->swap[3], total);
}

// ============================================================================
// 核心函数 3: get_parent_dentry() —— 获取父 dentry
// ============================================================================
//
// 对应 Elkeid hids.c:1146-1152
//
// 功能: 获取 dentry 的父节点，检测根节点
//
// Linux VFS 的 dentry 树:
//   每个目录/文件都有一个 dentry 结构
//   dentry->d_parent 指向父目录的 dentry
//   根目录特殊: d_parent 指向自身 (self-referencing)
//
// 检测根节点:
//   if (dentry == dentry->d_parent) → 这是根目录
//   返回 NULL 表示到达根，停止遍历
//
// 参数:
//   de - 当前 dentry
//
// 返回值:
//   父 dentry 指针, 或 NULL (到达根)
static __noinline struct dentry *get_parent_dentry(struct dentry *de)
{
    // 读取父 dentry 指针
    // 使用 BPF_CORE_READ 确保 CO-RE 兼容
    struct dentry *parent = BPF_CORE_READ(de, d_parent);

    // 根节点检测: dentry == d_parent 表示到达文件系统根
    // 这是 VFS 的约定: 根目录的 d_parent 指向自身
    if (de == parent)
        return NULL;

    return parent;
}

// ============================================================================
// 核心函数 4: build_dentry_path() —— 简单 dentry 路径构建
// ============================================================================
//
// 对应 Elkeid hids.c:1207-1225 (dentry_path)
//
// 功能: 从给定 dentry 开始，反向遍历到根，构建路径字符串
//
// 这是最简单的路径构建方式:
//   - 不处理挂载点穿越
//   - 只在单个文件系统内遍历
//   - 适合获取相对于挂载点的路径
//
// 遍历过程 (以 /usr/bin/ls 为例):
//   迭代 1: dentry="ls"    → 写入 "/ls\0"    → len=4
//   迭代 2: dentry="bin"   → 写入 "/bin"     → len=8
//   迭代 3: dentry="usr"   → 写入 "/usr"     → len=12
//   迭代 4: dentry="/"     → d_parent==self  → 停止
//
// 最终: buf[1024-12] = "/usr/bin/ls\0"
//
// 参数:
//   pb    - 路径缓冲区 (per-CPU)
//   de    - 起始 dentry (叶节点)
//   depth - 输出: 遍历深度
//
// 返回值: 路径在缓冲区中的起始位置, 负值表示失败
static __noinline int build_dentry_path(struct path_buffer *pb,
                                        struct dentry *de,
                                        __u32 *depth)
{
    // len: 追踪从右到左已使用的字节数
    // 初始为 0, 每次 prepend 后增加
    int len = 0;
    *depth = 0;

    // 首先写入一个 null terminator 到缓冲区最末尾
    // 这是整个路径字符串的结束标志
    // 位置: buf[PATH_BUF_SIZE - 1] = buf[1023] = '\0'
    pb->buf[PATH_BUF_SIZE - 1] = '\0';
    len = 1;    // null terminator 占 1 字节

    // 检查 dentry 有效性
    if (!de)
        return -1;

    // 循环遍历 dentry 链，从叶到根
    // 最多 MAX_PATH_DEPTH (16) 次迭代
    //
    // 条件展开:
    //   旧内核 (< 5.3): #pragma unroll 强制展开 16 次
    //   新内核 (>= 5.3): 验证器支持有界循环, 不需要展开
#ifdef LOOPS_UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        // 将当前 dentry 的名字 prepend 到缓冲区
        // prepend_entry 会在名字前加 '/'
        int ret = prepend_entry(pb, &len, de);
        if (ret < 0)
            break;

        // 更新深度计数器
        (*depth)++;

        // 获取父 dentry
        // 返回 NULL 表示到达根节点, 停止遍历
        de = get_parent_dentry(de);
        if (!de)
            break;
    }

    // 计算路径在缓冲区中的起始位置
    // pos = PATH_BUF_SIZE - len
    // & PATH_BUF_MASK 确保索引合法 (BPF 验证器要求)
    //
    // 此时 buf[pos..PATH_BUF_SIZE-1] = "/usr/bin/ls\0"
    int pos = (PATH_BUF_SIZE - len) & PATH_BUF_MASK;
    return pos;
}

// ============================================================================
// 核心函数 5: build_full_path() —— 完整路径 (含挂载穿越)
// ============================================================================
//
// 对应 Elkeid hids.c:1160-1204 (d_path)
//
// 功能: 构建完整的绝对路径，处理挂载边界
//
// 为什么需要挂载穿越?
//   Linux 文件系统是由多个挂载点组成的树:
//     /          (rootfs)
//     /mnt/data  (ext4 分区)
//     /proc      (procfs)
//
//   如果文件是 /mnt/data/file.txt:
//     1. 在 ext4 分区内, dentry 链是: file.txt → data (根)
//     2. data 的 dentry == vfsmount.mnt_root → 到达挂载点
//     3. 需要穿越到父挂载: vfsmount.mnt_mountpoint → data
//     4. 继续在 rootfs 中遍历: data → mnt → / (全局根)
//
// 三个终止条件:
//   1. dentry == d_parent: 到达文件系统根
//   2. dentry == mnt_root && mount == mnt_parent: 到达全局根
//   3. dentry == mnt_root && mount != mnt_parent: 穿越挂载边界
//
// 参数:
//   pb     - 路径缓冲区
//   de     - 起始 dentry
//   mnt    - 起始 vfsmount (从 f_path.mnt 获取)
//   depth  - 输出: 遍历深度
//
// 返回值: 路径在缓冲区中的起始位置, 负值表示失败
static __noinline int build_full_path(struct path_buffer *pb,
                                      struct dentry *de,
                                      struct vfsmount *mnt,
                                      __u32 *depth)
{
    int len = 0;
    *depth = 0;

    // 写入 null terminator
    pb->buf[PATH_BUF_SIZE - 1] = '\0';
    len = 1;

    if (!de || !mnt)
        return -1;

    // 获取 mount 结构体 (vfsmount 是 mount 的子结构)
    // 在内核中: struct mount { ...; struct vfsmount mnt; ...; }
    // 通过 container_of 可以从 vfsmount 得到 mount
    // 但在 BPF 中，我们直接读取 mount 的字段
    //
    // 注意: vfsmount 嵌入在 mount 结构体中
    // 我们需要通过 real_mount (container_of) 获取 mount
    // 在 CO-RE 中，我们利用 BTF 直接访问

    // 获取挂载根 dentry (当前文件系统的根)
    struct dentry *mnt_root = BPF_CORE_READ(mnt, mnt_root);

    // 使用 container_of 从 vfsmount 获取 mount 结构体
    // struct mount 包含 mnt_parent, mnt_mountpoint 等字段
    // vfsmount 是 mount 的一个成员
    struct mount *mnt_p = container_of(mnt, struct mount, mnt);
    struct mount *mnt_parent = BPF_CORE_READ(mnt_p, mnt_parent);

    // 主循环: 反向遍历 dentry + mount 链
#ifdef LOOPS_UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        // 获取父 dentry
        struct dentry *parent = BPF_CORE_READ(de, d_parent);

        // 判断是否到达当前文件系统的根
        if (de == mnt_root || de == parent) {

            // 情况 1: 到达全局根
            // mount == mnt_parent 说明这是最顶层的挂载
            // (根文件系统的 mnt_parent 指向自身)
            if (mnt_p == mnt_parent)
                break;

            // 情况 2: 到达挂载点，需要穿越到父挂载
            //
            // 穿越步骤:
            //   a. 将 dentry 切换到挂载点: mnt_mountpoint
            //      (这是父文件系统中对应的 dentry)
            //   b. 将 mount 切换到父挂载: mnt_parent
            //   c. 更新 mnt_root 和 mnt_parent 为新挂载的值
            //   d. 继续遍历
            //
            // 示例: /mnt/data/file.txt
            //   当前: dentry=data (ext4 根), mount=ext4_mount
            //   穿越后: dentry=data (rootfs 中), mount=rootfs_mount
            if (de == mnt_root) {
                de = BPF_CORE_READ(mnt_p, mnt_mountpoint);
                mnt_p = mnt_parent;

                // 更新新挂载的 mnt_root 和 mnt_parent
                mnt = &mnt_p->mnt;
                mnt_root = BPF_CORE_READ(mnt, mnt_root);
                mnt_parent = BPF_CORE_READ(mnt_p, mnt_parent);
                continue;
            }

            // de == parent 但 de != mnt_root:
            // 到达了不是挂载根的文件系统根 (异常情况)
            break;
        }

        // 正常情况: 还没到达文件系统根
        // 将当前 dentry 名字 prepend 到缓冲区
        int ret = prepend_entry(pb, &len, de);
        if (ret < 0)
            break;

        (*depth)++;

        // 移动到父 dentry, 继续遍历
        de = parent;
    }

    // 如果缓冲区还是空的 (只有 null terminator)
    // 说明路径就是根 "/"，写入一个 '/'
    if (len <= 1) {
        int pos = (PATH_BUF_SIZE - 2) & PATH_BUF_MASK;
        pb->buf[pos] = '/';
        len = 2;
    }

    return (PATH_BUF_SIZE - len) & PATH_BUF_MASK;
}

// ============================================================================
// 辅助函数: 填充事件公共字段
// ============================================================================
static __always_inline void fill_event_common(struct event *e, __u32 event_type)
{
    // 获取当前 task_struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 填充进程信息
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->event_type = event_type;
    e->_pad = 0;

    // 获取进程名
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// ============================================================================
// Hook 点 1: kprobe/security_inode_create
// ============================================================================
//
// 对应 Elkeid hids.c:3226-3264 (kp__inode_create)
//
// security_inode_create 原型:
//   int security_inode_create(struct inode *dir, struct dentry *dentry,
//                             umode_t mode)
//
// 这是 LSM hook, 在创建新 inode 时调用
// 我们从第 2 个参数 (dentry) 获取新创建文件的路径
//
// 注意: 此时 dentry 尚未关联到 inode (文件还没真正创建)
// 但 dentry->d_parent 链已经建好了, 所以可以构建路径
SEC("kprobe/security_inode_create")
int BPF_KPROBE(kp_security_inode_create,
               struct inode *dir, struct dentry *dentry, umode_t mode)
{
    // 获取 per-CPU 路径缓冲区
    struct path_buffer *pb = get_path_buffer();
    if (!pb)
        return 0;

    // 构建 dentry 路径 (不含挂载穿越)
    // 对于文件创建场景, 简单的 dentry 路径通常就够了
    // 因为我们只关心文件在当前文件系统中的位置
    __u32 depth = 0;
    int pos = build_dentry_path(pb, dentry, &depth);
    if (pos < 0)
        return 0;

    // 准备事件
    struct event e = {};
    fill_event_common(&e, EVENT_CREATE);
    e.depth = depth;

    // 复制路径到事件结构
    // 从 buf[pos] 开始, 最多复制 PATH_NAME_LEN 字节
    // & PATH_BUF_MASK 确保 pos 合法
    int path_len = PATH_BUF_SIZE - pos;
    if (path_len > PATH_NAME_LEN)
        path_len = PATH_NAME_LEN;
    if (path_len <= 0)
        return 0;

    e.path_len = path_len;
    bpf_probe_read_kernel(&e.path, path_len & PATH_NAME_MASK,
                          &pb->buf[pos & PATH_BUF_MASK]);

    // 发送事件到用户态
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));
    return 0;
}

// ============================================================================
// Hook 点 2: raw_tracepoint/sched_process_exec
// ============================================================================
//
// 对应 Elkeid hids.c:1243-1267 (d_tid_path)
//
// sched_process_exec 在进程 execve 成功后触发
// 我们通过 task->mm->exe_file->f_path 获取可执行文件路径
//
// 路径获取链:
//   current task
//     → mm (内存描述符)
//       → exe_file (可执行文件 struct file*)
//         → f_path.dentry (dentry)
//         → f_path.mnt    (vfsmount)
//
// 使用 build_full_path (含挂载穿越) 因为:
//   可执行文件可能在任何挂载点下
//   例如 /usr/bin/ls 可能在单独的 /usr 分区
SEC("raw_tracepoint/sched_process_exec")
int raw_tp_sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    // 获取 per-CPU 缓冲区
    struct path_buffer *pb = get_path_buffer();
    if (!pb)
        return 0;

    // 获取当前 task_struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    // 读取 exe_file 路径
    // task->mm->exe_file->f_path 包含 dentry 和 mnt
    //
    // 为什么用 BPF_CORE_READ?
    //   - task->mm 可能为 NULL (内核线程没有 mm)
    //   - 每次解引用都需要 CO-RE 重定位
    //   - BPF_CORE_READ 生成一系列 bpf_probe_read_kernel 调用
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;

    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return 0;

    // 从 f_path 获取 dentry 和 vfsmount
    struct dentry *de = BPF_CORE_READ(exe_file, f_path.dentry);
    struct vfsmount *mnt = BPF_CORE_READ(exe_file, f_path.mnt);
    if (!de || !mnt)
        return 0;

    // 构建完整路径 (含挂载穿越)
    __u32 depth = 0;
    int pos = build_full_path(pb, de, mnt, &depth);
    if (pos < 0)
        return 0;

    // 准备事件
    struct event e = {};
    fill_event_common(&e, EVENT_EXEC);
    e.depth = depth;

    // 复制路径
    int path_len = PATH_BUF_SIZE - pos;
    if (path_len > PATH_NAME_LEN)
        path_len = PATH_NAME_LEN;
    if (path_len <= 0)
        return 0;

    e.path_len = path_len;
    bpf_probe_read_kernel(&e.path, path_len & PATH_NAME_MASK,
                          &pb->buf[pos & PATH_BUF_MASK]);

    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &e, sizeof(e));
    return 0;
}

// ============================================================================
// License 声明
// ============================================================================
// BPF 程序必须声明 GPL 许可证
// 否则无法使用 bpf_probe_read_kernel 等 GPL-only helper
char LICENSE[] SEC("license") = "GPL";
