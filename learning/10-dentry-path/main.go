// 技术点 10: 反向 dentry 路径构建 - 用户态程序
//
// 功能:
//   1. 加载 eBPF 程序 (dentry_path.bpf.o)
//   2. 附加到 kprobe/security_inode_create 和 raw_tracepoint/sched_process_exec
//   3. 接收并展示文件创建和进程执行事件的路径信息
//
// 使用:
//   go run main.go
//   # 在另一个终端执行命令或创建文件触发事件
//
// 事件展示格式:
//   [CREATE] PID=1234 PPID=1000 COMM=touch DEPTH=3 PATH=/tmp/test.txt
//   [EXEC]   PID=5678 PPID=1234 COMM=ls    DEPTH=4 PATH=/usr/bin/ls

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// 路径名最大长度，与内核侧 PATH_NAME_LEN 对应
const pathNameLen = 256

// 事件类型常量，与内核侧 EVENT_CREATE/EVENT_EXEC 对应
const (
	eventCreate = 1 // 文件创建事件
	eventExec   = 2 // 进程执行事件
)

// Event 表示从内核上报的路径事件
// 字段布局必须与内核侧 struct event 完全一致
// 包括字段顺序、大小、对齐方式
type Event struct {
	PID       uint32             // 进程 ID (4 字节)
	PPID      uint32             // 父进程 ID (4 字节)
	EventType uint32             // 事件类型: 1=CREATE, 2=EXEC (4 字节)
	PathLen   uint32             // 路径长度 (4 字节)
	Depth     uint32             // 路径深度 (4 字节)
	Pad       uint32             // 填充对齐 (4 字节)
	Comm      [16]byte           // 进程名 (16 字节)
	Path      [pathNameLen]byte  // 路径字符串 (256 字节)
}

// eventTypeString 将事件类型转换为可读字符串
func eventTypeString(t uint32) string {
	switch t {
	case eventCreate:
		return "CREATE"
	case eventExec:
		return "EXEC"
	default:
		return "UNKNOWN"
	}
}

// nullTermStr 从字节数组中提取以 null 结尾的字符串
// 处理 C 字符串到 Go 字符串的转换
func nullTermStr(b []byte) string {
	// 查找第一个 null 字节
	idx := bytes.IndexByte(b, 0)
	if idx < 0 {
		return string(b)
	}
	return string(b[:idx])
}

// countDepth 统计路径中的深度（'/' 的个数）
// 这是对内核侧 depth 字段的补���验证
func countDepth(path string) int {
	return strings.Count(path, "/")
}

func main() {
	// ====================================================================
	// 步骤 1: 加载 eBPF 目标文件
	// ====================================================================
	//
	// dentry_path.bpf.o 是通过 clang 编译的 eBPF 字节码
	// cilium/ebpf 库会解析 ELF 文件, 提取:
	//   - BPF 程序 (kprobe, raw_tracepoint)
	//   - BPF Maps (path_buf, events)
	//   - BTF 信息 (用于 CO-RE 重定位)
	log.Println("加载 eBPF 程序: dentry_path.bpf.o")

	spec, err := ebpf.LoadCollectionSpec("dentry_path.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF 规格失败: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF 集合失败: %v", err)
	}
	defer coll.Close()

	log.Println("eBPF 程序加载成功")

	// ====================================================================
	// 步骤 2: 附加 kprobe 到 security_inode_create
	// ====================================================================
	//
	// security_inode_create 是 LSM (Linux Security Module) 钩子
	// 每当有新文件创建时被调用
	//
	// kprobe 类型: 在函数入口处插入断点
	// 可以通过 PT_REGS 访问函数参数
	log.Println("附加 kprobe 到 security_inode_create")

	kpCreate, err := link.Kprobe(
		"security_inode_create",
		coll.Programs["kp_security_inode_create"],
		nil,
	)
	if err != nil {
		log.Fatalf("附加 kprobe 失败: %v", err)
	}
	defer kpCreate.Close()

	log.Println("kprobe 附加成功")

	// ====================================================================
	// 步骤 3: 附加 raw_tracepoint 到 sched_process_exec
	// ====================================================================
	//
	// sched_process_exec 在进程执行 execve 系统调用后触发
	// raw_tracepoint 比 tracepoint 性能更好:
	//   - 不做参数序列化
	//   - 直接传递原始数据指针
	//   - 减少数据拷贝开销
	log.Println("附加 raw_tracepoint 到 sched_process_exec")

	tpExec, err := link.RawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: coll.Programs["raw_tp_sched_process_exec"],
	})
	if err != nil {
		log.Fatalf("附加 raw_tracepoint 失败: %v", err)
	}
	defer tpExec.Close()

	log.Println("raw_tracepoint 附加成功")

	// ====================================================================
	// 步骤 4: 创建 perf event reader
	// ====================================================================
	//
	// perf event 是内核到用户态的高性能数据通道
	// 每个 CPU 有独立的环形缓冲区
	// 用户态通过 epoll 监听数据到达
	log.Println("创建 perf event reader")

	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*16)
	if err != nil {
		log.Fatalf("创建 perf reader 失败: %v", err)
	}
	defer rd.Close()

	log.Println("perf event reader 创建成功")

	// ====================================================================
	// 步骤 5: 信号处理 (优雅退出)
	// ====================================================================
	//
	// 捕获 SIGINT (Ctrl+C) 和 SIGTERM
	// 收到信号时关闭 perf reader, 触发 Read() 返回错误, 退出循环
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		log.Println("\n收到退出信号, 正在清理...")
		rd.Close()
	}()

	// ====================================================================
	// 步骤 6: 事件处理主循环
	// ====================================================================

	// 打印表头
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("%-10s %-8s %-8s %-16s %-6s %s\n",
		"TYPE", "PID", "PPID", "COMM", "DEPTH", "PATH")
	fmt.Println(strings.Repeat("-", 100))

	// 统计计数器
	var createCount, execCount uint64

	for {
		// 阻塞读取下一个事件
		// 当 perf reader 被关闭时, 返回错误, 退出循环
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				break
			}
			log.Printf("读取 perf event 出错: %v", err)
			continue
		}

		// 跳过丢失的事件
		// 当内核产生事件的速度超过用户态消费速度时,
		// 环形缓冲区会溢出, 导致事件丢失
		if record.LostSamples > 0 {
			log.Printf("警告: 丢失 %d 个事件 (缓冲区溢出)", record.LostSamples)
			continue
		}

		// 解析事件数据
		var event Event
		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Printf("解析事件数据失败: %v", err)
			continue
		}

		// 提取字符串字段
		comm := nullTermStr(event.Comm[:])
		path := nullTermStr(event.Path[:])

		// 计算路径深度 (用户态验证)
		slashCount := countDepth(path)

		// 更新统计计数器
		typeStr := eventTypeString(event.EventType)
		switch event.EventType {
		case eventCreate:
			createCount++
		case eventExec:
			execCount++
		}

		// 格式化输出
		// [CREATE] 和 [EXEC] 使用不同的标签区分
		fmt.Printf("[%-6s]   %-8d %-8d %-16s %-6d %s",
			typeStr, event.PID, event.PPID, comm, event.Depth, path)

		// 如果内核深度和用户态计算不一致, 显示额外信息
		if int(event.Depth) != slashCount && slashCount > 0 {
			fmt.Printf("  (slashes=%d)", slashCount)
		}
		fmt.Println()
	}

	// ====================================================================
	// 步骤 7: 退出统计
	// ====================================================================
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("统计: CREATE=%d  EXEC=%d  TOTAL=%d\n",
		createCount, execCount, createCount+execCount)
	fmt.Println("程序已退出")
}
