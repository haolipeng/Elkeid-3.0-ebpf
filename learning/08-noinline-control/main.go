// 技术点 8: __noinline vs __always_inline - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (inline_control.bpf.o)
//   2. 附加到两个 raw_tracepoint: sched_process_exec 和 sched_process_exit
//   3. 通过 perf event 读取内核态发送的事件
//   4. 显示��件类型 (EXEC/EXIT)、进程信息、栈隔离计算结果
//   5. 退出时打印各函数的调用计数，验证 __noinline 共享和 __always_inline 展开
//
// 关键学习点:
//   - read_process_info 的调用次数 = exec 次数 + exit 次数 (共享函数)
//   - serialize_event 的调用次数 = exec 次数 + exit 次数 (虽然内联，逻辑上等价)
//   - stack_heavy_func_a/b 只在 exec 事件中调用
//
// 对应 Elkeid 用户态:
//   - ebpf/consume.c 中的 perf buffer 消费逻辑

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// OutputEvent 与内核态 struct output_event 完全对应
//
// 内存布局对照:
//
//   C 结构体:                       Go 结构体:
//   u32  event_type;    (4B)  →    EventType   uint32
//   u32  pid;           (4B)  →    Pid         uint32
//   u32  tid;           (4B)  →    Tid         uint32
//   u32  ppid;          (4B)  →    Ppid        uint32
//   u32  uid;           (4B)  →    Uid         uint32
//   u32  exit_code;     (4B)  →    ExitCode    uint32
//   u64  timestamp;     (8B)  →    Timestamp   uint64
//   char comm[16];      (16B) →    Comm        [16]byte
//   u32  stack_a_sum;   (4B)  →    StackASum   uint32
//   u32  stack_b_sum;   (4B)  →    StackBSum   uint32
//   u32  _pad;          (4B)  →    Pad         uint32
//
// 总计: 4*6 + 8 + 16 + 4*3 = 60 字节
type OutputEvent struct {
	EventType uint32
	Pid       uint32
	Tid       uint32
	Ppid      uint32
	Uid       uint32
	ExitCode  uint32
	Timestamp uint64
	Comm      [16]byte
	StackASum uint32
	StackBSum uint32
	Pad       uint32
}

// 计数器索引，与内核态 CNT_* 常量一一对应
const (
	cntReadProcessInfo = 0 // __noinline 共享函数
	cntSerializeEvent  = 1 // __always_inline 函数
	cntStackFuncA      = 2 // 栈隔离函数 A
	cntStackFuncB      = 3 // 栈隔离函数 B
	cntHookExec        = 4 // exec hook
	cntHookExit        = 5 // exit hook
	cntMax             = 6
)

// 计数器名称，用于友好输出
var counterNames = [cntMax]string{
	"read_process_info (__noinline 共享函数)",
	"serialize_event   (__always_inline 函数)",
	"stack_heavy_func_a (__noinline 栈隔离A)",
	"stack_heavy_func_b (__noinline 栈隔离B)",
	"tp_exec hook      (exec 入口)",
	"tp_exit hook      (exit 入口)",
}

func main() {
	// ============================================================
	// 步骤 1: 加载 eBPF ELF 文件
	// ============================================================
	//
	// 解析 .o 文件中的 map 和 program 定义:
	//   - events (PERF_EVENT_ARRAY)
	//   - call_counts (PERCPU_ARRAY, max_entries=6)
	//   - tp_exec, tp_exit (raw_tracepoint 程序)
	//
	// 加载时验证器会检查:
	//   - 每个函数栈帧 <= 512 字节 (__noinline 函数独立检查)
	//   - BPF-to-BPF 调用的参数数量 <= 5
	//   - 调用深度 <= 8
	spec, err := ebpf.LoadCollectionSpec("inline_control.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF collection 失败: %v\n"+
			"提示: 确保以 root 运行，且内核版本 >= 5.4\n"+
			"如果报 'too many args'，可能是 __noinline 函数参数超过 5 个", err)
	}
	defer coll.Close()

	// ============================================================
	// 步骤 2: 附加两个 raw_tracepoint
	// ============================================================
	//
	// 两个 hook 共享同一个 __noinline 的 read_process_info 函数，
	// 这是本 demo 演示的核心: 代码复用而非重复内联。

	// 附加 exec hook
	tpExec, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: coll.Programs["tp_exec"],
	})
	if err != nil {
		log.Fatalf("附加 exec tracepoint 失败: %v", err)
	}
	defer tpExec.Close()

	// 附加 exit hook
	tpExit, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exit",
		Program: coll.Programs["tp_exit"],
	})
	if err != nil {
		log.Fatalf("附加 exit tracepoint 失败: %v", err)
	}
	defer tpExit.Close()

	// ============================================================
	// 步骤 3: 创建 perf event reader
	// ============================================================
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*16)
	if err != nil {
		log.Fatalf("创建 perf reader 失败: %v", err)
	}
	defer rd.Close()

	// ============================================================
	// 步骤 4: 信号处理 - 优雅退出
	// ============================================================
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n收到退出信号，正在清理...")
		rd.Close()
	}()

	// ============================================================
	// 步骤 5: 事件循环
	// ============================================================
	fmt.Println("监控 __noinline/__always_inline 控制... 按 Ctrl+C 停止")
	fmt.Println()
	fmt.Println("说明:")
	fmt.Println("  EXEC 事件: read_process_info + stack_func_a/b + serialize_event")
	fmt.Println("  EXIT 事件: read_process_info + serialize_event")
	fmt.Println("  read_process_info 是 __noinline 共享函数，两种事件复用同一份代码")
	fmt.Println()
	fmt.Printf("%-6s %-8s %-8s %-8s %-6s %-16s %-10s %-10s %s\n",
		"TYPE", "PID", "TID", "PPID", "UID", "COMM", "STACK_A", "STACK_B", "EXIT_CODE")
	fmt.Println("------ -------- -------- -------- ------ ---------------- ---------- ---------- ---------")

	lostTotal := uint64(0)
	totalExec := 0
	totalExit := 0

	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}

		if rec.LostSamples > 0 {
			lostTotal += rec.LostSamples
			fmt.Printf("  [警告] 丢失 %d 个事件 (累计 %d)\n",
				rec.LostSamples, lostTotal)
			continue
		}

		var e OutputEvent
		if err := binary.Read(
			bytes.NewReader(rec.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			fmt.Printf("  [错误] 解析事件失败: %v\n", err)
			continue
		}

		comm := cStr(e.Comm[:])

		// 区分事件类型
		eventStr := "?"
		switch e.EventType {
		case 1:
			eventStr = "EXEC"
			totalExec++
		case 2:
			eventStr = "EXIT"
			totalExit++
		}

		// 栈隔离结果: 仅 EXEC 事件有效
		stackA := "-"
		stackB := "-"
		exitCode := "-"
		if e.EventType == 1 {
			stackA = fmt.Sprintf("0x%08X", e.StackASum)
			stackB = fmt.Sprintf("0x%08X", e.StackBSum)
		}
		if e.EventType == 2 {
			exitCode = fmt.Sprintf("%d", e.ExitCode)
		}

		fmt.Printf("%-6s %-8d %-8d %-8d %-6d %-16s %-10s %-10s %s\n",
			eventStr, e.Pid, e.Tid, e.Ppid, e.Uid,
			comm, stackA, stackB, exitCode)
	}

	// ============================================================
	// 步骤 6: 打印函数调用计数
	// ============================================================
	//
	// 从 PERCPU_ARRAY 读取计数器，对所有 CPU 的值求和。
	// 预期结果:
	//   read_process_info = exec + exit (被两个 hook 共享调用)
	//   serialize_event   = exec + exit (虽然内联，但逻辑上各调用一次)
	//   stack_func_a      = exec       (只在 exec 中调用)
	//   stack_func_b      = exec       (只在 exec 中调用)
	//   hook_exec         = exec
	//   hook_exit         = exit
	fmt.Println()
	fmt.Println("=== 函数调用计数 (所有 CPU 合计) ===")
	fmt.Println()

	callCounts := coll.Maps["call_counts"]
	if callCounts != nil {
		for i := uint32(0); i < cntMax; i++ {
			var values []uint64
			if err := callCounts.Lookup(i, &values); err != nil {
				fmt.Printf("  [%d] %s: 读取失败 (%v)\n", i, counterNames[i], err)
				continue
			}
			// 对所有 CPU 的值求和
			total := uint64(0)
			for _, v := range values {
				total += v
			}
			fmt.Printf("  [%d] %s: %d\n", i, counterNames[i], total)
		}
	}

	fmt.Println()
	fmt.Printf("事件统计: EXEC=%d, EXIT=%d\n", totalExec, totalExit)
	if lostTotal > 0 {
		fmt.Printf("丢失事件: %d\n", lostTotal)
	}

	fmt.Println()
	fmt.Println("验证要点:")
	fmt.Println("  1. read_process_info 调用次数 = EXEC + EXIT → 证明 __noinline 共享生效")
	fmt.Println("  2. stack_func_a/b 调用次数 = EXEC → 只在 exec hook 中调用")
	fmt.Println("  3. 程序能正常加载 → serialize_event 的 10 参数通过 __always_inline 解决")
	fmt.Println()
	fmt.Println("程序退出")
}

// cStr 从 C 风格字节数组中提取 Go 字符串
func cStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
