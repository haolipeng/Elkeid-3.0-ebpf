// 技术点 6: 条件 #pragma unroll 循环展开 - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (loop_unroll.bpf.o)
//   2. 附加到 raw_tracepoint/sched_process_exec
//   3. 通过 perf event 读取三个循环 demo 的结果
//   4. 显示当前编译模式 (展开/有界) 及各 demo 输出
//   5. 对比展开模式与有界模式下的行为差异
//
// 关键学习点:
//   - loops_unroll 字段: 1=展开模式(旧内核), 0=有界模式(新内核)
//   - name_max_iter 字段: 展开模式 12 次 vs 有界模式 20 次
//   - array_sum 在两种模式下结果相同 (固定计算)
//   - name_len 在展开模式下可能更短 (迭代次数受限)
//   - found_idx 在两种模式下结果相同 (早期退出不受影响)
//
// 对应 Elkeid 用户态:
//   - ebpf/consume.c 中的 perf buffer 消费逻辑
//   - ebpf/hids/hids_bpf.h 中的 skeleton 加载逻辑

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

// LoopEvent 与内核态 struct loop_event 完全对应
//
// 内存布局对照:
//
//   C 结构体:                          Go 结构体:
//   __u32 pid;              (4B)  →   Pid          uint32
//   __u32 ppid;             (4B)  →   Ppid         uint32
//   char  comm[16];         (16B) →   Comm         [16]byte
//   __u32 array_sum;        (4B)  →   ArraySum     uint32    ← Demo 1 结果
//   __u32 name_len;         (4B)  →   NameLen      uint32    ← Demo 2 结果
//   __u32 found_idx;        (4B)  →   FoundIdx     uint32    ← Demo 3 结果
//   __u32 loops_unroll;     (4B)  →   LoopsUnroll  uint32    ← 编译模式
//   __u32 name_max_iter;    (4B)  →   NameMaxIter  uint32    ← 最大迭代次数
//   char  parsed_name[256]; (256B)→   ParsedName   [256]byte ← 解析后字符串
//
// 注意:
//   - LoopsUnroll=1 表示编译时使用了 -DFORCE_UNROLL=1 (模拟旧内核)
//   - LoopsUnroll=0 表示默认编译 (现代内核，验证器支持有界循环)
//   - NameMaxIter 在展开模式下为 12，有界模式下为 20
type LoopEvent struct {
	Pid         uint32
	Ppid        uint32
	Comm        [16]byte
	ArraySum    uint32
	NameLen     uint32
	FoundIdx    uint32
	LoopsUnroll uint32
	NameMaxIter uint32
	ParsedName  [256]byte
}

func main() {
	// ============================================================
	// 步骤 1: 加载 eBPF ELF 文件
	// ============================================================
	//
	// 加载 loop_unroll.bpf.o，其中包含:
	//   - g_percpu_buf (PERCPU_ARRAY, max_entries=1) ← 字符串处理缓冲区
	//   - events (PERF_EVENT_ARRAY) ← 事件输出通道
	//   - tp_exec (raw_tracepoint 程序) ← 入口函数
	//
	// 编译时可选择两种模式:
	//   默认模式:        clang -O2 ... -c loop_unroll.bpf.c
	//   强制展开模式:    clang -O2 -DFORCE_UNROLL=1 ... -c loop_unroll.bpf.c
	spec, err := ebpf.LoadCollectionSpec("loop_unroll.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	// NewCollection 加载程序到内核验证器
	//
	// 验证器行为在两种模式下不同:
	//   展开模式: 验��器看到的是展开后的顺序指令，没有后向跳转
	//   有界模式: 验证器分析循环变量范围，证明循环在有限步内终止
	//
	// 在旧内核 (<= 5.2) 上如果不使用展开模式，
	// 验证器会报 "back-edge from insn X to Y" 错误
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF collection 失败: %v\n"+
			"提示: 确保以 root 运行，且内核版本 >= 5.4\n"+
			"如果在旧内核上运行，请用 -DFORCE_UNROLL=1 重新编译", err)
	}
	defer coll.Close()

	// ============================================================
	// 步骤 2: 附加 raw_tracepoint
	// ============================================================
	//
	// 挂载到 sched_process_exec:
	// 每次 exec 时触发，运行三个循环 demo 并发送结果
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: coll.Programs["tp_exec"],
	})
	if err != nil {
		log.Fatalf("附加 tracepoint 失败: %v", err)
	}
	defer tp.Close()

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
	// 步骤 5: 事件循环 - ��取并展示循环 demo 结果
	// ============================================================
	fmt.Println("监控循环展开 demo... 按 Ctrl+C 停止")
	fmt.Println()
	fmt.Println("说明:")
	fmt.Println("  UNROLL=1 → 编译时使用 #pragma unroll (模拟旧内核 <= 5.2)")
	fmt.Println("  UNROLL=0 → 不展开，依赖验证器的有界循环分析 (内核 >= 5.3)")
	fmt.Println("  Demo1(SUM)  → 固定数组遍历求和，预期值 256")
	fmt.Println("  Demo2(NAME) → 逐字符解析，展开模式最多处理 12 字符")
	fmt.Println("  Demo3(FD)   → 早期退出搜索，找 comm 中第一个 'a' 的位置")
	fmt.Println()
	fmt.Printf("%-8s %-8s %-16s %-7s %-5s %-6s %-8s %-5s %s\n",
		"PID", "PPID", "COMM", "UNROLL", "ITER", "SUM",
		"NAME_LEN", "FD", "PARSED_NAME")
	fmt.Println("-------- -------- ---------------- ------- ----- ------ -------- ----- ----------")

	lostTotal := uint64(0)
	totalEvents := 0

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

		// 反序列化事件
		var ev LoopEvent
		if err := binary.Read(
			bytes.NewReader(rec.RawSample),
			binary.LittleEndian,
			&ev,
		); err != nil {
			fmt.Printf("  [错误] 解析事件失败: %v\n", err)
			continue
		}

		totalEvents++

		// 提取字符串
		comm := cStr(ev.Comm[:])
		parsedName := cStr(ev.ParsedName[:])
		if ev.NameLen > 0 && ev.NameLen < 256 {
			parsedName = cStr(ev.ParsedName[:ev.NameLen])
		}

		// 格式化 found_idx: -1 (0xFFFFFFFF) 表示未找到
		fdStr := "N/A"
		if ev.FoundIdx != 0xFFFFFFFF {
			fdStr = fmt.Sprintf("%d", ev.FoundIdx)
		}

		fmt.Printf("%-8d %-8d %-16s %-7d %-5d %-6d %-8d %-5s %s\n",
			ev.Pid, ev.Ppid, comm, ev.LoopsUnroll, ev.NameMaxIter,
			ev.ArraySum, ev.NameLen, fdStr, parsedName)
	}

	// ============================================================
	// 退出统计
	// ============================================================
	fmt.Println()
	fmt.Println("=== 循环展开 demo 统计 ===")
	fmt.Printf("总事件数:   %d\n", totalEvents)
	if lostTotal > 0 {
		fmt.Printf("丢失事件:   %d\n", lostTotal)
	}
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
