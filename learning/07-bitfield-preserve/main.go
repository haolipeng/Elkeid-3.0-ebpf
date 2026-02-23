// 技术点 7: __builtin_preserve_field_info 位域读取 - 用户态程序
//
// 功能:
//   1. 加载编译好的 eBPF 程序 (bitfield.bpf.o)
//   2. 附加到 kprobe/tcp_connect
//   3. 通过 perf event 读取内核态发送的 socket 连接事件
//   4. 将协议号、socket 类型、地址族翻译为人类可读的名称
//   5. 格式化输出连接信息
//
// 关键学习点:
//   - protocol 字段来自位域读取 (__builtin_preserve_field_info)
//   - sock_type 字段通过 BPF_CORE_READ_BITFIELD 读取
//   - family / sport / dport 是普通字段，BPF_CORE_READ 即可
//   - 三种读取方式的对比验证: 如果 protocol 显示正确 (TCP=6)，
//     ���明位域的 CO-RE 重定位工作正常
//
// 对应 Elkeid 用户态:
//   - ebpf/consume.c 中的 perf buffer 消费逻辑
//   - 事件解析中协议号到名称的映射

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

// Event 与内核态 struct event 完全对应
//
// 内存布局对照:
//
//   C 结构体:                        Go 结构体:
//   u32  pid;           (4B)   →    Pid       uint32
//   u32  tid;           (4B)   →    Tid       uint32
//   u32  uid;           (4B)   →    Uid       uint32
//   u32  protocol;      (4B)   →    Protocol  uint32   ← 位域读取!
//   u32  sock_type;     (4B)   →    SockType  uint32
//   u16  family;        (2B)   →    Family    uint16
//   u16  sport;         (2B)   →    Sport     uint16
//   u16  dport;         (2B)   →    Dport     uint16
//   u16  _pad;          (2B)   →    Pad       uint16
//   char comm[16];      (16B)  →    Comm      [16]byte
//
// 总计: 4*5 + 2*4 + 16 = 44 字节
//
// 关键验证点:
//   Protocol 字段是通过 __builtin_preserve_field_info 从位域中提取的。
//   如果显示为 TCP(6) 或 UDP(17)，说明位域的 CO-RE 重定位成功。
//   如果显示为异常值 (如 0 或很大的数)，说明位域布局信息不正确。
type Event struct {
	Pid      uint32
	Tid      uint32
	Uid      uint32
	Protocol uint32
	SockType uint32
	Family   uint16
	Sport    uint16
	Dport    uint16
	Pad      uint16
	Comm     [16]byte
}

// protocolName 将协议号翻译为可读名称
//
// 常见协议号 (定义在 /etc/protocols):
//   1  = ICMP
//   6  = TCP (IPPROTO_TCP)
//   17 = UDP (IPPROTO_UDP)
//   58 = ICMPv6
//
// tcp_connect 中几乎只会看到 TCP(6)，
// 但如果位域读取出错，可能看到异常值。
func protocolName(proto uint32) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", proto)
	}
}

// sockTypeName 将 socket 类型翻译为可读名称
//
// socket 类型决定了通信语义:
//   SOCK_STREAM (1): 面向连接、可靠、有序的字节流 (TCP 使用)
//   SOCK_DGRAM  (2): 无连接、不可靠的数据报 (UDP 使用)
//   SOCK_RAW    (3): 原始 socket (需要 CAP_NET_RAW)
func sockTypeName(st uint32) string {
	switch st {
	case 1:
		return "STREAM"
	case 2:
		return "DGRAM"
	case 3:
		return "RAW"
	case 5:
		return "SEQPACKET"
	default:
		return fmt.Sprintf("TYPE(%d)", st)
	}
}

// familyName 将地址族翻译为可读名称
//
// 地址族决定了使用的网络协议:
//   AF_INET  (2):  IPv4
//   AF_INET6 (10): IPv6
func familyName(f uint16) string {
	switch f {
	case 2:
		return "IPv4"
	case 10:
		return "IPv6"
	default:
		return fmt.Sprintf("AF(%d)", f)
	}
}

func main() {
	// ============================================================
	// 步骤 1: 加载 eBPF ELF 文件
	// ============================================================
	//
	// LoadCollectionSpec 解析 .o 文件中的所有 map 和 program 定义:
	//   - events (PERF_EVENT_ARRAY)
	//   - kp_tcp_connect (kprobe 程序)
	//
	// 加载过程中，BPF loader 会处理 CO-RE 重定位:
	//   - 普通字段: 更新 BPF_CORE_READ 中的偏移量
	//   - 位域字段: 更新 __builtin_preserve_field_info 的 4 个常量
	//
	// 如果目标内核的 BTF 中 sk_protocol 是位域:
	//   offset/size/lshift/rshift 被设置为位域提取参数
	// 如果 sk_protocol 是独立字段 (>= 5.6):
	//   offset/size 为字段的实际偏移和大小
	//   lshift/rshift 使值不变 (即无需位操作)
	spec, err := ebpf.LoadCollectionSpec("bitfield.bpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF spec 失败: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("创建 eBPF collection 失败: %v\n"+
			"提示: 确保以 root 运行，且内核版本 >= 5.4，"+
			"内核需要开启 CONFIG_DEBUG_INFO_BTF", err)
	}
	defer coll.Close()

	// ============================================================
	// 步骤 2: 附加 kprobe 到 tcp_connect
	// ============================================================
	//
	// tcp_connect 是 TCP 主动建连的入口函数:
	//   用户态 connect() → sys_connect → ... → tcp_connect(sk)
	//
	// 参数: struct sock *sk，包含完整的 socket 状态。
	// 我们的 eBPF 程序从 sk 中读取:
	//   - sk_protocol (位域) → protocol
	//   - sk_type (可能是位域) → sock_type
	//   - skc_family → family
	//   - skc_num / skc_dport → sport / dport
	kp, err := link.Kprobe("tcp_connect", coll.Programs["kp_tcp_connect"], nil)
	if err != nil {
		log.Fatalf("附加 kprobe 失败: %v\n"+
			"提示: 确认 /proc/kallsyms 中存在 tcp_connect", err)
	}
	defer kp.Close()

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
	// 步骤 5: 事件循环 - 读取并展示 TCP 连接事件
	// ============================================================
	fmt.Println("监控 TCP 连接 (kprobe/tcp_connect)... 按 Ctrl+C 停止")
	fmt.Println()
	fmt.Println("位域读取验证说明:")
	fmt.Println("  PROTOCOL 列: 通过 __builtin_preserve_field_info 从位域中提取")
	fmt.Println("  TYPE 列:     通过 BPF_CORE_READ_BITFIELD 宏读取")
	fmt.Println("  FAMILY 列:   通过 BPF_CORE_READ 普通读取")
	fmt.Println("  若 PROTOCOL 正确显示为 TCP(6)，说明位域 CO-RE 重定位成功")
	fmt.Println()
	fmt.Printf("%-8s %-16s %-6s %-8s %-8s %-6s  %s\n",
		"PID", "COMM", "UID", "PROTO", "TYPE", "FAMILY", "CONNECTION")
	fmt.Println("-------- ---------------- ------ -------- -------- ------  --------------------")

	lostTotal := uint64(0)
	totalEvents := 0
	protoOK := 0

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

		var e Event
		if err := binary.Read(
			bytes.NewReader(rec.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			fmt.Printf("  [错误] 解析事件失败: %v\n", err)
			continue
		}

		comm := cStr(e.Comm[:])
		totalEvents++

		// 验证位域读取是否正确:
		// tcp_connect 中 protocol 应该是 TCP(6)
		if e.Protocol == 6 {
			protoOK++
		}

		// 构建连接描述: sport -> dport
		connStr := fmt.Sprintf(":%d -> :%d", e.Sport, e.Dport)

		fmt.Printf("%-8d %-16s %-6d %-8s %-8s %-6s  %s\n",
			e.Pid,
			comm,
			e.Uid,
			protocolName(e.Protocol),
			sockTypeName(e.SockType),
			familyName(e.Family),
			connStr)
	}

	// ============================================================
	// 退出统计
	// ============================================================
	fmt.Println()
	fmt.Println("=== 位域读取验证统计 ===")
	fmt.Printf("总事件数:          %d\n", totalEvents)
	fmt.Printf("协议正确 (TCP=6):  %d/%d\n", protoOK, totalEvents)
	if lostTotal > 0 {
		fmt.Printf("丢失事件:          %d\n", lostTotal)
	}
	if totalEvents > 0 && protoOK == totalEvents {
		fmt.Println("结论: __builtin_preserve_field_info 位域读取完全正确")
		fmt.Println("      CO-RE 重定位成功，位域的 offset/size/shift 参数正确")
	} else if totalEvents > 0 {
		fmt.Printf("结论: %d 个事件的协议号异常，位域读取可能存在问题\n",
			totalEvents-protoOK)
		fmt.Println("      检查: 1) 内核是否支持 BTF  2) vmlinux.h 版本是否匹配")
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
