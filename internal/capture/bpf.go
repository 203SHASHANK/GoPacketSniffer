// Package capture — bpf.go attaches a BPF filter to a raw socket so the
// kernel drops unwanted packets before they reach userspace.
//
// We use golang.org/x/net/bpf to compile a human-readable filter expression
// into BPF bytecode, then attach it via SO_ATTACH_FILTER.
//
// Reference: https://www.kernel.org/doc/Documentation/networking/filter.txt
package capture

import (
	"fmt"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// AttachBPFFilter compiles filterExpr into BPF bytecode and attaches it to fd.
//
// Supported expressions (subset of tcpdump syntax):
//
//	"tcp"              – only TCP packets
//	"udp"              – only UDP packets
//	"icmp"             – only ICMP packets
//	"tcp port 80"      – TCP on port 80
//	"udp port 53"      – UDP on port 53
//	"host 1.2.3.4"     – traffic to/from an IP (not yet implemented)
//
// For unsupported expressions an error is returned and no filter is applied.
func AttachBPFFilter(fd int, filterExpr string) error {
	insns, err := compileFilter(filterExpr)
	if err != nil {
		return fmt.Errorf("compile BPF filter %q: %w", filterExpr, err)
	}

	assembled, err := bpf.Assemble(insns)
	if err != nil {
		return fmt.Errorf("assemble BPF: %w", err)
	}

	return attachRaw(fd, assembled)
}

// attachRaw attaches pre-assembled BPF instructions to a socket via
// SO_ATTACH_FILTER (setsockopt).
func attachRaw(fd int, insns []bpf.RawInstruction) error {
	if len(insns) == 0 {
		return fmt.Errorf("empty BPF program")
	}

	// sock_fprog layout expected by the kernel:
	//   uint16 len
	//   pad[6]
	//   *sock_filter (pointer to array of {code,jt,jf,k})
	type sockFilter struct {
		Code uint16
		Jt   uint8
		Jf   uint8
		K    uint32
	}
	type sockFprog struct {
		Len    uint16
		_      [6]byte
		Filter *sockFilter
	}

	filters := make([]sockFilter, len(insns))
	for i, ins := range insns {
		filters[i] = sockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}

	prog := sockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}

	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		unix.SOL_SOCKET,
		unix.SO_ATTACH_FILTER,
		uintptr(unsafe.Pointer(&prog)),
		unsafe.Sizeof(prog),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("SO_ATTACH_FILTER: %w", errno)
	}
	return nil
}

// compileFilter translates a simple filter expression into BPF instructions.
//
// Ethernet frames carry an IPv4 header at offset 14.
// IP protocol byte is at offset 14+9 = 23.
// TCP/UDP source port is at offset 14+20 = 34, dest port at 36.
func compileFilter(expr string) ([]bpf.Instruction, error) {
	// Offsets within a raw Ethernet frame
	const (
		offEtherType  = 12 // 2 bytes
		offIPProto    = 23 // 1 byte  (Ethernet 14 + IP proto at byte 9)
		offTCPSrcPort = 34 // 2 bytes (Ethernet 14 + IP min 20)
		offTCPDstPort = 36 // 2 bytes
		offUDPSrcPort = 34
		offUDPDstPort = 36
	)

	switch expr {
	case "tcp":
		return []bpf.Instruction{
			bpf.LoadAbsolute{Off: offIPProto, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 0, SkipFalse: 1},
			bpf.RetConstant{Val: 0xFFFF},
			bpf.RetConstant{Val: 0},
		}, nil

	case "udp":
		return []bpf.Instruction{
			bpf.LoadAbsolute{Off: offIPProto, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 1},
			bpf.RetConstant{Val: 0xFFFF},
			bpf.RetConstant{Val: 0},
		}, nil

	case "icmp":
		return []bpf.Instruction{
			bpf.LoadAbsolute{Off: offIPProto, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 0, SkipFalse: 1},
			bpf.RetConstant{Val: 0xFFFF},
			bpf.RetConstant{Val: 0},
		}, nil
	}

	// "tcp port <N>" or "udp port <N>"
	var proto string
	var port uint32
	if n, _ := fmt.Sscanf(expr, "tcp port %d", &port); n == 1 {
		proto = "tcp"
	} else if n, _ := fmt.Sscanf(expr, "udp port %d", &port); n == 1 {
		proto = "udp"
	}

	if proto != "" && port > 0 {
		ipProto := uint32(6)
		srcOff := uint32(offTCPSrcPort)
		dstOff := uint32(offTCPDstPort)
		if proto == "udp" {
			ipProto = 17
			srcOff = offUDPSrcPort
			dstOff = offUDPDstPort
		}
		return []bpf.Instruction{
			// Check IP protocol
			bpf.LoadAbsolute{Off: offIPProto, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipProto, SkipTrue: 0, SkipFalse: 3},
			// Check src port
			bpf.LoadAbsolute{Off: srcOff, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: port, SkipTrue: 2, SkipFalse: 0},
			// Check dst port
			bpf.LoadAbsolute{Off: dstOff, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: port, SkipTrue: 0, SkipFalse: 1},
			bpf.RetConstant{Val: 0xFFFF},
			bpf.RetConstant{Val: 0},
		}, nil
	}

	return nil, fmt.Errorf("unsupported filter expression: %q", expr)
}
