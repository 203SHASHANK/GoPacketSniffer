package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Offsets into a raw Ethernet frame carrying IPv4.
const (
	offEtherType = 12 // 2 bytes
	offIPHeader  = 14 // first byte holds version and IHL
	offIPFrag    = 20 // 2 bytes: flags (3 bits) + fragment offset (13 bits)
	offIPProto   = 23 // 1 byte
	offIPSrc     = 26 // 4 bytes
	offIPDst     = 30 // 4 bytes

	etherTypeIPv4 = 0x0800
	fragOffMask   = 0x1fff

	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	// acceptLen is the value an accepting filter returns: the number of bytes
	// of the frame the kernel should keep. Anything at least as large as the
	// frame means "keep it all"; this matches tcpdump's default snapshot.
	acceptLen = 262144
)

// AttachBPFFilter compiles filterExpr into classic BPF bytecode and attaches
// it to the socket, so the kernel discards non-matching frames before they
// are copied to userspace.
//
// Supported expressions (a small subset of tcpdump syntax, IPv4 only):
//
//	tcp              only TCP packets
//	udp              only UDP packets
//	icmp             only ICMP packets
//	tcp port 80      TCP with source or destination port 80
//	udp port 53      UDP with source or destination port 53
//	host 1.2.3.4     packets to or from the given IPv4 address
//
// Any other expression returns an error and leaves the socket unfiltered.
//
// Reference: https://www.kernel.org/doc/Documentation/networking/filter.txt
func AttachBPFFilter(fd int, filterExpr string) error {
	insns, err := compileFilter(filterExpr)
	if err != nil {
		return fmt.Errorf("compile BPF filter %q: %w", filterExpr, err)
	}

	raw, err := bpf.Assemble(insns)
	if err != nil {
		return fmt.Errorf("assemble BPF: %w", err)
	}

	// Convert to the kernel's struct sock_filter layout.
	filters := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filters[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("SO_ATTACH_FILTER: %w", err)
	}
	return nil
}

// compileFilter translates a filter expression into BPF instructions.
func compileFilter(expr string) ([]bpf.Instruction, error) {
	fields := strings.Fields(strings.ToLower(expr))

	switch {
	case len(fields) == 1:
		proto, ok := protoNumber(fields[0])
		if !ok {
			break
		}
		return protoFilter(proto), nil

	case len(fields) == 2 && fields[0] == "host":
		ip := net.ParseIP(fields[1]).To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address %q", fields[1])
		}
		return hostFilter(binary.BigEndian.Uint32(ip)), nil

	case len(fields) == 3 && fields[1] == "port":
		proto, ok := protoNumber(fields[0])
		if !ok || proto == protoICMP {
			break
		}
		port, err := strconv.ParseUint(fields[2], 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid port %q (want 1-65535)", fields[2])
		}
		return portFilter(proto, uint32(port)), nil
	}

	return nil, fmt.Errorf("unsupported filter expression")
}

// protoNumber maps a protocol keyword to its IP protocol number.
func protoNumber(name string) (uint32, bool) {
	switch name {
	case "tcp":
		return protoTCP, true
	case "udp":
		return protoUDP, true
	case "icmp":
		return protoICMP, true
	}
	return 0, false
}

// protoFilter accepts IPv4 packets carrying the given IP protocol.
func protoFilter(proto uint32) []bpf.Instruction {
	var b builder
	b.requireIPv4()
	b.load(bpf.LoadAbsolute{Off: offIPProto, Size: 1})
	b.jumpEq(proto, next, reject)
	return b.finish()
}

// hostFilter accepts IPv4 packets whose source or destination address is ip.
func hostFilter(ip uint32) []bpf.Instruction {
	var b builder
	b.requireIPv4()
	b.load(bpf.LoadAbsolute{Off: offIPSrc, Size: 4})
	b.jumpEq(ip, accept, next)
	b.load(bpf.LoadAbsolute{Off: offIPDst, Size: 4})
	b.jumpEq(ip, next, reject)
	return b.finish()
}

// portFilter accepts IPv4 TCP or UDP packets whose source or destination
// port equals port.
func portFilter(proto, port uint32) []bpf.Instruction {
	var b builder
	b.requireIPv4()
	b.load(bpf.LoadAbsolute{Off: offIPProto, Size: 1})
	b.jumpEq(proto, next, reject)

	// Only the first fragment of a fragmented datagram contains the transport
	// header. In later fragments the same bytes are payload, so reject any
	// packet with a non-zero fragment offset.
	b.load(bpf.LoadAbsolute{Off: offIPFrag, Size: 2})
	b.jumpBitsSet(fragOffMask, reject, next)

	// The IP header is 20-60 bytes long depending on options. LoadMemShift
	// sets X = 4 * (IHL nibble), i.e. the header length in bytes, and the
	// ports are then read relative to X.
	b.load(bpf.LoadMemShift{Off: offIPHeader})
	b.load(bpf.LoadIndirect{Off: offIPHeader, Size: 2}) // source port
	b.jumpEq(port, accept, next)
	b.load(bpf.LoadIndirect{Off: offIPHeader + 2, Size: 2}) // destination port
	b.jumpEq(port, next, reject)
	return b.finish()
}

// target says where a conditional jump should land.
type target int

const (
	next   target = iota // fall through to the following instruction
	accept               // jump to the final "keep packet" return
	reject               // jump to the final "drop packet" return
)

// builder assembles a filter whose last two instructions are always
// "return accept" and "return reject". Conditional jumps are recorded with
// symbolic targets and converted to relative skip counts in finish, which
// avoids counting instructions by hand.
type builder struct {
	insns []bpf.Instruction
	jumps []pendingJump
}

type pendingJump struct {
	index           int        // position of the jump in insns
	ins             bpf.JumpIf // the jump, still without skip counts
	onTrue, onFalse target
}

func (b *builder) load(ins bpf.Instruction) {
	b.insns = append(b.insns, ins)
}

func (b *builder) jumpEq(val uint32, onTrue, onFalse target) {
	b.jump(bpf.JumpIf{Cond: bpf.JumpEqual, Val: val}, onTrue, onFalse)
}

func (b *builder) jumpBitsSet(mask uint32, onTrue, onFalse target) {
	b.jump(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: mask}, onTrue, onFalse)
}

func (b *builder) jump(ins bpf.JumpIf, onTrue, onFalse target) {
	b.jumps = append(b.jumps, pendingJump{len(b.insns), ins, onTrue, onFalse})
	b.insns = append(b.insns, ins) // placeholder, rewritten by finish
}

// requireIPv4 rejects every frame whose EtherType is not IPv4. Without it
// the fixed IP offsets would be compared against unrelated bytes of ARP or
// IPv6 frames.
func (b *builder) requireIPv4() {
	b.load(bpf.LoadAbsolute{Off: offEtherType, Size: 2})
	b.jumpEq(etherTypeIPv4, next, reject)
}

// finish appends the two return instructions and resolves the jump targets.
func (b *builder) finish() []bpf.Instruction {
	acceptIdx := len(b.insns)
	rejectIdx := acceptIdx + 1
	b.insns = append(b.insns,
		bpf.RetConstant{Val: acceptLen},
		bpf.RetConstant{Val: 0},
	)

	// A BPF skip count is relative to the instruction after the jump.
	skip := func(from int, t target) uint8 {
		switch t {
		case accept:
			return uint8(acceptIdx - from - 1)
		case reject:
			return uint8(rejectIdx - from - 1)
		}
		return 0
	}
	for _, j := range b.jumps {
		ins := j.ins
		ins.SkipTrue = skip(j.index, j.onTrue)
		ins.SkipFalse = skip(j.index, j.onFalse)
		b.insns[j.index] = ins
	}
	return b.insns
}
