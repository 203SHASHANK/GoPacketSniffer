package capture

import (
	"testing"

	"golang.org/x/net/bpf"

	"gopacketsniffer/test/testdata"
)

// runFilter compiles expr and evaluates it against frame in the userspace
// BPF virtual machine. It reports whether the filter accepted the frame.
func runFilter(t *testing.T, expr string, frame []byte) bool {
	t.Helper()
	insns, err := compileFilter(expr)
	if err != nil {
		t.Fatalf("compileFilter(%q): %v", expr, err)
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("NewVM(%q): %v", expr, err)
	}
	n, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("Run(%q): %v", expr, err)
	}
	return n > 0
}

// withIPOptions returns a copy of an Ethernet/IPv4 frame with 4 bytes of IP
// options inserted, so the transport header starts 24 bytes into the packet.
func withIPOptions(frame []byte) []byte {
	const ipEnd = 14 + 20
	out := make([]byte, 0, len(frame)+4)
	out = append(out, frame[:ipEnd]...)
	out = append(out, 0x01, 0x01, 0x01, 0x01) // four NOP options
	out = append(out, frame[ipEnd:]...)
	out[14] = 0x46 // version 4, IHL 6
	return out
}

func TestFilterMatching(t *testing.T) {
	// An ARP frame that happens to have 0x06 at offset 23, where an IPv4
	// frame keeps its protocol number.
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	arp[23] = 0x06

	// Non-first fragment of a TCP datagram: fragment offset 185.
	fragment := append([]byte(nil), testdata.TCPSynPacket...)
	fragment[20], fragment[21] = 0x00, 0xb9

	tests := []struct {
		name  string
		expr  string
		frame []byte
		want  bool
	}{
		{"tcp matches TCP", "tcp", testdata.TCPSynPacket, true},
		{"tcp rejects UDP", "tcp", testdata.UDPDNSPacket, false},
		{"tcp rejects ARP lookalike", "tcp", arp, false},
		{"udp matches UDP", "udp", testdata.UDPDNSPacket, true},
		{"icmp matches ICMP", "icmp", testdata.ICMPEchoPacket, true},
		{"icmp rejects TCP", "icmp", testdata.TCPSynPacket, false},
		{"keywords are case-insensitive", "TCP", testdata.TCPSynPacket, true},

		{"dst port", "tcp port 80", testdata.TCPSynPacket, true},
		{"src port", "tcp port 50000", testdata.TCPSynPacket, true},
		{"other port", "tcp port 443", testdata.TCPSynPacket, false},
		{"port with wrong protocol", "udp port 80", testdata.TCPSynPacket, false},
		{"udp port", "udp port 53", testdata.UDPDNSPacket, true},
		{"port honours IP options", "tcp port 80", withIPOptions(testdata.TCPSynPacket), true},
		{"port rejects later fragments", "tcp port 80", fragment, false},

		{"host matches source", "host 192.168.1.100", testdata.TCPSynPacket, true},
		{"host matches destination", "host 8.8.8.8", testdata.UDPDNSPacket, true},
		{"host rejects others", "host 10.0.0.1", testdata.TCPSynPacket, false},
		{"host rejects non-IP", "host 8.8.8.8", arp, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runFilter(t, tt.expr, tt.frame); got != tt.want {
				t.Errorf("filter %q accepted=%v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestFilterRejectsBadExpressions(t *testing.T) {
	for _, expr := range []string{
		"",
		"garbage",
		"tcp port",
		"tcp port 0",
		"tcp port 70000",
		"tcp port 80 and more",
		"tcp port eighty",
		"icmp port 1",
		"host",
		"host not-an-ip",
		"host ::1",
	} {
		if _, err := compileFilter(expr); err == nil {
			t.Errorf("compileFilter(%q): expected an error", expr)
		}
	}
}

func TestFiltersAssemble(t *testing.T) {
	for _, expr := range []string{"tcp", "udp", "icmp", "tcp port 80", "udp port 53", "host 1.2.3.4"} {
		insns, err := compileFilter(expr)
		if err != nil {
			t.Fatalf("compileFilter(%q): %v", expr, err)
		}
		if _, err := bpf.Assemble(insns); err != nil {
			t.Errorf("Assemble(%q): %v", expr, err)
		}
	}
}

func TestAttachBPFFilterBadExpression(t *testing.T) {
	// Compilation fails before any syscall, so no real socket is needed.
	if err := AttachBPFFilter(-1, "garbage"); err == nil {
		t.Error("expected an error for an unsupported expression")
	}
}
