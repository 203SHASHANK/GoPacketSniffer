package parser

import (
	"testing"
	"time"

	"gopacketsniffer/test/testdata"
)

// --- Ethernet ---

func TestParseEthernet(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantSrc   string
		wantDst   string
		wantType  uint16
		wantErr   bool
	}{
		{
			name:     "valid TCP SYN frame",
			input:    testdata.TCPSynPacket,
			wantSrc:  "00:11:22:33:44:55",
			wantDst:  "ff:ff:ff:ff:ff:ff",
			wantType: EtherTypeIPv4,
		},
		{
			name:    "too short",
			input:   []byte{0x00, 0x01, 0x02},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEthernet(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.SrcMAC.String() != tt.wantSrc {
				t.Errorf("SrcMAC=%s, want %s", got.SrcMAC, tt.wantSrc)
			}
			if got.DstMAC.String() != tt.wantDst {
				t.Errorf("DstMAC=%s, want %s", got.DstMAC, tt.wantDst)
			}
			if got.EtherType != tt.wantType {
				t.Errorf("EtherType=0x%04x, want 0x%04x", got.EtherType, tt.wantType)
			}
		})
	}
}

// --- IPv4 ---

func TestParseIPv4(t *testing.T) {
	ipPayload := testdata.TCPSynPacket[EthernetHeaderSize:]

	tests := []struct {
		name     string
		input    []byte
		wantSrc  string
		wantDst  string
		wantProto uint8
		wantErr  bool
	}{
		{
			name:      "valid IPv4 TCP",
			input:     ipPayload,
			wantSrc:   "192.168.1.100",
			wantDst:   "8.8.8.8",
			wantProto: IPProtocolTCP,
		},
		{
			name:    "too short",
			input:   []byte{0x45, 0x00},
			wantErr: true,
		},
		{
			name:    "wrong version",
			input:   append([]byte{0x65}, make([]byte, 19)...), // version=6
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPv4(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.SrcIP.String() != tt.wantSrc {
				t.Errorf("SrcIP=%s, want %s", got.SrcIP, tt.wantSrc)
			}
			if got.DstIP.String() != tt.wantDst {
				t.Errorf("DstIP=%s, want %s", got.DstIP, tt.wantDst)
			}
			if got.Protocol != tt.wantProto {
				t.Errorf("Protocol=%d, want %d", got.Protocol, tt.wantProto)
			}
		})
	}
}

// --- TCP ---

func TestParseTCP(t *testing.T) {
	// TCP payload starts after Ethernet (14) + IPv4 (20) = 34 bytes
	tcpPayload := testdata.TCPSynPacket[EthernetHeaderSize+IPv4MinHeaderSize:]

	tests := []struct {
		name      string
		input     []byte
		wantSrc   uint16
		wantDst   uint16
		wantFlags string
		wantErr   bool
	}{
		{
			name:      "SYN packet",
			input:     tcpPayload,
			wantSrc:   50000,
			wantDst:   80,
			wantFlags: "[SYN]",
		},
		{
			name:    "too short",
			input:   []byte{0x00, 0x50},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTCP(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.SrcPort != tt.wantSrc {
				t.Errorf("SrcPort=%d, want %d", got.SrcPort, tt.wantSrc)
			}
			if got.DstPort != tt.wantDst {
				t.Errorf("DstPort=%d, want %d", got.DstPort, tt.wantDst)
			}
			if got.FlagsStr != tt.wantFlags {
				t.Errorf("Flags=%s, want %s", got.FlagsStr, tt.wantFlags)
			}
		})
	}
}

func TestTCPFlagsString(t *testing.T) {
	tests := []struct {
		flags uint8
		want  string
	}{
		{TCPFlagSYN, "[SYN]"},
		{TCPFlagSYN | TCPFlagACK, "[SYN,ACK]"},
		{TCPFlagFIN | TCPFlagACK, "[ACK,FIN]"},
		{TCPFlagRST, "[RST]"},
		{0x00, "[]"},
	}
	for _, tt := range tests {
		got := tcpFlagsString(tt.flags)
		if got != tt.want {
			t.Errorf("flags=0x%02x: got %s, want %s", tt.flags, got, tt.want)
		}
	}
}

// --- UDP ---

func TestParseUDP(t *testing.T) {
	udpPayload := testdata.UDPDNSPacket[EthernetHeaderSize+IPv4MinHeaderSize:]

	tests := []struct {
		name    string
		input   []byte
		wantSrc uint16
		wantDst uint16
		wantErr bool
	}{
		{
			name:    "DNS query",
			input:   udpPayload,
			wantSrc: 12345,
			wantDst: 53,
		},
		{
			name:    "too short",
			input:   []byte{0x00, 0x35},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUDP(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.SrcPort != tt.wantSrc {
				t.Errorf("SrcPort=%d, want %d", got.SrcPort, tt.wantSrc)
			}
			if got.DstPort != tt.wantDst {
				t.Errorf("DstPort=%d, want %d", got.DstPort, tt.wantDst)
			}
		})
	}
}

// --- ICMP ---

func TestParseICMP(t *testing.T) {
	icmpPayload := testdata.ICMPEchoPacket[EthernetHeaderSize+IPv4MinHeaderSize:]

	tests := []struct {
		name        string
		input       []byte
		wantType    uint8
		wantTypeStr string
		wantErr     bool
	}{
		{
			name:        "echo request",
			input:       icmpPayload,
			wantType:    ICMPTypeEchoRequest,
			wantTypeStr: "EchoRequest",
		},
		{
			name:    "too short",
			input:   []byte{0x08, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseICMP(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.Type != tt.wantType {
				t.Errorf("Type=%d, want %d", got.Type, tt.wantType)
			}
			if got.TypeStr != tt.wantTypeStr {
				t.Errorf("TypeStr=%s, want %s", got.TypeStr, tt.wantTypeStr)
			}
		})
	}
}

// --- Decoder (end-to-end) ---

func TestDecodePacket(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		input     []byte
		wantProto string
		wantSrc   string
		wantDst   string
		wantFlags string
	}{
		{
			name:      "TCP SYN",
			input:     testdata.TCPSynPacket,
			wantProto: "TCP",
			wantSrc:   "192.168.1.100",
			wantDst:   "8.8.8.8",
			wantFlags: "[SYN]",
		},
		{
			name:      "UDP DNS",
			input:     testdata.UDPDNSPacket,
			wantProto: "UDP",
			wantSrc:   "192.168.1.100",
			wantDst:   "8.8.8.8",
		},
		{
			name:      "ICMP Echo",
			input:     testdata.ICMPEchoPacket,
			wantProto: "ICMP",
			wantSrc:   "192.168.1.100",
			wantDst:   "8.8.8.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodePacket(tt.input, now)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Protocol != tt.wantProto {
				t.Errorf("Protocol=%s, want %s", got.Protocol, tt.wantProto)
			}
			if got.SrcIP != tt.wantSrc {
				t.Errorf("SrcIP=%s, want %s", got.SrcIP, tt.wantSrc)
			}
			if got.DstIP != tt.wantDst {
				t.Errorf("DstIP=%s, want %s", got.DstIP, tt.wantDst)
			}
			if tt.wantFlags != "" && got.TCPFlags != tt.wantFlags {
				t.Errorf("TCPFlags=%s, want %s", got.TCPFlags, tt.wantFlags)
			}
		})
	}
}

// --- Benchmarks ---

func BenchmarkParseEthernet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseEthernet(testdata.TCPSynPacket)
	}
}

func BenchmarkParseIPv4(b *testing.B) {
	payload := testdata.TCPSynPacket[EthernetHeaderSize:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseIPv4(payload)
	}
}

func BenchmarkParseTCP(b *testing.B) {
	payload := testdata.TCPSynPacket[EthernetHeaderSize+IPv4MinHeaderSize:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseTCP(payload)
	}
}

func BenchmarkDecodePacket(b *testing.B) {
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodePacket(testdata.TCPSynPacket, now)
	}
}
