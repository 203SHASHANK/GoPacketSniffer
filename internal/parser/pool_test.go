package parser

import (
	"testing"
	"time"

	"gopacketsniffer/test/testdata"
)

func TestPacketPoolRoundTrip(t *testing.T) {
	info, err := DecodePacket(testdata.TCPSynPacket, time.Now())
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if info.Protocol != "TCP" {
		t.Errorf("Protocol=%s, want TCP", info.Protocol)
	}

	// Return to pool and get a fresh one — should be zeroed.
	PutPacketInfo(info)
	fresh := GetPacketInfo()
	if fresh.Protocol != "" {
		t.Errorf("pooled PacketInfo not zeroed: Protocol=%q", fresh.Protocol)
	}
	PutPacketInfo(fresh)
}

func BenchmarkDecodePacketPool(b *testing.B) {
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		info, _ := DecodePacket(testdata.TCPSynPacket, now)
		PutPacketInfo(info)
	}
}
