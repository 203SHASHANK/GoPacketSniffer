package pcap

import (
	"encoding/binary"
	"os"
	"testing"
	"time"
)

func TestWriterCreatesValidFile(t *testing.T) {
	path := t.TempDir() + "/test.pcap"

	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	payload := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	ts := time.Unix(1700000000, 500000*1000) // known timestamp

	if err := w.WritePacket(ts, payload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Global header is 24 bytes; verify magic number.
	if len(data) < 24 {
		t.Fatalf("file too short: %d bytes", len(data))
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != magicNumber {
		t.Errorf("magic=0x%08x, want 0x%08x", magic, magicNumber)
	}

	// Packet record starts at byte 24: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4) data(5)
	if len(data) < 24+16+len(payload) {
		t.Fatalf("file missing packet record, got %d bytes", len(data))
	}
	inclLen := binary.LittleEndian.Uint32(data[24+8 : 24+12])
	if inclLen != uint32(len(payload)) {
		t.Errorf("incl_len=%d, want %d", inclLen, len(payload))
	}
}

func TestWriterMultiplePackets(t *testing.T) {
	path := t.TempDir() + "/multi.pcap"
	w, _ := NewWriter(path)

	for i := 0; i < 5; i++ {
		w.WritePacket(time.Now(), []byte{byte(i), byte(i + 1)})
	}
	w.Close()

	data, _ := os.ReadFile(path)
	// 24 (global hdr) + 5 × (16 hdr + 2 data) = 24 + 90 = 114
	if len(data) != 114 {
		t.Errorf("file size=%d, want 114", len(data))
	}
}
