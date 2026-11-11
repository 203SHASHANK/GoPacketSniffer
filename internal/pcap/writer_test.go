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
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := w.WritePacket(time.Now(), []byte{byte(i), byte(i + 1)}); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// 24 (global header) + 5 x (16 header + 2 data) = 114
	if len(data) != 114 {
		t.Errorf("file size=%d, want 114", len(data))
	}
}

func TestWriterRecordHeader(t *testing.T) {
	path := t.TempDir() + "/hdr.pcap"
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ts := time.Unix(1700000000, 123456789)
	if err := w.WritePacket(ts, []byte{1, 2, 3}); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Global header fields after the magic number.
	if major, minor := binary.LittleEndian.Uint16(data[4:6]), binary.LittleEndian.Uint16(data[6:8]); major != 2 || minor != 4 {
		t.Errorf("version=%d.%d, want 2.4", major, minor)
	}
	if got := binary.LittleEndian.Uint32(data[16:20]); got != snapLen {
		t.Errorf("snaplen=%d, want %d", got, snapLen)
	}
	if got := binary.LittleEndian.Uint32(data[20:24]); got != linkTypeEN10MB {
		t.Errorf("linktype=%d, want %d", got, linkTypeEN10MB)
	}

	rec := data[globalHeaderLen:]
	if got := binary.LittleEndian.Uint32(rec[0:4]); got != 1700000000 {
		t.Errorf("ts_sec=%d, want 1700000000", got)
	}
	if got := binary.LittleEndian.Uint32(rec[4:8]); got != 123456 {
		t.Errorf("ts_usec=%d, want 123456", got)
	}
	if got := binary.LittleEndian.Uint32(rec[12:16]); got != 3 {
		t.Errorf("orig_len=%d, want 3", got)
	}
}

func TestWriterTruncatesOversizedPacket(t *testing.T) {
	path := t.TempDir() + "/big.pcap"
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	big := make([]byte, int(snapLen)+100)
	if err := w.WritePacket(time.Now(), big); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	rec := data[globalHeaderLen:]
	if got := binary.LittleEndian.Uint32(rec[8:12]); got != snapLen {
		t.Errorf("incl_len=%d, want %d", got, snapLen)
	}
	if got := binary.LittleEndian.Uint32(rec[12:16]); got != uint32(len(big)) {
		t.Errorf("orig_len=%d, want %d", got, len(big))
	}
	if want := globalHeaderLen + recordHeaderLen + int(snapLen); len(data) != want {
		t.Errorf("file size=%d, want %d", len(data), want)
	}
}

func TestNewWriterBadPath(t *testing.T) {
	if _, err := NewWriter(t.TempDir() + "/missing-dir/out.pcap"); err == nil {
		t.Error("expected an error for an unwritable path")
	}
}
