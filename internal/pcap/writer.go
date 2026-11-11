// Package pcap writes captured packets to a .pcap file in the classic
// libpcap format, readable by Wireshark, tcpdump and similar tools.
//
// File format reference:
// https://wiki.wireshark.org/Development/LibpcapFileFormat
package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
)

// Values defined by the libpcap file format.
const (
	magicNumber    uint32 = 0xA1B2C3D4 // marks a pcap file with microsecond timestamps
	versionMajor   uint16 = 2
	versionMinor   uint16 = 4
	linkTypeEN10MB uint32 = 1     // packets start with an Ethernet header
	snapLen        uint32 = 65535 // longest packet stored in full

	globalHeaderLen = 24
	recordHeaderLen = 16

	writeBufferSize = 1 << 20 // 1 MiB
)

// Writer writes raw Ethernet frames to a .pcap file. It is not safe for
// concurrent use.
type Writer struct {
	f   *os.File
	buf *bufio.Writer
	hdr [recordHeaderLen]byte // scratch space for per-packet headers
}

// NewWriter creates the file at path, truncating it if it already exists,
// and writes the global pcap header. Close must be called to flush buffered
// packets to disk.
func NewWriter(path string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create pcap file %q: %w", path, err)
	}

	// Packets are small and frequent; buffering turns thousands of tiny
	// write syscalls into a few large ones.
	w := &Writer{f: f, buf: bufio.NewWriterSize(f, writeBufferSize)}

	if err := w.writeGlobalHeader(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write pcap header: %w", err)
	}
	return w, nil
}

// WritePacket appends one packet record. ts is the capture time and data the
// raw Ethernet frame. Frames longer than the snapshot length are truncated,
// with the original length preserved in the record header.
func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	origLen := uint32(len(data))
	capLen := origLen
	if capLen > snapLen {
		capLen = snapLen
	}

	// Record header, all little-endian: ts_sec, ts_usec, incl_len, orig_len.
	binary.LittleEndian.PutUint32(w.hdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(w.hdr[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(w.hdr[8:12], capLen)
	binary.LittleEndian.PutUint32(w.hdr[12:16], origLen)

	if _, err := w.buf.Write(w.hdr[:]); err != nil {
		return err
	}
	_, err := w.buf.Write(data[:capLen])
	return err
}

// Close flushes buffered data and closes the file. The file is closed even
// if the flush fails; both errors are reported.
func (w *Writer) Close() error {
	return errors.Join(w.buf.Flush(), w.f.Close())
}

// writeGlobalHeader writes the 24-byte header that starts every pcap file.
func (w *Writer) writeGlobalHeader() error {
	var hdr [globalHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], magicNumber)
	binary.LittleEndian.PutUint16(hdr[4:6], versionMajor)
	binary.LittleEndian.PutUint16(hdr[6:8], versionMinor)
	// hdr[8:12]  thiszone: timestamps are UTC, so the offset stays 0
	// hdr[12:16] sigfigs:  timestamp accuracy, 0 by convention
	binary.LittleEndian.PutUint32(hdr[16:20], snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], linkTypeEN10MB)
	_, err := w.buf.Write(hdr[:])
	return err
}
