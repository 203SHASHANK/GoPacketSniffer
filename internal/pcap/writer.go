// Package pcap writes captured packets to a .pcap file in the libpcap format.
//
// File format reference:
// https://wiki.wireshark.org/Development/LibpcapFileFormat
package pcap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// Magic numbers and constants defined by the libpcap file format.
const (
	magicNumber  uint32 = 0xA1B2C3D4 // little-endian magic
	versionMajor uint16 = 2
	versionMinor uint16 = 4
	linkTypeEN10MB uint32 = 1 // Ethernet
	snapLen      uint32 = 65535
)

// Writer writes raw Ethernet frames to a .pcap file.
type Writer struct {
	f   *os.File
	buf *bufio.Writer
}

// NewWriter creates (or truncates) the file at path and writes the global
// PCAP header. Call Close when done to flush and close the file.
func NewWriter(path string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create pcap file %q: %w", path, err)
	}

	w := &Writer{f: f, buf: bufio.NewWriterSize(f, 1<<20)} // 1 MB write buffer

	if err := w.writeGlobalHeader(); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

// WritePacket appends a single packet record to the file.
// ts is the capture timestamp; data is the raw Ethernet frame.
func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	capLen := uint32(len(data))
	if capLen > snapLen {
		capLen = snapLen
	}

	// Per-packet header: ts_sec, ts_usec, incl_len, orig_len
	tsSec := uint32(ts.Unix())
	tsUsec := uint32(ts.Nanosecond() / 1000)

	if err := binary.Write(w.buf, binary.LittleEndian, tsSec); err != nil {
		return err
	}
	if err := binary.Write(w.buf, binary.LittleEndian, tsUsec); err != nil {
		return err
	}
	if err := binary.Write(w.buf, binary.LittleEndian, capLen); err != nil {
		return err
	}
	if err := binary.Write(w.buf, binary.LittleEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.buf.Write(data[:capLen])
	return err
}

// Close flushes the write buffer and closes the underlying file.
func (w *Writer) Close() error {
	if err := w.buf.Flush(); err != nil {
		return err
	}
	return w.f.Close()
}

// writeGlobalHeader writes the 24-byte PCAP file header.
func (w *Writer) writeGlobalHeader() error {
	hdr := struct {
		Magic        uint32
		VersionMajor uint16
		VersionMinor uint16
		ThisZone     int32  // GMT offset (0 = UTC)
		SigFigs      uint32 // accuracy of timestamps (always 0)
		SnapLen      uint32
		Network      uint32 // link-layer type
	}{
		Magic:        magicNumber,
		VersionMajor: versionMajor,
		VersionMinor: versionMinor,
		SnapLen:      snapLen,
		Network:      linkTypeEN10MB,
	}
	return binary.Write(w.buf, binary.LittleEndian, hdr)
}
