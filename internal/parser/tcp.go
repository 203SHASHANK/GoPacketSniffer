package parser

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// TCP flag bit masks (byte 13 of the TCP header).
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20

	TCPMinHeaderSize = 20
)

// TCPSegment holds the decoded TCP header fields.
type TCPSegment struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	HeaderLen  int    // data offset × 4, in bytes
	Flags      uint8  // raw flag byte
	FlagsStr   string // human-readable, e.g. "[SYN,ACK]"
	WindowSize uint16
	Checksum   uint16
	Payload    []byte
}

// ParseTCP decodes a TCP segment from raw bytes (starting at the TCP header).
//
// TCP header layout (20 bytes minimum, RFC 793):
//
//	Bytes 0-1  : Source Port
//	Bytes 2-3  : Destination Port
//	Bytes 4-7  : Sequence Number
//	Bytes 8-11 : Acknowledgment Number
//	Byte 12    : Data Offset (4 bits, top) | Reserved (4 bits)
//	Byte 13    : Flags (URG|ACK|PSH|RST|SYN|FIN)
//	Bytes 14-15: Window Size
//	Bytes 16-17: Checksum
//	Bytes 18-19: Urgent Pointer
//	Bytes 20+  : Options (if data offset > 5) then Payload
func ParseTCP(data []byte) (*TCPSegment, error) {
	if len(data) < TCPMinHeaderSize {
		return nil, fmt.Errorf("TCP segment too short: got %d bytes, need %d",
			len(data), TCPMinHeaderSize)
	}

	// Data offset is the top 4 bits of byte 12; value is in 32-bit words.
	dataOffset := (data[12] >> 4) & 0x0F
	headerLenBytes := int(dataOffset) * 4

	if headerLenBytes < TCPMinHeaderSize {
		return nil, fmt.Errorf("invalid TCP data offset=%d", dataOffset)
	}
	if len(data) < headerLenBytes {
		return nil, fmt.Errorf("TCP packet shorter than data offset: got %d, need %d",
			len(data), headerLenBytes)
	}

	flags := data[13]

	return &TCPSegment{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		HeaderLen:  headerLenBytes,
		Flags:      flags,
		FlagsStr:   tcpFlagsString(flags),
		WindowSize: binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Payload:    data[headerLenBytes:],
	}, nil
}

// tcpFlagsString converts the raw flags byte into a human-readable string
// like "[SYN,ACK]".
func tcpFlagsString(flags uint8) string {
	names := []struct {
		bit  uint8
		name string
	}{
		{TCPFlagSYN, "SYN"},
		{TCPFlagACK, "ACK"},
		{TCPFlagFIN, "FIN"},
		{TCPFlagRST, "RST"},
		{TCPFlagPSH, "PSH"},
		{TCPFlagURG, "URG"},
	}

	var active []string
	for _, f := range names {
		if flags&f.bit != 0 {
			active = append(active, f.name)
		}
	}
	if len(active) == 0 {
		return "[]"
	}
	return "[" + strings.Join(active, ",") + "]"
}
