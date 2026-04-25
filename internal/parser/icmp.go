package parser

import (
	"encoding/binary"
	"fmt"
)

// ICMP type constants (RFC 792).
const (
	ICMPTypeEchoReply      = 0
	ICMPTypeDestUnreachable = 3
	ICMPTypeEchoRequest    = 8
	ICMPTypeTimeExceeded   = 11

	ICMPHeaderSize = 8
)

// ICMPPacket holds the decoded ICMP header fields.
type ICMPPacket struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	TypeStr  string // human-readable type name
	Payload  []byte
}

// ParseICMP decodes an ICMP packet from raw bytes (starting at the ICMP header).
//
// ICMP header layout (8 bytes minimum, RFC 792):
//
//	Byte 0    : Type
//	Byte 1    : Code
//	Bytes 2-3 : Checksum
//	Bytes 4-7 : Type-specific data (e.g. identifier + sequence for echo)
//	Bytes 8+  : Data
func ParseICMP(data []byte) (*ICMPPacket, error) {
	if len(data) < ICMPHeaderSize {
		return nil, fmt.Errorf("ICMP packet too short: got %d bytes, need %d",
			len(data), ICMPHeaderSize)
	}

	icmpType := data[0]

	return &ICMPPacket{
		Type:     icmpType,
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		TypeStr:  icmpTypeString(icmpType),
		Payload:  data[ICMPHeaderSize:],
	}, nil
}

func icmpTypeString(t uint8) string {
	switch t {
	case ICMPTypeEchoReply:
		return "EchoReply"
	case ICMPTypeDestUnreachable:
		return "DestUnreachable"
	case ICMPTypeEchoRequest:
		return "EchoRequest"
	case ICMPTypeTimeExceeded:
		return "TimeExceeded"
	default:
		return fmt.Sprintf("Type%d", t)
	}
}
