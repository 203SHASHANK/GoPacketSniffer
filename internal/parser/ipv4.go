package parser

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IP protocol number constants (byte 9 of the IPv4 header).
const (
	IPProtocolICMP = 1
	IPProtocolTCP  = 6
	IPProtocolUDP  = 17

	IPv4MinHeaderSize = 20 // IHL=5 means 5×4=20 bytes
)

// IPv4Packet holds the decoded IPv4 header fields.
type IPv4Packet struct {
	Version    uint8
	HeaderLen  int    // in bytes (IHL × 4)
	TTL        uint8
	Protocol   uint8
	SrcIP      net.IP
	DstIP      net.IP
	Checksum   uint16
	Payload    []byte // bytes after the IP header (transport layer)
}

// ParseIPv4 decodes an IPv4 packet from raw bytes (starting at the IP header,
// i.e. after the Ethernet header has been stripped).
//
// IPv4 header layout (20 bytes minimum, RFC 791):
//
//	Byte 0     : Version (4 bits) | IHL (4 bits)
//	Byte 1     : DSCP / ECN
//	Bytes 2-3  : Total Length
//	Bytes 4-5  : Identification
//	Bytes 6-7  : Flags | Fragment Offset
//	Byte 8     : TTL
//	Byte 9     : Protocol
//	Bytes 10-11: Header Checksum
//	Bytes 12-15: Source IP
//	Bytes 16-19: Destination IP
//	Bytes 20+  : Options (if IHL > 5) then Payload
func ParseIPv4(data []byte) (*IPv4Packet, error) {
	if len(data) < IPv4MinHeaderSize {
		return nil, fmt.Errorf("IPv4 packet too short: got %d bytes, need %d",
			len(data), IPv4MinHeaderSize)
	}

	version := data[0] >> 4        // top 4 bits
	ihl := data[0] & 0x0F          // bottom 4 bits (header length in 32-bit words)
	headerLenBytes := int(ihl) * 4 // convert words → bytes

	if version != 4 {
		return nil, fmt.Errorf("not an IPv4 packet: version=%d", version)
	}
	if headerLenBytes < IPv4MinHeaderSize {
		return nil, fmt.Errorf("invalid IHL=%d (header would be %d bytes)", ihl, headerLenBytes)
	}
	if len(data) < headerLenBytes {
		return nil, fmt.Errorf("packet shorter than IHL indicates: got %d, need %d",
			len(data), headerLenBytes)
	}

	checksum := binary.BigEndian.Uint16(data[10:12])

	return &IPv4Packet{
		Version:   version,
		HeaderLen: headerLenBytes,
		TTL:       data[8],
		Protocol:  data[9],
		Checksum:  checksum,
		SrcIP:     net.IP(data[12:16]),
		DstIP:     net.IP(data[16:20]),
		Payload:   data[headerLenBytes:],
	}, nil
}
