package parser

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IP protocol numbers (byte 9 of the IPv4 header).
const (
	IPProtocolICMP = 1
	IPProtocolTCP  = 6
	IPProtocolUDP  = 17

	IPv4MinHeaderSize = 20 // IHL=5, i.e. five 32-bit words

	ipv4MoreFragments = 0x2000 // MF bit in the flags/fragment-offset field
	ipv4FragOffMask   = 0x1fff // low 13 bits: fragment offset in 8-byte units
)

// IPv4Packet holds the decoded IPv4 header fields.
type IPv4Packet struct {
	Version       uint8
	HeaderLen     int    // in bytes (IHL x 4)
	TotalLen      uint16 // header + payload length claimed by the header
	MoreFragments bool   // MF flag: more fragments of this datagram follow
	FragOffset    uint16 // position of this fragment, in 8-byte units
	TTL           uint8
	Protocol      uint8
	Checksum      uint16
	SrcIP         net.IP
	DstIP         net.IP
	Payload       []byte // bytes after the IP header (transport layer)
}

// IsLaterFragment reports whether this is the second or a later fragment of
// a fragmented datagram. Only the first fragment (offset 0) starts with the
// transport header; later ones contain a continuation of the payload.
func (p *IPv4Packet) IsLaterFragment() bool {
	return p.FragOffset != 0
}

// ParseIPv4 decodes an IPv4 packet from raw bytes, starting at the IP header
// (i.e. after the Ethernet header has been stripped).
//
// IPv4 header layout (20 bytes minimum, RFC 791):
//
//	Byte 0     : Version (4 bits) | IHL (4 bits)
//	Byte 1     : DSCP / ECN
//	Bytes 2-3  : Total Length
//	Bytes 4-5  : Identification
//	Bytes 6-7  : Flags (3 bits) | Fragment Offset (13 bits)
//	Byte 8     : TTL
//	Byte 9     : Protocol
//	Bytes 10-11: Header Checksum
//	Bytes 12-15: Source IP
//	Bytes 16-19: Destination IP
//	Bytes 20+  : Options (if IHL > 5), then payload
//
// The returned addresses and payload are slices of data, not copies.
func ParseIPv4(data []byte) (*IPv4Packet, error) {
	if len(data) < IPv4MinHeaderSize {
		return nil, fmt.Errorf("IPv4 packet too short: got %d bytes, need %d",
			len(data), IPv4MinHeaderSize)
	}

	version := data[0] >> 4        // top 4 bits
	ihl := data[0] & 0x0F          // bottom 4 bits: header length in 32-bit words
	headerLenBytes := int(ihl) * 4 // words to bytes

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

	totalLen := binary.BigEndian.Uint16(data[2:4])
	flagsAndOffset := binary.BigEndian.Uint16(data[6:8])

	// Ethernet pads short frames to 60 bytes, so the buffer can extend past
	// the end of the IP packet. Use Total Length to cut the padding off, or
	// it would be mistaken for transport payload. The field is only trusted
	// when it is plausible: with segmentation offload the kernel can show us
	// packets whose Total Length is 0 or smaller than the real size.
	end := len(data)
	if int(totalLen) >= headerLenBytes && int(totalLen) < end {
		end = int(totalLen)
	}

	return &IPv4Packet{
		Version:       version,
		HeaderLen:     headerLenBytes,
		TotalLen:      totalLen,
		MoreFragments: flagsAndOffset&ipv4MoreFragments != 0,
		FragOffset:    flagsAndOffset & ipv4FragOffMask,
		TTL:           data[8],
		Protocol:      data[9],
		Checksum:      binary.BigEndian.Uint16(data[10:12]),
		SrcIP:         net.IP(data[12:16]),
		DstIP:         net.IP(data[16:20]),
		Payload:       data[headerLenBytes:end],
	}, nil
}
