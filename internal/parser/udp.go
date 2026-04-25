package parser

import (
	"encoding/binary"
	"fmt"
)

const UDPHeaderSize = 8 // fixed-size header: ports (4) + length (2) + checksum (2)

// UDPDatagram holds the decoded UDP header fields.
type UDPDatagram struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16 // total length including header, in bytes
	Checksum uint16
	Payload  []byte
}

// ParseUDP decodes a UDP datagram from raw bytes (starting at the UDP header).
//
// UDP header layout (8 bytes, RFC 768):
//
//	Bytes 0-1: Source Port
//	Bytes 2-3: Destination Port
//	Bytes 4-5: Length (header + data)
//	Bytes 6-7: Checksum
//	Bytes 8+ : Data
func ParseUDP(data []byte) (*UDPDatagram, error) {
	if len(data) < UDPHeaderSize {
		return nil, fmt.Errorf("UDP datagram too short: got %d bytes, need %d",
			len(data), UDPHeaderSize)
	}

	length := binary.BigEndian.Uint16(data[4:6])

	return &UDPDatagram{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   length,
		Checksum: binary.BigEndian.Uint16(data[6:8]),
		Payload:  data[UDPHeaderSize:],
	}, nil
}
