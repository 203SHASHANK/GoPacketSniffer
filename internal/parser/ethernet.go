// Package parser decodes raw packet bytes into structured protocol types.
package parser

import (
	"encoding/binary"
	"fmt"
	"net"
)

// EtherType constants (bytes 12-13 of the Ethernet header, network byte order).
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86DD

	EthernetHeaderSize = 14 // 6 (dst MAC) + 6 (src MAC) + 2 (EtherType)
)

// EthernetFrame holds the decoded Ethernet II header fields.
type EthernetFrame struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16 // identifies the next-layer protocol
	Payload   []byte // bytes after the 14-byte header
}

// ParseEthernet decodes an Ethernet II frame from raw bytes.
//
// Ethernet II frame layout:
//
//	Bytes 0-5  : Destination MAC address
//	Bytes 6-11 : Source MAC address
//	Bytes 12-13: EtherType (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6)
//	Bytes 14+  : Payload (next protocol layer)
func ParseEthernet(data []byte) (*EthernetFrame, error) {
	if len(data) < EthernetHeaderSize {
		return nil, fmt.Errorf("ethernet frame too short: got %d bytes, need %d",
			len(data), EthernetHeaderSize)
	}

	return &EthernetFrame{
		DstMAC:    net.HardwareAddr(data[0:6]),
		SrcMAC:    net.HardwareAddr(data[6:12]),
		EtherType: binary.BigEndian.Uint16(data[12:14]),
		Payload:   data[EthernetHeaderSize:],
	}, nil
}
