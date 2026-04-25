package models

import (
	"time"
)

// PacketInfo holds decoded metadata extracted from a raw packet.
type PacketInfo struct {
	Timestamp time.Time

	// Ethernet
	SrcMAC string
	DstMAC string

	// Network
	SrcIP    string
	DstIP    string
	Protocol string // "TCP", "UDP", "ICMP", "ARP", "Other"
	TTL      uint8

	// Transport
	SrcPort uint16
	DstPort uint16

	// TCP-specific
	TCPFlags    string // human-readable e.g. "[SYN,ACK]"
	TCPRawFlags uint8  // raw flags byte for flow tracker
	SeqNum      uint32
	AckNum      uint32

	// Application layer (nil if not detected)
	HTTP *HTTPInfo

	// Sizes
	TotalBytes int
}

// HTTPInfo holds fields parsed from an HTTP/1.x request or response.
// Populated only when the TCP payload looks like HTTP.
type HTTPInfo struct {
	IsRequest  bool
	IsResponse bool

	// Request
	Method string
	URL    string
	Host   string

	// Response
	StatusCode int
	StatusText string
}
