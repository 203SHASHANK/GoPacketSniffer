// Package models defines the data types shared between the parser, the
// statistics engine and the display layer.
package models

import (
	"time"
)

// PacketInfo holds the metadata decoded from one captured frame. Fields that
// belong to a layer the packet does not have are left at their zero value.
type PacketInfo struct {
	Timestamp time.Time // when the frame was read from the socket

	// Link layer
	SrcMAC string
	DstMAC string

	// Network layer
	SrcIP    string
	DstIP    string
	Protocol string // "TCP", "UDP", "ICMP", or "Other" for anything else
	TTL      uint8

	// IsFragment is true for the second and later fragments of a fragmented
	// IP datagram. They carry no transport header, so the port, flag and
	// HTTP fields below are not populated for them.
	IsFragment bool

	// Transport layer (TCP and UDP)
	SrcPort uint16
	DstPort uint16

	// TCP only
	TCPFlags    string // human-readable, e.g. "[SYN,ACK]"
	TCPRawFlags uint8  // raw flags byte, consumed by the flow tracker
	SeqNum      uint32
	AckNum      uint32

	// ICMP only
	ICMPType string // human-readable, e.g. "EchoRequest"

	// Application layer; nil unless the TCP payload looks like HTTP/1.x
	HTTP *HTTPInfo

	// TotalBytes is the length of the whole frame as captured.
	TotalBytes int
}

// HTTPInfo holds fields parsed from the start of an HTTP/1.x request or
// response. Exactly one of IsRequest and IsResponse is set.
type HTTPInfo struct {
	IsRequest  bool
	IsResponse bool

	// Request fields
	Method string
	URL    string
	Host   string

	// Response fields
	StatusCode int
	StatusText string // full status line text, e.g. "200 OK"
}
