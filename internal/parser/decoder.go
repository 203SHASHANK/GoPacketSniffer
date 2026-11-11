package parser

import (
	"fmt"
	"sync"
	"time"

	"gopacketsniffer/internal/models"
)

// packetPool recycles PacketInfo values so the decode path does not allocate
// a new one for every packet.
var packetPool = sync.Pool{
	New: func() any { return new(models.PacketInfo) },
}

// GetPacketInfo returns a zeroed PacketInfo from the pool.
func GetPacketInfo() *models.PacketInfo {
	p, ok := packetPool.Get().(*models.PacketInfo)
	if !ok {
		return new(models.PacketInfo)
	}
	return p
}

// PutPacketInfo zeroes p and returns it to the pool. The caller must not use
// p afterwards.
func PutPacketInfo(p *models.PacketInfo) {
	if p == nil {
		return
	}
	*p = models.PacketInfo{} // clear so the next user never sees stale fields
	packetPool.Put(p)
}

// DecodePacket parses a raw Ethernet frame layer by layer and returns a
// PacketInfo with every field it could extract.
//
// The result comes from a pool: call PutPacketInfo once it is no longer
// needed. On error nothing needs to be returned.
//
// Frames that are not IPv4, and IPv4 packets carrying a protocol other than
// TCP, UDP or ICMP, are reported with Protocol "Other" and a nil error. They
// are valid traffic that this decoder simply does not look into. An error
// means the frame was truncated or malformed.
func DecodePacket(raw []byte, ts time.Time) (*models.PacketInfo, error) {
	info := GetPacketInfo()
	if err := decodeInto(info, raw); err != nil {
		PutPacketInfo(info)
		return nil, err
	}
	info.Timestamp = ts
	info.TotalBytes = len(raw)
	return info, nil
}

// decodeInto fills info from raw, stopping at the first layer it does not
// recognise.
func decodeInto(info *models.PacketInfo, raw []byte) error {
	info.Protocol = "Other"

	// Layer 2: Ethernet
	eth, err := ParseEthernet(raw)
	if err != nil {
		return fmt.Errorf("ethernet: %w", err)
	}
	info.SrcMAC = eth.SrcMAC.String()
	info.DstMAC = eth.DstMAC.String()

	if eth.EtherType != EtherTypeIPv4 {
		return nil // ARP, IPv6, ...
	}

	// Layer 3: IPv4
	ip, err := ParseIPv4(eth.Payload)
	if err != nil {
		return fmt.Errorf("ipv4: %w", err)
	}
	info.SrcIP = ip.SrcIP.String()
	info.DstIP = ip.DstIP.String()
	info.TTL = ip.TTL

	// Later fragments have no transport header: what sits at that position
	// is the middle of the original payload. Account for the packet under
	// its protocol but do not try to decode ports or flags from it.
	if ip.IsLaterFragment() {
		info.IsFragment = true
		switch ip.Protocol {
		case IPProtocolTCP:
			info.Protocol = "TCP"
		case IPProtocolUDP:
			info.Protocol = "UDP"
		case IPProtocolICMP:
			info.Protocol = "ICMP"
		}
		return nil
	}

	// Layer 4: TCP / UDP / ICMP
	switch ip.Protocol {
	case IPProtocolTCP:
		tcp, err := ParseTCP(ip.Payload)
		if err != nil {
			return fmt.Errorf("tcp: %w", err)
		}
		info.Protocol = "TCP"
		info.SrcPort = tcp.SrcPort
		info.DstPort = tcp.DstPort
		info.TCPFlags = tcp.FlagsStr
		info.TCPRawFlags = tcp.Flags
		info.SeqNum = tcp.SeqNum
		info.AckNum = tcp.AckNum

		// Layer 7: HTTP. Best effort; a nil result just means "not HTTP".
		if len(tcp.Payload) > 0 {
			info.HTTP = ParseHTTP(tcp.Payload)
		}

	case IPProtocolUDP:
		udp, err := ParseUDP(ip.Payload)
		if err != nil {
			return fmt.Errorf("udp: %w", err)
		}
		info.Protocol = "UDP"
		info.SrcPort = udp.SrcPort
		info.DstPort = udp.DstPort

	case IPProtocolICMP:
		icmp, err := ParseICMP(ip.Payload)
		if err != nil {
			return fmt.Errorf("icmp: %w", err)
		}
		info.Protocol = "ICMP"
		info.ICMPType = icmp.TypeStr
	}

	return nil
}
