package parser

import (
	"fmt"
	"sync"
	"time"

	"gopacketsniffer/internal/models"
)

// packetPool reduces GC pressure by reusing PacketInfo allocations in the
// hot decode path. Callers must reset fields before use.
var packetPool = sync.Pool{
	New: func() any { return &models.PacketInfo{} },
}

// GetPacketInfo retrieves a PacketInfo from the pool.
func GetPacketInfo() *models.PacketInfo {
	return packetPool.Get().(*models.PacketInfo)
}

// PutPacketInfo returns a PacketInfo to the pool after zeroing it.
func PutPacketInfo(p *models.PacketInfo) {
	*p = models.PacketInfo{} // zero all fields
	packetPool.Put(p)
}

// DecodePacket parses a raw Ethernet frame through all protocol layers and
// returns a PacketInfo with every extracted field populated.
//
// The returned *PacketInfo is owned by the caller. When done, call
// PutPacketInfo to return it to the pool.
//
// Unsupported EtherTypes or IP protocols are recorded with Protocol="Other"
// and no error is returned — unknown traffic is valid, just unrecognised.
func DecodePacket(raw []byte, ts time.Time) (*models.PacketInfo, error) {
	info := GetPacketInfo()
	info.Timestamp = ts
	info.TotalBytes = len(raw)
	info.Protocol = "Other"

	// --- Layer 2: Ethernet ---
	eth, err := ParseEthernet(raw)
	if err != nil {
		PutPacketInfo(info)
		return nil, fmt.Errorf("ethernet: %w", err)
	}
	info.SrcMAC = eth.SrcMAC.String()
	info.DstMAC = eth.DstMAC.String()

	if eth.EtherType != EtherTypeIPv4 {
		return info, nil
	}

	// --- Layer 3: IPv4 ---
	ip, err := ParseIPv4(eth.Payload)
	if err != nil {
		PutPacketInfo(info)
		return nil, fmt.Errorf("ipv4: %w", err)
	}
	info.SrcIP = ip.SrcIP.String()
	info.DstIP = ip.DstIP.String()
	info.TTL = ip.TTL

	// --- Layer 4: TCP / UDP / ICMP ---
	switch ip.Protocol {
	case IPProtocolTCP:
		info.Protocol = "TCP"
		tcp, err := ParseTCP(ip.Payload)
		if err != nil {
			PutPacketInfo(info)
			return nil, fmt.Errorf("tcp: %w", err)
		}
		info.SrcPort = tcp.SrcPort
		info.DstPort = tcp.DstPort
		info.TCPFlags = tcp.FlagsStr
		info.TCPRawFlags = tcp.Flags
		info.SeqNum = tcp.SeqNum
		info.AckNum = tcp.AckNum

		// --- Layer 7: HTTP (best-effort, no error on failure) ---
		if len(tcp.Payload) > 0 {
			info.HTTP = ParseHTTP(tcp.Payload)
		}

	case IPProtocolUDP:
		info.Protocol = "UDP"
		udp, err := ParseUDP(ip.Payload)
		if err != nil {
			PutPacketInfo(info)
			return nil, fmt.Errorf("udp: %w", err)
		}
		info.SrcPort = udp.SrcPort
		info.DstPort = udp.DstPort

	case IPProtocolICMP:
		info.Protocol = "ICMP"
		icmp, err := ParseICMP(ip.Payload)
		if err != nil {
			PutPacketInfo(info)
			return nil, fmt.Errorf("icmp: %w", err)
		}
		info.TCPFlags = icmp.TypeStr
	}

	return info, nil
}
