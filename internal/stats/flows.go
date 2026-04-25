package stats

import (
	"fmt"
	"sync"
	"time"
)

// FiveTuple uniquely identifies a TCP connection.
// We normalise direction so (A→B) and (B→A) map to the same key.
type FiveTuple struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string
}

// FlowStats holds per-connection metrics.
type FlowStats struct {
	Packets   uint64
	Bytes     uint64
	StartTime time.Time
	LastSeen  time.Time
	State     string // "SYN_SENT", "ESTABLISHED", "CLOSING", "CLOSED"
}

// FlowSnapshot is a point-in-time view of a single flow.
type FlowSnapshot struct {
	Key      FiveTuple
	Packets  uint64
	Bytes    uint64
	Duration time.Duration
	State    string
}

// FlowTracker maintains a map of active TCP flows.
type FlowTracker struct {
	mu    sync.Mutex
	flows map[FiveTuple]*FlowStats
}

// NewFlowTracker creates a ready-to-use FlowTracker.
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{flows: make(map[FiveTuple]*FlowStats)}
}

// Update records a packet for the given flow, creating it if new.
// flags is the raw TCP flags byte.
func (ft *FlowTracker) Update(srcIP, dstIP string, srcPort, dstPort uint16, proto string, flags uint8, bytes int) {
	key := normalise(srcIP, dstIP, srcPort, dstPort, proto)

	ft.mu.Lock()
	defer ft.mu.Unlock()

	flow, exists := ft.flows[key]
	if !exists {
		flow = &FlowStats{StartTime: time.Now(), State: "SYN_SENT"}
		ft.flows[key] = flow
	}

	flow.Packets++
	flow.Bytes += uint64(bytes)
	flow.LastSeen = time.Now()
	flow.State = tcpState(flow.State, flags)

	// Remove closed flows to keep the map bounded.
	if flow.State == "CLOSED" {
		delete(ft.flows, key)
	}
}

// Snapshot returns a slice of all active flows sorted by start time.
func (ft *FlowTracker) Snapshot() []FlowSnapshot {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	out := make([]FlowSnapshot, 0, len(ft.flows))
	for k, v := range ft.flows {
		out = append(out, FlowSnapshot{
			Key:      k,
			Packets:  v.Packets,
			Bytes:    v.Bytes,
			Duration: time.Since(v.StartTime),
			State:    v.State,
		})
	}
	return out
}

// ActiveCount returns the number of currently tracked flows.
func (ft *FlowTracker) ActiveCount() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return len(ft.flows)
}

// normalise returns a canonical FiveTuple regardless of packet direction.
func normalise(srcIP, dstIP string, srcPort, dstPort uint16, proto string) FiveTuple {
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return FiveTuple{srcIP, dstIP, srcPort, dstPort, proto}
	}
	return FiveTuple{dstIP, srcIP, dstPort, srcPort, proto}
}

// tcpState advances the connection state machine based on TCP flags.
func tcpState(current string, flags uint8) string {
	const (
		flagFIN = 0x01
		flagSYN = 0x02
		flagRST = 0x04
		flagACK = 0x10
	)

	switch {
	case flags&flagRST != 0:
		return "CLOSED"
	case flags&flagFIN != 0:
		return "CLOSING"
	case flags&flagSYN != 0 && flags&flagACK != 0:
		return "ESTABLISHED"
	case flags&flagSYN != 0:
		return "SYN_SENT"
	default:
		return current
	}
}

// String returns a human-readable key for logging.
func (f FiveTuple) String() string {
	return fmt.Sprintf("%s:%d↔%s:%d/%s", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol)
}
