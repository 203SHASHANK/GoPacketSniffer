package stats

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Connection states reported by the flow tracker. This is a simplified view
// of the TCP state machine as seen by a passive observer.
const (
	StateSynSent     = "SYN_SENT"    // SYN seen, no SYN+ACK yet
	StateEstablished = "ESTABLISHED" // handshake completed, or joined mid-stream
	StateClosing     = "CLOSING"     // at least one side has sent FIN
	StateClosed      = "CLOSED"      // RST or completed FIN exchange
)

// TCP flag bits used by the state machine (byte 13 of the TCP header).
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

// Idle limits after which a flow is forgotten. Connections often end without
// the tracker seeing a clean close (lost packets, capture started late, peer
// vanished), so without these the flow table would grow without bound.
const (
	establishedIdleTimeout = 5 * time.Minute
	transientIdleTimeout   = 30 * time.Second // SYN_SENT and CLOSING

	// closedLinger is how long a closed flow is remembered. Stray packets
	// commonly trail a close (the last ACK, retransmissions, duplicates);
	// without this short memory each of them would look like the first
	// packet of a new connection. It plays the role of TCP's TIME_WAIT.
	closedLinger = 10 * time.Second
)

// FiveTuple identifies a connection. The endpoints are stored in a canonical
// order (see normalise), so both directions of a connection share one key.
type FiveTuple struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string
}

// String returns a human-readable form of the key for logging.
func (f FiveTuple) String() string {
	return fmt.Sprintf("%s:%d<->%s:%d/%s", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol)
}

// FlowStats holds per-connection metrics.
type FlowStats struct {
	Packets   uint64
	Bytes     uint64
	StartTime time.Time
	LastSeen  time.Time
	State     string // one of the State* constants

	// finSeen records which side has sent a FIN: index 0 is the endpoint
	// stored as Src in the key, index 1 the one stored as Dst.
	finSeen [2]bool
}

// FlowSnapshot is a point-in-time view of a single flow.
type FlowSnapshot struct {
	Key      FiveTuple
	Packets  uint64
	Bytes    uint64
	Duration time.Duration
	State    string
}

// FlowTracker maintains the table of TCP flows. Closed flows stay in the
// table for closedLinger but are not reported as active. It is safe for
// concurrent use.
type FlowTracker struct {
	mu    sync.Mutex
	flows map[FiveTuple]*FlowStats
	now   func() time.Time // replaceable clock, for tests
}

// NewFlowTracker creates a ready-to-use FlowTracker.
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		flows: make(map[FiveTuple]*FlowStats),
		now:   time.Now,
	}
}

// Update records one packet for the flow it belongs to, creating the flow if
// this is its first packet. flags is the raw TCP flags byte.
func (ft *FlowTracker) Update(srcIP, dstIP string, srcPort, dstPort uint16, proto string, flags uint8, bytes int) {
	key, reversed := normalise(srcIP, dstIP, srcPort, dstPort, proto)
	side := 0
	if reversed {
		side = 1
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	now := ft.now()
	flow, exists := ft.flows[key]

	// A SYN on a closed flow means the same address/port pair is being
	// reused for a new connection, so start counting from scratch.
	reopened := exists && flow.State == StateClosed && flags&flagSYN != 0 && flags&flagRST == 0

	if !exists || reopened {
		// A flow whose first observed packet is not a SYN was already open
		// when the capture started, so it begins as established.
		flow = &FlowStats{StartTime: now, State: StateEstablished}
		ft.flows[key] = flow
	}

	flow.Packets++
	flow.Bytes += uint64(bytes)
	flow.LastSeen = now
	flow.State = nextState(flow, side, flags)
}

// nextState advances the connection state for a packet with the given flags
// sent by side (0 or 1).
func nextState(flow *FlowStats, side int, flags uint8) string {
	if flow.State == StateClosed {
		return StateClosed // trailing packets do not reopen a connection
	}

	switch {
	case flags&flagRST != 0:
		return StateClosed

	case flags&flagFIN != 0:
		flow.finSeen[side] = true
		return StateClosing

	case flags&flagSYN != 0 && flags&flagACK != 0:
		return StateEstablished

	case flags&flagSYN != 0:
		return StateSynSent

	case flow.finSeen[0] && flow.finSeen[1] && flags&flagACK != 0:
		// Both sides have sent FIN and this is the ACK of the second one:
		// the four-way close is complete.
		return StateClosed
	}
	return flow.State
}

// Expire removes flows that have been idle for longer than the limit for
// their state and returns how many were removed. Statistics.GetSnapshot
// calls it on every refresh.
func (ft *FlowTracker) Expire() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	now := ft.now()
	removed := 0
	for key, flow := range ft.flows {
		var limit time.Duration
		switch flow.State {
		case StateEstablished:
			limit = establishedIdleTimeout
		case StateClosed:
			limit = closedLinger
		default:
			limit = transientIdleTimeout
		}
		if now.Sub(flow.LastSeen) > limit {
			delete(ft.flows, key)
			removed++
		}
	}
	return removed
}

// Snapshot returns a copy of all active flows, oldest first.
func (ft *FlowTracker) Snapshot() []FlowSnapshot {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	now := ft.now()
	out := make([]FlowSnapshot, 0, len(ft.flows))
	for k, v := range ft.flows {
		if v.State == StateClosed {
			continue
		}
		out = append(out, FlowSnapshot{
			Key:      k,
			Packets:  v.Packets,
			Bytes:    v.Bytes,
			Duration: now.Sub(v.StartTime),
			State:    v.State,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Duration != out[j].Duration {
			return out[i].Duration > out[j].Duration
		}
		return out[i].Key.String() < out[j].Key.String()
	})
	return out
}

// ActiveCount returns the number of flows that are not closed.
func (ft *FlowTracker) ActiveCount() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	active := 0
	for _, flow := range ft.flows {
		if flow.State != StateClosed {
			active++
		}
	}
	return active
}

// normalise returns the canonical key for a packet, with the smaller
// (IP, port) endpoint first, so that A->B and B->A map to the same flow.
// reversed is true when the packet's source ended up in the Dst fields.
func normalise(srcIP, dstIP string, srcPort, dstPort uint16, proto string) (key FiveTuple, reversed bool) {
	if srcIP < dstIP || (srcIP == dstIP && srcPort <= dstPort) {
		return FiveTuple{srcIP, dstIP, srcPort, dstPort, proto}, false
	}
	return FiveTuple{dstIP, srcIP, dstPort, srcPort, proto}, true
}
