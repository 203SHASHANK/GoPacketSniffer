// Package stats aggregates packet metrics for real-time display.
package stats

import (
	"sync"
	"time"
)

// Snapshot is an immutable copy of Statistics taken at a point in time.
// The display layer reads this without holding any lock.
type Snapshot struct {
	TotalPackets   uint64
	TotalBytes     uint64
	DroppedPackets uint64
	Elapsed        time.Duration
	CurrentBPS     float64 // bytes per second over the last interval
	PeakBPS        float64
	PeakBPSAt      time.Time
	Protocols      map[string]ProtoStats // keyed by "TCP", "UDP", etc.
	TopTalkers     []Talker
	HTTPRequests   uint64
	HTTP2xx        uint64
	HTTP4xx        uint64
	HTTP5xx        uint64
	ActiveFlows    int
}

// ProtoStats holds per-protocol counters.
type ProtoStats struct {
	Packets uint64
	Bytes   uint64
}

// Statistics is the central, goroutine-safe metrics store.
type Statistics struct {
	mu sync.Mutex

	totalPackets   uint64
	totalBytes     uint64
	droppedPackets uint64
	protocols      map[string]*ProtoStats

	// bandwidth tracking
	intervalBytes uint64    // bytes seen since last snapshot
	lastTick      time.Time // time of last GetSnapshot call
	currentBPS    float64
	peakBPS       float64
	peakBPSAt     time.Time

	// HTTP counters
	httpRequests uint64
	http2xx      uint64
	http4xx      uint64
	http5xx      uint64

	startTime   time.Time
	topTalkers  *TopTalkers
	FlowTracker *FlowTracker
}

// New creates a ready-to-use Statistics instance.
func New() *Statistics {
	return &Statistics{
		protocols:   make(map[string]*ProtoStats),
		startTime:   time.Now(),
		lastTick:    time.Now(),
		topTalkers:  newTopTalkers(10),
		FlowTracker: NewFlowTracker(),
	}
}

// Record updates all counters for one decoded packet.
func (s *Statistics) Record(protocol, srcIP string, bytes int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalPackets++
	s.totalBytes += uint64(bytes)
	s.intervalBytes += uint64(bytes)

	if _, ok := s.protocols[protocol]; !ok {
		s.protocols[protocol] = &ProtoStats{}
	}
	s.protocols[protocol].Packets++
	s.protocols[protocol].Bytes += uint64(bytes)

	s.topTalkers.add(srcIP, uint64(bytes))
}

// RecordDrop increments the dropped-packet counter.
func (s *Statistics) RecordDrop() {
	s.mu.Lock()
	s.droppedPackets++
	s.mu.Unlock()
}

// RecordHTTP updates HTTP-specific counters.
func (s *Statistics) RecordHTTP(isRequest bool, statusCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isRequest {
		s.httpRequests++
		return
	}
	switch {
	case statusCode >= 200 && statusCode < 300:
		s.http2xx++
	case statusCode >= 400 && statusCode < 500:
		s.http4xx++
	case statusCode >= 500:
		s.http5xx++
	}
}

// GetSnapshot returns an immutable copy of the current statistics and resets
// the per-interval bandwidth counter.
func (s *Statistics) GetSnapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(s.lastTick).Seconds()
	if elapsed > 0 {
		s.currentBPS = float64(s.intervalBytes) / elapsed
	}
	s.intervalBytes = 0
	s.lastTick = now

	if s.currentBPS > s.peakBPS {
		s.peakBPS = s.currentBPS
		s.peakBPSAt = now
	}

	// Deep-copy protocol map so the caller can read without holding the lock.
	protosCopy := make(map[string]ProtoStats, len(s.protocols))
	for k, v := range s.protocols {
		protosCopy[k] = ProtoStats{Packets: v.Packets, Bytes: v.Bytes}
	}

	return Snapshot{
		TotalPackets:   s.totalPackets,
		TotalBytes:     s.totalBytes,
		DroppedPackets: s.droppedPackets,
		Elapsed:        now.Sub(s.startTime),
		CurrentBPS:     s.currentBPS,
		PeakBPS:        s.peakBPS,
		PeakBPSAt:      s.peakBPSAt,
		Protocols:      protosCopy,
		TopTalkers:     s.topTalkers.topN(),
		HTTPRequests:   s.httpRequests,
		HTTP2xx:        s.http2xx,
		HTTP4xx:        s.http4xx,
		HTTP5xx:        s.http5xx,
		ActiveFlows:    s.FlowTracker.ActiveCount(),
	}
}
