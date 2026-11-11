// Package stats aggregates packet metrics for real-time display.
package stats

import (
	"sync"
	"time"
)

// Snapshot is an independent copy of Statistics taken at a point in time.
// The display layer reads it without holding any lock.
type Snapshot struct {
	TotalPackets   uint64
	TotalBytes     uint64
	DroppedPackets uint64 // frames lost to a full queue or failed decoding
	Elapsed        time.Duration
	CurrentBPS     float64               // bits per second over the last interval
	PeakBPS        float64               // highest CurrentBPS seen so far
	PeakBPSAt      time.Time             // zero until some traffic has been seen
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

// Statistics is the central metrics store. All methods are safe for
// concurrent use; mu guards every unexported field.
type Statistics struct {
	mu sync.Mutex

	totalPackets   uint64
	totalBytes     uint64
	droppedPackets uint64
	protocols      map[string]*ProtoStats

	// bandwidth tracking
	intervalBytes uint64    // bytes seen since the last GetSnapshot call
	lastTick      time.Time // time of the last GetSnapshot call
	currentBPS    float64   // bits per second
	peakBPS       float64
	peakBPSAt     time.Time

	// HTTP counters
	httpRequests uint64
	http2xx      uint64
	http4xx      uint64
	http5xx      uint64

	startTime  time.Time
	topTalkers *TopTalkers

	// FlowTracker has its own lock and may be used directly.
	FlowTracker *FlowTracker
}

// New creates a ready-to-use Statistics instance.
func New() *Statistics {
	now := time.Now()
	return &Statistics{
		protocols:   make(map[string]*ProtoStats),
		startTime:   now,
		lastTick:    now,
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

	ps, ok := s.protocols[protocol]
	if !ok {
		ps = &ProtoStats{}
		s.protocols[protocol] = ps
	}
	ps.Packets++
	ps.Bytes += uint64(bytes)

	s.topTalkers.add(srcIP, uint64(bytes))
}

// RecordDrop counts one frame that was captured but could not be processed,
// either because the queue to the parser was full or because it was
// malformed.
func (s *Statistics) RecordDrop() {
	s.mu.Lock()
	s.droppedPackets++
	s.mu.Unlock()
}

// RecordHTTP counts one HTTP message: a request when isRequest is true,
// otherwise a response bucketed by the class of statusCode. 1xx and 3xx
// responses are not shown on the dashboard and are not counted.
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

// GetSnapshot returns a copy of the current statistics.
//
// It also closes the current bandwidth interval: the rate reported is the
// traffic seen since the previous call, so the caller's polling period is
// the averaging window. Calling it from more than one place would shorten
// that window and skew the reading.
func (s *Statistics) GetSnapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if elapsed := now.Sub(s.lastTick).Seconds(); elapsed > 0 {
		s.currentBPS = float64(s.intervalBytes) * 8 / elapsed
	}
	s.intervalBytes = 0
	s.lastTick = now

	if s.currentBPS > s.peakBPS {
		s.peakBPS = s.currentBPS
		s.peakBPSAt = now
	}

	// Drop flows that went quiet without a visible close.
	s.FlowTracker.Expire()

	// Copy the protocol map so the caller can read it after the lock is
	// released while Record keeps updating the original.
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
