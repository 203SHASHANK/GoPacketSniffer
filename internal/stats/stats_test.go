package stats

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRecordAndSnapshot(t *testing.T) {
	s := New()
	s.Record("TCP", "1.2.3.4", 100)
	s.Record("TCP", "1.2.3.4", 200)
	s.Record("UDP", "5.6.7.8", 50)

	snap := s.GetSnapshot()

	if snap.TotalPackets != 3 {
		t.Errorf("TotalPackets=%d, want 3", snap.TotalPackets)
	}
	if snap.TotalBytes != 350 {
		t.Errorf("TotalBytes=%d, want 350", snap.TotalBytes)
	}
	if snap.Protocols["TCP"].Packets != 2 {
		t.Errorf("TCP packets=%d, want 2", snap.Protocols["TCP"].Packets)
	}
	if snap.Protocols["UDP"].Bytes != 50 {
		t.Errorf("UDP bytes=%d, want 50", snap.Protocols["UDP"].Bytes)
	}
}

func TestConcurrentRecord(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	const goroutines = 10
	const recordsEach = 1000

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < recordsEach; j++ {
				s.Record("TCP", "1.1.1.1", 64)
			}
		}()
	}
	wg.Wait()

	snap := s.GetSnapshot()
	want := uint64(goroutines * recordsEach)
	if snap.TotalPackets != want {
		t.Errorf("TotalPackets=%d, want %d", snap.TotalPackets, want)
	}
}

func TestTopTalkers(t *testing.T) {
	s := New()
	s.Record("TCP", "10.0.0.1", 1000)
	s.Record("TCP", "10.0.0.2", 5000)
	s.Record("TCP", "10.0.0.3", 500)

	snap := s.GetSnapshot()
	if len(snap.TopTalkers) == 0 {
		t.Fatal("expected top talkers, got none")
	}
	if snap.TopTalkers[0].IP != "10.0.0.2" {
		t.Errorf("top talker=%s, want 10.0.0.2", snap.TopTalkers[0].IP)
	}
}

func TestDropCounter(t *testing.T) {
	s := New()
	s.RecordDrop()
	s.RecordDrop()
	snap := s.GetSnapshot()
	if snap.DroppedPackets != 2 {
		t.Errorf("DroppedPackets=%d, want 2", snap.DroppedPackets)
	}
}

func TestBandwidthIsBitsPerSecond(t *testing.T) {
	s := New()
	// Pretend the interval started exactly one second ago.
	s.lastTick = time.Now().Add(-time.Second)
	s.Record("TCP", "1.1.1.1", 1000)

	snap := s.GetSnapshot()
	// 1000 bytes in ~1s is ~8000 bit/s; allow for scheduling jitter.
	if snap.CurrentBPS < 7000 || snap.CurrentBPS > 8000 {
		t.Errorf("CurrentBPS=%.0f, want about 8000", snap.CurrentBPS)
	}
	if snap.PeakBPS != snap.CurrentBPS || snap.PeakBPSAt.IsZero() {
		t.Errorf("peak not recorded: %.0f at %v", snap.PeakBPS, snap.PeakBPSAt)
	}
}

func TestRecordHTTP(t *testing.T) {
	s := New()
	s.RecordHTTP(true, 0)
	for _, code := range []int{200, 204, 301, 404, 500, 503} {
		s.RecordHTTP(false, code)
	}

	snap := s.GetSnapshot()
	if snap.HTTPRequests != 1 || snap.HTTP2xx != 2 || snap.HTTP4xx != 1 || snap.HTTP5xx != 2 {
		t.Errorf("requests=%d 2xx=%d 4xx=%d 5xx=%d, want 1/2/1/2",
			snap.HTTPRequests, snap.HTTP2xx, snap.HTTP4xx, snap.HTTP5xx)
	}
}

func TestTopTalkersStableOrderOnTies(t *testing.T) {
	s := New()
	for _, ip := range []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"} {
		s.Record("UDP", ip, 100)
	}
	got := s.GetSnapshot().TopTalkers
	for i, want := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if got[i].IP != want {
			t.Fatalf("talker %d = %s, want %s", i, got[i].IP, want)
		}
	}
}

func TestTopTalkersBounded(t *testing.T) {
	tt := newTopTalkers(3)
	tt.limit = 8

	tt.add("heavy", 1_000_000)
	for i := 0; i < 100; i++ {
		tt.add(fmt.Sprintf("10.0.0.%d", i), 1)
	}

	if len(tt.counts) > tt.limit {
		t.Errorf("tracking %d addresses, limit is %d", len(tt.counts), tt.limit)
	}
	if top := tt.topN(); len(top) == 0 || top[0].IP != "heavy" {
		t.Errorf("heaviest talker lost during pruning: %+v", top)
	}
}
