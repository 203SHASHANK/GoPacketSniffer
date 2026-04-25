package stats

import (
	"sync"
	"testing"
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
