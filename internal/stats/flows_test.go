package stats

import (
	"sync"
	"testing"
	"time"
)

func TestFlowTrackerNewFlow(t *testing.T) {
	ft := NewFlowTracker()
	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x02 /*SYN*/, 60)

	if ft.ActiveCount() != 1 {
		t.Errorf("ActiveCount=%d, want 1", ft.ActiveCount())
	}
}

func TestFlowTrackerStateTransitions(t *testing.T) {
	ft := NewFlowTracker()

	// SYN_SENT, ESTABLISHED, CLOSING, then removed on RST.
	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x02, 60) // SYN
	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x12, 60) // SYN+ACK: ESTABLISHED
	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x01, 60) // FIN: CLOSING
	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x04, 60) // RST: closed

	if ft.ActiveCount() != 0 {
		t.Errorf("expected flow removed after RST, got %d active", ft.ActiveCount())
	}
}

func TestFlowTrackerNormalisation(t *testing.T) {
	ft := NewFlowTracker()
	// Forward and reverse direction should map to the same flow.
	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x02, 60)
	ft.Update("2.2.2.2", "1.1.1.1", 80, 1000, "TCP", 0x12, 60)

	if ft.ActiveCount() != 1 {
		t.Errorf("expected 1 flow (bidirectional), got %d", ft.ActiveCount())
	}
	snaps := ft.Snapshot()
	if snaps[0].Packets != 2 {
		t.Errorf("Packets=%d, want 2", snaps[0].Packets)
	}
}

func TestFlowTrackerConcurrent(t *testing.T) {
	ft := NewFlowTracker()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ft.Update("1.1.1.1", "2.2.2.2", uint16(i+1000), 80, "TCP", 0x02, 60)
		}(i)
	}
	wg.Wait()
	if ft.ActiveCount() != 20 {
		t.Errorf("ActiveCount=%d, want 20", ft.ActiveCount())
	}
}

func TestFlowTrackerMidStreamPickup(t *testing.T) {
	ft := NewFlowTracker()
	// First packet seen is a plain ACK: the connection predates the capture.
	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x10, 60)

	snaps := ft.Snapshot()
	if len(snaps) != 1 || snaps[0].State != StateEstablished {
		t.Fatalf("got %+v, want one ESTABLISHED flow", snaps)
	}
}

func TestFlowTrackerGracefulClose(t *testing.T) {
	ft := NewFlowTracker()
	a, b := "1.1.1.1", "2.2.2.2"

	ft.Update(a, b, 1000, 80, "TCP", 0x02, 60) // SYN
	ft.Update(b, a, 80, 1000, "TCP", 0x12, 60) // SYN+ACK
	ft.Update(a, b, 1000, 80, "TCP", 0x10, 60) // ACK
	ft.Update(a, b, 1000, 80, "TCP", 0x11, 60) // FIN+ACK from client

	if got := ft.Snapshot()[0].State; got != StateClosing {
		t.Fatalf("state after first FIN = %s, want %s", got, StateClosing)
	}

	// The server's ACK of the first FIN must not close the flow: only one
	// side has finished sending.
	ft.Update(b, a, 80, 1000, "TCP", 0x10, 60)
	if ft.ActiveCount() != 1 {
		t.Fatal("flow removed before the second FIN")
	}

	ft.Update(b, a, 80, 1000, "TCP", 0x11, 60) // FIN+ACK from server
	ft.Update(a, b, 1000, 80, "TCP", 0x10, 60) // final ACK
	if ft.ActiveCount() != 0 {
		t.Errorf("flow still active after a complete FIN exchange")
	}

	// A late duplicate ACK must not bring the connection back to life.
	ft.Update(b, a, 80, 1000, "TCP", 0x10, 60)
	if ft.ActiveCount() != 0 {
		t.Errorf("trailing ACK reopened a closed flow")
	}

	// A fresh SYN on the same ports is a new connection.
	ft.Update(a, b, 1000, 80, "TCP", 0x02, 60)
	snaps := ft.Snapshot()
	if len(snaps) != 1 || snaps[0].State != StateSynSent || snaps[0].Packets != 1 {
		t.Errorf("port reuse not tracked as a new flow: %+v", snaps)
	}
}

func TestFlowTrackerClosedFlowsAreForgotten(t *testing.T) {
	ft := NewFlowTracker()
	clock := time.Unix(1700000000, 0)
	ft.now = func() time.Time { return clock }

	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x02, 60)
	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x04, 60) // RST

	clock = clock.Add(closedLinger + time.Second)
	if removed := ft.Expire(); removed != 1 {
		t.Errorf("removed %d closed flows, want 1", removed)
	}
}

func TestFlowTrackerExpire(t *testing.T) {
	ft := NewFlowTracker()
	clock := time.Unix(1700000000, 0)
	ft.now = func() time.Time { return clock }

	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x02, 60) // stays SYN_SENT
	ft.Update("3.3.3.3", "4.4.4.4", 2000, 80, "TCP", 0x10, 60) // ESTABLISHED

	clock = clock.Add(transientIdleTimeout + time.Second)
	if removed := ft.Expire(); removed != 1 {
		t.Errorf("removed %d flows after the transient timeout, want 1", removed)
	}

	clock = clock.Add(establishedIdleTimeout)
	if removed := ft.Expire(); removed != 1 {
		t.Errorf("removed %d flows after the established timeout, want 1", removed)
	}
	if ft.ActiveCount() != 0 {
		t.Errorf("ActiveCount=%d, want 0", ft.ActiveCount())
	}
}

func TestFlowSnapshotOldestFirst(t *testing.T) {
	ft := NewFlowTracker()
	clock := time.Unix(1700000000, 0)
	ft.now = func() time.Time { return clock }

	ft.Update("1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 0x02, 60)
	clock = clock.Add(time.Second)
	ft.Update("1.1.1.1", "2.2.2.2", 1001, 80, "TCP", 0x02, 60)
	clock = clock.Add(time.Second)

	snaps := ft.Snapshot()
	if len(snaps) != 2 || snaps[0].Key.SrcPort != 1000 || snaps[1].Key.SrcPort != 1001 {
		t.Errorf("flows not ordered oldest first: %+v", snaps)
	}
}
