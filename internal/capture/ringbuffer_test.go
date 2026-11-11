package capture

import (
	"encoding/binary"
	"runtime"
	"testing"
)

func TestRingBufferEnqueueDequeue(t *testing.T) {
	rb := NewRingBuffer(4)

	data := []byte("hello")
	if !rb.Enqueue(data) {
		t.Fatal("expected enqueue to succeed on empty buffer")
	}

	got, ok := rb.Dequeue()
	if !ok {
		t.Fatal("expected dequeue to succeed")
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestRingBufferFull(t *testing.T) {
	rb := NewRingBuffer(4)

	for i := 0; i < 4; i++ {
		if !rb.Enqueue([]byte{byte(i)}) {
			t.Fatalf("enqueue %d failed unexpectedly", i)
		}
	}

	// Buffer is full, so the next enqueue must fail.
	if rb.Enqueue([]byte{99}) {
		t.Fatal("expected enqueue to fail on full buffer")
	}
}

func TestRingBufferEmpty(t *testing.T) {
	rb := NewRingBuffer(4)
	_, ok := rb.Dequeue()
	if ok {
		t.Fatal("expected dequeue to fail on empty buffer")
	}
}

func TestRingBufferWrapAround(t *testing.T) {
	rb := NewRingBuffer(4)

	// Fill and drain twice to exercise wrap-around.
	for round := 0; round < 2; round++ {
		for i := 0; i < 4; i++ {
			rb.Enqueue([]byte{byte(i)})
		}
		for i := 0; i < 4; i++ {
			pkt, ok := rb.Dequeue()
			if !ok || pkt[0] != byte(i) {
				t.Fatalf("round %d item %d: got ok=%v val=%v", round, i, ok, pkt)
			}
		}
	}
}

func BenchmarkRingBuffer(b *testing.B) {
	rb := NewRingBuffer(1 << 20) // 1M slots
	data := make([]byte, 1500)   // typical MTU-sized packet

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Enqueue(data)
		rb.Dequeue()
	}
}

func TestRingBufferRoundsCapacityUp(t *testing.T) {
	tests := []struct{ in, want uint64 }{
		{0, 2}, {1, 2}, {2, 2}, {3, 4}, {4, 4}, {5, 8}, {1000, 1024},
	}
	for _, tt := range tests {
		if got := NewRingBuffer(tt.in).Cap(); got != tt.want {
			t.Errorf("NewRingBuffer(%d).Cap() = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestRingBufferConcurrent(t *testing.T) {
	const total = 100000
	rb := NewRingBuffer(64)
	done := make(chan struct{})

	// Single consumer: values must arrive in order with none missing.
	go func() {
		defer close(done)
		for want := 0; want < total; {
			pkt, ok := rb.Dequeue()
			if !ok {
				runtime.Gosched()
				continue
			}
			if got := int(binary.LittleEndian.Uint32(pkt)); got != want {
				t.Errorf("dequeued %d, want %d", got, want)
				return
			}
			want++
		}
	}()

	// Single producer.
	for i := 0; i < total; {
		pkt := make([]byte, 4)
		binary.LittleEndian.PutUint32(pkt, uint32(i))
		if rb.Enqueue(pkt) {
			i++
			continue
		}
		select {
		case <-done:
			return // consumer already failed
		default:
			runtime.Gosched()
		}
	}
	<-done
}
