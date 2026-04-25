package capture

import (
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

	// Buffer is full — next enqueue must fail.
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
