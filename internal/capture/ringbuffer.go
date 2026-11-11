package capture

import (
	"math/bits"
	"sync/atomic"
)

// RingBuffer is a lock-free, single-producer / single-consumer circular
// buffer for passing raw packet bytes between two goroutines.
//
// It is safe only when exactly one goroutine calls Enqueue and exactly one
// goroutine calls Dequeue. The capture pipeline in main currently uses a
// buffered channel instead; the ring buffer is kept as a faster alternative
// for that hand-off.
type RingBuffer struct {
	slots [][]byte
	mask  uint64        // len(slots) - 1, used to wrap indices
	write atomic.Uint64 // total number of packets ever enqueued
	read  atomic.Uint64 // total number of packets ever dequeued
}

// NewRingBuffer creates a RingBuffer that holds at least capacity packets.
//
// The capacity is rounded up to the next power of two so that an index can
// be wrapped with a bitmask instead of a modulo.
func NewRingBuffer(capacity uint64) *RingBuffer {
	if capacity < 2 {
		capacity = 2
	}
	if capacity&(capacity-1) != 0 {
		capacity = 1 << bits.Len64(capacity)
	}
	return &RingBuffer{
		slots: make([][]byte, capacity),
		mask:  capacity - 1,
	}
}

// Enqueue adds a packet to the buffer. It returns false, without storing the
// packet, when the buffer is full.
func (rb *RingBuffer) Enqueue(packet []byte) bool {
	writeIdx := rb.write.Load()
	readIdx := rb.read.Load()

	// The indices only ever grow, so their difference is the fill level.
	if writeIdx-readIdx > rb.mask {
		return false
	}

	// Store the packet before publishing the new write index, so the
	// consumer never observes an index whose slot is not yet filled.
	rb.slots[writeIdx&rb.mask] = packet
	rb.write.Add(1)
	return true
}

// Dequeue removes and returns the oldest packet. It returns nil, false when
// the buffer is empty.
func (rb *RingBuffer) Dequeue() ([]byte, bool) {
	readIdx := rb.read.Load()
	writeIdx := rb.write.Load()

	if readIdx == writeIdx {
		return nil, false
	}

	packet := rb.slots[readIdx&rb.mask]
	rb.slots[readIdx&rb.mask] = nil // drop the reference so the GC can free it
	rb.read.Add(1)
	return packet, true
}

// Len returns the number of packets currently in the buffer.
func (rb *RingBuffer) Len() uint64 {
	return rb.write.Load() - rb.read.Load()
}

// Cap returns the number of packets the buffer can hold.
func (rb *RingBuffer) Cap() uint64 {
	return rb.mask + 1
}
