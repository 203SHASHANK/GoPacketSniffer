package capture

import (
	"sync/atomic"
)

// RingBuffer is a lock-free, single-producer / single-consumer circular buffer
// for passing raw packet bytes from the capture goroutine to parse workers.
//
// Size must be a power of two so the modulo can be replaced with a bitmask.
type RingBuffer struct {
	slots [][]byte
	mask  uint64
	write atomic.Uint64 // next write index
	read  atomic.Uint64 // next read index
}

// NewRingBuffer creates a RingBuffer with the given capacity.
// capacity must be a power of two (e.g. 1024, 65536, 1<<20).
func NewRingBuffer(capacity uint64) *RingBuffer {
	return &RingBuffer{
		slots: make([][]byte, capacity),
		mask:  capacity - 1,
	}
}

// Enqueue adds a packet to the buffer. Returns false if the buffer is full
// (packet is dropped — caller should increment a drop counter).
func (rb *RingBuffer) Enqueue(packet []byte) bool {
	writeIdx := rb.write.Load()
	readIdx := rb.read.Load()

	// Buffer is full when write is exactly one lap ahead of read.
	if writeIdx-readIdx > rb.mask {
		return false
	}

	rb.slots[writeIdx&rb.mask] = packet
	rb.write.Add(1)
	return true
}

// Dequeue removes and returns the next packet. Returns nil, false if empty.
func (rb *RingBuffer) Dequeue() ([]byte, bool) {
	readIdx := rb.read.Load()
	writeIdx := rb.write.Load()

	if readIdx == writeIdx {
		return nil, false // empty
	}

	packet := rb.slots[readIdx&rb.mask]
	rb.slots[readIdx&rb.mask] = nil // release reference for GC
	rb.read.Add(1)
	return packet, true
}

// Len returns the number of packets currently in the buffer.
func (rb *RingBuffer) Len() uint64 {
	return rb.write.Load() - rb.read.Load()
}
