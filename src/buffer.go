package main

import "sync"

type PacketRingBuffer struct {
	packets []*detailedPacket
	size    int
	index   int
	count   int
	mu      sync.Mutex
}

func NewPacketRingBuffer(size int) *PacketRingBuffer {
	return &PacketRingBuffer{
		packets: make([]*detailedPacket, size),
		size:    size,
	}
}

func (r *PacketRingBuffer) Add(p *detailedPacket) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.packets[r.index] = p
	r.index = (r.index + 1) % r.size
	if r.count < r.size {
		r.count++
	}
}

// Snapshot returns all stored packets in chronological order (oldest first).
func (r *PacketRingBuffer) Snapshot() []*detailedPacket {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]*detailedPacket, r.count)
	if r.count < r.size {
		copy(out, r.packets[:r.count])
	} else {
		// buffer has wrapped: oldest entry is at r.index
		n := copy(out, r.packets[r.index:])
		copy(out[n:], r.packets[:r.index])
	}
	return out
}
