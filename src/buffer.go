package main

import "sync"

// PacketRingBuffer is the application's single source of truth for captured
// packets. It's a fixed-capacity ring with monotonic global IDs.
//
// Why global IDs?
//   The buffer wraps once it fills up — slot 0 will eventually be reused for
//   a brand-new packet. If the inspect/edit pages remembered "slot 0", they
//   could end up looking at a different packet than the user selected. So
//   every Add() assigns the new packet a global ID that never repeats:
//   packet #0 is the first one ever captured, packet #1 the second, and so
//   on. Pages remember IDs; the buffer translates them back to slots and
//   reports honestly when a packet has been evicted.
//
// Concurrency:
//   Add() runs on the bubbletea command goroutine that drains the pcap
//   channel. Snapshot() and At() run on the bubbletea Update goroutine
//   when pages render or navigate. The RWMutex lets reads run in parallel
//   while writes serialize.
type PacketRingBuffer struct {
	packets []*detailedPacket
	size    uint64
	total   uint64 // total packets ever added; also the global ID assigned to the next Add
	mu      sync.RWMutex
}

// NewPacketRingBuffer allocates a buffer with room for `size` packets.
// Older entries are silently overwritten once the buffer is full.
func NewPacketRingBuffer(size int) *PacketRingBuffer {
	return &PacketRingBuffer{
		packets: make([]*detailedPacket, size),
		size:    uint64(size),
	}
}

// Add stores a packet and returns the global ID assigned to it. The caller
// (the root model on packetMsg) doesn't usually need the ID, but tests do.
func (r *PacketRingBuffer) Add(p *detailedPacket) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := r.total
	r.packets[id%r.size] = p
	r.total++
	return id
}

// At looks a packet up by global ID. The second return value is false if
// the packet was never seen (id >= total) or has been evicted from the
// window (id is older than the oldest entry still buffered). Callers should
// treat the false case as "the packet you wanted is no longer available"
// and surface that to the user — don't dereference the nil pointer.
func (r *PacketRingBuffer) At(id uint64) (*detailedPacket, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if id >= r.total {
		return nil, false
	}
	if r.total > r.size && id < r.total-r.size {
		return nil, false
	}
	return r.packets[id%r.size], true
}

// Snapshot returns every packet currently in the window in chronological
// order (oldest first), along with the global ID of the first (oldest)
// entry. Row N of the returned slice has global ID firstID + N — that
// mapping is how the capture page's table cursor turns into a stable
// reference for the inspect/edit pages.
func (r *PacketRingBuffer) Snapshot() (packets []*detailedPacket, firstID uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.total == 0 {
		return nil, 0
	}

	var n uint64
	if r.total <= r.size {
		firstID = 0
		n = r.total
	} else {
		firstID = r.total - r.size
		n = r.size
	}

	packets = make([]*detailedPacket, n)
	for i := uint64(0); i < n; i++ {
		packets[i] = r.packets[(firstID+i)%r.size]
	}
	return packets, firstID
}

// Total returns the lifetime count of packets ever added (including those
// already evicted). Useful for the footer's "packets seen" stat.
func (r *PacketRingBuffer) Total() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.total
}

// Len is the number of packets currently in the window — Total() until the
// buffer fills, then capped at size after it wraps. Useful for showing "X of
// Y in buffer" when a UI is rendering a filtered subset.
func (r *PacketRingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.total < r.size {
		return int(r.total)
	}
	return int(r.size)
}

// Reset empties the buffer and resets the global ID counter. The capture
// page's "clear" hotkey calls this; ID #0 will start over from the next
// Add() so the user gets a clean view.
func (r *PacketRingBuffer) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.packets {
		r.packets[i] = nil
	}
	r.total = 0
}
