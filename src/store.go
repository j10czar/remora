package main

import (
	"sync"

	"github.com/google/gopacket"
)

//ring buffer of sorts of size 1000 that evicts the oldest packet once the window size is reached

const MaxPackets = 1000

type PacketRingBuffer struct {
	packets [MaxPackets]gopacket.Packet
	index   int
	count   int
	mu      sync.Mutex
}

func (s *PacketRingBuffer) Add(p gopacket.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.packets[s.index] = p
	s.index = (s.index + 1) % MaxPackets
	if s.count < MaxPackets {
		s.count++
	}
}
