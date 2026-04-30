package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// savesRoot is the parent directory under the working dir where every
// timestamped save folder is created. Each save call mints a fresh
// subdirectory so concurrent saves never collide.
const savesRoot = "saves"

// SavePacket writes a single detailedPacket to its own timestamped
// directory under saves/ as a standard libpcap file. The returned path
// points at the .pcap so callers can show it to the user.
func SavePacket(p *detailedPacket) (string, error) {
	if p == nil || p.Raw == nil {
		return "", fmt.Errorf("save: nil packet")
	}

	dir, err := makeStampedDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "packet.pcap")
	return path, writePcap(path, []*detailedPacket{p})
}

// SavePackets writes every packet whose global ID is listed in `ids` to a
// single pcap file in a fresh timestamped directory under saves/. IDs that
// have been evicted from the ring or were never captured are skipped
// silently — the resulting file contains only the packets still available.
func SavePackets(ids []uint64, buf *PacketRingBuffer) (string, error) {
	if buf == nil {
		return "", fmt.Errorf("save: nil buffer")
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("save: no packets to save")
	}

	packets := make([]*detailedPacket, 0, len(ids))
	for _, id := range ids {
		if p, ok := buf.At(id); ok && p != nil && p.Raw != nil {
			packets = append(packets, p)
		}
	}
	if len(packets) == 0 {
		return "", fmt.Errorf("save: none of the requested packets are still in the buffer")
	}

	dir, err := makeStampedDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "packets.pcap")
	return path, writePcap(path, packets)
}

// writePcap is the shared body that opens the file, writes the libpcap
// header, and appends each packet's raw bytes with its original capture
// metadata.
func writePcap(path string, packets []*detailedPacket) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return err
	}

	for _, p := range packets {
		data := p.Raw.Data()
		ci := gopacket.CaptureInfo{
			Timestamp:     p.Timestamp,
			CaptureLength: len(data),
			Length:        p.WireLength,
		}
		if err := w.WritePacket(ci, data); err != nil {
			return err
		}
	}
	return nil
}

// makeStampedDir creates `saves/<YYYY-MM-DD_HH-MM-SS.mmm>` and returns its
// path. Millisecond precision keeps two saves within the same second from
// landing in the same directory.
func makeStampedDir() (string, error) {
	stamp := time.Now().Format("2006-01-02_15-04-05.000")
	dir := filepath.Join(savesRoot, stamp)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}
