package main

import (
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Capture struct {
	handle *pcap.Handle
	device string
}

type Packet struct {
	metadata string
}

func detectTCPProtocol(srcPort, dstPort uint16) string {
	ports := map[uint16]string{
		21:   "FTP",
		22:   "SSH",
		25:   "SMTP",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		3306: "MySQL",
		5432: "PostgreSQL",
		6379: "Redis",
		8080: "HTTP-ALT",
	}
	if proto, ok := ports[dstPort]; ok {
		return proto
	}
	if proto, ok := ports[srcPort]; ok {
		return proto
	}
	return ""
}

func detectUDPProtocol(srcPort, dstPort uint16) string {
	ports := map[uint16]string{
		53:   "DNS",
		67:   "DHCP",
		68:   "DHCP",
		69:   "TFTP",
		123:  "NTP",
		161:  "SNMP",
		162:  "SNMP",
		514:  "Syslog",
		4789: "VXLAN",
		5353: "mDNS",
	}
	if proto, ok := ports[dstPort]; ok {
		return proto
	}
	if proto, ok := ports[srcPort]; ok {
		return proto
	}
	return ""
}

func inspectPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}

	s := string(payload[:min(len(payload), 8)])

	switch {
	case strings.HasPrefix(s, "GET "),
		strings.HasPrefix(s, "POST "),
		strings.HasPrefix(s, "HTTP/"):
		return "HTTP"
	case strings.HasPrefix(s, "SSH-"):
		return "SSH"
	}

	// DNS — check UDP port 53 payload structure
	// first two bytes are transaction ID, safer to combine with port check
	return ""
}

// detailedPacket is a richer view of a captured packet than PacketSummary.
// PacketSummary is the trimmed-down version used by the TUI;
// detailedPacket keeps every field needed to reconstruct and retransmit a
// modified copy of the packet — all layer values are stored as their native
// gopacket types rather than display strings.
type detailedPacket struct {
	// metadata
	Timestamp     time.Time
	CaptureLength int
	WireLength    int

	// ethernet (link layer)
	SrcMAC       net.HardwareAddr
	DstMAC       net.HardwareAddr
	EthernetType layers.EthernetType // e.g. layers.EthernetTypeIPv4

	// network layer — only one of the two blocks below is populated
	NetworkType string // "IPv4", "IPv6", or ""
	SrcIP       net.IP
	DstIP       net.IP

	// IPv4-specific
	IPv4ID        uint16
	IPv4TOS       uint8
	IPv4Flags     layers.IPv4Flag // DF, MF
	IPv4FragOffset uint16
	IPv4TTL       uint8
	IPv4Protocol  layers.IPProtocol // TCP, UDP, ICMP …

	// IPv6-specific
	IPv6HopLimit     uint8
	IPv6TrafficClass uint8
	IPv6FlowLabel    uint32
	IPv6NextHeader   layers.IPProtocol

	// application layer
	ApplicationProtocol string

	// transport layer (TCP or UDP)
	TransportType string // "TCP", "UDP", or ""
	SrcPort       uint16
	DstPort       uint16

	// TCP-specific (zero / nil on UDP / non-TCP)
	Seq        uint32
	Ack        uint32
	SYN        bool
	ACK        bool
	FIN        bool
	RST        bool
	PSH        bool
	URG        bool
	Window     uint16
	TCPOptions []layers.TCPOption // MSS, SACK, timestamps, window-scale …

	// payload bytes from the transport layer
	Payload []byte

	// raw packet preserved as a fast path for unmodified retransmit
	Raw gopacket.Packet
}

// toDetailedPacket walks the layers of a gopacket.Packet and copies the
// interesting fields into a detailedPacket. Layers that aren't present are
// just left as zero values.
func toDetailedPacket(packet gopacket.Packet) *detailedPacket {
	d := &detailedPacket{
		Timestamp:     packet.Metadata().Timestamp,
		CaptureLength: packet.Metadata().CaptureLength,
		WireLength:    packet.Metadata().Length,
		Raw:           packet,
	}

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		d.SrcMAC = eth.SrcMAC
		d.DstMAC = eth.DstMAC
		d.EthernetType = eth.EthernetType
	}

	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4, _ := ip4Layer.(*layers.IPv4)
		d.NetworkType = "IPv4"
		d.SrcIP = ip4.SrcIP
		d.DstIP = ip4.DstIP
		d.IPv4ID = ip4.Id
		d.IPv4TOS = ip4.TOS
		d.IPv4Flags = ip4.Flags
		d.IPv4FragOffset = ip4.FragOffset
		d.IPv4TTL = ip4.TTL
		d.IPv4Protocol = ip4.Protocol
	}

	if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		d.NetworkType = "IPv6"
		d.SrcIP = ip6.SrcIP
		d.DstIP = ip6.DstIP
		d.IPv6HopLimit = ip6.HopLimit
		d.IPv6TrafficClass = ip6.TrafficClass
		d.IPv6FlowLabel = ip6.FlowLabel
		d.IPv6NextHeader = ip6.NextHeader
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		d.TransportType = "TCP"
		d.SrcPort = uint16(tcp.SrcPort)
		d.DstPort = uint16(tcp.DstPort)
		d.Seq = tcp.Seq
		d.Ack = tcp.Ack
		d.SYN = tcp.SYN
		d.ACK = tcp.ACK
		d.FIN = tcp.FIN
		d.RST = tcp.RST
		d.PSH = tcp.PSH
		d.URG = tcp.URG
		d.Window = tcp.Window
		d.TCPOptions = tcp.Options
		d.Payload = tcp.Payload
		d.ApplicationProtocol = inspectPayload(tcp.Payload)
		if d.ApplicationProtocol == "" {
			d.ApplicationProtocol = detectTCPProtocol(d.SrcPort, d.DstPort)
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		d.TransportType = "UDP"
		d.SrcPort = uint16(udp.SrcPort)
		d.DstPort = uint16(udp.DstPort)
		d.Payload = udp.Payload
		d.ApplicationProtocol = detectUDPProtocol(d.SrcPort, d.DstPort)
	}

	return d
}

// PacketSummary is the trimmed-down view used by the TUI: just enough fields
// to render one row in the table.
type PacketSummary struct {
	// metadata
	Timestamp time.Time
	Length    int

	// network
	SrcIP net.IP
	DstIP net.IP

	//application
	ApplicationProtocol string

	// transport
	TransportProtocol string
	SrcPort           uint16
	DstPort           uint16

	// payload
	Payload []byte

	// keep the original for anything you didn't extract
	Raw gopacket.Packet
}

// InterpretPacketInterface pulls the fields the TUI needs out of a raw
// gopacket.Packet and returns a PacketSummary.
func toSummaryPacket(packet gopacket.Packet) *PacketSummary {
	info := &PacketSummary{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		Raw:       packet,
	}

	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4, _ := ip4Layer.(*layers.IPv4)
		info.SrcIP = ip4.SrcIP
		info.DstIP = ip4.DstIP
		info.TransportProtocol = ip4.Protocol.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
		info.Payload = tcp.Payload
		info.ApplicationProtocol = inspectPayload(tcp.Payload)
		if info.ApplicationProtocol == "" {
			info.ApplicationProtocol = detectTCPProtocol(info.SrcPort, info.DstPort)
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
		info.Payload = udp.Payload
		info.ApplicationProtocol = detectUDPProtocol(info.SrcPort, info.DstPort)
	}

	return info
}

// we are returning a capture pointer
func NewCapture(device string) *Capture {
	//get address to capture struct being returned
	return &Capture{
		device: device,
	}
}

func (c *Capture) Start() {
	handle, err := pcap.OpenLive(c.device, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	c.handle = handle
}

func (c *Capture) Stop() {
	// safe to call even if Start was never called (handle stays nil).
	if c.handle != nil {
		c.handle.Close()
	}
}

// <- means that im giving you a channel that you can only receive from not write
func (c *Capture) Output() <-chan gopacket.Packet {

	packetChannel := make(chan gopacket.Packet)

	// go routine (thread) to feed packets into our channel

	go func() {
		defer close(packetChannel)

		source := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
		for packet := range source.Packets() {
			packetChannel <- packet
		}

	}()
	return packetChannel
}

// =============================================================================
// TOP LEVEL — gopacket.Packet methods
// =============================================================================
// packet.Metadata()          → timestamp, length, capture length
// packet.Layers()            → []gopacket.Layer, every layer in the packet
// packet.Layer(type)         → a specific layer by type
// packet.NetworkLayer()      → the IP layer (IPv4 or IPv6)
// packet.TransportLayer()    → the TCP/UDP layer
// packet.ApplicationLayer()  → the payload/data layer
// packet.LinkLayer()         → the Ethernet layer
// packet.ErrorLayer()        → non-nil if packet was malformed
// =============================================================================

// =============================================================================
// METADATA
// =============================================================================
// meta := packet.Metadata()
// meta.Timestamp             → time.Time — when the packet was captured
// meta.Length                → int — original length on the wire
// meta.CaptureLength         → int — how many bytes were actually captured
// =============================================================================

// =============================================================================
// ETHERNET (Layer 1)
// =============================================================================
// ethLayer := packet.Layer(layers.LayerTypeEthernet)
// if ethLayer != nil {
//     eth, ok := ethLayer.(*layers.Ethernet)
//     eth.SrcMAC              → net.HardwareAddr
//     eth.DstMAC              → net.HardwareAddr
//     eth.EthernetType        → layers.EthernetType (IPv4, IPv6, ARP...)
// }
// =============================================================================

// =============================================================================
// IPv4 (Layer 2)
// =============================================================================
// ip4Layer := packet.Layer(layers.LayerTypeIPv4)
// if ip4Layer != nil {
//     ip4, ok := ip4Layer.(*layers.IPv4)
//     ip4.SrcIP               → net.IP
//     ip4.DstIP               → net.IP
//     ip4.TTL                 → uint8
//     ip4.Protocol            → layers.IPProtocol (TCP, UDP, ICMP...)
//     ip4.Length              → uint16
//     ip4.TOS                 → uint8 — type of service
//     ip4.Flags               → layers.IPv4Flag (DF, MF...)
// }
// =============================================================================

// =============================================================================
// IPv6 (Layer 2)
// =============================================================================
// ip6Layer := packet.Layer(layers.LayerTypeIPv6)
// if ip6Layer != nil {
//     ip6, ok := ip6Layer.(*layers.IPv6)
//     ip6.SrcIP               → net.IP
//     ip6.DstIP               → net.IP
//     ip6.HopLimit            → uint8 (same as TTL in IPv4)
//     ip6.Length              → uint16
//     ip6.NextHeader          → layers.IPProtocol
//     ip6.TrafficClass        → uint8
//     ip6.FlowLabel           → uint32
// }
// =============================================================================

// =============================================================================
// TCP (Layer 3)
// =============================================================================
// tcpLayer := packet.Layer(layers.LayerTypeTCP)
// if tcpLayer != nil {
//     tcp, ok := tcpLayer.(*layers.TCP)
//     tcp.SrcPort             → layers.TCPPort
//     tcp.DstPort             → layers.TCPPort
//     tcp.Seq                 → uint32 — sequence number
//     tcp.Ack                 → uint32 — acknowledgement number
//     tcp.SYN                 → bool
//     tcp.ACK                 → bool
//     tcp.FIN                 → bool
//     tcp.RST                 → bool
//     tcp.PSH                 → bool
//     tcp.URG                 → bool
//     tcp.Window              → uint16
//     tcp.Checksum            → uint16
//     tcp.Payload             → []byte — the actual data
// }
// =============================================================================

// =============================================================================
// UDP (Layer 3)
// =============================================================================
// udpLayer := packet.Layer(layers.LayerTypeUDP)
// if udpLayer != nil {
//     udp, ok := udpLayer.(*layers.UDP)
//     udp.SrcPort             → layers.UDPPort
//     udp.DstPort             → layers.UDPPort
//     udp.Length              → uint16
//     udp.Checksum            → uint16
//     udp.Payload             → []byte
// }
// =============================================================================
