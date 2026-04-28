package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket/layers"
)

// =============================================================================
// INSPECT PAGE — read-only deep view of a single packet
// =============================================================================
// Two layouts share the same page; `x` toggles between them:
//
//   collapsed (default) — full per-layer field breakdown, no hex pane
//   expanded            — compressed one-line-per-layer summary + a tall
//                         scrollable hex/ASCII payload dump
//
// If the packet has been evicted from the buffer between selection and
// rendering, the page degrades gracefully to a "no longer available"
// notice instead of crashing.
// =============================================================================

const hexBytesPerRow = 16

type inspectPage struct {
	app   *app
	pktID uint64
	pkt   *detailedPacket
	avail bool // false if the packet was evicted before we got a chance to look at it

	// hex pane state. Pane is only rendered when expanded; the scroll
	// offset persists across toggles so reopening returns to the same row.
	hexExpanded bool
	hexOffset   int

	// terminal size, tracked via WindowSizeMsg so the expanded hex pane can
	// fill remaining vertical space instead of guessing.
	height int
}

func newInspectPage(a *app, id uint64) *inspectPage {
	pkt, ok := a.buf.At(id)
	return &inspectPage{app: a, pktID: id, pkt: pkt, avail: ok}
}

func (p *inspectPage) Init() tea.Cmd { return nil }

func (p *inspectPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.height = msg.Height
		p.clampHexOffset()
		return p, nil

	case tea.KeyMsg:
		key := normalizeKey(msg.String())
		switch key {
		case "esc":
			return p, navigate(pageCapture, nil)
		case "x":
			if !p.avail || len(p.pkt.Payload) == 0 {
				return p, showMsg("no payload to view")
			}
			p.hexExpanded = !p.hexExpanded
			return p, p.app.flashHotkey("x")
		}
		// scroll keys are only meaningful when the hex pane is open
		if !p.hexExpanded {
			return p, nil
		}
		switch key {
		case "up", "k":
			if p.hexOffset > 0 {
				p.hexOffset--
			}
		case "down", "j":
			p.hexOffset++
			p.clampHexOffset()
		case "pgup":
			p.hexOffset -= p.hexVisibleRows()
			p.clampHexOffset()
		case "pgdown":
			p.hexOffset += p.hexVisibleRows()
			p.clampHexOffset()
		case "home", "g":
			p.hexOffset = 0
		case "end", "G":
			p.hexOffset = p.maxHexOffset()
		}
	}
	return p, nil
}

func (p *inspectPage) View() string {
	title := pageTitle("INSPECT  ·  packet #"+fmt.Sprint(p.pktID), accentInspect)

	var body string
	switch {
	case !p.avail:
		body = warnStyle.Render(fmt.Sprintf(
			"packet #%d is no longer in the ring buffer\n"+
				"(evicted to make room for newer captures)",
			p.pktID,
		))
	case p.hexExpanded:
		body = lipgloss.JoinVertical(lipgloss.Left,
			compressedBody(p.pkt),
			"",
			p.hexPane(),
		)
	default:
		body = inspectBody(p.pkt)
	}

	bar := renderHotkeyBar(p.hotkeys(), p.app.flashKey)

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		accentBorder(accentInspect).Render(body),
		bar,
	)
}

func (p *inspectPage) hotkeys() []hotkey {
	hexLabel := "open hex"
	if p.hexExpanded {
		hexLabel = "close hex"
	}
	keys := []hotkey{
		{Key: "x", Label: hexLabel, Disabled: !p.avail || len(p.pkt.Payload) == 0},
	}
	if p.hexExpanded {
		keys = append(keys,
			hotkey{Key: "↑/↓", Label: "scroll"},
			hotkey{Key: "pgup/pgdn", Label: "page"},
		)
	}
	keys = append(keys, hotkey{Key: "esc", Label: "back to capture"})
	return keys
}

// -----------------------------------------------------------------------------
// LAYERED FIELD VIEW (collapsed / default mode)
// -----------------------------------------------------------------------------
// inspectBody renders a per-layer breakdown of every populated field on the
// detailedPacket. Sections are emitted only when their layer is present —
// e.g. an ARP frame skips the IP/TCP sections rather than printing zero
// values that look like real data.

func inspectBody(d *detailedPacket) string {
	var sections []string

	sections = append(sections, layerSection("Metadata", [][2]string{
		{"captured at", d.Timestamp.Format("15:04:05.000")},
		{"wire length", fmt.Sprintf("%d bytes", d.WireLength)},
		{"capture length", fmt.Sprintf("%d bytes", d.CaptureLength)},
	}))

	if d.SrcMAC != nil || d.DstMAC != nil {
		sections = append(sections, layerSection("Ethernet", [][2]string{
			{"src mac", macString(d.SrcMAC)},
			{"dst mac", macString(d.DstMAC)},
			{"type", d.EthernetType.String()},
		}))
	}

	switch d.NetworkType {
	case "IPv4":
		sections = append(sections, layerSection("Network · IPv4", [][2]string{
			{"src ip", d.SrcIP.String()},
			{"dst ip", d.DstIP.String()},
			{"id", fmt.Sprintf("0x%04x", d.IPv4ID)},
			{"tos", fmt.Sprintf("0x%02x", d.IPv4TOS)},
			{"flags", ipv4FlagsString(d.IPv4Flags)},
			{"frag offset", fmt.Sprintf("%d", d.IPv4FragOffset)},
			{"ttl", fmt.Sprintf("%d", d.IPv4TTL)},
			{"protocol", d.IPv4Protocol.String()},
		}))
	case "IPv6":
		sections = append(sections, layerSection("Network · IPv6", [][2]string{
			{"src ip", d.SrcIP.String()},
			{"dst ip", d.DstIP.String()},
			{"hop limit", fmt.Sprintf("%d", d.IPv6HopLimit)},
			{"traffic class", fmt.Sprintf("0x%02x", d.IPv6TrafficClass)},
			{"flow label", fmt.Sprintf("0x%05x", d.IPv6FlowLabel)},
			{"next header", d.IPv6NextHeader.String()},
		}))
	}

	switch d.TransportType {
	case "TCP":
		sections = append(sections, layerSection("Transport · TCP", [][2]string{
			{"src port", fmt.Sprintf("%d", d.SrcPort)},
			{"dst port", fmt.Sprintf("%d", d.DstPort)},
			{"seq", fmt.Sprintf("%d", d.Seq)},
			{"ack", fmt.Sprintf("%d", d.Ack)},
			{"flags", tcpFlagsString(d)},
			{"window", fmt.Sprintf("%d", d.Window)},
			{"options", tcpOptionsString(d.TCPOptions)},
		}))
	case "UDP":
		sections = append(sections, layerSection("Transport · UDP", [][2]string{
			{"src port", fmt.Sprintf("%d", d.SrcPort)},
			{"dst port", fmt.Sprintf("%d", d.DstPort)},
		}))
	}

	app := d.ApplicationProtocol
	if app == "" {
		app = "—"
	}
	sections = append(sections, layerSection("Application", [][2]string{
		{"protocol", app},
		{"payload bytes", fmt.Sprintf("%d", len(d.Payload))},
	}))

	return strings.Join(sections, "\n")
}

// -----------------------------------------------------------------------------
// COMPRESSED VIEW (hex-expanded mode)
// -----------------------------------------------------------------------------
// One short line per layer — just enough to keep context while the hex pane
// takes the bulk of the screen. Unpopulated layers are skipped.

func compressedBody(d *detailedPacket) string {
	var lines []string

	lines = append(lines, fmt.Sprintf(
		"meta      %s  ·  %d bytes wire (%d captured)",
		d.Timestamp.Format("15:04:05.000"), d.WireLength, d.CaptureLength,
	))

	if d.SrcMAC != nil || d.DstMAC != nil {
		lines = append(lines, fmt.Sprintf(
			"ethernet  %s → %s  (%s)",
			macString(d.SrcMAC), macString(d.DstMAC), d.EthernetType,
		))
	}

	switch d.NetworkType {
	case "IPv4":
		lines = append(lines, fmt.Sprintf(
			"network   IPv4  %s → %s  ttl=%d  proto=%s",
			d.SrcIP, d.DstIP, d.IPv4TTL, d.IPv4Protocol,
		))
	case "IPv6":
		lines = append(lines, fmt.Sprintf(
			"network   IPv6  %s → %s  hop=%d  next=%s",
			d.SrcIP, d.DstIP, d.IPv6HopLimit, d.IPv6NextHeader,
		))
	}

	switch d.TransportType {
	case "TCP":
		lines = append(lines, fmt.Sprintf(
			"transport TCP   :%d → :%d  flags=[%s]  win=%d",
			d.SrcPort, d.DstPort, tcpFlagsString(d), d.Window,
		))
	case "UDP":
		lines = append(lines, fmt.Sprintf(
			"transport UDP   :%d → :%d", d.SrcPort, d.DstPort,
		))
	}

	app := d.ApplicationProtocol
	if app == "" {
		app = "—"
	}
	lines = append(lines, fmt.Sprintf(
		"app       %s  ·  payload %d bytes", app, len(d.Payload),
	))

	return strings.Join(lines, "\n")
}

// layerSection formats a header line followed by aligned `key : value` rows.
// Empty values are still printed so the layout stays predictable.
func layerSection(title string, fields [][2]string) string {
	var b strings.Builder
	b.WriteString(layerHeaderStyle.Render("── " + title + " ──"))
	b.WriteByte('\n')
	for _, kv := range fields {
		fmt.Fprintf(&b, "  %-14s : %s\n", kv[0], kv[1])
	}
	return strings.TrimRight(b.String(), "\n")
}

func macString(m []byte) string {
	if len(m) == 0 {
		return "—"
	}
	parts := make([]string, len(m))
	for i, b := range m {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

func ipv4FlagsString(f layers.IPv4Flag) string {
	if f == 0 {
		return "—"
	}
	return f.String()
}

func tcpFlagsString(d *detailedPacket) string {
	flags := []string{}
	for _, f := range []struct {
		on   bool
		name string
	}{
		{d.SYN, "SYN"},
		{d.ACK, "ACK"},
		{d.FIN, "FIN"},
		{d.RST, "RST"},
		{d.PSH, "PSH"},
		{d.URG, "URG"},
	} {
		if f.on {
			flags = append(flags, f.name)
		}
	}
	if len(flags) == 0 {
		return "—"
	}
	return strings.Join(flags, " ")
}

// tcpOptionsString summarizes the TCP option list. Common options get
// human-friendly names; the rest fall back to their numeric kind.
func tcpOptionsString(opts []layers.TCPOption) string {
	if len(opts) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(opts))
	for _, opt := range opts {
		switch opt.OptionType {
		case layers.TCPOptionKindEndList:
			parts = append(parts, "EOL")
		case layers.TCPOptionKindNop:
			parts = append(parts, "NOP")
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) == 2 {
				mss := uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
				parts = append(parts, fmt.Sprintf("MSS=%d", mss))
			} else {
				parts = append(parts, "MSS")
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) == 1 {
				parts = append(parts, fmt.Sprintf("WS=%d", opt.OptionData[0]))
			} else {
				parts = append(parts, "WS")
			}
		case layers.TCPOptionKindSACKPermitted:
			parts = append(parts, "SACK-OK")
		case layers.TCPOptionKindSACK:
			parts = append(parts, "SACK")
		case layers.TCPOptionKindTimestamps:
			parts = append(parts, "TS")
		default:
			parts = append(parts, fmt.Sprintf("kind=%d", opt.OptionType))
		}
	}
	return strings.Join(parts, ", ")
}

// -----------------------------------------------------------------------------
// HEX / ASCII PANE — only rendered in expanded mode
// -----------------------------------------------------------------------------
// Standard hexdump layout: 8-digit offset, 16 bytes per row split into two
// 8-byte groups, and the ASCII rendering of those 16 bytes between pipes.
// Non-printable bytes are shown as `.` so column alignment never breaks.
// Only the visible row range is formatted, so big payloads stay cheap to
// render.

func (p *inspectPage) hexPane() string {
	totalRows := p.hexTotalRows()
	visible := p.hexVisibleRows()

	if totalRows == 0 {
		return lipgloss.JoinVertical(lipgloss.Left,
			layerHeaderStyle.Render("── Payload (hex) ──"),
			"  (empty)",
		)
	}

	end := min(p.hexOffset+visible, totalRows)
	dump := strings.Join(p.hexLinesRange(p.hexOffset, end), "\n")
	header := layerHeaderStyle.Render(fmt.Sprintf(
		"── Payload (hex)  ·  rows %d–%d of %d ──",
		p.hexOffset+1, end, totalRows,
	))
	return lipgloss.JoinVertical(lipgloss.Left, header, dump)
}

func (p *inspectPage) hexTotalRows() int {
	if !p.avail {
		return 0
	}
	return (len(p.pkt.Payload) + hexBytesPerRow - 1) / hexBytesPerRow
}

// hexVisibleRows is how many dump rows the expanded pane shows. We let it
// fill the terminal — the compressed summary above is short and fixed, so
// (height − chrome) is a good budget. Falls back to 24 before the first
// WindowSizeMsg lands.
func (p *inspectPage) hexVisibleRows() int {
	const chrome = 14 // title + summary lines + section header + border + hotkey bar + margins
	rows := p.height - chrome
	if rows < 8 {
		return 24
	}
	return rows
}

func (p *inspectPage) maxHexOffset() int {
	max := p.hexTotalRows() - p.hexVisibleRows()
	if max < 0 {
		return 0
	}
	return max
}

func (p *inspectPage) clampHexOffset() {
	max := p.maxHexOffset()
	if p.hexOffset > max {
		p.hexOffset = max
	}
	if p.hexOffset < 0 {
		p.hexOffset = 0
	}
}

func (p *inspectPage) hexLinesRange(start, end int) []string {
	payload := p.pkt.Payload
	lines := make([]string, 0, end-start)
	for row := start; row < end; row++ {
		offset := row * hexBytesPerRow
		chunkEnd := min(offset+hexBytesPerRow, len(payload))
		chunk := payload[offset:chunkEnd]

		var hex, ascii strings.Builder
		for j := range hexBytesPerRow {
			if j == 8 {
				hex.WriteByte(' ') // extra gap between the two 8-byte groups
			}
			if j < len(chunk) {
				fmt.Fprintf(&hex, " %02x", chunk[j])
				c := chunk[j]
				if c >= 32 && c < 127 {
					ascii.WriteByte(c)
				} else {
					ascii.WriteByte('.')
				}
			} else {
				hex.WriteString("   ")
				ascii.WriteByte(' ')
			}
		}
		lines = append(lines, fmt.Sprintf("%08x %s  |%s|", offset, hex.String(), ascii.String()))
	}
	return lines
}

var layerHeaderStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color(accentInspect)).
	Bold(true)
