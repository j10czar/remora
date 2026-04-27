package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// INSPECT PAGE — read-only deep view of a single packet
// =============================================================================
// Looks up the packet by global ring-buffer ID and renders its full layered
// structure. If the packet has been evicted from the buffer between
// selection and rendering, the page degrades gracefully to a "no longer
// available" notice instead of crashing.
//
// This is a stub: real implementation will tab through layers and render
// them field by field. The plumbing — eviction handling, accent color,
// esc-to-return — is in place so that work can drop in by replacing
// inspectBody.
// =============================================================================

type inspectPage struct {
	app    *app
	pktID  uint64
	pkt    *detailedPacket
	avail  bool // false if the packet was evicted before we got a chance to look at it
}

func newInspectPage(a *app, id uint64) *inspectPage {
	pkt, ok := a.buf.At(id)
	return &inspectPage{app: a, pktID: id, pkt: pkt, avail: ok}
}

func (p *inspectPage) Init() tea.Cmd { return nil }

func (p *inspectPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		if normalizeKey(k.String()) == "esc" {
			return p, navigate(pageCapture, nil)
		}
	}
	return p, nil
}

func (p *inspectPage) View() string {
	title := pageTitle("INSPECT  ·  packet #"+fmt.Sprint(p.pktID), accentInspect)

	var body string
	if !p.avail {
		body = warnStyle.Render(fmt.Sprintf(
			"packet #%d is no longer in the ring buffer\n"+
				"(evicted to make room for newer captures)",
			p.pktID,
		))
	} else {
		body = inspectBody(p.pkt)
	}

	bar := renderHotkeyBar([]hotkey{
		{Key: "esc", Label: "back to capture"},
	}, p.app.flashKey)

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		accentBorder(accentInspect).Render(body),
		bar,
	)
}

// inspectBody renders a flat summary of the packet's most useful fields.
// TODO: replace with a real layered view (Ethernet → IP → TCP/UDP → app)
// with collapsible sections and hex/ascii payload dump.
func inspectBody(d *detailedPacket) string {
	var b strings.Builder
	fmt.Fprintf(&b, "captured at   : %s\n", d.Timestamp.Format("15:04:05.000"))
	fmt.Fprintf(&b, "wire length   : %d bytes\n", d.WireLength)
	fmt.Fprintf(&b, "ethernet      : %s → %s  (%s)\n", d.SrcMAC, d.DstMAC, d.EthernetType)
	fmt.Fprintf(&b, "network       : %s  %s → %s\n", d.NetworkType, d.SrcIP, d.DstIP)
	if d.TransportType != "" {
		fmt.Fprintf(&b, "transport     : %s  :%d → :%d\n", d.TransportType, d.SrcPort, d.DstPort)
	}
	if d.ApplicationProtocol != "" {
		fmt.Fprintf(&b, "application   : %s\n", d.ApplicationProtocol)
	}
	fmt.Fprintf(&b, "payload bytes : %d", len(d.Payload))
	return b.String()
}
