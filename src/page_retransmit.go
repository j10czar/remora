package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// RETRANSMIT PAGE — list of edited packets queued for retransmit
// =============================================================================
// Lists every packet currently in app.edited and (will) let the user fire
// them onto the wire one by one or all at once. The capture page only
// allows navigating here when the list is non-empty, so we always have at
// least one entry to render.
//
// This is a stub: the actual gopacket.SerializeLayers + pcap.WritePacketData
// work goes here. The list rendering and esc-to-back are wired up.
// =============================================================================

type retransmitPage struct {
	app    *app
	cursor int // index into app.edited
}

func newRetransmitPage(a *app) *retransmitPage {
	return &retransmitPage{app: a}
}

func (p *retransmitPage) Init() tea.Cmd { return nil }

func (p *retransmitPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch normalizeKey(k.String()) {
		case "esc":
			return p, navigate(pageCapture, nil)
		case "up", "k":
			if p.cursor > 0 {
				p.cursor--
			}
		case "down", "j":
			if p.cursor < len(p.app.edited)-1 {
				p.cursor++
			}
		case "enter":
			return p, tea.Batch(p.app.flashHotkey("enter"), p.fire())
		}
	}
	return p, nil
}

func (p *retransmitPage) View() string {
	title := pageTitle(fmt.Sprintf("RETRANSMIT  ·  %d edited packet(s)", len(p.app.edited)),
		accentRetransmit)

	var body string
	if len(p.app.edited) == 0 {
		// shouldn't happen — capture page guards against this, but just in case
		body = warnStyle.Render("no edited packets queued")
	} else {
		body = p.list()
	}

	keys := []hotkey{
		{Key: "↑/↓", Label: "select"},
		{Key: "enter", Label: "fire"},
		{Key: "esc", Label: "back to capture"},
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		accentBorder(accentRetransmit).Render(body),
		renderHotkeyBar(keys, p.app.flashKey),
	)
}

// list renders one row per edited packet. The cursor row is marked with a
// caret; everything else is plain.
func (p *retransmitPage) list() string {
	var b strings.Builder
	for i, d := range p.app.edited {
		marker := "  "
		if i == p.cursor {
			marker = "▸ "
		}
		fmt.Fprintf(&b, "%s%2d. %s → %s   %s\n",
			marker, i,
			d.SrcIP, d.DstIP,
			transportName(d),
		)
	}
	return b.String()
}

// fire (will) serialize the selected packet via gopacket.SerializeLayers
// and write it onto the capture handle. Stub for now — leaves a message
// so the wiring is observable.
func (p *retransmitPage) fire() tea.Cmd {
	if len(p.app.edited) == 0 {
		return showMsg("nothing to fire")
	}
	// TODO: build layers from p.app.edited[p.cursor], serialize with
	// SetNetworkLayerForChecksum so checksums get recomputed, then call
	// p.app.cap.handle.WritePacketData(buf.Bytes()).
	return showMsg(fmt.Sprintf("would retransmit packet %d  (serializer not wired yet)",
		p.cursor))
}
