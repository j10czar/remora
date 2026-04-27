package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// EDIT PAGE — modify a packet's fields and save it for retransmit
// =============================================================================
// Pulls the packet by global ring-buffer ID, lets the user mutate any of
// the typed fields on detailedPacket (addresses, ports, TCP flags, payload
// bytes, etc.), then on save (`s`) appends a copy to app.edited. The
// retransmit page consumes that slice — once anything is in there, the
// retransmit hotkey on the capture page becomes live.
//
// This is a stub: forms / field navigation / hex payload editing all live
// in here when the page is fleshed out. The selection plumbing, save flow
// and esc-to-back are wired up.
// =============================================================================

type editPage struct {
	app   *app
	pktID uint64
	pkt   *detailedPacket
	avail bool
}

func newEditPage(a *app, id uint64) *editPage {
	pkt, ok := a.buf.At(id)
	return &editPage{app: a, pktID: id, pkt: pkt, avail: ok}
}

func (p *editPage) Init() tea.Cmd { return nil }

func (p *editPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch normalizeKey(k.String()) {
		case "esc":
			return p, navigate(pageCapture, nil)
		case "s":
			return p, tea.Batch(p.app.flashHotkey("s"), p.save())
		}
	}
	return p, nil
}

func (p *editPage) View() string {
	title := pageTitle("EDIT  ·  packet #"+fmt.Sprint(p.pktID), accentEdit)

	var body string
	if !p.avail {
		body = warnStyle.Render(fmt.Sprintf(
			"packet #%d is no longer in the ring buffer\n"+
				"(evicted to make room for newer captures)",
			p.pktID,
		))
	} else {
		body = "TODO: editable form for ethernet / IP / TCP|UDP / payload fields\n\n" +
			"current values:\n" +
			inspectBody(p.pkt)
	}

	keys := []hotkey{
		{Key: "esc", Label: "back to capture"},
		{Key: "s", Label: "save edit", Disabled: !p.avail},
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		accentBorder(accentEdit).Render(body),
		renderHotkeyBar(keys, p.app.flashKey),
	)
}

// save appends a copy of the (possibly modified) packet to the app's
// edited list. Once the list is non-empty, the capture page's retransmit
// hotkey lights up.
//
// Currently this saves the packet as-is — no editing UI yet — so it's
// effectively "pin this packet for retransmit". The save plumbing lives
// here so the future form work just has to mutate a local copy and call
// this.
func (p *editPage) save() tea.Cmd {
	if !p.avail {
		return showMsg("packet no longer available — cannot save")
	}
	cp := *p.pkt
	p.app.edited = append(p.app.edited, &cp)
	return showMsg(fmt.Sprintf("packet #%d saved  (%d edited packets ready)",
		p.pktID, len(p.app.edited)))
}
