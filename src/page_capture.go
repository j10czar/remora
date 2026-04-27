package main

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// CAPTURE PAGE — the home screen
// =============================================================================
// The live table of captured packets plus the page's hotkey bar. Rows are
// rebuilt from the ring buffer's snapshot on every render — that keeps the
// table and buffer in lock-step, so "clear" is just a buffer reset and any
// other page (inspect/edit) sees the same data the table sees.
//
// Selection model
//   The bubbles/table cursor sits on a row; row N corresponds to global
//   ring-buffer ID firstID + N (firstID is returned by Snapshot()). When
//   the user hits a navigation hotkey, that global ID is the handle we
//   pass to the next page. Global IDs are stable even after the buffer
//   wraps, so an inspect page opened on packet #4321 keeps referring to
//   the same packet even if the table itself has scrolled past it.
// =============================================================================

type capturePage struct {
	app     *app
	table   table.Model
	firstID uint64 // global ID of the topmost row, refreshed on every render
}

func newCapturePage(a *app) *capturePage {
	columns := []table.Column{
		{Title: "Time", Width: 13},
		{Title: "Transport", Width: 9},
		{Title: "App", Width: 10},
		{Title: "Source", Width: 24},
		{Title: "Destination", Width: 24},
		{Title: "Len", Width: 6},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithHeight(20),
		table.WithFocused(true),
	)
	t.SetStyles(tableStyles())

	return &capturePage{app: a, table: t}
}

// Init has no async work — the packet pump is owned by the root model and
// runs across page transitions, not per-page.
func (p *capturePage) Init() tea.Cmd { return nil }

func (p *capturePage) Update(msg tea.Msg) (Page, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch normalizeKey(msg.String()) {
		case "c":
			return p, tea.Batch(p.app.flashHotkey("c"), p.clear())
		case "i":
			return p, tea.Batch(p.app.flashHotkey("i"), p.openInspect())
		case "e":
			return p, tea.Batch(p.app.flashHotkey("e"), p.openEdit())
		case "r":
			return p, tea.Batch(p.app.flashHotkey("r"), p.openRetransmit())
		}
	}

	// arrow keys / page up/down / etc. go to the table for cursor movement.
	var cmd tea.Cmd
	p.table, cmd = p.table.Update(msg)
	return p, cmd
}

func (p *capturePage) View() string {
	// The buffer is the source of truth — pull a fresh snapshot every
	// render. At ~100 rows this is essentially free and removes any chance
	// of the table drifting from the buffer.
	p.refreshTable()

	header := lipgloss.JoinVertical(lipgloss.Left,
		asciiStyle.Render(remoraASCII),
		subtitleStyle.Render("packet sniffer  ·  "+p.statusText()),
	)

	bar := renderHotkeyBar(p.hotkeys(), p.app.flashKey)

	footer := footerStyle.Render(
		fmt.Sprintf("© 2026 Jason Tenczar  ·  packets: %d  ·  buffered: %d",
			p.app.buf.Total(), len(p.table.Rows())),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		p.tableArea(),
		bar,
		footer,
	)
}

// refreshTable pulls the latest snapshot from the ring buffer and rebuilds
// the table rows. firstID is captured here so selectedID() can translate
// the cursor into a global ID without re-snapshotting.
func (p *capturePage) refreshTable() {
	snap, firstID := p.app.buf.Snapshot()
	p.firstID = firstID

	rows := make([]table.Row, len(snap))
	for i, d := range snap {
		rows[i] = buildRow(d)
	}
	p.table.SetRows(rows)
}

func (p *capturePage) statusText() string {
	switch p.app.state {
	case stateRunning:
		return "running  ·  space to pause  ·  q to quit"
	case statePaused:
		return "paused  ·  space to resume  ·  q to quit"
	default:
		return "press space to start  ·  q to quit"
	}
}

// tableArea draws the bordered region holding the table — or a centered
// splash before the user has started capture, so the first frame isn't a
// blank box.
func (p *capturePage) tableArea() string {
	if p.app.state == stateIdle {
		splash := splashStyle.Render("◆  press space to start capturing  ◆")
		return tableBorder.Render(
			lipgloss.Place(75, 20, lipgloss.Center, lipgloss.Center, splash),
		)
	}
	return tableBorder.Render(p.table.View())
}

// selectedID is the global ring-buffer ID of the row the cursor is on.
// Returns false when the table is empty so callers can show a "no packet
// selected" notice instead of navigating with a bogus ID.
func (p *capturePage) selectedID() (uint64, bool) {
	if len(p.table.Rows()) == 0 {
		return 0, false
	}
	return p.firstID + uint64(p.table.Cursor()), true
}

// -----------------------------------------------------------------------------
// HOTKEY ACTIONS
// -----------------------------------------------------------------------------

// clear empties the ring buffer. Refuses while the capture is running so
// the user doesn't lose half a second of in-flight packets to a misclick;
// they have to pause first.
func (p *capturePage) clear() tea.Cmd {
	if p.app.state == stateRunning {
		return showMsg("pause capture before clearing  (space → pause, then c)")
	}
	p.app.buf.Reset()
	return nil
}

func (p *capturePage) openInspect() tea.Cmd {
	id, ok := p.selectedID()
	if !ok {
		return showMsg("no packet selected")
	}
	return navigate(pageInspect, id)
}

func (p *capturePage) openEdit() tea.Cmd {
	id, ok := p.selectedID()
	if !ok {
		return showMsg("no packet selected")
	}
	return navigate(pageEdit, id)
}

// openRetransmit refuses unless the user has actually edited and saved
// some packets — there's nothing to retransmit otherwise.
func (p *capturePage) openRetransmit() tea.Cmd {
	if len(p.app.edited) == 0 {
		return showMsg("no edited packets to retransmit  (use 'e' to edit and save first)")
	}
	return navigate(pageRetransmit, nil)
}

// hotkeys is the bar this page renders. retransmit is greyed out until
// edited packets exist; the others are always live.
func (p *capturePage) hotkeys() []hotkey {
	return []hotkey{
		{Key: "space", Label: "start/pause"},
		{Key: "c", Label: "clear"},
		{Key: "i", Label: "inspect"},
		{Key: "e", Label: "edit"},
		{Key: "r", Label: "retransmit", Disabled: len(p.app.edited) == 0},
		{Key: "h", Label: "help"},
	}
}

// -----------------------------------------------------------------------------
// ROW BUILDER + TABLE STYLES
// -----------------------------------------------------------------------------

// buildRow turns a detailedPacket into one display row. Lives here because
// the capture page is the only place table rows are rendered.
func buildRow(d *detailedPacket) table.Row {
	if d == nil {
		return table.Row{"—", "—", "—", "—", "—", "—"}
	}

	src := d.SrcIP.String()
	dst := d.DstIP.String()
	if d.SrcPort != 0 {
		src += ":" + strconv.Itoa(int(d.SrcPort))
	}
	if d.DstPort != 0 {
		dst += ":" + strconv.Itoa(int(d.DstPort))
	}

	transport := transportName(d)
	if transport == "" {
		transport = "—"
	}
	app := d.ApplicationProtocol
	if app == "" {
		app = "—"
	}

	return table.Row{
		d.Timestamp.Format("15:04:05.000"),
		transport,
		app,
		src,
		dst,
		strconv.Itoa(d.WireLength),
	}
}

// transportName picks a display-friendly transport name out of the typed
// IP-protocol field. Falls back to empty if the network type is something
// we don't decode (ARP, etc.).
func transportName(d *detailedPacket) string {
	switch d.NetworkType {
	case "IPv4":
		return d.IPv4Protocol.String()
	case "IPv6":
		return d.IPv6NextHeader.String()
	}
	return ""
}

// tableStyles tweaks the bubbles/table defaults so headers and the
// selected row stand out.
func tableStyles() table.Styles {
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("63")).
		BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	return s
}
