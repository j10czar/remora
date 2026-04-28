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
	app   *app
	table table.Model

	// rowIDs is the global packet ID for each visible row. Without a filter
	// it's a contiguous range; with a filter active the mapping is
	// non-linear, so we cache it on every refresh and consult it in
	// selectedID/saveCursor.
	rowIDs []uint64

	// filter popup — modal sub-component. While popup.IsActive() the page
	// forwards every key into it instead of running its own hotkeys.
	popup *filterPopup
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

	return &capturePage{app: a, table: t, popup: newFilterPopup()}
}

// IsModal lets the root model know to bypass global hotkeys (q, space) while
// the filter popup is collecting input — otherwise space would toggle
// capture instead of inserting into the textinput. The interface is
// duck-typed in app.Update; only pages with modal sub-components implement it.
func (p *capturePage) IsModal() bool { return p.popup.IsActive() }

// Init has no async work — the packet pump is owned by the root model and
// runs across page transitions, not per-page.
func (p *capturePage) Init() tea.Cmd { return nil }

func (p *capturePage) Update(msg tea.Msg) (Page, tea.Cmd) {
	// While the filter popup is open, every key belongs to the popup.
	if p.popup.IsActive() {
		if _, ok := msg.(tea.KeyMsg); ok {
			submit, cancel, cmd := p.popup.Update(msg)
			switch {
			case submit:
				p.app.filter = p.popup.Value()
				p.popup.Close()
				// re-arm follow so the cursor jumps to the newest matching
				// packet rather than staying on a stale ID that the filter
				// may have just hidden.
				p.app.captureFollow = true
			case cancel:
				p.popup.Close()
			}
			return p, cmd
		}
	}

	if msg, ok := msg.(tea.KeyMsg); ok {
		switch normalizeKey(msg.String()) {
		case "c":
			return p, tea.Batch(p.app.flashHotkey("c"), p.clear())
		case "i":
			return p, tea.Batch(p.app.flashHotkey("i"), p.openInspect())
		case "e":
			return p, tea.Batch(p.app.flashHotkey("e"), p.openEdit())
		case "r":
			return p, tea.Batch(p.app.flashHotkey("r"), p.openRetransmit())
		case "f":
			p.popup.Open(p.app.filter)
			return p, p.app.flashHotkey("f")
		case "l":
			// jump to latest + re-enable follow. refreshTable will pin
			// the cursor to the last row on the next render.
			p.app.captureFollow = true
			return p, p.app.flashHotkey("l")
		case "end", "G":
			// table will move cursor to last; we also flip follow on so
			// subsequent packets keep scrolling into view.
			p.app.captureFollow = true
		case "up", "k", "down", "j", "pgup", "pgdown", "home", "g":
			// any manual scroll detaches us from the live tail.
			p.app.captureFollow = false
		}
	}

	// arrow keys / page up/down / etc. go to the table for cursor movement.
	var cmd tea.Cmd
	p.table, cmd = p.table.Update(msg)
	p.saveCursor()
	return p, cmd
}

// saveCursor persists the cursor's global ID onto the app so it survives
// page swaps (capture → inspect → back rebuilds the page from scratch).
// With a filter active, row indices are non-contiguous, so we read the ID
// from the rowIDs cache rather than firstID + cursor.
func (p *capturePage) saveCursor() {
	if len(p.rowIDs) == 0 {
		return
	}
	idx := p.table.Cursor()
	if idx < 0 || idx >= len(p.rowIDs) {
		return
	}
	p.app.captureCursorID = p.rowIDs[idx]
	p.app.captureCursorValid = true
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

	// `buffered` is the visible row count; with a filter active that's a
	// subset of the actual ring buffer occupancy, so we surface both numbers
	// and tag the line so the user doesn't read it as the whole picture.
	bufLine := fmt.Sprintf("buffered: %d", len(p.table.Rows()))
	if p.app.filter.Active() {
		bufLine = fmt.Sprintf("buffered: %d of %d  (showing filtered packets only)",
			len(p.table.Rows()), p.app.buf.Len())
	}
	footer := footerStyle.Render(
		fmt.Sprintf("© 2026 Jason Tenczar  ·  packets: %d  ·  %s",
			p.app.buf.Total(), bufLine),
	)

	// Compose the variable middle: table, then the active-filter banner if
	// any, then the popup if open. Empty strings are dropped so JoinVertical
	// doesn't leave blank lines behind.
	middle := []string{p.tableArea()}
	if banner := renderFilterBanner(p.app.filter); banner != "" {
		middle = append(middle, banner)
	}
	if p.popup.IsActive() {
		middle = append(middle, p.popup.View())
	}
	middle = append(middle, bar, footer)

	return lipgloss.JoinVertical(lipgloss.Left, append([]string{header}, middle...)...)
}

// refreshTable pulls the latest snapshot from the ring buffer and rebuilds
// the table rows. firstID is captured here so selectedID() can translate
// the cursor into a global ID without re-snapshotting.
//
// After repopulating the rows, the cursor is repositioned according to two
// pieces of app-level state:
//   - captureFollow=true → pin to the last row so the view tracks new
//     arrivals (the default, and the fix for "view stuck at the top when
//     capture starts").
//   - captureFollow=false → restore to the saved global ID if it is still
//     in the buffer; if it has been evicted, fall back to the oldest row
//     so the user lands near where they were rather than the live tail.
func (p *capturePage) refreshTable() {
	snap, firstID := p.app.buf.Snapshot()

	// Apply the filter (no-op when inactive). The returned indices give us
	// the position of each match within `snap`, which we add to firstID to
	// get the stable global ID — that mapping is what makes inspect/edit
	// continue to work even when the table is showing a filtered subset.
	matched, indices := p.app.filter.Apply(snap)
	rows := make([]table.Row, len(matched))
	p.rowIDs = make([]uint64, len(matched))
	for i, d := range matched {
		rows[i] = buildRow(d)
		if p.app.filter.Active() {
			p.rowIDs[i] = firstID + uint64(indices[i])
		} else {
			p.rowIDs[i] = firstID + uint64(i)
		}
	}
	p.table.SetRows(rows)

	if len(rows) == 0 {
		return
	}

	target := -1
	switch {
	case p.app.captureFollow:
		target = len(rows) - 1
	case p.app.captureCursorValid:
		target = indexOfID(p.rowIDs, p.app.captureCursorID)
		if target < 0 {
			target = 0 // saved packet evicted or filtered out; show first visible
		}
	}

	// SetCursor moves the index but leaves viewport.YOffset alone — the
	// cursor lands below the visible window unless we go through MoveUp /
	// MoveDown / GotoBottom, which sync the offset. GotoBottom keeps the
	// selected row pinned to the bottom of the viewport in follow mode;
	// MoveUp/MoveDown from the current cursor handle saved-position
	// restores while keeping the cursor visible.
	if target >= 0 {
		switch {
		case p.app.captureFollow:
			p.table.GotoBottom()
		case target > p.table.Cursor():
			p.table.MoveDown(target - p.table.Cursor())
		case target < p.table.Cursor():
			p.table.MoveUp(p.table.Cursor() - target)
		}
	}
	p.saveCursor()
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
	idx := p.table.Cursor()
	if idx < 0 || idx >= len(p.rowIDs) {
		return 0, false
	}
	return p.rowIDs[idx], true
}

// indexOfID is a small linear search over rowIDs. The list maxes out at the
// ring buffer's capacity (default 1000), so this is fine to call on every
// render without indexing it.
func indexOfID(ids []uint64, target uint64) int {
	for i, id := range ids {
		if id == target {
			return i
		}
	}
	return -1
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
	// nothing left to anchor on — drop saved cursor and re-arm follow so
	// the next batch of packets scrolls into view automatically.
	p.app.captureCursorValid = false
	p.app.captureFollow = true
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
// edited packets exist; the others are always live. The `f` label flips
// to "edit filter" when one is set so the user knows reopening will show
// pre-filled values they can wipe to clear.
func (p *capturePage) hotkeys() []hotkey {
	filterLabel := "filter"
	if p.app.filter.Active() {
		filterLabel = "edit filter"
	}
	return []hotkey{
		{Key: "space", Label: "start/pause"},
		{Key: "c", Label: "clear"},
		{Key: "i", Label: "inspect"},
		{Key: "e", Label: "edit"},
		{Key: "r", Label: "retransmit", Disabled: len(p.app.edited) == 0},
		{Key: "f", Label: filterLabel},
		{Key: "l", Label: "latest"},
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
