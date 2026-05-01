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

	// save flow — multi-step state machine driven by the `s` hotkey.
	//   1. inactive       — capture page behaves normally
	//   2. selectStart    — orange selection bar; user navigates to the
	//                       first packet of the range and presses enter
	//   3. selectEnd      — start ID locked; user navigates to the last
	//                       packet of the range and presses enter
	//   4. rangeSet       — both bounds locked; pressing `s` again opens
	//                       the name popup; esc cancels
	//   5. naming popup   — saveNamePopup.IsActive() takes over input
	saveStage     saveStage
	saveStartID   uint64
	saveEndID     uint64
	saveNamePopup *saveNamePopup
}

func newCapturePage(a *app) *capturePage {
	// First column is a 3-wide save-flow marker. It's empty during normal
	// capture; the save flow paints ▶ on the start row, ◀ on the end (or
	// the live cursor during selectEnd), and • on every row in the band.
	// Keeping the column always-present means the table layout doesn't
	// shift when save mode toggles.
	columns := []table.Column{
		{Title: "", Width: 3},
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

	return &capturePage{
		app:           a,
		table:         t,
		popup:         newFilterPopup(),
		saveNamePopup: newSaveNamePopup(),
	}
}

// saveStage drives the capture page's save flow. See capturePage docs for
// the full state machine.
type saveStage int

const (
	saveStageInactive saveStage = iota
	saveStageSelectStart
	saveStageSelectEnd
	saveStageRangeSet
)

// IsModal lets the root model know to bypass global hotkeys (q, space) while
// any popup is collecting input — otherwise space would toggle capture
// instead of inserting into the textinput. Save mode also reports modal so
// space can act as the range-selector key without flipping capture state.
// The interface is duck-typed in app.Update; only pages with modal
// sub-components implement it.
func (p *capturePage) IsModal() bool {
	return p.popup.IsActive() || p.saveNamePopup.IsActive() || p.saveStage != saveStageInactive
}

// Init has no async work — the packet pump is owned by the root model and
// runs across page transitions, not per-page.
func (p *capturePage) Init() tea.Cmd { return nil }

func (p *capturePage) Update(msg tea.Msg) (Page, tea.Cmd) {
	// While the save-name popup is open, every key belongs to the popup —
	// it's the final stage of the save flow and modal until submit/esc.
	if p.saveNamePopup.IsActive() {
		if _, ok := msg.(tea.KeyMsg); ok {
			submit, cancel, cmd := p.saveNamePopup.Update(msg)
			switch {
			case submit:
				name := p.saveNamePopup.Value()
				p.saveNamePopup.Close()
				saveCmd := p.commitSave(name)
				p.exitSaveMode()
				return p, saveCmd
			case cancel:
				p.saveNamePopup.Close()
				p.exitSaveMode()
				return p, showMsg("save canceled")
			}
			return p, cmd
		}
	}

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

	// While in any save stage (selectStart / selectEnd / rangeSet), we
	// intercept keys so the user can't accidentally trigger inspect/edit/
	// clear/etc. during a multi-step selection. Cursor movement still
	// passes through to the table; everything else is handled here.
	if p.saveStage != saveStageInactive {
		if msg, ok := msg.(tea.KeyMsg); ok {
			return p.updateSave(msg)
		}
		// non-key messages (window resize, etc.) flow to the table normally
		var cmd tea.Cmd
		p.table, cmd = p.table.Update(msg)
		p.saveCursor()
		return p, cmd
	}

	if msg, ok := msg.(tea.KeyMsg); ok {
		switch normalizeKey(msg.String()) {
		case "c":
			return p, tea.Batch(p.app.flashHotkey("c"), p.clear())
		case "i":
			return p, tea.Batch(p.app.flashHotkey("i"), p.openInspect())
		case "r":
			return p, tea.Batch(p.app.flashHotkey("r"), p.openRetransmit())
		case "f":
			p.popup.Open(p.app.filter)
			return p, p.app.flashHotkey("f")
		case "s":
			return p, tea.Batch(p.app.flashHotkey("s"), p.startSave())
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

// updateSave handles every keypress while the save flow is active (any
// stage other than inactive, and the name popup isn't yet open). The flow:
//
//	selectStart : ↑↓ navigate · space locks start, advances to selectEnd
//	selectEnd   : ↑↓ navigate · space locks end,   advances to rangeSet
//	rangeSet    : s opens the name popup; esc cancels
//
// Save mode reports IsModal=true, so the app no longer routes space to
// toggleCapture — the keystroke flows in here as the selector instead.
// esc cancels from any stage. Hotkeys that aren't part of the save flow
// are swallowed silently so they can't fire mid-selection — the user's
// muscle memory might press `i` or `c`, but we don't want to navigate
// away or wipe the buffer while they're picking a range.
func (p *capturePage) updateSave(msg tea.KeyMsg) (Page, tea.Cmd) {
	key := normalizeKey(msg.String())

	switch key {
	case "esc":
		p.exitSaveMode()
		return p, showMsg("save canceled")
	case "space":
		return p, p.handleSaveSelect()
	case "s":
		if p.saveStage == saveStageRangeSet {
			p.saveNamePopup.Open()
			return p, p.app.flashHotkey("s")
		}
		// `s` mid-selection has no meaning; show a hint instead of silently
		// eating the keystroke so the user knows what to do.
		return p, showMsg("press space to lock the current selection first")
	}

	// Cursor movement still flows through to the table. Follow mode is
	// forced off during save so new packet arrivals don't yank the cursor
	// away from where the user is aiming.
	switch key {
	case "up", "k", "down", "j", "pgup", "pgdown", "home", "g", "end", "G":
		p.app.captureFollow = false
		var cmd tea.Cmd
		p.table, cmd = p.table.Update(msg)
		p.saveCursor()
		return p, cmd
	}

	// any other key is intentionally ignored mid-save
	return p, nil
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
	// any, then the save instruction banner if mid-save, then any open
	// popup. Empty strings are dropped so JoinVertical doesn't leave blank
	// lines behind.
	middle := []string{p.tableArea()}
	if banner := renderFilterBanner(p.app.filter); banner != "" {
		middle = append(middle, banner)
	}
	if banner := renderSaveBanner(p.saveStage, p.saveBannerInfo()); banner != "" {
		middle = append(middle, banner)
	}
	if p.popup.IsActive() {
		middle = append(middle, p.popup.View())
	}
	if p.saveNamePopup.IsActive() {
		middle = append(middle, p.saveNamePopup.View())
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

	// Save-flow visual feedback: paint a marker on every row inside the
	// active band. Computed off rowIDs (not the table cursor) so the
	// markers reflect intent before SetRows churns the cursor position.
	if startIdx, endIdx, ok := p.saveBand(); ok {
		lo, hi := startIdx, endIdx
		if lo > hi {
			lo, hi = hi, lo
		}
		for i := lo; i <= hi && i < len(rows); i++ {
			switch i {
			case startIdx:
				rows[i][0] = "▶"
			case endIdx:
				rows[i][0] = "◀"
			default:
				rows[i][0] = "•"
			}
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

// openRetransmit always navigates — the retransmit page renders its own
// empty state if the saves/ directory has no captures yet.
func (p *capturePage) openRetransmit() tea.Cmd {
	return navigate(pageRetransmit, nil)
}

// hotkeys is the bar this page renders. While the save flow is active we
// swap in a stage-specific bar so the user only ever sees the keys that
// will actually do something — nothing greyed out, nothing misleading.
// The `f` label flips to "edit filter" when one is set so the user knows
// reopening will show pre-filled values they can wipe to clear.
func (p *capturePage) hotkeys() []hotkey {
	if p.saveStage != saveStageInactive {
		return p.saveHotkeys()
	}
	filterLabel := "filter"
	if p.app.filter.Active() {
		filterLabel = "edit filter"
	}
	return []hotkey{
		{Key: "space", Label: "start/pause"},
		{Key: "c", Label: "clear"},
		{Key: "i", Label: "inspect"},
		{Key: "r", Label: "retransmit"},
		{Key: "f", Label: filterLabel},
		{Key: "s", Label: "save"},
		{Key: "l", Label: "latest"},
		{Key: "h", Label: "help"},
	}
}

// saveHotkeys is the contextual hotkey bar shown during the save flow.
// Each stage advertises only the keys that move it forward.
func (p *capturePage) saveHotkeys() []hotkey {
	switch p.saveStage {
	case saveStageSelectStart:
		return []hotkey{
			{Key: "↑↓", Label: "navigate"},
			{Key: "space", Label: "set start"},
			{Key: "esc", Label: "cancel"},
		}
	case saveStageSelectEnd:
		return []hotkey{
			{Key: "↑↓", Label: "navigate"},
			{Key: "space", Label: "set end"},
			{Key: "esc", Label: "cancel"},
		}
	case saveStageRangeSet:
		return []hotkey{
			{Key: "s", Label: "name & save"},
			{Key: "esc", Label: "cancel"},
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// SAVE FLOW
// -----------------------------------------------------------------------------

// saveBand returns the row-index span the save flow has bracketed (or is
// live-bracketing during selectEnd). The two indices are returned in
// flow order — startIdx is always the start row, endIdx is the end (or
// the current cursor while the user is still aiming) — so glyphs can
// distinguish ▶ from ◀ regardless of which one is numerically smaller.
// Returns ok=false when the flow is inactive or either bound has been
// evicted from the visible window.
func (p *capturePage) saveBand() (startIdx, endIdx int, ok bool) {
	switch p.saveStage {
	case saveStageSelectEnd:
		s := indexOfID(p.rowIDs, p.saveStartID)
		// During selectEnd the "end" rides with the cursor — use the saved
		// cursor ID so we don't depend on the table's internal state being
		// up-to-date when refreshTable consults us.
		e := indexOfID(p.rowIDs, p.app.captureCursorID)
		if s < 0 || e < 0 {
			return 0, 0, false
		}
		return s, e, true
	case saveStageRangeSet:
		s := indexOfID(p.rowIDs, p.saveStartID)
		e := indexOfID(p.rowIDs, p.saveEndID)
		if s < 0 || e < 0 {
			return 0, 0, false
		}
		return s, e, true
	}
	return 0, 0, false
}

// saveBannerInfo gathers the user-facing values the banner needs:
// timestamps for the start/end packets and the live packet count of the
// bracketed range. Empty/zero on stages where a value isn't relevant yet
// (e.g. no end timestamp until rangeSet).
func (p *capturePage) saveBannerInfo() saveInfo {
	var info saveInfo
	if p.saveStage == saveStageInactive {
		return info
	}
	if pk, ok := p.app.buf.At(p.saveStartID); ok && p.saveStage != saveStageSelectStart {
		info.StartTime = pk.Timestamp.Format("15:04:05.000")
	}
	if p.saveStage == saveStageRangeSet {
		if pk, ok := p.app.buf.At(p.saveEndID); ok {
			info.EndTime = pk.Timestamp.Format("15:04:05.000")
		}
	}
	if s, e, ok := p.saveBand(); ok {
		if s > e {
			s, e = e, s
		}
		info.Count = e - s + 1
	}
	return info
}

// startSave kicks off the multi-step save flow. Refuses if the table has
// no rows — there's nothing to bracket. Switches the table's selection bar
// to the orange save palette and detaches follow so the cursor stays put
// while the user aims.
func (p *capturePage) startSave() tea.Cmd {
	if len(p.rowIDs) == 0 {
		return showMsg("no packets to save")
	}
	p.saveStage = saveStageSelectStart
	p.app.captureFollow = false
	p.table.SetStyles(tableStylesSave())
	return showMsg("select the START packet of the range, then press space")
}

// handleSaveSelect advances the state machine on each space press. The
// pattern is: take the cursor's current ID, store it as the next bound,
// and bump the stage. selectedID() returning false (empty table / cursor
// out of range) keeps us in place and surfaces the reason.
func (p *capturePage) handleSaveSelect() tea.Cmd {
	id, ok := p.selectedID()
	if !ok {
		return showMsg("no packet selected — move the cursor onto a row first")
	}
	switch p.saveStage {
	case saveStageSelectStart:
		p.saveStartID = id
		p.saveStage = saveStageSelectEnd
		return showMsg(fmt.Sprintf("start locked at #%d  ·  now select END and press space", id))
	case saveStageSelectEnd:
		p.saveEndID = id
		p.saveStage = saveStageRangeSet
		lo, hi := p.saveStartID, p.saveEndID
		if lo > hi {
			lo, hi = hi, lo
		}
		return showMsg(fmt.Sprintf("range #%d → #%d locked  ·  press s to name & save", lo, hi))
	}
	return nil
}

// exitSaveMode resets the save state machine and restores the normal table
// styling. Called on cancel, on error, and after a successful commit.
func (p *capturePage) exitSaveMode() {
	p.saveStage = saveStageInactive
	p.saveStartID = 0
	p.saveEndID = 0
	p.table.SetStyles(tableStyles())
}

// commitSave writes the bracketed range to disk under the user-supplied
// name. The range is taken from rowIDs (the visible rows), so a save with
// a filter active only includes packets that match the filter. Bounds are
// normalized so the user can pick start>end without the save failing.
func (p *capturePage) commitSave(name string) tea.Cmd {
	startIdx := indexOfID(p.rowIDs, p.saveStartID)
	endIdx := indexOfID(p.rowIDs, p.saveEndID)
	if startIdx < 0 || endIdx < 0 {
		return showMsg("save failed: one of the selected packets is no longer in the buffer")
	}
	if startIdx > endIdx {
		startIdx, endIdx = endIdx, startIdx
	}
	ids := append([]uint64(nil), p.rowIDs[startIdx:endIdx+1]...)

	path, err := SavePacketsNamed(name, ids, p.app.buf)
	if err != nil {
		return showMsg("save failed: " + err.Error())
	}
	return showMsg(fmt.Sprintf("saved %d packets → %s", len(ids), path))
}

// -----------------------------------------------------------------------------
// ROW BUILDER + TABLE STYLES
// -----------------------------------------------------------------------------

// buildRow turns a detailedPacket into one display row. The leading
// element is the save-flow marker — left blank here and overwritten by
// refreshTable for rows that fall inside an active save band.
func buildRow(d *detailedPacket) table.Row {
	if d == nil {
		return table.Row{"", "—", "—", "—", "—", "—", "—"}
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
		"",
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

// tableStylesSave is the orange variant the capture page swaps in while
// the save flow is active — the cursor's selection bar shifts hue so the
// user gets an immediate visual cue that they're in selection mode and
// not the usual table.
func tableStylesSave() table.Styles {
	s := tableStyles()
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("232")).
		Background(lipgloss.Color("#F6AD55")).
		Bold(true)
	return s
}
