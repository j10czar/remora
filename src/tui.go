package main

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
)

// =============================================================================
// HOW THIS FILE WORKS
// =============================================================================
// This file holds the *root model* — `app`. It is intentionally small:
//   - it owns the shared state every page needs (capture handle, ring
//     buffer, edited-packets list, capture state machine, message box)
//   - it routes incoming messages: a few global concerns are handled here
//     (quit, capture toggle, packet arrivals, navigation, message box)
//     and everything else is forwarded to the current page
//   - it composes the final view by stacking the page's view with the
//     message-box overlay
//
// The router is dumb on purpose. All page-specific UI logic lives in the
// page_* files. To add a new page, see page.go for the contract.
// =============================================================================

// remoraASCII is the splash banner painted at the top of the capture page.
// Other pages can use it too if they want, but most of them have their own
// title strip instead so the user gets a clear sense of "which screen am I on".
const remoraASCII = `
██████╗ ███████╗███╗   ███╗ ██████╗ ██████╗  █████╗
██╔══██╗██╔════╝████╗ ████║██╔═══██╗██╔══██╗██╔══██╗
██████╔╝█████╗  ██╔████╔██║██║   ██║██████╔╝███████║
██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║
██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
`

// -----------------------------------------------------------------------------
// MESSAGES — typed events that flow through bubbletea's message loop.
// -----------------------------------------------------------------------------

// packetMsg is delivered for every packet the capture goroutine reads. The
// pointer is owned by the message; once Add() puts it in the ring buffer
// it's safe for any page to dereference via At() / Snapshot().
type packetMsg *detailedPacket

// clearFlashMsg / clearMsgBoxMsg are time-driven messages that reset
// transient UI state. The id field is a generation counter — when the
// state has changed since the timer was scheduled, an old timer must not
// clobber the newer state, so the handler checks id matches.
type clearFlashMsg struct{ id int }
type clearMsgBoxMsg struct{ id int }

// flashDuration / msgBoxDuration are how long transient UI states linger.
const (
	flashDuration  = 180 * time.Millisecond
	msgBoxDuration = 4 * time.Second
)

// -----------------------------------------------------------------------------
// CAPTURE STATE
// -----------------------------------------------------------------------------

// captureState drives the start/pause flow. It begins idle (pcap handle not
// yet opened), flips to running on the first space press, then alternates
// running ↔ paused on subsequent presses. The state is consulted in two
// places: the packetMsg handler (only adds to the ring buffer when running)
// and the capture page's status text.
type captureState int

const (
	stateIdle captureState = iota
	stateRunning
	statePaused
)

// -----------------------------------------------------------------------------
// ROOT MODEL — the single owner of state shared across pages.
// -----------------------------------------------------------------------------

// app is the bubbletea root model. Everything that must outlive a page
// transition lives here. Pages get a *app pointer at construction time
// for read access to shared fields; they request mutations by emitting
// tea.Cmds (navigate, showMsg) so the message flow stays one-directional.
type app struct {
	// capture pipeline
	cap   *Capture
	buf   *PacketRingBuffer
	pkts  <-chan gopacket.Packet
	state captureState

	// edited packets the user has saved out of the edit page. The
	// retransmit page reads this; it's empty until the user actually
	// edits + saves something. Hotkey bars grey out "retransmit" when
	// this is empty.
	edited []*detailedPacket

	// routing
	page   Page
	pageID pageID

	// message box (rendered below the current page's content)
	msgBox   string
	msgBoxID int

	// hotkey flash — pages render their own bars but read the flashed key
	// from here so all flashes share one debounce counter.
	flashKey string
	flashID  int

	// capture-page persistence. The capture page is reconstructed on every
	// navigation back from inspect/edit, so its scroll state has to live
	// here to survive page swaps.
	//   captureCursorID    — global packet ID the cursor was on
	//   captureCursorValid — false until the cursor has been on a real row
	//   captureFollow      — when true, refreshTable pins the cursor to the
	//                        newest packet so the live view scrolls along
	//                        with arrivals; toggled off by manual scroll
	//                        and back on by the "latest" hotkey.
	captureCursorID    uint64
	captureCursorValid bool
	captureFollow      bool

	// filter applied to the capture table. The zero value is the inactive
	// "match everything" filter — no nil-checks needed at the call sites.
	// Lives on the app (not the capture page) so future pages can read it
	// without coupling to capture-page internals.
	filter PacketFilter
}

// newApp constructs the root model with a capture handle and a ring buffer
// sized per the user's CLI flag. The starting page is the capture page.
func newApp(cap *Capture, bufSize int) *app {
	a := &app{
		cap:           cap,
		buf:           NewPacketRingBuffer(bufSize),
		state:         stateIdle,
		captureFollow: true,
	}
	a.page = newCapturePage(a)
	a.pageID = pageCapture
	return a
}

// -----------------------------------------------------------------------------
// THE BUBBLETEA INTERFACE — Init / Update / View
// -----------------------------------------------------------------------------

// Init delegates to the current page so pages can kick off any async work
// they need on first display (timers, initial fetches, etc.). The capture
// pipeline is *not* started here — the user has to press space first.
func (a *app) Init() tea.Cmd {
	return a.page.Init()
}

// Update is the top-level dispatcher. It handles a small set of global
// concerns and forwards everything else to the current page.
//
// What's global:
//   - quit shortcuts (q / ctrl+c)
//   - space toggles the capture state from any page so packets keep
//     flowing into the buffer while the user is on inspect/edit
//   - packetMsg: feed the ring buffer (when running)
//   - navMsg: page transitions
//   - showMsgMsg / clearMsgBoxMsg: message box lifecycle
//   - clearFlashMsg: hotkey flash decay
//
// Everything else (arrow keys, custom page messages, window resizes) gets
// passed through to the page.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		keyStr := normalizeKey(msg.String())
		// When a page is in modal mode (a popup is collecting input), the
		// global hotkeys (q, space) would otherwise eat keystrokes the user
		// is trying to type into a textinput. Forward everything but
		// ctrl+c — keeping that as an unconditional escape hatch.
		if mp, ok := a.page.(interface{ IsModal() bool }); ok && mp.IsModal() {
			if keyStr == "ctrl+c" {
				return a, tea.Quit
			}
			var cmd tea.Cmd
			a.page, cmd = a.page.Update(msg)
			return a, cmd
		}
		switch keyStr {
		case "q", "ctrl+c":
			return a, tea.Quit
		case "space":
			actionCmd := a.toggleCapture()
			flashCmd := a.flashHotkey("space")
			return a, tea.Batch(flashCmd, actionCmd)
		}
		// not a global key — let the page handle it.
		var cmd tea.Cmd
		a.page, cmd = a.page.Update(msg)
		return a, cmd

	case packetMsg:
		// pcap delivered a packet. If running, file it into the ring
		// buffer; either way, re-arm the read loop so the next packet
		// keeps flowing. The capture page's table will pick the new
		// packet up on its next render via Snapshot().
		if a.state == stateRunning {
			a.buf.Add((*detailedPacket)(msg))
		}
		return a, waitForPacket(a.pkts)

	case navMsg:
		a.swapPage(msg.target, msg.arg)
		return a, a.page.Init()

	case showMsgMsg:
		return a, a.showMessage(msg.text)

	case clearMsgBoxMsg:
		if msg.id == a.msgBoxID {
			a.msgBox = ""
		}
		return a, nil

	case clearFlashMsg:
		if msg.id == a.flashID {
			a.flashKey = ""
		}
		return a, nil
	}

	// fall-through: anything we didn't intercept goes to the page
	// (window-size events, custom page messages, etc.).
	var cmd tea.Cmd
	a.page, cmd = a.page.Update(msg)
	return a, cmd
}

// View composes the final frame: the current page's view, plus the message
// box overlay if anything is currently shown.
func (a *app) View() string {
	pageView := a.page.View()
	if a.msgBox == "" {
		return pageView
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		pageView,
		msgBoxStyle.Render("  "+a.msgBox),
	)
}

// -----------------------------------------------------------------------------
// PAGE NAVIGATION
// -----------------------------------------------------------------------------

// swapPage replaces the current page with a fresh instance of the target
// page, threading any per-page argument through. Pages get a back-pointer
// to the app so they can read shared state.
func (a *app) swapPage(target pageID, arg any) {
	switch target {
	case pageCapture:
		a.page = newCapturePage(a)
	case pageInspect:
		id, _ := arg.(uint64)
		a.page = newInspectPage(a, id)
	case pageEdit:
		id, _ := arg.(uint64)
		a.page = newEditPage(a, id)
	case pageRetransmit:
		a.page = newRetransmitPage(a)
	}
	a.pageID = target
}

// -----------------------------------------------------------------------------
// CAPTURE STATE MACHINE + ASYNC HELPERS
// -----------------------------------------------------------------------------

// toggleCapture advances the start/pause state machine on a space press:
//
//	idle    → running   (open the pcap handle, start the read loop)
//	running → paused    (incoming packetMsgs get dropped on the floor)
//	paused  → running   (subsequent packetMsgs hit the buffer again)
//
// Only the first idle→running transition has a Cmd to return — that's the
// initial waitForPacket that primes the read loop.
func (a *app) toggleCapture() tea.Cmd {
	switch a.state {
	case stateIdle:
		a.cap.Start()
		a.pkts = a.cap.Output()
		a.state = stateRunning
		return waitForPacket(a.pkts)
	case stateRunning:
		a.state = statePaused
	case statePaused:
		a.state = stateRunning
	}
	return nil
}

// showMessage flashes text in the bottom message box for ~4 seconds. Any
// page can request this by emitting showMsg(...) as a Cmd; this function
// is the actual side-effect side. The generation counter prevents an old
// timer from clearing a newer message.
func (a *app) showMessage(text string) tea.Cmd {
	a.msgBox = text
	a.msgBoxID++
	id := a.msgBoxID
	return tea.Tick(msgBoxDuration, func(time.Time) tea.Msg {
		return clearMsgBoxMsg{id: id}
	})
}

// flashHotkey highlights the named key in whatever hotkey bar is currently
// rendered, for a fraction of a second. Pages render their own bars but
// read the flashed key from a.flashKey, so the same flash mechanism works
// everywhere.
func (a *app) flashHotkey(key string) tea.Cmd {
	a.flashKey = key
	a.flashID++
	id := a.flashID
	return tea.Tick(flashDuration, func(time.Time) tea.Msg {
		return clearFlashMsg{id: id}
	})
}

// waitForPacket bridges the capture goroutine into the bubbletea message
// loop. It blocks on the packet channel and returns the next packet as a
// packetMsg. Bubbletea runs the cmd in its own goroutine so blocking here
// doesn't freeze the UI.
//
// Pattern: Update handles a packetMsg, then returns waitForPacket again
// as the next Cmd. That keeps the channel drained as long as packets keep
// coming.
func waitForPacket(ch <-chan gopacket.Packet) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return nil
		}
		return packetMsg(toDetailedPacket(p))
	}
}

// normalizeKey collapses bubbletea's two reportings of the spacebar (" "
// vs "space") into one form so keyswitches stay clean.
func normalizeKey(k string) string {
	if k == " " {
		return "space"
	}
	return k
}

// -----------------------------------------------------------------------------
// SHARED STYLES — lipgloss is essentially CSS for the terminal.
// Page-specific styles live in their own files; this block holds the ones
// used across multiple pages or by the root model itself.
// -----------------------------------------------------------------------------

var (
	asciiStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Bold(true)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Italic(true).
			MarginBottom(1)

	tableBorder = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63"))

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			MarginTop(1)

	splashStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Bold(true)

	// hotkey bar — three states.
	hotkeyStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Foreground(lipgloss.Color("250")).
			MarginRight(1).
			MarginTop(1)

	hotkeyFlashStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#7D56F4")).
				Foreground(lipgloss.Color("230")).
				Background(lipgloss.Color("#7D56F4")).
				Bold(true).
				MarginRight(1).
				MarginTop(1)

	hotkeyDisabledStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("236")).
				Foreground(lipgloss.Color("238")).
				MarginRight(1).
				MarginTop(1)

	// message box — amber border.
	msgBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#F4A827")).
			Foreground(lipgloss.Color("#F4A827")).
			Bold(true).
			MarginTop(1).
			Padding(0, 1)

	// warning / unavailable text inside accent-bordered pages.
	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F4A827")).
			Bold(true)
)
