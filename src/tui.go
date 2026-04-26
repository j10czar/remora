package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
)

// =============================================================================
// HOW THIS FILE WORKS  —  the 30-second tour
// =============================================================================
// Bubbletea uses an "Elm-style" architecture, three pieces:
//
//   1. Model   — a struct holding every bit of UI state.
//   2. Update  — given the current model + an event ("message"), produce a
//                new model and optionally a Command to run next.
//   3. View    — turn the current model into a string and print it.
//
// Bubbletea sits in a loop: it waits for a message, calls Update, calls View,
// repeats. Every event — a keypress, a window resize, a custom event we make
// up ourselves — is just a value passed through Update as a tea.Msg.
//
// To do async work (network, channels, timers) you return a tea.Cmd from
// Update. Bubbletea runs the cmd in a goroutine, and whatever the cmd returns
// becomes the next message. That's the trick we use to bridge the packet
// channel into the UI: see waitForPacket below.
// =============================================================================

// remoraASCII is the splash banner painted at the top of the screen.
const remoraASCII = `
██████╗ ███████╗███╗   ███╗ ██████╗ ██████╗  █████╗
██╔══██╗██╔════╝████╗ ████║██╔═══██╗██╔══██╗██╔══██╗
██████╔╝█████╗  ██╔████╔██║██║   ██║██████╔╝███████║
██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║
██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
`

// -----------------------------------------------------------------------------
// MESSAGES
// -----------------------------------------------------------------------------

// packetMsg is our own custom message type. Anything we want Update to react
// to has to be a tea.Msg (which is just `any` — bubbletea uses a type-switch
// in Update to dispatch on it). Built-in messages like tea.KeyMsg or
// tea.WindowSizeMsg arrive automatically; custom ones like this one only
// arrive if some Cmd we wrote returns it.
type packetMsg *PacketSummary

// clearFlashMsg is fired by a tea.Tick a short time after a hotkey is pressed,
// to "un-flash" the hotkey box. The id field is a generation counter — if a
// newer flash has happened in the meantime, an older clearFlashMsg is ignored.
type clearFlashMsg struct{ id int }

// -----------------------------------------------------------------------------
// HOTKEYS
// -----------------------------------------------------------------------------

// hotkey is one entry in the bar at the bottom of the screen.
// Key is the literal key the user presses; Label is the displayed name.
// Behaviour is intentionally not wired up yet — the entries are placeholders.
type hotkey struct {
	Key   string
	Label string
}

var hotkeys = []hotkey{
	{Key: "space", Label: "start/pause"},
	{Key: "f", Label: "filter"},
	{Key: "c", Label: "clear"},
	{Key: "s", Label: "save"},
	{Key: "i", Label: "inspect"},
	{Key: "h", Label: "help"},
}

// flashDuration is how long a hotkey stays highlighted after a press.
const flashDuration = 180 * time.Millisecond

// -----------------------------------------------------------------------------
// CAPTURE STATE
// -----------------------------------------------------------------------------

// captureState is a tiny three-state machine driving the start/pause flow.
// It starts in stateIdle (capture hardware not yet opened), flips to
// stateRunning on the first space press, and toggles between running and
// paused on subsequent presses.
type captureState int

const (
	stateIdle captureState = iota
	stateRunning
	statePaused
)

// -----------------------------------------------------------------------------
// MODEL
// -----------------------------------------------------------------------------

// model is the entire UI state. Bubbletea passes us the same model on every
// update so we can mutate and return it.
type model struct {
	table    table.Model            // the scrollable table from bubbles
	cap      *Capture               // the pcap capture (not started until first space)
	pkts     <-chan gopacket.Packet // populated once capture is started
	state    captureState           // idle / running / paused
	count    int                    // total packets seen — shown in footer
	flashIdx int                    // index of the hotkey currently flashing, -1 if none
	flashID  int                    // generation counter so stale clear-ticks are ignored
}

// newModel builds the initial model: an empty table with our column layout,
// styled and ready to start receiving packets.
func newModel(cap *Capture) model {
	// Width is in terminal cells (≈ one ASCII char wide).
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
		table.WithHeight(20),    // visible rows; older rows scroll off
		table.WithFocused(true), // table receives arrow-key input
	)
	t.SetStyles(tableStyles())

	return model{table: t, cap: cap, state: stateIdle, flashIdx: -1}
}

// -----------------------------------------------------------------------------
// THE BUBBLETEA INTERFACE — Init / Update / View
// -----------------------------------------------------------------------------

// Init runs once when the program starts. We don't kick off any work here —
// the user has to press space to actually start the capture.
func (m model) Init() tea.Cmd {
	return nil
}

// Update is the heart of the program. Every event funnels through here as a
// tea.Msg; we type-switch on it, mutate the model, and optionally return a
// Cmd telling bubbletea what async work to kick off next.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		// bubbletea sometimes reports space as " " and sometimes as "space".
		// normalise so our hotkey table can use "space".
		keyStr := msg.String()
		if keyStr == " " {
			keyStr = "space"
		}

		// quit shortcuts.
		switch keyStr {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

		// is this one of our hotkeys?
		hotkeyIdx := -1
		for i, hk := range hotkeys {
			if keyStr == hk.Key {
				hotkeyIdx = i
				break
			}
		}

		if hotkeyIdx >= 0 {
			flashCmd := m.triggerFlash(hotkeyIdx)

			// space is the only hotkey with real behavior right now —
			// it drives the start/pause state machine.
			if keyStr == "space" {
				actionCmd := m.toggleCapture()
				return m, tea.Batch(flashCmd, actionCmd)
			}

			// every other hotkey just flashes; behavior TBD.
			return m, flashCmd
		}

	case clearFlashMsg:
		// only honor the clear if no newer flash has happened since.
		if msg.id == m.flashID {
			m.flashIdx = -1
		}
		return m, nil

	case packetMsg:
		// A new packet was delivered by waitForPacket. If we're running,
		// add it to the table; if we're paused, silently drop it. Either
		// way, re-arm so the loop keeps draining the channel.
		if m.state == stateRunning {
			m.count++
			m.appendRow(buildRow((*PacketSummary)(msg)))
		}
		return m, waitForPacket(m.pkts)
	}

	// Anything we didn't handle (arrow keys, page up/down, etc.) gets
	// forwarded to the table so it can scroll itself.
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

// View renders the current model as a string. Bubbletea calls this after
// every Update and writes the result to the terminal. lipgloss.JoinVertical
// stacks the pieces top-to-bottom.
func (m model) View() string {
	header := lipgloss.JoinVertical(lipgloss.Left,
		asciiStyle.Render(remoraASCII),
		subtitleStyle.Render("packet sniffer  ·  "+m.statusText()),
	)

	footer := footerStyle.Render(
		"© 2026 Jason Tenczar  ·  packets: " + strconv.Itoa(m.count),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		m.tableArea(),
		m.hotkeyBar(),
		footer,
	)
}

// statusText is the right-hand half of the subtitle: tells the user what
// state the capture is in and which key advances it.
func (m model) statusText() string {
	switch m.state {
	case stateRunning:
		return "running  ·  space to pause  ·  q to quit"
	case statePaused:
		return "paused  ·  space to resume  ·  q to quit"
	default:
		return "press space to start  ·  q to quit"
	}
}

// tableArea draws the bordered region between header and hotkey bar.
// When idle, it shows a centered splash instead of the (empty) table so the
// user has something to read on first launch.
func (m model) tableArea() string {
	if m.state == stateIdle {
		splash := splashStyle.Render("◆  press space to start capturing  ◆")
		// Place the splash in a box roughly the same size the live table
		// will occupy, so the layout doesn't jump when capture starts.
		return tableBorder.Render(
			lipgloss.Place(75, 20, lipgloss.Center, lipgloss.Center, splash),
		)
	}
	return tableBorder.Render(m.table.View())
}

// hotkeyBar renders the row of hotkey boxes that lives just under the table.
// The currently-flashing hotkey (if any) is drawn with hotkeyFlashStyle.
func (m model) hotkeyBar() string {
	boxes := make([]string, len(hotkeys))
	for i, hk := range hotkeys {
		style := hotkeyStyle
		if i == m.flashIdx {
			style = hotkeyFlashStyle
		}
		boxes[i] = style.Render(fmt.Sprintf(" %s  %s ", hk.Key, hk.Label))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, boxes...)
}

// -----------------------------------------------------------------------------
// CHANNEL → MESSAGE BRIDGE
// -----------------------------------------------------------------------------

// waitForPacket returns a tea.Cmd that blocks on the packet channel and
// returns the next packet as a packetMsg. Bubbletea runs the cmd in a
// goroutine, so blocking here doesn't freeze the UI.
//
// The pattern is: Update handles a packetMsg, then returns waitForPacket
// again as the next Cmd. That keeps the pipe drained as long as packets
// keep coming.
func waitForPacket(ch <-chan gopacket.Packet) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			// channel closed — returning nil ends the loop for this cmd.
			return nil
		}
		return packetMsg(toSummaryPacket(p))
	}
}

// -----------------------------------------------------------------------------
// HELPERS
// -----------------------------------------------------------------------------

// buildRow turns one PacketSummary into one table row.
func buildRow(info *PacketSummary) table.Row {
	src := info.SrcIP.String()
	dst := info.DstIP.String()
	if info.SrcPort != 0 {
		src += ":" + strconv.Itoa(int(info.SrcPort))
	}
	if info.DstPort != 0 {
		dst += ":" + strconv.Itoa(int(info.DstPort))
	}

	transport := info.TransportProtocol
	if transport == "" {
		transport = "—"
	}

	app := info.ApplicationProtocol
	if app == "" {
		app = "—"
	}

	return table.Row{
		info.Timestamp.Format("15:04:05.000"),
		transport,
		app,
		src,
		dst,
		strconv.Itoa(info.Length),
	}
}

// triggerFlash marks the given hotkey as flashed, bumps the generation
// counter, and returns a Cmd that will un-flash it after flashDuration.
// The id capture means rapid presses don't step on each other.
func (m *model) triggerFlash(idx int) tea.Cmd {
	m.flashIdx = idx
	m.flashID++
	id := m.flashID
	return tea.Tick(flashDuration, func(time.Time) tea.Msg {
		return clearFlashMsg{id: id}
	})
}

// toggleCapture advances the state machine on a space press:
//
//	idle    → running   (open the pcap handle, start the read loop)
//	running → paused    (incoming packetMsgs get dropped in Update)
//	paused  → running   (Update will start adding rows again)
//
// Returns a Cmd to run if needed (only the first idle→running transition
// has one — the initial waitForPacket).
func (m *model) toggleCapture() tea.Cmd {
	switch m.state {
	case stateIdle:
		m.cap.Start()
		m.pkts = m.cap.Output()
		m.state = stateRunning
		return waitForPacket(m.pkts)
	case stateRunning:
		m.state = statePaused
	case statePaused:
		m.state = stateRunning
	}
	return nil
}

// appendRow adds a row to the table, caps the buffer at 1000 rows so memory
// doesn't grow forever, and auto-scrolls to the newest row.
func (m *model) appendRow(row table.Row) {
	rows := append(m.table.Rows(), row)
	if len(rows) > 1000 {
		rows = rows[len(rows)-1000:]
	}
	m.table.SetRows(rows)
	m.table.GotoBottom()
}

// -----------------------------------------------------------------------------
// STYLES  —  lipgloss is essentially CSS for the terminal.
// Each style object holds foreground/background/border/margin rules.
// `.Render(s)` wraps a string with the right ANSI escape codes.
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

	// shown in the middle of the table area before the user starts capture.
	splashStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Bold(true)

	// resting state for a hotkey box: bordered, dim text.
	hotkeyStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Foreground(lipgloss.Color("250")).
			MarginRight(1).
			MarginTop(1)

	// flashed state: bright background to make the press visible for a moment.
	hotkeyFlashStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#7D56F4")).
				Foreground(lipgloss.Color("230")).
				Background(lipgloss.Color("#7D56F4")).
				Bold(true).
				MarginRight(1).
				MarginTop(1)
)

// tableStyles tweaks the bubbles/table defaults so headers and the selected
// row stand out a bit more.
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
