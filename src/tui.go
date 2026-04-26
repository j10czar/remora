package main

import (
	"strconv"

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

// -----------------------------------------------------------------------------
// MODEL
// -----------------------------------------------------------------------------

// model is the entire UI state. Bubbletea passes us the same model on every
// update so we can mutate and return it.
type model struct {
	table table.Model            // the scrollable table from bubbles
	pkts  <-chan gopacket.Packet // receive-only channel of raw packets
	count int                    // total packets seen — shown in footer
}

// newModel builds the initial model: an empty table with our column layout,
// styled and ready to start receiving packets.
func newModel(pkts <-chan gopacket.Packet) model {
	// Width is in terminal cells (≈ one ASCII char wide).
	columns := []table.Column{
		{Title: "Time", Width: 13},
		{Title: "Proto", Width: 8},
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

	return model{table: t, pkts: pkts}
}

// -----------------------------------------------------------------------------
// THE BUBBLETEA INTERFACE — Init / Update / View
// -----------------------------------------------------------------------------

// Init runs once when the program starts. The Cmd we return here is the first
// thing bubbletea executes — for us, "start listening for the first packet."
func (m model) Init() tea.Cmd {
	return waitForPacket(m.pkts)
}

// Update is the heart of the program. Every event funnels through here as a
// tea.Msg; we type-switch on it, mutate the model, and optionally return a
// Cmd telling bubbletea what async work to kick off next.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		// quit shortcuts.
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case packetMsg:
		// A new packet was delivered by waitForPacket. Add it to the table
		// and re-arm the listener so the stream keeps flowing.
		m.count++
		m.appendRow(buildRow((*PacketSummary)(msg)))
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
		subtitleStyle.Render("packet sniffer  ·  press q to quit"),
	)

	footer := footerStyle.Render(
		"© 2026 Jason Tenczar  ·  packets: " + strconv.Itoa(m.count),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		tableBorder.Render(m.table.View()),
		footer,
	)
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
		return packetMsg(InterpretPacketInterface(p))
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

	proto := info.Protocol
	if proto == "" {
		proto = "—"
	}

	return table.Row{
		info.Timestamp.Format("15:04:05.000"),
		proto,
		src,
		dst,
		strconv.Itoa(info.Length),
	}
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
