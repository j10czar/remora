package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// =============================================================================
// RETRANSMIT PAGE — pick a saved pcap, verify it can be read
// =============================================================================
// The retransmit screen now starts as a chooser: it scans the saves/
// directory for *.pcap files and lets the user pick one. Selecting a file
// runs it through pcapgo.NewReader() which validates the libpcap header —
// if that succeeds, the page swaps to a verified view showing the file
// metadata. Actual replay-onto-the-wire is intentionally deferred; this
// is just the "I can open the file" half of the contract.
//
// State machine:
//   chooser  → list of saves/*.pcap, cursor selects one, enter opens
//   opened   → verified-view panel; esc returns to the chooser
//   error    → couldn't read the selected file; esc returns to the chooser
// =============================================================================

type retransmitPage struct {
	app    *app
	files  []savedPcap
	cursor int

	// opened/err describe the result of the most recent enter press.
	// Both nil means we're in the chooser. esc clears them.
	opened *openedPcap
	err    error
}

// savedPcap is one row in the chooser list — populated from os.ReadDir.
type savedPcap struct {
	Name string
	Path string
	Size int64
}

// openedPcap is what we have to show after a successful pcapgo.NewReader.
// No packets are decoded — this is just the header-level proof we can
// read the file.
type openedPcap struct {
	Name     string
	Size     int64
	LinkType layers.LinkType
	Snaplen  uint32
}

func newRetransmitPage(a *app) *retransmitPage {
	return &retransmitPage{
		app:   a,
		files: listSavedPcaps(),
	}
}

func (p *retransmitPage) Init() tea.Cmd { return nil }

func (p *retransmitPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch normalizeKey(k.String()) {
	case "esc":
		// One esc clears an opened/error panel and drops back to the
		// chooser; a second esc leaves the page entirely. That mirrors
		// the way most file-pickers handle drill-in/drill-out.
		if p.opened != nil || p.err != nil {
			p.opened = nil
			p.err = nil
			return p, nil
		}
		return p, navigate(pageCapture, nil)
	case "up", "k":
		if p.opened == nil && p.err == nil && p.cursor > 0 {
			p.cursor--
		}
	case "down", "j":
		if p.opened == nil && p.err == nil && p.cursor < len(p.files)-1 {
			p.cursor++
		}
	case "enter":
		if p.opened == nil && p.err == nil {
			return p, tea.Batch(p.app.flashHotkey("enter"), p.openSelected())
		}
	}
	return p, nil
}

// openSelected runs the cursor's file through pcapgo and stashes the
// result on the page. Returns a flash command for the enter hotkey;
// the actual file IO is synchronous since reading a pcap header is
// effectively instant.
func (p *retransmitPage) openSelected() tea.Cmd {
	if p.cursor < 0 || p.cursor >= len(p.files) {
		return nil
	}
	file := p.files[p.cursor]
	info, err := readPcapHeader(file.Path)
	if err != nil {
		p.err = fmt.Errorf("%s: %w", file.Name, err)
		return nil
	}
	info.Name = file.Name
	info.Size = file.Size
	p.opened = info
	return nil
}

func (p *retransmitPage) View() string {
	title := retransmitTitleArt()

	var body string
	switch {
	case p.opened != nil:
		body = p.openedView()
	case p.err != nil:
		body = p.errorView()
	case len(p.files) == 0:
		body = p.emptyView()
	default:
		body = p.chooserView()
	}

	bar := renderHotkeyBar(p.hotkeys(), p.app.flashKey)

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		accentBorder(accentRetransmit).Render(body),
		bar,
	)
}

// chooserView renders the saves/ file list. The cursor row is painted in
// the accent color with a leading ▸; the rest are dim. File sizes are
// right-padded so they line up regardless of name length.
func (p *retransmitPage) chooserView() string {
	maxName := 0
	for _, f := range p.files {
		if n := lipgloss.Width(f.Name); n > maxName {
			maxName = n
		}
	}

	header := retransmitDimStyle.Render(
		fmt.Sprintf("found %d capture%s in saves/", len(p.files), plural(len(p.files))),
	)

	rows := make([]string, 0, len(p.files)+2)
	rows = append(rows, header, "")
	for i, f := range p.files {
		var marker, name, size string
		paddedName := f.Name + strings.Repeat(" ", maxName-lipgloss.Width(f.Name))
		if i == p.cursor {
			marker = retransmitCursorStyle.Render("▸ ")
			name = retransmitCursorStyle.Render(paddedName)
			size = retransmitCursorStyle.Render(formatSize(f.Size))
		} else {
			marker = "  "
			name = retransmitFileStyle.Render(paddedName)
			size = retransmitDimStyle.Render(formatSize(f.Size))
		}
		rows = append(rows, marker+name+"  "+size)
	}

	return strings.Join(rows, "\n")
}

// openedView is the "we successfully read this file" panel. Big check,
// file metadata, and a placeholder line for the not-yet-wired replay.
func (p *retransmitPage) openedView() string {
	check := retransmitCheckStyle.Render("✓  successfully read")
	name := retransmitFileStyle.Bold(true).Render(p.opened.Name)

	meta := lipgloss.JoinVertical(lipgloss.Left,
		retransmitMetaRow("size", formatSize(p.opened.Size)),
		retransmitMetaRow("link type", p.opened.LinkType.String()),
		retransmitMetaRow("snaplen", fmt.Sprintf("%d bytes", p.opened.Snaplen)),
	)

	pending := retransmitPendingStyle.Render("(replay onto the wire — not yet wired)")

	return lipgloss.JoinVertical(lipgloss.Left,
		check,
		"   "+name,
		"",
		meta,
		"",
		pending,
	)
}

func (p *retransmitPage) errorView() string {
	x := retransmitErrorStyle.Render("✗  could not read pcap")
	detail := retransmitDimStyle.Render(p.err.Error())
	hint := retransmitDimStyle.Render("(press esc to pick another file)")
	return lipgloss.JoinVertical(lipgloss.Left, x, "", detail, "", hint)
}

func (p *retransmitPage) emptyView() string {
	main := retransmitDimStyle.Render("no captures found in saves/")
	hint := retransmitDimStyle.Render("press 's' on the capture page to save a range")
	return lipgloss.JoinVertical(lipgloss.Left, main, "", hint)
}

func (p *retransmitPage) hotkeys() []hotkey {
	switch {
	case p.opened != nil, p.err != nil:
		return []hotkey{
			{Key: "esc", Label: "back to list"},
		}
	case len(p.files) == 0:
		return []hotkey{
			{Key: "esc", Label: "back to capture"},
		}
	default:
		return []hotkey{
			{Key: "↑↓", Label: "select"},
			{Key: "enter", Label: "open"},
			{Key: "esc", Label: "back to capture"},
		}
	}
}

// -----------------------------------------------------------------------------
// FILE IO HELPERS
// -----------------------------------------------------------------------------

// listSavedPcaps scans the saves/ directory for *.pcap files and returns
// them sorted newest-first by mtime. A missing directory is treated as
// "no saves yet" — not an error.
func listSavedPcaps() []savedPcap {
	entries, err := os.ReadDir(savesRoot)
	if err != nil {
		return nil
	}
	out := make([]savedPcap, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".pcap") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, savedPcap{
			Name: e.Name(),
			Path: filepath.Join(savesRoot, e.Name()),
			Size: info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		ii, _ := os.Stat(out[i].Path)
		jj, _ := os.Stat(out[j].Path)
		if ii == nil || jj == nil {
			return out[i].Name < out[j].Name
		}
		return ii.ModTime().After(jj.ModTime())
	})
	return out
}

// readPcapHeader opens a pcap file and parses just its libpcap header.
// Success means the file is structurally a pcap; we don't iterate any
// packets here — that's deferred to a future replay implementation.
func readPcapHeader(path string) (*openedPcap, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}
	return &openedPcap{
		LinkType: r.LinkType(),
		Snaplen:  r.Snaplen(),
	}, nil
}

// formatSize renders a byte count as B / KB / MB to whichever unit keeps
// the number readable.
func formatSize(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
}

// -----------------------------------------------------------------------------
// VISUAL FLAIR
// -----------------------------------------------------------------------------
// The retransmit page leans into the orange accent more than its siblings
// because "replay" is the loudest action in the app. The title art stacks
// a mini remora wordmark (purple, matching the capture-page banner) over
// signal-wave ornaments and a double-bordered orange name plate, so the
// page reads as "remora's transmitter" rather than another generic header.

const retransmitWaves = "⌁⌁⌁  ((( ◉ )))  ⌁⌁⌁"

// remoraMiniASCII is a 3-line wordmark sized to fit comfortably above the
// retransmit name plate. Same letterforms as remoraASCII on the capture
// page, just rendered with box-drawing glyphs instead of full blocks so
// the total height stays low.
const remoraMiniASCII = `┏━┓┏━╸┏┳┓┏━┓┏━┓┏━┓
┣┳┛┣╸ ┃┃┃┃ ┃┣┳┛┣━┫
╹╰╴┗━╸╹ ╹┗━┛╹╰╴╹ ╹`

func retransmitTitleArt() string {
	logo := remoraMiniStyle.Render(remoraMiniASCII)
	waves := retransmitWavesStyle.Render(retransmitWaves)
	plate := retransmitPlateStyle.Render("⚡  R E T R A N S M I T  ⚡")
	sub := retransmitSubStyle.Render("replay engine  ·  saved captures")
	stack := lipgloss.JoinVertical(lipgloss.Center, logo, waves, plate, sub)
	return lipgloss.NewStyle().MarginBottom(1).Render(stack)
}

// retransmitMetaRow lays out one "label   value" line in the verified
// panel. The label is dim-and-padded so values line up like a key/value
// table without us having to introduce a real table widget.
func retransmitMetaRow(label, value string) string {
	l := retransmitMetaLabelStyle.Render(fmt.Sprintf("%-12s", label))
	v := retransmitMetaValueStyle.Render(value)
	return "   " + l + v
}

var (
	remoraMiniStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Bold(true).
			MarginBottom(1)

	retransmitWavesStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F6AD55")).
				Faint(true)

	retransmitPlateStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.DoubleBorder()).
				BorderForeground(lipgloss.Color("#F6AD55")).
				Foreground(lipgloss.Color("#F6AD55")).
				Bold(true).
				Padding(0, 3)

	retransmitSubStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("245")).
				Italic(true).
				MarginTop(1)

	retransmitDimStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("245"))

	retransmitFileStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("250"))

	retransmitCursorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F6AD55")).
				Bold(true)

	retransmitCheckStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#48BB78")).
				Bold(true)

	retransmitErrorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F56565")).
				Bold(true)

	retransmitMetaLabelStyle = lipgloss.NewStyle().
					Foreground(lipgloss.Color("245"))

	retransmitMetaValueStyle = lipgloss.NewStyle().
					Foreground(lipgloss.Color("#F6AD55")).
					Bold(true)

	retransmitPendingStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("241")).
				Italic(true)
)
