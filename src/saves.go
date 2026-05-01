package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// savesRoot is the directory under the working dir where pcap files are
// written. Files land directly at saves/<name>.pcap; when the user
// doesn't supply a name, the current date/time is used so two unnamed
// saves don't collide.
const savesRoot = "saves"

// SavePacket writes a single detailedPacket to saves/<timestamp>.pcap.
// The returned path points at the .pcap so callers can show it to the user.
func SavePacket(p *detailedPacket) (string, error) {
	if p == nil || p.Raw == nil {
		return "", fmt.Errorf("save: nil packet")
	}
	if err := os.MkdirAll(savesRoot, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(savesRoot, defaultSaveName()+".pcap")
	return path, writePcap(path, []*detailedPacket{p})
}

// SavePackets writes every packet whose global ID is listed in `ids` to a
// single pcap file in saves/. IDs that have been evicted from the ring or
// were never captured are skipped silently — the resulting file contains
// only the packets still available.
func SavePackets(ids []uint64, buf *PacketRingBuffer) (string, error) {
	return SavePacketsNamed("", ids, buf)
}

// SavePacketsNamed is SavePackets with a user-supplied filename (no
// extension). The name is sanitized to keep filesystem-hostile characters
// out; an empty/all-stripped name falls back to the current date/time so
// two unnamed saves don't overwrite each other. The output lands at
// saves/<safe-name>.pcap.
func SavePacketsNamed(name string, ids []uint64, buf *PacketRingBuffer) (string, error) {
	if buf == nil {
		return "", fmt.Errorf("save: nil buffer")
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("save: no packets to save")
	}

	packets := make([]*detailedPacket, 0, len(ids))
	for _, id := range ids {
		if p, ok := buf.At(id); ok && p != nil && p.Raw != nil {
			packets = append(packets, p)
		}
	}
	if len(packets) == 0 {
		return "", fmt.Errorf("save: none of the requested packets are still in the buffer")
	}

	if err := os.MkdirAll(savesRoot, 0755); err != nil {
		return "", err
	}
	safe := sanitizeFilename(name)
	if safe == "" {
		safe = defaultSaveName()
	}
	path := filepath.Join(savesRoot, safe+".pcap")
	return path, writePcap(path, packets)
}

// defaultSaveName is the filename stem used when the user submits an
// empty name. Seconds-precision keeps two back-to-back unnamed saves from
// landing on the same path.
func defaultSaveName() string {
	return time.Now().Format("2006-01-02_15-04-05")
}

// writePcap is the shared body that opens the file, writes the libpcap
// header, and appends each packet's raw bytes with its original capture
// metadata.
func writePcap(path string, packets []*detailedPacket) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return err
	}

	for _, p := range packets {
		data := p.Raw.Data()
		ci := gopacket.CaptureInfo{
			Timestamp:     p.Timestamp,
			CaptureLength: len(data),
			Length:        p.WireLength,
		}
		if err := w.WritePacket(ci, data); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeFilename keeps only characters that are safe in a pcap filename
// across macOS, Linux, and Windows. Spaces are converted to underscores so
// "my capture" still produces a usable name. Anything else is dropped.
func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('_')
		}
	}
	return b.String()
}

// =============================================================================
// SAVE NAME POPUP — modal text input for naming a save before commit
// =============================================================================
// The capture page enters this popup as the final step of its save flow:
// after the user has bracketed a packet range with start/end markers, they
// press `s` once more to open this popup and type a filename. The popup
// follows the same host/embed pattern as filterPopup — host forwards keys
// while IsActive() reports true and reads Value() once Update returns
// submit=true.
// =============================================================================

type saveNamePopup struct {
	input  textinput.Model
	active bool
}

func newSaveNamePopup() *saveNamePopup {
	ti := textinput.New()
	ti.Placeholder = "e.g. http-traffic"
	ti.CharLimit = 64
	ti.Width = 32
	return &saveNamePopup{input: ti}
}

func (p *saveNamePopup) IsActive() bool { return p.active }

// Open enters modal mode with an empty input — the user types fresh each
// save rather than seeing the previous name pre-filled, which would be
// surprising for a one-shot action.
func (p *saveNamePopup) Open() {
	p.active = true
	p.input.SetValue("")
	p.input.Focus()
}

func (p *saveNamePopup) Close() {
	p.active = false
	p.input.Blur()
}

func (p *saveNamePopup) Value() string {
	return strings.TrimSpace(p.input.Value())
}

// Update routes a message into the popup while it's active.
//
//	submit — user pressed enter; host should pull Value() and Close()
//	cancel — user pressed esc; host should Close() without saving
func (p *saveNamePopup) Update(msg tea.Msg) (submit, cancel bool, cmd tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			return false, true, nil
		case "enter":
			return true, false, nil
		}
	}
	var c tea.Cmd
	p.input, c = p.input.Update(msg)
	return false, false, c
}

func (p *saveNamePopup) View() string {
	label := saveNameLabelStyle.Render("name")
	row := lipgloss.JoinHorizontal(lipgloss.Top, label, p.input.View())
	help := saveNameHelpStyle.Render("enter save  ·  esc cancel  ·  blank → date/time")
	body := row + "\n\n" + help
	return saveNamePopupStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			saveNamePopupTitleStyle.Render("◆  SAVE  ◆"),
			body,
		),
	)
}

// saveInfo is the user-facing state of a save in progress. Internal
// global IDs are deliberately not surfaced — they're meaningless to the
// user. Timestamps and a live packet count tell the story instead.
type saveInfo struct {
	StartTime string // wall-clock time of the start packet (empty until selectEnd)
	EndTime   string // wall-clock time of the end packet (empty until rangeSet)
	Count     int    // packets that will be written if the user commits now
}

// renderSaveBanner is the orange status strip a host page shows under the
// table while a save is in progress. The text is stage-specific so the
// user always sees what action will happen next, and what they have so far.
func renderSaveBanner(stage saveStage, info saveInfo) string {
	var msg string
	switch stage {
	case saveStageSelectStart:
		msg = "SAVE  ·  select START packet  ·  ↑↓ navigate  ·  space set start  ·  esc cancel"
	case saveStageSelectEnd:
		msg = fmt.Sprintf(
			"SAVE  ·  start: %s  ·  selecting END (%d packet%s)  ·  ↑↓ navigate  ·  space set end  ·  esc cancel",
			info.StartTime, info.Count, plural(info.Count),
		)
	case saveStageRangeSet:
		msg = fmt.Sprintf(
			"SAVE  ·  range %s → %s  ·  %d packet%s  ·  press s to name & save  ·  esc cancel",
			info.StartTime, info.EndTime, info.Count, plural(info.Count),
		)
	default:
		return ""
	}
	return saveBannerStyle.Render(msg)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

var (
	saveNamePopupStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#F6AD55")).
				Padding(1, 2).
				MarginTop(1)

	saveNamePopupTitleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F6AD55")).
				Bold(true).
				MarginBottom(1)

	saveNameLabelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("245")).
				Width(8)

	saveNameHelpStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("241"))

	saveBannerStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#F6AD55")).
			Foreground(lipgloss.Color("#F6AD55")).
			Bold(true).
			Padding(0, 1).
			MarginTop(1)
)
