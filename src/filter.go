package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// PACKET FILTER — reusable matcher + popup editor
// =============================================================================
// PacketFilter is value-typed and self-contained: anywhere in the app that
// holds a slice of *detailedPacket can call Apply / Match without owning any
// UI state. The popup (filterPopup) is a separate component a page can embed
// when it wants to let the user mutate a filter; on submit it hands the
// caller back a fresh PacketFilter.
//
// Empty fields mean "any" — a filter where every field is "" is inactive
// and Match always returns true. That keeps callers free of "if filter !=
// nil" branching: the zero value is a valid pass-through.
// =============================================================================

type PacketFilter struct {
	SrcIP    string // exact match against d.SrcIP.String()
	DstIP    string // exact match against d.DstIP.String()
	Port     string // numeric; matches src OR dst port
	AppProto string // case-insensitive equality on d.ApplicationProtocol
}

func (f PacketFilter) Active() bool {
	return f.SrcIP != "" || f.DstIP != "" || f.Port != "" || f.AppProto != ""
}

// Match returns true if the packet satisfies every populated field. An
// unpopulated field is a wildcard. A malformed Port (non-numeric) rejects
// every packet — that is intentional: silently matching everything on a
// typo would hide the bug from the user.
func (f PacketFilter) Match(d *detailedPacket) bool {
	if !f.Active() || d == nil {
		return !f.Active()
	}
	if f.SrcIP != "" && d.SrcIP.String() != f.SrcIP {
		return false
	}
	if f.DstIP != "" && d.DstIP.String() != f.DstIP {
		return false
	}
	if f.Port != "" {
		port, err := strconv.ParseUint(f.Port, 10, 16)
		if err != nil {
			return false
		}
		p := uint16(port)
		if d.SrcPort != p && d.DstPort != p {
			return false
		}
	}
	if f.AppProto != "" && !strings.EqualFold(d.ApplicationProtocol, f.AppProto) {
		return false
	}
	return true
}

// Apply returns the subset of `packets` that match. Indices into the
// original slice are returned alongside the matches so callers that need to
// preserve a separate ID mapping (like the capture table's global IDs) can
// reconstruct it without a second pass.
func (f PacketFilter) Apply(packets []*detailedPacket) (matched []*detailedPacket, indices []int) {
	if !f.Active() {
		return packets, nil
	}
	for i, d := range packets {
		if f.Match(d) {
			matched = append(matched, d)
			indices = append(indices, i)
		}
	}
	return matched, indices
}

// Description renders the filter as a short single-line summary suitable for
// a status banner. Returns "" when inactive so callers can skip rendering.
func (f PacketFilter) Description() string {
	if !f.Active() {
		return ""
	}
	parts := make([]string, 0, 4)
	if f.SrcIP != "" {
		parts = append(parts, "src="+f.SrcIP)
	}
	if f.DstIP != "" {
		parts = append(parts, "dst="+f.DstIP)
	}
	if f.Port != "" {
		parts = append(parts, "port="+f.Port)
	}
	if f.AppProto != "" {
		parts = append(parts, "app="+f.AppProto)
	}
	return strings.Join(parts, "  ·  ")
}

// -----------------------------------------------------------------------------
// FILTER POPUP — modal editor a page embeds and forwards keys to
// -----------------------------------------------------------------------------
// Not a Page: it's a sub-component meant to overlay a host page. The host
// calls Open() to enter modal mode, forwards keys via Update() while
// IsActive() reports true, and reads the result via Value() once Update
// reports a submit. Closing leaves the inputs in place so reopening shows
// whatever the user last typed.
// =============================================================================

type filterField int

const (
	filterFieldSrc filterField = iota
	filterFieldDst
	filterFieldPort
	filterFieldApp
	filterFieldCount
)

type filterPopup struct {
	inputs []textinput.Model
	focus  filterField
	active bool
}

func newFilterPopup() *filterPopup {
	p := &filterPopup{
		inputs: make([]textinput.Model, filterFieldCount),
	}
	placeholders := [filterFieldCount]string{
		"e.g. 192.168.1.5",
		"e.g. 8.8.8.8",
		"e.g. 443",
		"e.g. HTTP, DNS, SSH",
	}
	for i := range p.inputs {
		ti := textinput.New()
		ti.Placeholder = placeholders[i]
		ti.CharLimit = 64
		ti.Width = 28
		p.inputs[i] = ti
	}
	return p
}

func (p *filterPopup) IsActive() bool { return p.active }

// Open enters modal mode, pre-filling the fields with the caller's current
// filter so the user can edit (or wipe) it. Focus snaps back to the first
// field every time so reopening is predictable.
func (p *filterPopup) Open(current PacketFilter) {
	p.active = true
	p.focus = filterFieldSrc
	values := [filterFieldCount]string{current.SrcIP, current.DstIP, current.Port, current.AppProto}
	for i := range p.inputs {
		p.inputs[i].SetValue(values[i])
		if filterField(i) == p.focus {
			p.inputs[i].Focus()
		} else {
			p.inputs[i].Blur()
		}
	}
}

func (p *filterPopup) Close() {
	p.active = false
	for i := range p.inputs {
		p.inputs[i].Blur()
	}
}

// Value snapshots the current inputs as a PacketFilter. Whitespace is
// trimmed so an accidental space doesn't make a field "active".
func (p *filterPopup) Value() PacketFilter {
	return PacketFilter{
		SrcIP:    strings.TrimSpace(p.inputs[filterFieldSrc].Value()),
		DstIP:    strings.TrimSpace(p.inputs[filterFieldDst].Value()),
		Port:     strings.TrimSpace(p.inputs[filterFieldPort].Value()),
		AppProto: strings.TrimSpace(p.inputs[filterFieldApp].Value()),
	}
}

// Clear empties every field. The host page typically follows this with a
// re-render so the active-filter banner disappears.
func (p *filterPopup) Clear() {
	for i := range p.inputs {
		p.inputs[i].SetValue("")
	}
}

// Update routes a message into the popup while it's active. The two booleans
// tell the host what happened:
//
//	submit — user pressed enter; host should pull Value() and Close()
//	cancel — user pressed esc; host should Close() without saving
//
// Anything else (typing, focus cycling) is handled internally.
func (p *filterPopup) Update(msg tea.Msg) (submit, cancel bool, cmd tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			return false, true, nil
		case "enter":
			return true, false, nil
		case "tab", "down":
			p.cycleFocus(+1)
			return false, false, nil
		case "shift+tab", "up":
			p.cycleFocus(-1)
			return false, false, nil
		case "ctrl+x":
			p.Clear()
			return false, false, nil
		}
	}
	var c tea.Cmd
	p.inputs[p.focus], c = p.inputs[p.focus].Update(msg)
	return false, false, c
}

func (p *filterPopup) cycleFocus(delta int) {
	p.inputs[p.focus].Blur()
	p.focus = filterField((int(p.focus) + delta + int(filterFieldCount)) % int(filterFieldCount))
	p.inputs[p.focus].Focus()
}

func (p *filterPopup) View() string {
	labels := [filterFieldCount]string{"source ip", "dest ip", "port", "app proto"}
	rows := make([]string, filterFieldCount)
	for i := range p.inputs {
		label := filterLabelStyle.Render(labels[i])
		rows[i] = lipgloss.JoinHorizontal(lipgloss.Top, label, p.inputs[i].View())
	}
	help := filterHelpStyle.Render(
		"tab/↑↓ field  ·  enter apply  ·  ctrl+x clear all  ·  esc cancel",
	)
	body := strings.Join(rows, "\n") + "\n\n" + help
	return filterPopupStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			filterPopupTitleStyle.Render("◆  FILTER  ◆"),
			body,
		),
	)
}

// renderFilterBanner is the thin status strip a host page shows under the
// table when a filter is active. Returns "" when inactive so callers can
// JoinVertical it unconditionally.
func renderFilterBanner(f PacketFilter) string {
	if !f.Active() {
		return ""
	}
	return filterBannerStyle.Render(fmt.Sprintf(
		"filter active  ·  %s  ·  press f to edit / clear",
		f.Description(),
	))
}

var (
	filterPopupStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#7D56F4")).
				Padding(1, 2).
				MarginTop(1)

	filterPopupTitleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#7D56F4")).
				Bold(true).
				MarginBottom(1)

	filterLabelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("245")).
				Width(12)

	filterHelpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	filterBannerStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#F4A827")).
				Foreground(lipgloss.Color("#F4A827")).
				Bold(true).
				Padding(0, 1).
				MarginTop(1)
)