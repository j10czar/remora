package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// PAGE ARCHITECTURE — the 30-second tour
// =============================================================================
// The application is a small router. The root model in tui.go owns shared
// state (the capture handle, the ring buffer, the message box) and holds a
// single Page. Every keypress / message / render flows through the root
// first; whatever the root doesn't intercept is forwarded to the current
// page via this interface.
//
// Pages don't talk to each other directly. To navigate, a page emits a
// navMsg via tea.Cmd; the root model intercepts it, instantiates the new
// page (passing a pointer to the root for shared-state access), and swaps
// it in. Same idea for the message box: pages emit showMsgMsg, root model
// owns the rendering and the auto-hide tick.
//
// New pages should:
//   1. Implement the Page interface below.
//   2. Get a `*app` back-pointer so they can read shared state (ring
//      buffer, edited packets list, capture state).
//   3. Use navigate(...) and showMsg(...) helpers — never mutate the app
//      pointer directly.
//   4. Render their own hotkey bar via renderHotkeyBar(...).
// =============================================================================

// Page is implemented by every full-screen view. The root model holds one
// at a time and delegates all three lifecycle calls to it.
type Page interface {
	Init() tea.Cmd
	Update(msg tea.Msg) (Page, tea.Cmd)
	View() string
}

// pageID identifies each page so the root model knows which constructor to
// call when handling a navMsg. Add new constants here when adding a page.
type pageID int

const (
	pageCapture pageID = iota
	pageInspect
	pageEdit
	pageRetransmit
)

// navMsg asks the root model to switch to a different page. The arg field
// carries page-specific context — for inspect/edit it's the global ring
// buffer ID of the packet to focus on; retransmit doesn't need anything.
type navMsg struct {
	target pageID
	arg    any
}

// navigate is the helper pages call to request a page change. The returned
// tea.Cmd, when executed, fires a navMsg back through the message loop
// where the root model intercepts it.
func navigate(target pageID, arg any) tea.Cmd {
	return func() tea.Msg {
		return navMsg{target: target, arg: arg}
	}
}

// showMsgMsg asks the root model to flash a notice in the bottom message
// box. Pages call showMsg(text) without having to know how the box is
// rendered or how long it stays visible.
type showMsgMsg struct{ text string }

func showMsg(text string) tea.Cmd {
	return func() tea.Msg {
		return showMsgMsg{text: text}
	}
}

// -----------------------------------------------------------------------------
// HOTKEY BAR
// -----------------------------------------------------------------------------

// hotkey is one entry in the bar at the bottom of any page. Disabled keys
// are rendered dim — used by the capture page to grey out "retransmit"
// when no packets have been edited yet.
type hotkey struct {
	Key      string
	Label    string
	Disabled bool
}

// renderHotkeyBar draws a row of hotkey boxes. Pages own their own keys
// (each page has different actions); flashedKey is sourced from the app
// model so flashes work uniformly across pages.
func renderHotkeyBar(keys []hotkey, flashedKey string) string {
	boxes := make([]string, len(keys))
	for i, hk := range keys {
		var style lipgloss.Style
		switch {
		case hk.Disabled:
			style = hotkeyDisabledStyle
		case hk.Key == flashedKey:
			style = hotkeyFlashStyle
		default:
			style = hotkeyStyle
		}
		boxes[i] = style.Render(fmt.Sprintf(" %s  %s ", hk.Key, hk.Label))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, boxes...)
}

// -----------------------------------------------------------------------------
// PAGE CHROME — title + accent border
// -----------------------------------------------------------------------------
// Each non-capture page (inspect / edit / retransmit) gets its own accent
// color so the user can tell at a glance which screen they're on. These
// helpers keep that consistent without copy-pasting style blocks.

const (
	accentInspect    = "#4FD1C5" // teal
	accentEdit       = "#F687B3" // pink
	accentRetransmit = "#F6AD55" // orange
)

// pageTitle renders a centered title bar in the page's accent color.
func pageTitle(text, accent string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(accent)).
		Bold(true).
		MarginBottom(1).
		Render("◆  " + text + "  ◆")
}

// accentBorder returns a bordered container styled with the page's accent.
// Pages wrap their main body in this to visually separate page content
// from the global chrome.
func accentBorder(accent string) lipgloss.Style {
	return lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(accent)).
		Padding(1, 2)
}
