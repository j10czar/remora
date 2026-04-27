# Remora — Codebase Guide

This document explains how the Remora codebase is organized, the architectural patterns it uses, and how to extend it. If you're adding a new page, a new packet field, or a new capture feature, start here.

For the project vision and stretch goals, see `intro.md`.

---

## 1. Architecture at a Glance

Remora is a real-time TUI packet sniffer with three layers:

```
┌──────────────────────────────────────────────────────────────┐
│                    BUBBLETEA TUI (root model)                │
│                                                              │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐               │
│   │ capture  │ ↔  │ inspect  │ ↔  │   edit   │ ↔ retransmit  │
│   │   page   │    │   page   │    │   page   │               │
│   └──────────┘    └──────────┘    └──────────┘               │
│         ▲                ▲                ▲                  │
│         │                │                │                  │
│         └────────┐ ┌─────┘    ┌───────────┘                  │
│                  ▼ ▼          ▼                              │
│         ┌─────────────────────────────┐                      │
│         │   PacketRingBuffer          │                      │
│         │   (single source of truth)  │                      │
│         └──────────────▲──────────────┘                      │
│                        │                                     │
│                        │ Add(*detailedPacket)                │
└────────────────────────┼─────────────────────────────────────┘
                         │
            ┌────────────┴─────────────┐
            │   Capture goroutine      │
            │   gopacket → channel     │
            └──────────────────────────┘
```

The bubbletea root model owns shared state. Pages render and handle local input. The ring buffer is the only place packet data lives long-term — every page reads from it, never from each other.

---

## 2. File Layout

| File | Purpose |
|---|---|
| `main.go` | Entry point. Parses CLI flags (`--buffer`, `--iface`), creates the capture handle, hands control to the bubbletea program. |
| `capture.go` | Packet capture (libpcap via gopacket) and the `detailedPacket` decoder. Pure data — no UI. |
| `buffer.go` | `PacketRingBuffer` — fixed-capacity ring with monotonic global IDs. The application's source of truth. |
| `tui.go` | Root bubbletea model (`app`). Owns shared state, routes messages, swaps pages, manages the message box. |
| `page.go` | The `Page` interface, navigation messages (`navMsg`, `showMsgMsg`), shared widgets (`renderHotkeyBar`, `pageTitle`, `accentBorder`). |
| `page_capture.go` | Capture page — live table of packets, hotkey bar, navigation triggers. |
| `page_inspect.go` | Read-only view of one packet looked up by global ID. |
| `page_edit.go` | Modify a packet's fields and save it to the edited list. |
| `page_retransmit.go` | List + fire of edited packets. |

Everything lives in package `main`. There are no subpackages — the codebase is small enough that file boundaries do the organizing.

---

## 3. Core Concepts

### 3.1 The capture pipeline

```
pcap.OpenLive → gopacket.NewPacketSource → chan gopacket.Packet
                                                  │
                                                  ▼
                                     waitForPacket (tea.Cmd)
                                                  │
                                                  ▼
                                            packetMsg
                                                  │
                                                  ▼
                              app.Update → buf.Add(*detailedPacket)
```

The capture goroutine sits in `Capture.Output()` and pumps packets into a Go channel. The bubbletea cmd `waitForPacket` blocks on that channel and returns each packet as a `packetMsg`. The root model handles the message and adds the packet to the ring buffer (only when capture state is `running`).

The cmd re-arms itself: every `packetMsg` handler returns `waitForPacket(a.pkts)` so the loop keeps draining as long as packets keep coming.

### 3.2 `detailedPacket` — the canonical packet struct

`detailedPacket` (in `capture.go`) is the only packet representation. It stores every field needed to:

1. Display a row in the capture table
2. Render a deep inspect view
3. Modify and re-serialize the packet for retransmit

All field types are native gopacket types (e.g. `layers.IPProtocol`, `layers.EthernetType`, `[]layers.TCPOption`) — not strings — so the struct is round-trippable through `gopacket.SerializeLayers`. The original `gopacket.Packet` is also kept in the `Raw` field as a fast path for unmodified retransmit.

When you add a new field that needs to survive retransmit, add it to `detailedPacket` *and* to the assignments in `toDetailedPacket`.

### 3.3 The ring buffer

`PacketRingBuffer` (in `buffer.go`) is fixed-capacity, monotonic-ID, and goroutine-safe:

```go
buf := NewPacketRingBuffer(1000)        // capacity from CLI flag
id := buf.Add(pkt)                      // assigns a global ID
pkt, ok := buf.At(id)                   // false if evicted or unseen
snap, firstID := buf.Snapshot()         // chronological copy
buf.Reset()                             // empties + resets ID counter
buf.Total()                             // lifetime count
```

#### Why global IDs?

Slot indices are not stable. Once the buffer fills, slot 0 will be reused for a brand-new packet. If the inspect page remembered "slot 0", it would silently start showing a different packet. Global IDs solve this:

- `Add` returns a monotonic `uint64` that never repeats
- `At(id)` returns `(nil, false)` if the packet has been evicted
- Pages remember IDs, not slots, and degrade gracefully when a packet ages out

#### Concurrency

`Add` runs on the bubbletea cmd goroutine that drains the pcap channel. `At` and `Snapshot` run on the bubbletea Update goroutine when pages render. The buffer uses `sync.RWMutex` so reads can run in parallel.

---

## 4. The Page Architecture

### 4.1 The `Page` interface

```go
type Page interface {
    Init() tea.Cmd
    Update(msg tea.Msg) (Page, tea.Cmd)
    View() string
}
```

Every full-screen view implements this. The root model holds exactly one `Page` at a time and delegates lifecycle calls through the interface.

### 4.2 The router

The root model (`app` in `tui.go`) is a thin router. It handles **only** these top-level concerns:

- Quit shortcuts (`q`, `ctrl+c`)
- The capture state machine (toggled by `space`, globally)
- Packet arrival (`packetMsg` → `buf.Add`)
- Page swaps (`navMsg`)
- The message box (`showMsgMsg`, `clearMsgBoxMsg`)
- Hotkey flash decay (`clearFlashMsg`)

Everything else is forwarded to `a.page.Update(msg)`. Pages own their local state and their own keyboard handling.

### 4.3 Navigation flow

Pages don't reach into other pages — they emit a `navMsg` via `tea.Cmd` and the root model handles the swap:

```
page (returns)  →  navigate(pageInspect, id)  →  tea.Cmd
                                                    │
                                                    ▼
                                              navMsg{...}
                                                    │
                                                    ▼
                                  app.Update intercepts
                                            │
                                            ▼
                                  app.swapPage(target, arg)
                                            │
                                            ▼
                              new page = newInspectPage(a, id)
                                            │
                                            ▼
                              return new page's Init() cmd
```

The argument carried in `navMsg.arg` is page-specific. For inspect/edit it's a `uint64` global ring buffer ID. Retransmit takes no argument (it reads the whole `app.edited` slice).

### 4.4 The `*app` back-pointer

Each page is constructed with a pointer to the root model (`a *app`). Pages use this for **read-only access** to shared state:

- `p.app.buf` — the ring buffer
- `p.app.state` — capture state (running / paused / idle)
- `p.app.edited` — saved edited packets
- `p.app.flashKey` — currently flashed hotkey, for the bar to render

Pages do **not** write to fields on `*app` directly. Mutations flow through messages (`showMsg`, `navigate`) so the data flow stays one-directional and testable.

### 4.5 Global vs. page-local keys

| Key | Where handled | Reason |
|---|---|---|
| `q`, `ctrl+c` | root model | Quit anywhere |
| `space` | root model | Pause/resume from any page so packets keep flowing |
| `esc` | each page | Page decides what "back" means |
| `c`, `i`, `e`, `r` | capture page | Page-specific hotkeys |
| `↑/↓/pgup/pgdn` | forwarded to page | Pages forward to their bubbles widgets |

---

## 5. Accessing the Ring Buffer From a Page

The buffer is accessed differently depending on what the page is doing. Pick the matching pattern:

### Pattern 1: Snapshot every frame (capture page)

You want a live view of every currently-buffered packet, rebuilt on every render.

```go
func (p *capturePage) View() string {
    snap, firstID := p.app.buf.Snapshot()
    p.firstID = firstID  // remember for selection mapping

    rows := make([]table.Row, len(snap))
    for i, d := range snap {
        rows[i] = buildRow(d)
    }
    p.table.SetRows(rows)
    // ... render
}
```

Use this when:
- You're showing a list/table that should auto-update as packets arrive
- You need the `firstID` to translate a cursor index back into a stable global ID

Cost is `O(n)` per render where `n` is the buffer size. Cheap for buffers up to ~10k.

### Pattern 2: Lookup by global ID (inspect/edit pages)

You have a global ID handed to you via `navMsg.arg` and want a single packet. Handle the eviction case.

```go
func newInspectPage(a *app, id uint64) *inspectPage {
    pkt, ok := a.buf.At(id)
    return &inspectPage{app: a, pktID: id, pkt: pkt, avail: ok}
}

func (p *inspectPage) View() string {
    if !p.avail {
        return warnStyle.Render(fmt.Sprintf(
            "packet #%d is no longer in the ring buffer", p.pktID,
        ))
    }
    // ... render p.pkt
}
```

Use this when:
- A previous page selected a specific packet and you need to focus on it
- The packet might have been evicted between selection and your render — always check `ok`

Look up at construction time and cache the pointer. The packet won't move once you've got it (other goroutines can call `Add` but never overwrite a `*detailedPacket` you already hold).

### Pattern 3: Read independent state (retransmit page)

You don't read from the ring buffer at all — you read from `app.edited`, which is a separate slice of edited packets.

```go
for i, d := range p.app.edited {
    // ...
}
```

Use this when:
- The data you care about isn't capture data — it's something the user has explicitly saved or built up

### What pages should NOT do

- Don't call `buf.Add` from a page. Adds happen only in the root model's `packetMsg` handler.
- Don't call `buf.Reset` from anywhere except the capture page's clear hotkey.
- Don't store a long-lived reference to a `*detailedPacket` from a `Snapshot()` and assume the user can navigate to it later — use the global ID for that, not the pointer.

---

## 6. How to Add a New Page

This is the contributor's checklist.

### Step 1: Create `page_yourname.go`

Implement the `Page` interface:

```go
package main

import (
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
)

type yourPage struct {
    app *app
    // page-local state (cursor, form values, etc.)
}

func newYourPage(a *app /*, args... */) *yourPage {
    return &yourPage{app: a}
}

func (p *yourPage) Init() tea.Cmd { return nil }

func (p *yourPage) Update(msg tea.Msg) (Page, tea.Cmd) {
    if k, ok := msg.(tea.KeyMsg); ok {
        switch normalizeKey(k.String()) {
        case "esc":
            return p, navigate(pageCapture, nil)
        }
    }
    return p, nil
}

func (p *yourPage) View() string {
    // use pageTitle(...) and accentBorder(...) for chrome
    // use renderHotkeyBar(...) for the bottom bar
    return ""
}
```

### Step 2: Register the page ID in `page.go`

```go
const (
    pageCapture pageID = iota
    pageInspect
    pageEdit
    pageRetransmit
    pageYour     // ← add here
)
```

### Step 3: Wire the constructor in `tui.go`

In `app.swapPage`:

```go
case pageYour:
    p.page = newYourPage(a)
```

If your page takes an argument from `navMsg.arg`, type-assert it like inspect/edit do.

### Step 4: Pick an accent color in `page.go`

```go
const (
    accentInspect    = "#4FD1C5"
    accentEdit       = "#F687B3"
    accentRetransmit = "#F6AD55"
    accentYour       = "#XXXXXX"  // ← add here
)
```

### Step 5: Trigger navigation from somewhere

Usually a hotkey on the capture page. Add to `capturePage.hotkeys()` and the keyswitch in `capturePage.Update`:

```go
case "y":
    return p, tea.Batch(p.app.flashHotkey("y"), navigate(pageYour, nil))
```

### Step 6: Build, run, esc back to capture works automatically

The router handles the `esc → navigate(pageCapture, nil)` flow as long as your page emits it. Re-entering will create a fresh page instance.

---

## 7. Messages Reference

All messages flow through bubbletea's `tea.Msg` system. Here's every type and where it's handled.

| Message | Source | Handler | Purpose |
|---|---|---|---|
| `tea.KeyMsg` | terminal | root, then current page | Keypress |
| `tea.WindowSizeMsg` | terminal | current page | Terminal resize |
| `packetMsg` | `waitForPacket` cmd | root only | Packet arrival → ring buffer |
| `navMsg` | `navigate(...)` | root only | Page swap request |
| `showMsgMsg` | `showMsg(...)` | root only | Display message box |
| `clearMsgBoxMsg` | timer | root only | Hide message box |
| `clearFlashMsg` | timer | root only | Un-flash hotkey |

To add a new message type, define it in the file most relevant to its handler. Page-local message types should live in the page file. Globals (intercepted by the root) live in `tui.go` or `page.go`.

---

## 8. Capture State Machine

```
        space
   ┌──────────────┐
   │              │
   ▼              │
 idle ─── space ─→ running ⇄ paused
                          space
```

- `stateIdle`: pcap handle not opened; pressing space opens it and starts the read loop.
- `stateRunning`: `packetMsg` handler adds to the buffer.
- `statePaused`: `packetMsg` handler drops the packet.

The state lives on the root model (`a.state`). The capture page reads it for the status line and to gate the `clear` hotkey. Other pages can read it but typically don't need to.

The packet pump keeps running across page transitions — capture state controls whether arrivals are stored, not whether they're delivered. So you can navigate into the inspect page, leave capture running, come back, and see new packets.

---

## 9. Styling and UI Conventions

### Per-page accent colors

Each non-capture page uses its own accent so the user always knows which screen they're on:

- Capture: purple (`#7D56F4`) — the home screen, no accent border
- Inspect: teal (`#4FD1C5`)
- Edit: pink (`#F687B3`)
- Retransmit: orange (`#F6AD55`)

Use `pageTitle("NAME", accentX)` and `accentBorder(accentX).Render(body)` for the standard chrome.

### Shared styles (in `tui.go`)

| Style | Use |
|---|---|
| `asciiStyle` | The ASCII banner color |
| `subtitleStyle` | Italic grey subtitle line |
| `tableBorder` | Bordered region around the capture table |
| `splashStyle` | Pre-capture splash text |
| `hotkeyStyle` / `hotkeyFlashStyle` / `hotkeyDisabledStyle` | The three hotkey bar states |
| `msgBoxStyle` | Amber message box border |
| `warnStyle` | Yellow warning text inside accent borders |
| `footerStyle` | Dim footer line |

### The hotkey bar

Every page renders its own bar. Construct a `[]hotkey` and call `renderHotkeyBar(keys, a.flashKey)`. The flashed-key state lives on `*app` so pressing a key on any page lights up correctly. Set `Disabled: true` on a hotkey to grey it out (e.g. retransmit when no edited packets exist).

### The message box

Pages don't render the box — they emit `showMsg("text")` as a `tea.Cmd`. The root model handles display and auto-hides after 4 seconds. The box appears below the page's content; the layout shifts up by one bordered row while it's visible.

---

## 10. CLI Flags

```
--buffer N    Ring buffer size (default 1000)
--iface NAME  Interface to capture on (default en0)
```

The buffer size sets the max number of packets retained in memory. Larger means longer retrospective inspect coverage at the cost of memory; 1000 packets is roughly 1.5 MB at typical packet sizes.

Add new flags in `main.go` between `flag.Parse()` and the `tea.NewProgram` call. Pass them through `newApp(...)` if pages need them.

---

## 11. Build and Run

```bash
cd src
go build .
sudo ./remora                     # default 1000 packet buffer, en0
sudo ./remora --buffer 10000      # bigger buffer
sudo ./remora --iface en1         # different interface
```

Capture requires elevated privileges. On macOS you generally need `sudo`; on Linux you can grant `CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw+ep ./remora
```

---

## 12. Contribution Guidelines

### Project values

1. **Single source of truth.** The ring buffer is canonical. Don't introduce parallel storage that could drift from it. The capture page rebuilds its rows from `Snapshot()` on every render specifically to enforce this invariant.
2. **One-directional data flow.** Pages emit messages and read shared state — they don't mutate the root model directly. If you find yourself wanting to do `p.app.something = ...` from a page, define a message instead.
3. **Pages are independent.** No page imports or types-asserts another page. Navigation goes through the router. Argument types passed via `navMsg.arg` are documented per-page in the `swapPage` switch.
4. **Native types over strings.** Anything that might need to be serialized (TCP options, protocol numbers, ethernet types) is stored as the native gopacket type, not its `.String()` form.

### Style

- Follow existing comment density: comment the *why*, especially around concurrency, message flow, and design decisions. Don't comment what the code obviously does.
- Group related code with section banners (`// =====`) when a file gets long.
- Keep page files self-contained — helpers used only by one page live in that page's file.

### Adding fields to `detailedPacket`

If a new field is needed for inspect/edit/retransmit:

1. Add the field to `detailedPacket` in `capture.go` as the native gopacket type
2. Populate it in `toDetailedPacket` from the right layer
3. Update inspect/edit views as needed

Don't add display-formatted strings to the struct. Format at render time.

### Tests

There are no tests yet. Reasonable places to start:

- `buffer_test.go`: ring buffer wraps correctly, `At` returns false for evicted/unseen IDs, `Snapshot` ordering
- `capture_test.go`: `toDetailedPacket` round-trips correctly with synthetic gopacket frames

UI/page tests via bubbletea's `teatest` package would also help once the form/edit functionality lands.

### Commit hygiene

- Commits should be focused on one change. The ring buffer refactor was its own commit; the page architecture was a follow-up.
- Mention which file(s) were touched and why in the body. The codebase is small enough that "what" is easy to read from the diff — invest the commit message budget in "why".
