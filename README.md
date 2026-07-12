<div align="center">

```
██████╗ ███████╗███╗   ███╗ ██████╗ ██████╗  █████╗
██╔══██╗██╔════╝████╗ ████║██╔═══██╗██╔══██╗██╔══██╗
██████╔╝█████╗  ██╔████╔██║██║   ██║██████╔╝███████║
██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║
██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

**A real-time network packet sniffer with a terminal UI — think Wireshark, in your terminal, built from scratch in Go.**

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![libpcap](https://img.shields.io/badge/capture-libpcap%20%2F%20gopacket-blue)
![TUI](https://img.shields.io/badge/UI-Bubble%20Tea-FF75B7)

</div>

---

## What it does

**Remora** captures live network traffic straight off a network interface, decodes each packet layer by layer (Ethernet → IP → TCP/UDP → application), and streams it into an interactive terminal dashboard. From there you can pause the feed, drill into any individual packet down to a byte-level hex dump, filter the stream on the fly, and save slices of traffic to standard `.pcap` files that open in Wireshark or `tcpdump`.

It's a systems-programming project that touches raw packet capture, binary protocol parsing, concurrency, and terminal UI design — all in a single statically-compiled Go binary with no external runtime dependencies beyond `libpcap`.

## Highlights

- **Live capture** from any network interface using `libpcap` (via [`gopacket`](https://github.com/google/gopacket)), with a pause/resume state machine so the feed never runs away from you.
- **Layer-by-layer decoding** — Ethernet, IPv4/IPv6, TCP/UDP, plus lightweight application-protocol heuristics (HTTP, DNS, SSH, HTTPS, and ~20 well-known ports).
- **Deep packet inspector** — a full per-layer field breakdown for any packet, plus a scrollable hex/ASCII payload dump rendered like a classic hexdump.
- **On-the-fly filtering** by source IP, destination IP, port, or application protocol, applied live without dropping the underlying capture.
- **Range save to `.pcap`** — bracket a start and end packet visually, name the capture, and write a real libpcap file to `saves/` for later analysis in Wireshark.
- **Retransmit / replay module** — a file chooser that reads and validates saved captures (on-wire replay is the next milestone).
- **A single source of truth** — a fixed-capacity ring buffer with stable global packet IDs backs every screen, so views never drift out of sync with what was actually captured.

## How it works

Remora is organized as three cooperating layers, all in one Go binary:

```
┌──────────────────────────────────────────────────────────┐
│                  Bubble Tea TUI (root model)               │
│                                                            │
│    ┌─────────┐     ┌─────────┐     ┌──────────────┐        │
│    │ capture │ ↔   │ inspect │ ↔   │  retransmit  │        │
│    │  page   │     │  page   │     │    page      │        │
│    └─────────┘     └─────────┘     └──────────────┘        │
│         │               │                 │                │
│         └───────────────┼─────────────────┘                │
│                         ▼                                  │
│          ┌───────────────────────────────┐                 │
│          │   PacketRingBuffer            │  ← source of     │
│          │   (fixed cap, global IDs)     │    truth         │
│          └───────────────▲───────────────┘                 │
└──────────────────────────┼─────────────────────────────────┘
                          │  Add(*detailedPacket)
              ┌────────────┴─────────────┐
              │   Capture goroutine       │
              │   gopacket → Go channel   │
              └───────────────────────────┘
```

1. **Capture goroutine.** A dedicated goroutine sits on `pcap.OpenLive`, wraps the handle in a `gopacket.PacketSource`, and pumps decoded packets into a Go channel. Capture, decode, and display never block one another.
2. **Decode.** Each raw frame is walked layer by layer and copied into a `detailedPacket` struct that stores every field as its *native* gopacket type (not a display string) — so a packet stays round-trippable and can be re-serialized when saved.
3. **Ring buffer.** Every packet lands in a fixed-capacity, goroutine-safe ring buffer that hands out monotonic global IDs. Slots get reused as the buffer wraps, but IDs never repeat — so an inspector opened on packet `#4321` keeps pointing at the same packet even after the table has scrolled far past it.
4. **TUI.** A [Bubble Tea](https://github.com/charmbracelet/bubbletea) root model routes keystrokes and messages, and swaps between full-screen "pages." Pages are independent: they read shared state through the ring buffer and communicate via messages rather than reaching into each other, keeping data flow one-directional.

> For a deeper tour of the architecture, message flow, and how to add a new page, see [`CODEBASE.md`](./CODEBASE.md).

## Tech stack

| Concern | Choice |
|---|---|
| Language | Go |
| Packet capture & decode | [`google/gopacket`](https://github.com/google/gopacket) + `libpcap` |
| Terminal UI | [`charmbracelet/bubbletea`](https://github.com/charmbracelet/bubbletea), `bubbles`, `lipgloss` |
| Storage format | Standard libpcap `.pcap` (via `pcapgo`) |

## Installation

### Prerequisites

You'll need Go and `libpcap`:

```bash
# macOS
brew install go libpcap

# Debian / Ubuntu
sudo apt install golang libpcap-dev

# Fedora / RHEL
sudo dnf install golang libpcap-devel
```

### Build

```bash
git clone <this-repo> remora
cd remora/src
go build -o remora .
```

### Run

Packet capture needs elevated privileges to open a raw socket on the interface:

```bash
# macOS — run with sudo
sudo ./remora

# Linux — either sudo, or grant the capability once and run unprivileged
sudo setcap cap_net_raw+ep ./remora
./remora
```

By default Remora binds to interface `en0` and keeps the last 1000 packets in memory. Both are configurable:

```bash
sudo ./remora --iface en1        # capture on a different interface
sudo ./remora --buffer 10000     # keep a larger backlog in memory
```

| Flag | Default | Description |
|---|---|---|
| `--iface` | `en0` | Network interface to capture on |
| `--buffer` | `1000` | Number of packets retained in the ring buffer |

## Using it

Remora boots into a splash screen. Press **space** to start capturing. Everything else is driven by single-key hotkeys shown along the bottom of every screen:

| Key | Action |
|---|---|
| `space` | Start / pause / resume the capture |
| `↑ ↓` | Move the cursor through the packet table |
| `i` | **Inspect** the selected packet (press `x` inside to open the hex dump) |
| `f` | **Filter** by source/dest IP, port, or app protocol |
| `s` | **Save** a range of packets to a `.pcap` file |
| `r` | **Retransmit** — browse and validate saved captures |
| `l` | Jump to the **latest** packet and follow the live tail |
| `c` | **Clear** the buffer (pause first) |
| `q` | Quit |

## Project status & roadmap

Remora is an active learning project. The capture, decode, inspect, filter, and save pipelines are complete and stable. The next milestone is wiring the retransmit page to replay saved packets back onto the wire; further out are a live statistics dashboard (top talkers, packets/sec, protocol mix) and a packet-editing view for crafting modified frames before replay.

---

<div align="center">
<sub>Built by Jason Tenczar · Go · gopacket · Bubble Tea</sub>
</div>
