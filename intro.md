# Network Packet Capture & Analyzer in Go

## What Is This Project?

This project is a command-line tool written in Go that captures live network traffic directly from a network interface and decodes it into human-readable output. Think of it as a stripped-down, programmable version of Wireshark — built by you, in Go, from the ground up.

Under the hood, it uses **gopacket**, a Go library that wraps `libpcap` (the same C library that powers Wireshark and tcpdump). You'll open a raw socket on a network interface, intercept packets as they flow through, and walk each one layer by layer — Ethernet → IP → TCP/UDP → application payload — extracting whatever metadata and content you care about.

## What You'll Build

At its core, the analyzer will:

- Bind to a live network interface (e.g. `eth0`, `en0`) or read from a `.pcap` file
- Capture packets in real time using a raw socket
- Decode protocol layers — Ethernet, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP
- Filter traffic by port, protocol, or IP address using BPF (Berkeley Packet Filter) expressions
- Display a live feed of packet summaries in the terminal
- Optionally write captured packets to a `.pcap` file for later analysis

A stretch goal is a statistics dashboard that tracks things like top talkers by IP, packets per second, and protocol distribution — all rendered live in the terminal using a library like `bubbletea` or `termui`.

## Why Go?

Go is a natural fit for this kind of tool. Goroutines make it trivial to separate the capture loop, the decoding pipeline, and the display layer into concurrent workers without the complexity of manual threading. The standard library's `net` package gives you solid primitives, and `gopacket` handles the heavy lifting of binary protocol parsing. The result compiles to a single static binary you can drop onto any Linux box.

## Core Libraries

| Library | Purpose |
|---|---|
| `google/gopacket` | Packet capture and protocol decoding |
| `google/gopacket/pcap` | libpcap bindings (live capture + pcap file I/O) |
| `google/gopacket/layers` | Typed structs for Ethernet, IP, TCP, UDP, DNS, etc. |
| `charmbracelet/bubbletea` | *(Optional)* Terminal UI for live stats dashboard |

## Prerequisites

You'll need `libpcap` installed on your system:

```bash
# Debian / Ubuntu
sudo apt install libpcap-dev

# macOS
brew install libpcap

# Fedora / RHEL
sudo dnf install libpcap-devel
```

Packet capture also requires elevated privileges. You'll run the tool with `sudo`, or grant the binary the `CAP_NET_RAW` capability on Linux:

```bash
sudo setcap cap_net_raw+ep ./analyzer
```

## Project Structure

```
packet-analyzer/
├── main.go           # Entry point, CLI flag parsing
├── capture/
│   └── capture.go    # Open interface, start capture loop
├── decode/
│   └── decode.go     # Layer-by-layer packet decoding
├── filter/
│   └── filter.go     # BPF filter construction and application
├── display/
│   └── display.go    # Terminal output, live stats
└── writer/
    └── writer.go     # Optional .pcap file writer
```

## Key Concepts You'll Learn

**Raw sockets and libpcap** — how packet capture actually works at the OS level, below the normal socket API.

**Protocol layering** — why a single packet is really four or five nested structures stacked on top of each other, and how to peel them apart.

**BPF filters** — the mini-language used by tcpdump, Wireshark, and this tool to efficiently discard packets in the kernel before they ever reach userspace.

**Concurrent pipelines in Go** — decoupling capture, decoding, and display using channels so no stage blocks another.

**Binary protocol parsing** — reading fixed-width fields, bit flags, and variable-length records directly out of raw byte slices.

## What a Sample Run Looks Like

```
$ sudo ./analyzer -i eth0 -filter "tcp port 443"

Capturing on eth0  |  Filter: tcp port 443
──────────────────────────────────────────────────────────────
TIME         SRC                  DST                  PROTO  LEN
12:04:01.221 192.168.1.42:54312   142.250.80.46:443    TCP    74b   [SYN]
12:04:01.224 142.250.80.46:443    192.168.1.42:54312   TCP    74b   [SYN-ACK]
12:04:01.224 192.168.1.42:54312   142.250.80.46:443    TCP    66b   [ACK]
12:04:01.226 192.168.1.42:54312   142.250.80.46:443    TCP    583b  [PSH-ACK] TLS ClientHello
12:04:01.231 142.250.80.46:443    192.168.1.42:54312   TCP    1514b [PSH-ACK] TLS ServerHello
```

## Where to Take It Next

Once the core capture and decode pipeline is solid, there are a few natural directions to extend it. You could add HTTP/1.1 payload reconstruction to reassemble request/response pairs from a stream of TCP segments. You could ship it as a container and run it as a DaemonSet in Kubernetes, giving you per-node traffic visibility across your cluster. Or you could expose the packet stream over a gRPC endpoint and build a separate visualization service that consumes it — a genuine distributed observability tool.

This project sits at the intersection of systems programming, networking fundamentals, and Go concurrency. By the end of it, you'll have a clear mental model of how every packet on your network actually travels — not just the abstract version taught in textbooks.
