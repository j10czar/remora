package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	bufSize := flag.Int("buffer", 1000, "ring buffer size — number of packets retained in memory")
	iface := flag.String("iface", "en0", "network interface to capture on")
	flag.Parse()

	cap := NewCapture(*iface)
	defer cap.Stop()

	// The TUI calls cap.Start() on the first space press — the program
	// boots into an idle state so the user sees a splash before any
	// pcap activity.
	p := tea.NewProgram(newApp(cap, *bufSize), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
