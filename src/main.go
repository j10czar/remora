package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	cap := NewCapture("en0")
	defer cap.Stop()

	// We don't start the capture here anymore. The TUI calls cap.Start()
	// the first time the user hits space.
	p := tea.NewProgram(newModel(cap), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
