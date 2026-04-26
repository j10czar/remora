package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	cap := NewCapture("en0")
	cap.Start()
	defer cap.Stop()

	p := tea.NewProgram(newModel(cap.Output()), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
