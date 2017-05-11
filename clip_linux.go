package main

import (
	"fmt"
	"log"
	"os/exec"
)

// toClipboard attempts to copy the given password to the system clipboard.
func toClipboard(pw string) error {
	cmd := exec.Command("xsel", "--clipboard")
	p, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	fmt.Fprint(p, pw)

	// We must close the pipe, so the process can exit.
	if err := p.Close(); err != nil {
		log.Printf("Error closing pipe: %v", err)
	}
	return cmd.Wait()
}
