package main

import (
	"os/exec"
	"strings"
)

// toClipboard attempts to copy the given password to the system clipboard.
func toClipboard(pw string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(pw)
	return cmd.Run()
}
