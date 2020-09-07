package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

// toClipboard attempts to copy the given password to the system clipboard.
func toClipboard(pw string) error {
	// We can't call xsel if there isn't a DISPLAY set, since it won't work.
	if os.Getenv("DISPLAY") == "" {
		return errors.New("unable to copy to clipboard (no DISPLAY)")
	}
	cmd := exec.Command("xsel", "--clipboard")
	cmd.Stdin = strings.NewReader(pw)
	return cmd.Run()
}
