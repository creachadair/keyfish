package clipboard

import (
	"os/exec"
	"strings"
)

// WriteString attempts to copy the given string to the system clipboard.
func WriteString(s string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run()
}
