package clipboard

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

// WriteString attempts to copy the given string to the system clipboard.
func WriteString(s string) error {
	// We can't call xsel if there isn't a DISPLAY set, since it won't work.
	if os.Getenv("DISPLAY") == "" {
		return errors.New("unable to copy to clipboard (no DISPLAY)")
	}
	cmd := exec.Command("xsel", "--clipboard")
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run()
}
