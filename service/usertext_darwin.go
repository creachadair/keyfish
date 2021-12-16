package service

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// userText prompts the user for textual input.
func userText(prompt, defaultValue string, hidden bool) (string, error) {
	if prompt == "" {
		return "", errors.New("missing prompt")
	}

	// Ask osascript to send error text to stdout to simplify error plumbing.
	cmd := exec.Command("osascript", "-s", "ho")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(`display dialog %q default answer %q hidden answer %v`,
		prompt, defaultValue, hidden))
	raw, err := cmd.Output()
	out := strings.TrimRight(string(raw), "\n")
	if err != nil {
		if strings.Contains(out, "User canceled") {
			return "", errors.New("user cancelled")
		}
		return "", err
	}

	// Parse the result out of the text delivered to stdout.
	const needle = "text returned:"
	if i := strings.Index(out, needle); i >= 0 {
		return out[i+len(needle):], nil
	}
	return "", errors.New("missing user input")
}

// insertText inserts text at the cursor location.
func insertText(text string) error {
	cmd := exec.Command("osascript", "-s", "ho")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(`tell application "System Events"
  keystroke %q
end tell`, text))
	raw, err := cmd.Output()
	out := strings.TrimSpace(string(raw))
	if err != nil {
		return fmt.Errorf("insert failed: %s", out)
	}
	return nil
}
