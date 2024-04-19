//go:build !darwin

package service

// userText prompts the user for textual input.
func userText(prompt, defaultValue string, hidden bool) (string, error) {
	panic("prompt command not implemented")
}

// insertText inserts text at the cursor location.
func insertText(text string) error {
	panic("insert command not implemented")
}
