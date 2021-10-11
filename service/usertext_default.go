//go:build !darwin

package service

// userText prompts the user for textual input.
func userText(prompt, defaultValue string, hidden bool) (string, error) {
	panic("prompt command not implemented")
}
