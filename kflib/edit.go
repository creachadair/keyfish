package kflib

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/creachadair/mds/mdiff"
	"github.com/creachadair/mds/mstr"
	"golang.org/x/term"
	yaml "gopkg.in/yaml.v3"
)

// Edit invokes an editor with the specified object rendered as YAML.  The
// editor is selected by the EDITOR environment variable.  When the editor
// exits, the user is prompted to confirm any changes.  If they do, the results
// are unmarshaled back into a new value, which is returned; otherwise an error
// is reported.
//
// If the edit did not change the input, Edit returns (value, ErrNoChange).
// If the user rejected the changes, Edit returns (value, ErrUserReject).
func Edit[T any](ctx context.Context, value T) (T, error) {
	var out T

	// Indent the input value as JSON for the editor.
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(3)
	if err := enc.Encode(value); err != nil {
		return out, fmt.Errorf("marshal value: %w", err)
	}

	// Create a temp directory for the file to edit.  We do this instead of a
	// temp file so that the name shown by the editor does not have random nonce
	// garbage in it.
	dir, err := os.MkdirTemp("", "kfedit*")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(dir)

	epath := filepath.Join(dir, "value.yaml")
	if err := os.WriteFile(epath, buf.Bytes(), 0600); err != nil {
		return out, err
	}

	// Run the editor on that file.
	name := cmp.Or(os.Getenv("EDITOR"), "vi")
	cmd := exec.CommandContext(ctx, name, "value.yaml")
	cmd.Dir = dir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return out, fmt.Errorf("editor failed: %w", err)
	}

	// Read back the edited file and check for differences.
	edited, err := os.ReadFile(epath)
	if err != nil {
		return out, fmt.Errorf("read editor output: %w", err)
	}
	diff := mdiff.New(mstr.Lines(buf.String()), mstr.Lines(string(edited)))
	if len(diff.Chunks) == 0 {
		return value, ErrNoChange
	}

	// Reaching here, the files differ. Ask the user if it's OK to proceed.
	// Create a terminal attached to the tty to manage reading input.
	oldst, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return out, err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldst)
	vt := term.NewTerminal(os.Stdin, "")

	diff.AddContext(3).Unify().Format(vt, mdiff.Unified, nil)

confirm:
	for {
		fmt.Fprint(vt, "▷ Keep changes? (y/n) ")
		ln, err := vt.ReadLine()
		if err != nil {
			return out, err
		}
		switch strings.ToLower(ln) {
		case "y", "yes":
			break confirm
		case "n", "no":
			return value, ErrUserReject
		default:
			fmt.Fprintln(vt, "** Please enter y(es) or n(o)")
		}
	}

	err = yaml.Unmarshal(edited, &out)
	return out, err
}

var (
	// ErrNoChange is reported by Edit if the resulting value did not change.
	ErrNoChange = errors.New("input was not changed")

	// ErrUserReject is reported by Edit if the user rejected the changed file.
	ErrUserReject = errors.New("the user rejected the edits")
)
