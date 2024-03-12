// Package kflib is a support library for the KeyFish tool.
package kflib

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/getpass"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/otp"
	"github.com/creachadair/otp/otpauth"
)

// OpenDB opens the specified database store.
func OpenDB(dbPath string) (*kfdb.Store, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer f.Close()

	passphrase, err := GetPassphrase("Passphrase: ")
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return kfdb.Open(f, passphrase)
}

// SaveDB writes the specified database store to dbPath.
func SaveDB(s *kfdb.Store, dbPath string) error {
	return atomicfile.Tx(dbPath, 0600, func(f *atomicfile.File) error {
		_, err := s.WriteTo(f)
		return err
	})
}

// GetPassphrase prompts the user at the terminal for a passphrase with echo
// disabled.  An empty passprase is permitted; the caller must check for that
// case if an empty passphrase is not wanted.
func GetPassphrase(prompt string) (string, error) {
	passphrase, err := getpass.Prompt(prompt)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return passphrase, nil
}

// ConfirmPassphrase prompts the user at the terminal for a passphrase with
// echo disabled, then prompts again for confirmation and reports an error if
// the two copies are not equal.
func ConfirmPassphrase(prompt string) (string, error) {
	passphrase, err := getpass.Prompt(prompt)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	confirm, err := getpass.Prompt("Confirm " + strings.ToLower(prompt))
	if err != nil {
		return "", fmt.Errorf("read confirmation: %w", err)
	}
	if confirm != passphrase {
		return "", errors.New("passphrases do not match")
	}
	return passphrase, nil
}

// GenerateOTP returns a TOTP code based on url.  The time code is shifted by
// offset steps (based on the size of the window specified by url).
func GenerateOTP(url *otpauth.URL, offset int) (string, error) {
	step := (time.Now().Unix() / int64(url.Period)) + int64(offset)
	cfg := otp.Config{Digits: url.Digits}
	if err := cfg.ParseKey(url.RawSecret); err != nil {
		return "", err
	}
	return cfg.HOTP(uint64(step)), nil

	// TODO(creachadair): Other algorithms, HOTP.
}
