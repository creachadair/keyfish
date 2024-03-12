package kflib_test

import (
	crand "crypto/rand"
	"io"
	"log"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/mtest"
)

func TestRandomChars(t *testing.T) {
	mtest.Swap[io.Reader](t, &crand.Reader, mrand.New(mrand.NewSource(20240323171652)))

	tests := []struct {
		length  int
		charset kflib.Charset
	}{
		{5, 0},
		{8, 0},
		{12, kflib.AllChars},
		{25, kflib.Letters | kflib.Symbols},
		{37, kflib.Letters | kflib.Digits},
		{42, kflib.AllChars},
	}
	for _, tc := range tests {
		got := kflib.RandomChars(tc.length, tc.charset)
		if len(got) < 8 {
			t.Errorf("Got length %d, want at least 8", len(got))
		} else if tc.length >= 8 && len(got) != tc.length {
			t.Errorf("Got length %d, want %d", len(got), tc.length)
		}
		log.Printf("Generated %q", got)
		hasLetter, hasDigit, hasSymbol := checkPW(got)
		if !hasLetter {
			t.Error("No letters found")
		}
		if wd := tc.charset&kflib.Digits != 0; wd != hasDigit {
			t.Errorf("Has digit = %v, want %v", hasDigit, wd)
		}
		if ws := tc.charset&kflib.Symbols != 0; ws != hasSymbol {
			t.Errorf("Has symbol = %v, want %v", hasSymbol, ws)
		}
	}
}

func checkPW(s string) (hasLetter, hasDigit, hasOther bool) {
	for i := range s {
		if s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z' {
			hasLetter = true
		} else if s[i] >= '0' && s[i] <= '9' {
			hasDigit = true
		} else {
			hasOther = true
		}
	}
	return
}

func TestRandomWords(t *testing.T) {
	mtest.Swap[io.Reader](t, &crand.Reader, mrand.New(mrand.NewSource(20240323173139)))

	tests := []struct {
		numWords int
		sep      string
	}{
		{1, "-"},
		{3, " "},
		{5, " "},
		{6, "|"},
	}
	for _, tc := range tests {
		raw := kflib.RandomWords(tc.numWords, tc.sep)
		got := strings.Split(raw, tc.sep)
		if len(got) < 3 {
			t.Errorf("Got length %d, want at least 3", len(got))
		} else if tc.numWords >= 3 && len(got) != tc.numWords {
			t.Errorf("Got length %d, want %d", len(got), tc.numWords)
		}
		log.Printf("Generated %q %q", raw, got)
	}
}
