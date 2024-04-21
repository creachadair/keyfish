package kflib_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/mtest"
)

func TestChars(t *testing.T) {
	type tcase struct {
		length  int
		charset kflib.Charset
	}
	tests := []tcase{
		{5, 0},
		{8, 0},
		{12, kflib.AllChars},
		{25, kflib.Letters | kflib.Symbols},
		{37, kflib.Letters | kflib.Digits},
		{42, kflib.AllChars},
	}
	check := func(t *testing.T, got string, tc tcase) {
		if len(got) < 8 {
			t.Errorf("Got length %d, want at least 8", len(got))
		} else if tc.length >= 8 && len(got) != tc.length {
			t.Errorf("Got length %d, want %d", len(got), tc.length)
		}
		t.Logf("Generated %q", got)
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
	t.Run("Random", func(t *testing.T) {
		mtest.Swap[io.Reader](t, &crand.Reader, mrand.New(mrand.NewSource(20240323171652)))

		for _, tc := range tests {
			check(t, kflib.RandomChars(tc.length, tc.charset), tc)
		}
	})
	t.Run("Hashed", func(t *testing.T) {
		const passphrase, seed = "magic is as magic does", "example.com"
		for i, tc := range tests {
			salt := fmt.Sprintf("%d", i+1)
			check(t, kflib.HashedChars(tc.length, tc.charset, passphrase, seed, salt), tc)
		}
	})
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
