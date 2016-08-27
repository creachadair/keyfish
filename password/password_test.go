// Unit tests for package keyfish/password
// Author: M. J. Fromberger <michael.j.fromberger@gmail.com>

package password

import (
	"testing"

	"bitbucket.org/creachadair/keyfish/alphabet"
)

// Check test vectors confirmed against the Chrome extension.
func TestKnownValues(t *testing.T) {
	const site = "xyzzy"
	tests := []struct {
		alpha              alphabet.Alphabet
		secret, salt, want string
	}{
		{alphabet.All, "cabezon", "", "Hf*w_Tv/nZRWDVJf#=9u$Yhu@DnKl@ez"},
		{alphabet.All, "cabezon", "foo", "B,&?!nPrd/Y&CbE%CYxz&bwOL!Ym16P:"},
		{alphabet.NoPunct, "bloodfish", "", "jq77585eZJxN2uyD5IUEKcNxll2jWQys"},
		{alphabet.NoPunct, "bloodfish", "foo", "ZenZA1Ht88eewraGuFLkXIu92NQlV3rk"},
		{alphabet.Lowercase + alphabet.Digits, "cabezon", "foo", "a8592shtn9k5amb4blwx5mwgf2kry0h8"},
	}
	for _, test := range tests {
		c := &Context{
			Secret:   test.secret,
			Alphabet: test.alpha,
			Salt:     test.salt,
		}
		if got := c.Password(site); got != test.want {
			t.Errorf("Password %q [%q]: got %q, want %q", site, test.secret, got, test.want)
		}
	}
}

// Verify that the Format function works as intended.
func TestFormat(t *testing.T) {
	c := &Context{Secret: "cabezon"}

	const site = "xyzzy"
	// These examples were hand-checked.
	tests := []struct {
		salt, format, expect string
	}{
		// Examples with mixed uppercase and lowercase.
		{"", "________", "ckwpxgpz"},
		{"", "^___^___", "CkwpXgpz"},

		// The asterisk can generate upper and lowercase results.
		{"", "_**^", "cUtP"},

		// Characters not in the alphabets are passed through unchanged.
		{"", "<____>", "<kwpx>"},

		// Some examples with punctuation wildcards.
		{"", "^_?_?", "Ck/p/"},
		{"", "^_?_?^_?_^^^^^^_??", "Ck/p/Gp?mIFHBHDk./"},

		// Punctuation marks other than the wildcards are preserved, but the
		// wildcards work.
		{"", "[%.+&@%]", "[%.+&@%]"},
		{"", "[%.??@%]", "[%.=/@%]"},
		{"", "[%.??^%]", "[%.=/G%]"},

		// Password generation respects the seed.
		{"foo", "^????_^__", "A?:?.nFoj"},

		// The exact identity of characters doesn't matter, only category.
		{"foo", "_####____#", "a9897nfoj9"},
	}
	for _, test := range tests {
		c.Salt = test.salt
		if s := c.Format(site, test.format); s != test.expect {
			t.Errorf("Format %q salt %q: got %q, want %q", test.format, test.salt, s, test.expect)
		}
	}
}
