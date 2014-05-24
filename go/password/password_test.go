// Unit tests for package keyfish/password
// Author: M. J. Fromberger <michael.j.fromberger@gmail.com>

package password

import (
	"testing"

	"bitbucket.org/creachadair/keyfish/go/alphabet"
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
		{"", "password", "ckwpxgpz"},
		{"", "PassWord", "CkwpXgpz"},

		// The asterisk can generate upper and lowercase results.
		{"", "a**A", "cUtP"},

		// Characters not in the alphabets are passed through unchanged.
		{"", "<pass>", "<kwpx>"},

		// Some examples with punctuation wildcards.
		{"", "Aa?a?", "Ck/p/"},
		{"", "Aa?b?Bb?cDDDDDDe??", "Ck/p/Gp?mIFHBHDk./"},

		// Punctuation other than the '?' wildcard is preserved, but the
		// wildcard does work.
		{"", "[%.+&#%]", "[%.+&#%]"},
		{"", "[%.??#%]", "[%.=/#%]"},

		// Password generation respects the seed.
		{"foo", "A????bCde", "A?:?.nFoj"},

		// The exact identity of characters doesn't matter, only category.
		{"foo", "a0000bcde1", "a9897nfoj9"},
		{"foo", "a0503bcqe9", "a9897nfoj9"},
		{"foo", "z1503bkqe0", "a9897nfoj9"},
	}
	for _, test := range tests {
		c.Salt = test.salt
		if s := c.Format(site, test.format); s != test.expect {
			t.Errorf("Format %q salt %q: got %q, want %q", test.format, test.salt, s, test.expect)
		}
	}
}
