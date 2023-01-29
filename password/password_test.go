// Unit tests for package keyfish/password
// Author: M. J. Fromberger <michael.j.fromberger@gmail.com>

package password

import (
	"testing"

	"github.com/creachadair/keyfish/alphabet"
)

// Check test vectors confirmed against the Chrome extension.
func TestKnownValues(t *testing.T) {
	const site = "xyzzy"
	tests := []struct {
		alpha        alphabet.Alphabet
		size         int
		secret, salt string
		want         string
	}{
		{alphabet.All, 10, "cabezon", "", "Hf*w_Tv/nZ"},
		{alphabet.All, 32, "cabezon", "", "Hf*w_Tv/nZRWDVJf#=9u$Yhu@DnKl@ez"},
		{alphabet.All, 32, "cabezon", "foo", "B,&?!nPrd/Y&CbE%CYxz&bwOL!Ym16P:"},
		{alphabet.All, 50, "cabezon", "foo", "B,&?!nPrd/Y&CbE%CYxz&bwOL!Ym16P:IM$a-a$C,DQOSj-Mdm"},
		{alphabet.All, 50, "cabezon", "bar", "l!?9F+hJq8F^ewy%5l:YEt!H?73/bCWAj#GD2jI1jzu^-tC20F"},
		{alphabet.NoPunct, 32, "bloodfish", "", "jq77585eZJxN2uyD5IUEKcNxll2jWQys"},
		{alphabet.NoPunct, 32, "bloodfish", "foo", "ZenZA1Ht88eewraGuFLkXIu92NQlV3rk"},
		{alphabet.Lowercase + alphabet.Digits, 32, "cabezon", "foo", "a8592shtn9k5amb4blwx5mwgf2kry0h8"},
	}
	for _, test := range tests {
		c := Context{
			Secret:   test.secret,
			Alphabet: test.alpha,
			Salt:     test.salt,
			Site:     site,
		}
		if got := c.Password(test.size); got != test.want {
			t.Errorf("Password %q [%q]: got %q, want %q", site, test.secret, got, test.want)
		}
	}
}

// Verify that the Format function works as intended.
func TestFormat(t *testing.T) {
	c := Context{Secret: "cabezon"}

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

		// The tilde covers letters and digits.
		{"0", "~~~~~~~~", "PZpkOX2o"},

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

		// Length and salt.
		{"", "?????????????????? ??????????????????????", "@&/=/%=?-^$%!%#&./ =:^*_.!-#-.&+:#/+.!*?,"},
		{"", "__________________ ______________________", "ckwpxgpzmifhbhdkvx pvhlpubmdmujqveyrvblzs"},
		{"", "^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^", "CKWPXGPZMIFHBHDKVX PVHLPUBMDMUJQVEYRVBLZS"},
		{"", "****************** **********************", "EUtfuMfzZQLPCOGUqv eqPWepCZGYpThrJwiqCXzk"},
		{"", "################## ######################", "048692594322021489 5834580414836819680497"},
		{"q", "????????????????????????????????????????", ",@?_$^!$*,/,*/-=$!^?:,-&:+$&..-?##@#=@^/"},
		{"r", "________________________________________", "cxrmjefrfpovbxfikkaxrmmzzljqrqoomeyqsqsw"},
		{"s", "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", "IABGPSJYGWECVOLVJTTJBYVISEJDHLCAFANMWRGY"},
		{"t", "****************************************", "aoUqoKKrLyxHBtcypBMzPukXNcTbOJpBBrMVxqoq"},
		{"u", "########################################", "8364621019243126110487340041013933601615"},
	}
	for _, test := range tests {
		c.Salt = test.salt
		c.Site = site
		if s := c.Format(test.format); s != test.expect {
			t.Errorf("Format %q salt %q: got %q, want %q", test.format, test.salt, s, test.expect)
		}
	}
}
