// Unit tests for package keyfish/internal/hashpass
// Author: M. J. Fromberger <michael.j.fromberger@gmail.com>

package hashpass_test

import (
	"testing"

	"github.com/creachadair/keyfish/internal/hashpass"
)

// Check test vectors confirmed against the Chrome extension.
func TestKnownValues(t *testing.T) {
	const site = "xyzzy"
	tests := []struct {
		alpha        hashpass.Alphabet
		size         int
		secret, salt string
		want         string
	}{
		{hashpass.All, 10, "cabezon", "", "Hf*w_Tv/nZ"},
		{hashpass.All, 32, "cabezon", "", "Hf*w_Tv/nZRWDVJf#=9u$Yhu@DnKl@ez"},
		{hashpass.All, 32, "cabezon", "foo", "B,&?!nPrd/Y&CbE%CYxz&bwOL!Ym16P:"},
		{hashpass.All, 50, "cabezon", "foo", "B,&?!nPrd/Y&CbE%CYxz&bwOL!Ym16P:IM$a-a$C,DQOSj-Mdm"},
		{hashpass.All, 50, "cabezon", "bar", "l!?9F+hJq8F^ewy%5l:YEt!H?73/bCWAj#GD2jI1jzu^-tC20F"},
		{hashpass.NoPunct, 32, "bloodfish", "", "jq77585eZJxN2uyD5IUEKcNxll2jWQys"},
		{hashpass.NoPunct, 32, "bloodfish", "foo", "ZenZA1Ht88eewraGuFLkXIu92NQlV3rk"},
		{hashpass.Letters + hashpass.Digits, 32, "cabezon", "foo", "B619wfMiW9S1BVDzBTno2VmLIwSeqtM8"},
	}
	for _, test := range tests {
		c := hashpass.Context{
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
	c := hashpass.Context{Secret: "cabezon"}

	const site = "xyzzy"
	// These examples were hand-checked.
	tests := []struct {
		salt, format, expect string
	}{
		// The asterisk can generate upper and lowercase results.
		{"", "****", "EUtf"},

		// The tilde covers letters and digits.
		{"0", "~~~~~~~~", "PZpkOX2o"},

		// Characters not in the alphabets are passed through unchanged.
		{"", "<****>", "<Utfu>"},

		// Some examples with punctuation wildcards.
		{"", "**?*?", "EU/f/"},
		{"", "**?*?**?********??", "EU/f/Mf?ZQLPCOGU./"},

		// Punctuation marks other than the wildcards are preserved, but the
		// wildcards work.
		{"", "[%.+&@%]", "[%.+&@%]"},
		{"", "[%.??@%]", "[%.=/@%]"},
		{"", "[%.??*%]", "[%.=/M%]"},

		// Password generation respects the seed.
		{"foo", "~????****", "B?:?.aKcT"},

		// The exact identity of characters doesn't matter, only category.
		{"foo", "*####****#", "B9897aKcT9"},

		// Length and salt.
		{"", "?????????????????? ??????????????????????", "@&/=/%=?-^$%!%#&./ =:^*_.!-#-.&+:#/+.!*?,"},
		{"", "****************** **********************", "EUtfuMfzZQLPCOGUqv eqPWepCZGYpThrJwiqCXzk"},
		{"", "################## ######################", "048692594322021489 5834580414836819680497"},
		{"q", "????????????????????????????????????????", ",@?_$^!$*,/,*/-=$!^?:,-&:+$&..-?##@#=@^/"},
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
