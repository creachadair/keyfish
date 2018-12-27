// Package password implements the KeyFish password generation scheme.  KeyFish
// generates site-specific passwords by computing a HMAC/SHA256 of a site name
// and salt string, using a secret key chosen by the end user.  The resulting
// hash is used to select a password.
//
// The password selection algorithm chooses bytes from an alphabet string with
// uniform probability.  Each byte of the hash will select a single byte of the
// password.
package password

import (
	"crypto/hmac"
	"crypto/sha256"
	"math"
	"strconv"

	"bitbucket.org/creachadair/keyfish/alphabet"
)

// A Context contains the information needed to generate a password given the
// name of a site.
type Context struct {
	alphabet.Alphabet        // The alphabet from which passwords are drawn
	Salt              string // A non-secret salt mixed in to the HMAC (optional)
	Secret            string // The user's secret password
}

// Password returns a password of n bytes for the given site based on the
// stored settings in the context. If n ≤ 0 a default length is chosen.
func (c *Context) Password(site string, n int) string {
	if n <= 0 {
		n = 8
	}
	buf := make([]byte, n)
	c.makeHash(site, buf)
	for i := 0; i < len(buf); i++ {
		buf[i] = c.Pick(buf[i])
	}
	return string(buf)
}

// Format returns a password for the given site based on a template that
// describes the desired output string.
//
// The format string specifies the format of the resulting password: Each
// character of the format chooses a single character of the password.
//
// A hash mark ("#") in the format is a wildcard for a decimal digit.
// An asterisk ("*") is a wildcard for a letter of either case.
// A caret ("^") is a wildcard for an uppercase letter.
// An underscore ("_") is a wildcard for a lowercase letter.
// A question mark ("?") is a wildcard for any punctuation character.
// A tilde ("~") is a wildcard for any non-punctuation character.
// All other characters are copied literally to the output.
func (c *Context) Format(site, format string) string {
	if format == "" {
		return format
	}
	pw := make([]byte, len(format))
	c.makeHash(site, pw)

	for i := 0; i < len(pw); i++ {
		switch rune(format[i]) {
		case '*':
			pw[i] = alphabet.Letters.Pick(pw[i])
		case '?':
			pw[i] = alphabet.Puncts.Pick(pw[i])
		case '#':
			pw[i] = alphabet.Digits.Pick(pw[i])
		case '^':
			pw[i] = alphabet.Uppercase.Pick(pw[i])
		case '_':
			pw[i] = alphabet.Lowercase.Pick(pw[i])
		case '~':
			pw[i] = alphabet.NoPunct.Pick(pw[i])
		default:
			pw[i] = format[i]
		}
	}
	return string(pw)
}

// Entropy returns an estimate of the bits of entropy for a password of the
// given length generated with the current settings.  The result may be zero.
func (c *Context) Entropy(length int) int {
	if length < 0 || len(c.Alphabet) == 0 {
		return 0
	}
	bpc := int(math.Floor(-math.Log2(1 / float64(len(c.Alphabet)))))
	return bpc * length
}

// makeHash computes the HMAC/SHA256 of the site key using the salt from the
// context.  Returns the digest as a slice of raw bytes.
func (c *Context) makeHash(site string, bits []byte) {
	siteKey := site
	if s := c.Salt; s != "" {
		siteKey += "/" + s
	}
	h := hmac.New(sha256.New, []byte(c.Secret))
	h.Write([]byte(siteKey))
	i := 0
	for i < len(bits) {
		sum := h.Sum(nil)
		i += copy(bits[i:], sum)
		h.Write([]byte(siteKey + "/" + strconv.Itoa(i)))
	}
}
