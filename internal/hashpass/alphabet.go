package hashpass

import (
	"errors"
	"math"
	"strings"
)

// An Alphabet is a string of printable characters used to convert hash bytes
// into a printable password.  Order is significant.
type Alphabet string

const (
	// Uppercase is an alphabet of the uppercase ASCII letters.
	Uppercase = Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	// Lowercase is an alphabet of the lowercase ASCII letters.
	Lowercase = Alphabet("abcdefghijklmnopqrstuvwxyz")

	// Letters is an alphabet of the ASCII letters.
	Letters = Uppercase + Lowercase

	// Digits is an alphabet comprising the ASCII decimal digits.
	Digits = Alphabet("0123456789")

	// Puncts is an alphabet consisting of various ASCII punctuation.
	Puncts = Alphabet("!@#$%^&*-_=+,.:/?")

	// NoPunct is an alphabet comprising Letters and Digits.
	NoPunct = Letters + Digits

	// All is an alphabet comprising Letters, Digits, and Puncts.
	All = Letters + Digits + Puncts
)

// Pick chooses a display byte for the given hash byte based on the alphabet.
// The choice is made by scaling the byte value to the length of the alphabet,
// solving for x in b/256 = x/len(a).
func (a Alphabet) Pick(b byte) byte {
	if len(a) == 0 {
		return 0
	}
	pos := math.Ceil((float64(b)+1)/256*float64(len(a))) - 1
	return a[int(pos)]
}

// Contains reports whether r is a member of this alphabet.
func (a Alphabet) Contains(r rune) bool {
	return strings.ContainsRune(string(a), r)
}

func (a Alphabet) String() string { return string(a) }

// Get implements the flag.Getter interface.  The concrete value is a string.
func (a Alphabet) Get() interface{} { return string(a) }

// Set implements the flag.Value interface.
func (a *Alphabet) Set(s string) error {
	if s == "" {
		return errors.New("invalid alphabet")
	}
	*a = Alphabet(s)
	return nil
}
