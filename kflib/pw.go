package kflib

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	_ "embed"
)

// To update the word list, run "go generate ./kflib".
// Commit the file if it changes.

//go:generate ./update-wordlist.sh wordlist.txt

var (
	//go:embed wordlist.txt
	wordList string

	words       []string
	bitsPerWord int
	wordListLen uint64
)

func init() {
	words = strings.Split(strings.TrimSpace(wordList), "\n")
	if len(words) < 256 {
		panic(fmt.Sprintf("word list has only %d elements", len(words)))
	}
	bitsPerWord = int(math.Ceil(math.Log2(float64(len(words))))) // round up
	wordListLen = uint64(len(words))
}

// Charset is a bit mask specifying which letters to use in a character-based
// password. A Charset always includes letters.
type Charset int

const (
	// Letters denotes the capital and lowercase ASCII English letters.
	Letters Charset = 0

	// Digits denotes the set of ASCII decimal digits.
	Digits Charset = 1

	// Symbols denotes a set of ASCII punctuation symbols.
	Symbols Charset = 2

	// AllChars denotes a combination of letters, digits, and symbols.
	AllChars = Letters | Digits | Symbols
)

// RandomChars creates a new randomly-generated password of the given length
// and using the specified character types. A minimum length of 8 is enforced.
func RandomChars(length int, charset Charset) string {
	chars := pwLetters
	if charset&Digits != 0 {
		chars += pwDigits
	}
	if charset&Symbols != 0 {
		chars += pwSymbols
	}
	clen := uint64(len(chars))

	length = max(length, 8)
	out := make([]byte, length)
	var bits uint64 // entropy bits
	var nb int      // unconsumed entropy count
	for i := range length {
		if nb < bitsPerChar {
			bits, nb = randomUint64(), 64
		}
		out[i] = chars[int(bits%clen)]
		bits /= clen
		nb -= bitsPerChar
	}
	return string(out)
}

// RandomWords creates a new randomly-generated password comprising the
// specified number of wordlist entries. The words are separated by the
// specified joiner.  A minimum of 3 words is enforced.
func RandomWords(numWords int, joiner string) string {
	numWords = max(numWords, 3)
	out := make([]string, numWords)
	var bits uint64 // entropy bits
	var nb int      // unconsumed entropy count
	for i := range numWords {
		if nb < bitsPerWord {
			bits, nb = randomUint64(), 64
		}
		out[i] = words[int(bits%wordListLen)]
		bits /= wordListLen
		nb -= bitsPerWord
	}
	return strings.Join(out, joiner)
}

const (
	pwLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" // 52 letters
	pwDigits  = "0123456789"                                           // 10 digits
	pwSymbols = `!#$%&()*+,-./:;<=>?@[]^_{|}~`                         // 28 symbols

	// This list of symbols is based on
	// https://owasp.org/www-community/password-special-characters.
	// Removed: space, single quote, double quote, backquote, backslash

	// The number of entropy bits to charge for each character.  This is an
	// overestimate safe to use regardless which subset of alphabets are
	// selected. If you change the alphabets, update this constant.
	bitsPerChar = 7 // log2(52 + 10 + 28) = 6.492, round up to 7
)

func randomUint64() uint64 {
	var buf [8]byte
	if _, err := crand.Read(buf[:]); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(buf[:])
}
