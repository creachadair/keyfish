package wordhash

import (
	"hash/crc32"
	"testing"
)

func TestString(t *testing.T) {
	// These test vectors were constructed by hand for the built-in word list,
	// and must be updated if the word list changes.
	//
	// To construct a test case, compute the CRC32 of the input string with the
	// IEEE polynomial (a.k.a., crc32.ChecksumIEEE) and map each byte into the
	// word list in increasing order of significance.
	tests := []struct {
		input, want string
	}{
		{"", "abbot-abbot-abbot-abbot"},
		{"\x00", "meter-whale-anode-torch"},
		{"a", "friar-ridge-quill-vixen"},
		{"b", "yeast-whale-ridge-joker"},
		{"aa", "twist-camel-mango-attic"},
		{"correct horse battery staple", "boron-jenny-koala-spade"},
		{"0123456789abcdef!@#$%^&;", "hover-black-monad-jenny"},
	}
	for _, test := range tests {
		got := String(test.input)
		t.Logf("Input: %q, CRC: %08x, Hash: %q",
			test.input, crc32.ChecksumIEEE([]byte(test.input)), got)
		if got != test.want {
			t.Errorf("String(%q): got %q, want %q", test.input, got, test.want)
		}
		got = Bytes([]byte(test.input))
		if got != test.want {
			t.Errorf("Bytes(%q): got %q, want %q", test.input, got, test.want)
		}
	}
}
