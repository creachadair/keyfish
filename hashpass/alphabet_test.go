package hashpass_test

import (
	"testing"

	"github.com/creachadair/keyfish/hashpass"
)

func TestPick(t *testing.T) {
	tests := []struct {
		alpha      hashpass.Alphabet
		pick, want byte
	}{
		// An empty alphabet always returns 0.
		{"", 0, 0},
		{"", 1, 0},
		{"", 17, 0},
		{"", 255, 0},

		// Correct scaling for a simple alphabet.
		{"ABCD", 0, 'A'},
		{"ABCD", 63, 'A'},
		{"ABCD", 64, 'B'},
		{"ABCD", 127, 'B'},
		{"ABCD", 128, 'C'},
		{"ABCD", 191, 'C'},
		{"ABCD", 192, 'D'},
		{"ABCD", 255, 'D'},

		// Correct scaling for a more complex case (hand-computed).
		{"0123456789", 0, '0'},
		{"0123456789", 26, '1'}, // break at 25.6
		{"0123456789", 87, '3'},
		{"0123456789", 101, '3'},
		{"0123456789", 136, '5'},
		{"0123456789", 211, '8'},
		{"0123456789", 234, '9'},
	}
	for _, test := range tests {
		got := test.alpha.Pick(test.pick)
		if got != test.want {
			t.Errorf("Pick %v from %q: got %v, want %v", test.pick, test.alpha, got, test.want)
		}
	}
}
