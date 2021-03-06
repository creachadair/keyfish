// Package wordhash converts digests into a reasonably-memorable human-readable
// form. The resulting output is not of cryptographic quality -- in particular
// it is not collision resistant -- but should be sufficient to give a human
// viewer moderate confidence that they are viewing the same value.
package wordhash

import (
	"hash/crc32"
	"strings"
)

// String generates a human-readable digest of data as a printable string.
func String(data string) string { return words.hash([]byte(data)) }

// Bytes generates a human-readable digest of data as a printable string.
func Bytes(data []byte) string { return words.hash(data) }

type wordmap [256]string

func (w wordmap) hash(data []byte) string {
	crc := crc32.ChecksumIEEE(data)
	segments := make([]string, 4)
	for i := 0; i < 4; i++ {
		segments[i] = w[crc&0xff]
		crc >>= 8
	}
	return strings.Join(segments, "-")
}

var words = wordmap{
	// This word list was constructed by hand. If you make any changes here,
	// either to the order or content of entries, you will need to update the
	// test cases too.
	"abbot", "adder", "anode", "apple", "argon", "ashes", "aster", "attic", // 0
	"axiom", "azure", "baker", "banjo", "baron", "birch", "black", "blame",
	"boron", "botch", "brief", "brine", "burro", "bylaw", "cabin", "cable", // 1
	"calyx", "camel", "cedar", "child", "clank", "cobra", "coral", "cross",
	"cumin", "cubic", "daily", "dance", "decal", "delta", "demon", "diary", // 2
	"dodge", "dogma", "dolor", "dough", "drape", "dryad", "eagle", "edict",
	"eight", "elope", "embed", "epoch", "erode", "erupt", "essay", "ethos", // 3
	"evoke", "exile", "fable", "facet", "false", "favor", "feral", "finch",
	"focus", "forty", "found", "friar", "frost", "fuzzy", "gamma", "gavel", // 4
	"gecko", "geode", "gills", "glade", "goose", "grave", "grind", "guess",
	"guide", "guilt", "habit", "handy", "happy", "heath", "hedge", "heron", // 5
	"hippo", "holly", "horse", "hover", "humor", "hyena", "ictus", "idiom",
	"idler", "igloo", "image", "incur", "infix", "ingot", "inlay", "ionic", // 6
	"itchy", "ivory", "jabot", "jaded", "jaunt", "jeans", "jenny", "jewel",
	"joint", "joker", "jolly", "joust", "jumbo", "juror", "kazoo", "kebab", // 7
	"kefir", "ketch", "knave", "kneel", "knife", "knoll", "koala", "kudzu",
	"label", "lance", "lapse", "larch", "linen", "lithe", "llama", "loose", // 8
	"lucid", "lyric", "mango", "marsh", "mason", "meter", "mimic", "miser",
	"monad", "moose", "motet", "music", "naiad", "nerve", "niche", "nifty", // 9
	"night", "noise", "nonce", "notch", "novel", "nymph", "oasis", "ocean",
	"octet", "omega", "opera", "orbit", "otter", "ovary", "oxide", "ozone", // A
	"paint", "panda", "parse", "perch", "pique", "pixie", "plumb", "pouch",
	"proto", "proxy", "quail", "quake", "quart", "queen", "queue", "quill", // B
	"quote", "radar", "rainy", "razor", "reset", "rhyme", "ridge", "river",
	"roost", "rowan", "royal", "rumor", "sable", "satin", "scarf", "screw", // C
	"shark", "sixty", "slate", "spade", "stash", "sugar", "table", "tease",
	"thane", "timer", "torch", "totem", "triad", "tulip", "tuner", "twist", // D
	"umber", "unary", "unbox", "uncle", "unity", "upset", "urban", "usurp",
	"utter", "uvula", "vague", "verse", "vetch", "vigil", "viola", "vivid", // E
	"vixen", "vocal", "vodka", "voter", "wager", "waist", "water", "whale",
	"wharf", "wheat", "whelp", "woman", "wrist", "xenon", "xylem", "yacht", // F
	"yucca", "yeast", "yodel", "yield", "youth", "zebra", "zesty", "zippy",
}
