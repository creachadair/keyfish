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
func String(data []byte) string { return words.hash(data) }

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
	"abbot", "adder", "anode", "apple", "argon", "ashes", "aster", "attic",
	"axiom", "azure", "baker", "banjo", "baron", "birch", "black", "blame",
	"boron", "botch", "brief", "brine", "burro", "bylaw", "cabin", "cable",
	"calyx", "camel", "cedar", "child", "clank", "cobra", "coral", "cross",
	"cumin", "cubic", "daily", "dance", "decal", "delta", "demon", "diary",
	"dodge", "dogma", "dolor", "dough", "drape", "dryad", "eagle", "edict",
	"eight", "elope", "embed", "epoch", "erode", "erupt", "essay", "ethos",
	"evoke", "exile", "fable", "facet", "false", "favor", "feral", "finch",
	"focus", "forty", "found", "friar", "frost", "fuzzy", "gamma", "gavel",
	"gecko", "geode", "gills", "glade", "goose", "grave", "grind", "guess",
	"guide", "guilt", "habit", "handy", "happy", "heath", "hedge", "heron",
	"hippo", "holly", "horse", "hover", "humor", "hyena", "ictus", "idiom",
	"idler", "igloo", "image", "incur", "infix", "ingot", "inlay", "ionic",
	"itchy", "ivory", "jabot", "jaded", "jaunt", "jeans", "jenny", "jewel",
	"joint", "joker", "jolly", "joust", "jumbo", "juror", "kazoo", "kebab",
	"kefir", "ketch", "knave", "kneel", "knife", "knoll", "koala", "kudzu",
	"label", "lance", "lapse", "larch", "linen", "lithe", "llama", "loose",
	"lucid", "lyric", "mango", "marsh", "mason", "meter", "mimic", "miser",
	"monad", "moose", "motet", "music", "naiad", "nerve", "niche", "nifty",
	"night", "noise", "nonce", "notch", "novel", "nymph", "oasis", "ocean",
	"octet", "omega", "opera", "orbit", "otter", "ovary", "oxide", "ozone",
	"paint", "panda", "parse", "perch", "pique", "pixie", "plumb", "pouch",
	"proto", "proxy", "quail", "quake", "quart", "queen", "queue", "quill",
	"quote", "radar", "rainy", "razor", "reset", "rhyme", "ridge", "river",
	"roost", "rowan", "royal", "rumor", "sable", "satin", "scarf", "screw",
	"shark", "sixty", "slate", "spade", "stash", "sugar", "table", "tease",
	"thane", "timer", "torch", "totem", "triad", "tulip", "tuner", "twist",
	"umber", "unary", "unbox", "uncle", "unity", "upset", "urban", "usurp",
	"utter", "uvula", "vague", "verse", "vetch", "vigil", "viola", "vivid",
	"vixen", "vocal", "vodka", "voter", "wager", "waist", "water", "whale",
	"wharf", "wheat", "whelp", "woman", "wrist", "xenon", "xylem", "yacht",
	"yucca", "yeast", "yodel", "yield", "youth", "zebra", "zesty", "zippy",
}
