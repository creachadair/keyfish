// WordHash converts digests into a reasonably-memorable human-readable
// form. The resulting output is not of cryptographic quality -- in particular
// it is not collision resistant -- but should be sufficient to give a human
// viewer moderate confidence that they are viewing the same value.
var WordHash = (function() {
    const ieeePoly = 0xedb88320;
    const table = new Uint32Array(256);

    // Precompute a lookup table for byte values. We don't actually care about
    // performance for short strings, but this is less code.
    for (var i = 0; i < 256; i++) {
	var crc = i;
	for (var j = 0; j < 8; j++) {
	    if (crc&1 == 1) {
		crc = (crc >>> 1) ^ ieeePoly;
	    } else {
		crc >>>= 1;
	    }
	}
	table[i] = crc;
    }
    function crc32(str) {
	var bytes = str.split("").map(function (c) {
	    return c.charCodeAt(0);
	});
	var crc = ~0;
	for (var i = 0; i < bytes.length; i++) {
	    crc = table[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
	}
	return ~crc;
    }

    const words = [
	// This word list was copied from the Go implementation.
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
    ];

    return function (str) {
	var crc = crc32(str);
	var segments = new Array(4);
	for (var i = 0; i < 4; i++) {
	    segments[i] = words[crc & 0xff];
	    crc >>>= 8;
	}
	return segments.join("-");
    }
})();


