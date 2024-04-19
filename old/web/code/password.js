// Implementation of the KeyFish site-specific password algorithm.
// by Michael J. Fromberger <michael.j.fromberger@gmail.com>

// KeyFish contains the information needed to generate a password given the
// name of a site.
var KeyFish = function(alphabet, salt, secret) {
    this.alphabet = alphabet;
    this.salt = salt;
    this.secret = secret;
}

function log2(x) { return Math.log(x) / Math.log(2); }

// Various alphabet definitions.
var Alphabet = {
    Uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    Lowercase: "abcdefghijklmnopqrstuvwxyz",
    Digits:    "0123456789",
    Puncts:    "!@#$%^&*-_=+,.:/?",
};
Alphabet.Letters = Alphabet.Uppercase + Alphabet.Lowercase;
Alphabet.NoPunct = Alphabet.Letters + Alphabet.Digits;
Alphabet.All     = Alphabet.NoPunct + Alphabet.Puncts;

// Entropy returns the number of bits of entropy in a password of the given
// length, assuming a random selection of characters.  May be zero, if the
// length is zero or the alphabet is empty.
KeyFish.prototype.Entropy = function(length) {
    if (length <= 0 || this.alphabet == "") {
	return 0;
    }
    var bpc = Math.floor(-log2(1/this.alphabet.length));
    return bpc * length;
}

// Password returns the password for the given site based on the stored
// settings in the object.  The longest possible password is returned; the
// caller is responsible for truncating it if desired.
KeyFish.prototype.Password = function(site) {
    var p = this.parseSite(site);
    var buf = [];
    var raw = this.Hash(p.site, p.salt);
    for (var i = 0; i < raw.length; i++) {
	buf.push(this.Pick(raw[i]));
    }
    return buf.join("");
}

// parseSite parses a site of the form [salt@]hostname, returning an object
// with site and salt keys. The salt defaults to this.salt if not specified.
KeyFish.prototype.parseSite = function(site) {
    var salt = this.salt;
    var i = site.search("@");
    if (i >= 0) {
	salt = site.substr(0, i);
	site = site.substr(i+1);
    }
    return {site: site, salt: salt}
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
// All other characters are copied literally to the output.
KeyFish.prototype.Format = function(site, format) {
    if (format == "") {
	return format
    }
    if (format.length > 32) {
	format = format.substr(0, 32);
    }
    var p = this.parseSite(site);
    var buf = [];
    var raw = this.Hash(p.site, p.salt);
    for (var i = 0; i < format.length; i++) {
	if (format[i] == "*") {
	    buf.push(pick(Alphabet.Letters, raw[i]));
	} else if (format[i] == "?") {
	    buf.push(pick(Alphabet.Puncts, raw[i]));
	} else if (format[i] == "#") {
	    buf.push(pick(Alphabet.Digits, raw[i]));
	} else if (format[i] == "^") {
	    buf.push(pick(Alphabet.Uppercase, raw[i]));
	} else if (format[i] == "_") {
	    buf.push(pick(Alphabet.Lowercase, raw[i]));
	} else {
	    buf.push(format[i]);
	}
    }
    return buf.join("");
}

// Hash computes the HMAC/SHA256 of the given site key using the stored salt
// and secret from the object.  Returns an array of octet values.
KeyFish.prototype.Hash = function(site, salt) {
    if (salt != "") {
	site += "/" + salt;
    }
    var hex = CryptoJS.HmacSHA256(site, this.secret).toString();
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) {
	bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

function pick(alpha, byte) {
    if (alpha == "") {
	return "\x00";
    }
    var pos = Math.ceil((byte + 1) / 256 * alpha.length) - 1;
    return alpha[pos];
}

// Pick returns the letter from the stored alphabet corresponding to the given
// byte value from a password hash.
KeyFish.prototype.Pick = function(byte) { return pick(this.alphabet, byte); }
