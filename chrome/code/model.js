//
// Name:     model.js
// Purpose:  Data model for KeyFish.
// Author:   M. J. Fromberger <michael.j.fromberger@gmail.com>
//

function intCheck(min, max) {
    return function(v) {
	var w = parseInt(v)
	return (w != NaN &&
		(min == null || w >= min) &&
		(max == null || w <= max)) ? w : null
    }
}

function readFrom(field, check) {
    return function(v) {
	return check ? check(v[field]) : v[field];
    }
}

function assignTo(field) {
    return function(v, x) { v[field] = x }
}

var KeyFish = new (function() {
    // Attach a field of this object to a DOM view object.
    // mname -- the name of my field
    // view  -- the DOM object
    // v2m   -- load a view value into the model
    // m2v   -- store a model value to the view
    this.bind = function(mname, view, v2m, m2v) {
	if (v2m == null)
	    v2m = (function(v) {})
	if (m2v == null)
	    m2v = (function(v, x) {})

	var iname = '_' + mname
	var init = this[mname]
	this.__defineGetter__(mname, function() {
	    return this[iname]
	})
	this.__defineSetter__(mname, function(nv) {
	    var old = this[iname]
	    this[iname] = nv
	    m2v(view, nv)
	    var evt = document.createEvent('MutationEvents')

	    evt.initMutationEvent('change', true, true, view,
				  old, nv, 'value', 1)
	    view.dispatchEvent(evt)
	})
	var obj = this
	var listener = function(evt) {
	    var v = v2m(view)
	    if (v == null)
		m2v(view, obj[iname])
	    else
		obj[iname] = v
	}
	view.addEventListener('change', listener)
	this[mname] = init
    }
    this.bindValue = function(mname, view, field) {
	if (field == null)
	    field = 'value'
	this.bind(mname, view, readFrom(field), assignTo(field))
    }
    this.bindInt = function(mname, view, min, max) {
	this.bind(mname, view,
		  readFrom('value', intCheck(min, max)),
		  assignTo('value'))
    }
    this.bindCheck = function(mname, view) {
	this.bindValue(mname, view, 'checked')
    }

    // Models for the UI components
    this.site      = ''
    this.salt      = ''
    this.secret    = ''
    this.showKey   = false
    this.saveKey   = false
    this.pwLength  = 18
    this.minLength = 4
    this.maxLength = 32
    this.useUpper  = true
    this.useLower  = true
    this.useDigit  = true
    this.usePunct  = false
    this.keyFormat = ''
    this.password  = ''

    // Returns the password alphabet based on the current settings.
    this.getAlphabet = function() {
	var alpha = ""
	if (this.useUpper)
	    alpha += this.Uppers
	if (this.useLower)
	    alpha += this.Lowers
	if (this.useDigit)
	    alpha += this.Digits
	if (this.usePunct)
	    alpha += this.Puncts
	return alpha
    };

    // Returns the site key based on the current settings.
    this.getSiteKey = function() {
	var key = this.site.trim()
	if (this.salt)
	    key += '/' + this.salt.trim()
	return key
    };

    // Returns the raw hash bytes based on the current settings.
    this.getHash = function() {
	return this.makeHash(this.getSiteKey(), this.secret)
    };

    // Returns the password based on the current settings.
    this.getPassword = function() {
	var hash = this.getHash()
	if (this.keyFormat) {
	    return this.formatPassword(hash, this.keyFormat)
	} else {
	    var alpha = this.getAlphabet()
	    return this.makePassword(hash, alpha, this.pwLength)
	}
    };

    // Returns the number of bits of entropy based on the current settings.
    this.getPasswordBits = function() {
	if (this.keyFormat)
	    return this.countFormatBits(this.keyFormat)
	else
	    return this.countPasswordBits(this.getAlphabet(), this.pwLength)
    };

    // Returns the raw hash bytes for the given site key and secret.
    this.makeHash = function(site, secret) {
	return Crypto.HMAC(Crypto.SHA256, site, secret, {asBytes: true})
    };

    // Returns the password letter selected by byte value from alpha.
    this.pickLetter = function(value, alpha) {
	var pos = Math.ceil((value + 1) / 256 * alpha.length) - 1
	return alpha.charAt(pos)
    };

    // Constructs a password from the given parameters.
    this.makePassword = function(bytes, alpha, count) {
	if (count <= 0 || alpha.length == 0)
	    return ""
	var pw = []
	for (var i = 0; i < count; ++i)
	    pw[i] = this.pickLetter(bytes[i], alpha)
	return pw.join('')
    };

    // Constructs a password for a format string.
    this.formatPassword = function(bytes, format) {
	if (format.length == 0)
	    return "";

	var cap = Math.min(format.length, this.maxLength)
	var pw = ""
	for (var i = 0; i < cap; ++i) {
	    var kind = this.classify(format[i])
	    if (kind == 'A')
		pw += this.pickLetter(bytes[i], this.Letters);
	    else if (kind == 'U')
		pw += this.pickLetter(bytes[i], this.Uppers);
	    else if (kind == 'L')
		pw += this.pickLetter(bytes[i], this.Lowers);
	    else if (kind == 'D')
		pw += this.pickLetter(bytes[i], this.Digits);
	    else if (kind == 'P')
		pw += this.pickLetter(bytes[i], this.Puncts);
	    else
		pw += format[i];
	}
	return pw
    };

    this.countBits = function(len, count) {
	if (len == 0)
	    return 0
	if (!count)
	    count = 1
	var bpc = -(Math.log(1 / len) / Math.log(2))
	return bpc * count
    }

    // Returns the number of bits of entropy for the given parameters.
    this.countPasswordBits = function(alpha, count) {
	if (alpha.length == 0 || count < 0)
	    return 0
	return Math.floor(this.countBits(alpha.length, count))
    };

    // Classify a password-template character:
    // A -- any letter
    // D -- decimal digit
    // L -- lowercase letter
    // P -- punctuation
    // U -- uppercase letter
    // ? -- literal (self-printing)
    //
    // Classification is done based on the alphabet contents, so what counts as
    // a letter or digit depends on those values.
    this.classify = function(char) {
	if (char == '*')
	    return 'A'
	else if (this.Uppers.indexOf(char) >= 0)
	    return 'U'
	else if (this.Lowers.indexOf(char) >= 0)
	    return 'L'
	else if (this.Digits.indexOf(char) >= 0)
	    return 'D'
	else if (this.Puncts.indexOf(char) >= 0)
	    return (char == '?') ? 'P' : '?'
	else
	    return '?'
    }

    this.countFormatBits = function(format) {
	var cap = Math.min(format.length, this.maxLength)
	var aBits = this.countBits(this.Letters.length, 1)
	var uBits = this.countBits(this.Uppers.length, 1)
	var lBits = this.countBits(this.Lowers.length, 1)
	var dBits = this.countBits(this.Digits.length, 1)
	var pBits = this.countBits(this.Puncts.length, 1)
	var bits = 0.0

	for (var i = 0; i < cap; ++i) {
	    var kind = this.classify(format[i])
	    if (kind == 'A')
		bits += aBits
	    else if (kind == 'U')
		bits += uBits
	    else if (kind == 'L')
		bits += lBits
	    else if (kind == 'D')
		bits += dBits
	    else if (kind == 'P')
		bits += pBits
	}
	return Math.floor(bits)
    }

    // Various alphabets.
    this.Uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    this.Lowers = "abcdefghijklmnopqrstuvwxyz"
    this.Letters = this.Uppers + this.Lowers
    this.Digits = "0123456789"
    this.Puncts = "!@#$%^&*-_=+,.:/?"
})();
