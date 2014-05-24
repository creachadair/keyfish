//
// Name:     view.js
// Purpose:  User interface controls for KeyFish.
// Author:   M. J. Fromberger <michael.j.fromberger@gmail.com>
//

// One-time initialization of the user interface.
// Should be called after the DOM is generated (e.g., onload).
function initKeyFish() {
    // Saves the master key to local storage.  This is not secure.
    KeyFish.saveMasterKey = function() {
	localStorage.setItem("masterKey", btoa(KeyFish.secret))
    }

    // Loads the master key from local storage.  This is not secure.
    KeyFish.loadMasterKey = function() {
	var raw = localStorage.getItem("masterKey")
	if (raw != null) {
	    KeyFish.saveKey = true
	    KeyFish.secret = atob(raw)
	}
    }

    // Clears the master key from storage, if present.
    KeyFish.clearMasterKey = function() {
	localStorage.removeItem("masterKey")
    }

    // Saves the model's data to local storage under the site key.  Pickles the
    // appropriate settings to JSON.
    KeyFish.saveModelData = function(key) {
	var data = {
	    site:      KeyFish.site,
	    salt:      KeyFish.salt,
	    pwLength:  KeyFish.pwLength,
	    keyFormat: KeyFish.keyFormat,
	    useLower:  KeyFish.useLower,
	    useUpper:  KeyFish.useUpper,
	    useDigit:  KeyFish.useDigit,
	    usePunct:  KeyFish.usePunct,
	};
	localStorage.setItem(key, JSON.stringify(data))
    }
    KeyFish.saveSiteData = function() {
	var key = KeyFish.site.trim()
	if (key)
	    KeyFish.saveModelData('#'+key)
	else
	    KeyFish.saveModelData("defaultSettings")
    }
    KeyFish.clearModelData = function(key) {
	localStorage.removeItem(key)
    }
    KeyFish.clearSiteData = function() {
	var key = KeyFish.site.trim()
	if (key)
	    return KeyFish.clearModelData('#'+key)
	else
	    return KeyFish.clearModelData("defaultSettings")
    }

    // Loads data into the model from local storage.  Returns whether any data
    // were found for the given key.
    KeyFish.loadModelData = function(key) {
	if (!key)
	    return false

	var raw = localStorage.getItem(key)
	if (raw == null) {
	    return false
	}

	var data = JSON.parse(raw)
	if (data.salt != null)     KeyFish.salt = data.salt
	if (data.pwLength != null) KeyFish.pwLength = data.pwLength
	if (data.keyFormat != null) KeyFish.keyFormat = data.keyFormat
	if (data.useLower != null) KeyFish.useLower = data.useLower
	if (data.useUpper != null) KeyFish.useUpper = data.useUpper
	if (data.useDigit != null) KeyFish.useDigit = data.useDigit
	if (data.usePunct != null) KeyFish.usePunct = data.usePunct
	return true
    }
    KeyFish.loadSiteData = function(key) {
	return key ? KeyFish.loadModelData('#'+key) : false
    }
    KeyFish.loadSiteDefaults = function() {
	return KeyFish.loadModelData("defaultSettings")
    }

    KeyFish.loadSiteKeys = function() {
	var keys = []
	for (var i = 0; i < localStorage.length; ++i) {
	    var k = localStorage.key(i)
	    if (k.charAt(0) == '#')
		keys.push(k.substr(1))
	}
	return keys
    }

    KeyFish.loadBrowserSite = function() {
	siteFromEnvironment(function(site) {
	    KeyFish.site = trimHostName(site)
	})
    }

    KeyFish.loadMasterKey()
    KeyFish.loadModelData("defaultSettings")
    KeyFish.bindValue('site',      document.forms.iomain.site)
    KeyFish.bindValue('salt',      document.forms.ioadv.salt)
    KeyFish.bindValue('keyFormat', document.forms.ioadv.format)
    KeyFish.bindValue('secret',    document.forms.iomain.secret)
    KeyFish.bindCheck('showKey',   document.forms.iomain.show_pw)
    KeyFish.bindCheck('useUpper',  document.forms.ioadv.a_upper)
    KeyFish.bindCheck('useLower',  document.forms.ioadv.a_lower)
    KeyFish.bindCheck('useDigit',  document.forms.ioadv.a_digit)
    KeyFish.bindCheck('usePunct',  document.forms.ioadv.a_punct)
    KeyFish.bindInt('pwLength',    document.forms.ioadv.passlen)
    if (KeyFish.site == "")
	KeyFish.loadBrowserSite()
}

// Extract a site name from wherever it's available.
function siteFromEnvironment(cont) {
    if (chrome == null || chrome.tabs == null)
	siteFromLocation(cont)
    else
	siteFromCurrentTab(cont)
}

// Extracts and calls cont for a site name from the location bar.
function siteFromLocation(cont) {
    var site = location.hostname, hash = unescape(location.hash)
    if (!site) {
	var parsed = parseURI(hash)
	site = (parsed && parsed.host) || location.pathname
    }
    cont(site.trim())
}

// Extracts and calls cont for a site name from the current active tab.  This
// only works when running as a Chrome extension with the "tabs" permission.
function siteFromCurrentTab(cont) {
    chrome.tabs.getSelected(null, function(tab) {
	var site = tab.url
	var parsed = parseURI(site)
	if (parsed) {
	    if (parsed.scheme == "chrome:")
		site = ""
	    else
		site = parsed.host || parsed.path
	}
	cont(site.trim())
    })
}

// Posts a status message for the given section key, optionally with a timeout
// before the message is removed.
function postStatus(idkey, message, timeout) {
    var elt = document.getElementById(idkey + "_status");
    elt.innerText = message
    if (timeout != null) {
	setTimeout(function() {
	    elt.innerText = "";
	}, timeout);
    }
}

// Obtains the password from the model and stores it in the output box.
function updatePassword() {
    var update = function(site) {
        if (site != null)
           KeyFish.site = site
	var pw = KeyFish.getPassword();
	document.output.result.value = pw;
        document.output.result.select()
        document.execCommand("Copy")
	document.output.result.value = KeyFish.showKey ? pw : obscurePassword(pw);
	setEntropy(KeyFish.getPasswordBits())
    }
    if (KeyFish.site == "")
	siteFromEnvironment(update);
    else
	update(null)
}

// Stores various diagnostic parameters in the UI, if they are defined.
function updateDiagnostics() {
    var bytes = KeyFish.getHash()
    var hash = Crypto.util.bytesToHex(bytes);
    var alpha = KeyFish.getAlphabet()

    setField("d_hash", hash)
    setField("d_bytes", bytes)
    setField("d_site", KeyFish.getSiteKey())
    setField("d_secret", KeyFish.secret)
    setField("d_alpha", alpha ? '"' + alpha + '"' : "(no available symbols)")
    setField("d_entropy", KeyFish.getPasswordBits() + " bits")
}

function setEntropy(value) {
    setField("d_entropy", value + " bits")
    var elt = document.getElementById("m_entropy")
    elt.value = value
}

// Updates the text of the element whose ID is given, if it exists.  Silently
// does nothing if the element is not found.
function setField(name, text) {
    var elt = document.getElementById(name)
    if (elt != null)
	elt.innerText = text
}

// Updates an indicator label for a range slider.
function updateLabel(who) {
    var elt = document.getElementById(who.target.name + '_label')
    elt.innerText = who.target.value
}

// Sets a highlight around the specified element if its value is empty.
function checkEmpty(who) {
    who.target.style.borderColor = (who.target.value == "") ? "red" : "#cccccc";
}
