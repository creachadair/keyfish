// Helper functions used by the UI for interacting with local storage.
//
// Settings are saved as a JSON object under the name "settings".  This
// includes various UI configurations like whether the advanced section of the
// form is displayed.
//
// Site configurations are saved as a JSON object under the name "sites".
// Each key represents a site name, with "" denoting the default settings.
// The value is an object with keys:
//   s=sitename, u=usepunct, n=length, t=salt, f=format
//
// Secret keys are saved as a JSON object under the name "keys".  Each key
// represents a user name, with "" denoting the default setting.  The value is
// the obfuscated secret key (obfuscation is just encoding with base64, and is
// not a security measure).

// The default state values used when nothing is found in local storage.
var defaultState =  {s:"", n:18, t:"", f:"", u:false};

// Apply fn to the current settings data.  If fn returns true, the modified
// value is written back; otherwise not.
function modifySettings(fn) {
    var settings = {};
    if ("settings" in window.localStorage) {
	settings = JSON.parse(window.localStorage.settings);
    }
    if (fn(settings)) {
	window.localStorage.setItem("settings", JSON.stringify(settings));
    }
}

// Fetch the named setting.
function loadSetting(key) {
    var value = undefined;
    modifySettings(function (settings) {
	value = settings[key];
	return false;
    });
    return value;
}

// Store the named setting.
function storeSetting(key, val) {
    modifySettings(function (settings) {
	settings[key] = val;
	return true;
    });
}

// Apply fn to the current keys data.  If fn returns true, the modified value
// is written back; otherwise not.
function modifyKeys(fn) {
    var keys = {};
    if ("keys" in window.localStorage) {
	keys = JSON.parse(window.localStorage.keys);
    }
    if (fn(keys)) {
	window.localStorage.setItem("keys", JSON.stringify(keys));
    }
}

// Fetch and de-obfuscate the key for the named user.
function loadKey(user) {
    var value = undefined;
    modifyKeys(function (keys) {
	value = keys[user];
	return false;
    });
    return value && deobfuscateKey(value);
}

// Obfuscate and store the given key for the specified user.
function storeKey(user, key) {
    modifyKeys(function (keys) {
	keys[user] = obfuscateKey(key);
	return true;
    });
}

// Remove the key for the specified user.
function removeKey(user) {
    modifyKeys(function (keys) {
	delete keys[user];
	return true;
    });
}

// Apply fn to the current saved sites data.  If fn returns true, the modified
// value is written back; otherwise not.
function modifyState(fn) {
    var sites = {};
    if ("sites" in window.localStorage) {
	sites = JSON.parse(window.localStorage.sites);
    }
    if (fn(sites)) {
	window.localStorage.setItem("sites", JSON.stringify(sites));
    }
}

// Set the current state of the UI to the given values.  If a field value is
// not present in s, but is present in fb, the value from fb is used.
function setState(s, fb) {
    var kf = document.forms.kf;

    kf.siteName.value   = s.s || fb.s;
    kf.pwLength.value   = s.n || fb.n;
    kf.salt.value       = s.t || fb.t;
    kf.fmt.value        = s.f || fb.f;
    kf.usePunct.checked = s.u || fb.u;

    kf.password.value = "";
}

// Capture the savable state in local storage.
function saveState(state) {
    modifyState(function (sites) {
	sites[state.s || ""] = state;
	return true;
    });
}

// Load and return a state object for key from local storage.
// Returns defaultState if no state is found for that key.
function loadState(key) {
    var pod = undefined;
    modifyState(function (sites) {
	if (key in sites) {
	    pod = sites[key];
	}
	return false;
    });
    return pod;
}

// Returns an object capturing the current state of the UI.
function currentState() {
    var kf = document.forms.kf;
    return {
	s: kf.siteName.value,
	n: parseInt(kf.pwLength.value),
	t: kf.salt.value,
	u: kf.usePunct.checked,
	f: kf.fmt.value,
    }
}

// Return a state object based on the query parameters.
// The query fields are: s=site, p=password, n=length, t=salt, u=usepunct.
function stateFromQuery() {
    var href = location.href;
    var ls = window.localStorage;
    var raw = href.slice(href.indexOf("?") + 1).split("&");
    var q = {};
    for (var i = 0; i < raw.length; i++) {
	var eq = raw[i].indexOf("=");
	var key = decodeURIComponent(raw[i]), val = "";
	if (eq > 0) {
	    key = raw[i].substr(0, eq);
	    val = decodeURIComponent(raw[i].substr(eq+1));
	} else {
            val = true;
        }
	q[key] = val;
    }
    return q;
}

// Set the visibility of the "advanced" controls.
function showAdvanced(tf) {
    var div = document.getElementById("adv");
    if (tf) {
	div.style.display = "block";
    } else {
	div.style.display = "none";
    }
}

// Retrieve the list of saved sites from local storage.
function loadSiteNames() {
    var names = [];
    modifyState(function (sites) {
	names = Object.keys(sites);
	return false;
    });
    names.sort();
    return names;
}

// Update the text on the state buttons to reflect the value of site.
function updateStateButtons(site) {
    if (site == "") {
	document.getElementById("ssbtn").firstChild.nodeValue = "Save Defaults";
	document.getElementById("csbtn").firstChild.nodeValue = "Clear Defaults";
    } else {
	document.getElementById("ssbtn").firstChild.nodeValue = 'Save "'+site+'"';
	document.getElementById("csbtn").firstChild.nodeValue = 'Clear "'+site+'"';
    }
}

// Insecurely obfuscate a secret key for recording in local storage.
function obfuscateKey(key) { return btoa(key); }

// Reverse the obfuscation performed by obfuscateKey.
function deobfuscateKey(key) { return atob(key); }

// Remove all the children from the given tag.
function removeKids(tag) {
    while (tag.firstChild) {
	tag.removeChild(tag.firstChild);
    }
}

// Make a good-faith effort to extract the URL hostname from the browser,
// and calls cont with it.  Calls with "" if no hostname as found.
function getBrowserHost(cont) {
    if (typeof chrome == 'undefined' || chrome.tabs == null) {
	cont(location.hostname || "");
	return;
    }

    // Who thought this design was a good idea? :P
    chrome.tabs.query({active:true, currentWindow:true}, function (tabs) {
	if (tabs.length == 0) {
	    cont("");
	    return;
	}
	var site = tabs[0].url, parsed;
	console.log("SITE: "+site);
	try {
	    parsed = new URL(site);
	} catch (err) {
	    console.log("Invalid tab URL: "+site);
	    cont("");
	    return;
	}
	console.log("URL: "+parsed);
	if (parsed.protocol != "chrome:") {
	    cont(parsed.hostname.trim());
	}
    });
}

// Make a good-faith effort to extract the refering URL's hostname.
// Returns "" if that is impossible.
function getPreviousHost() {
    try {
	var parsed = new URL(document.referrer);
	return parsed.hostname || "";
    } catch (err) {
	console.log("Invalid referring URL: "+document.referrer);
    }
    return "";
}

// Remove all but the last two components of a hostname, e.g., "www.foo.com"
// becomes "foo.com", but "bar.org" remains "bar.org".
function trimHost(host) {
    var parts = host.split(".")
    if (parts.length > 2) {
       return parts.slice(1).join('.')
    }
    return host
}
