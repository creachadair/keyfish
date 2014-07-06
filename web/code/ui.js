// One-time initialization for the main UI.
// Invoke from body.onload.
function init() {
    var kf = document.forms.kf;

    showAdvanced(getSetting("adv"));

    // Populate input fields from the query, if possible.
    // If not, fall back to local storage if available.
    var q = stateFromQuery();
    var s = loadState(q.s) || loadState("") || currentState();
    setState(q, s);

    // If we have enough information to generate a password, do it.
    if (kf.siteName.value && kf.secretKey.value) {
	uiComputePassword();
    } else if (kf.siteName.value) {
	kf.secretKey.focus();
    } else {
	kf.siteName.focus();
    }
}

// Compute the password from the current settings and store it into the output
// text field.
function uiComputePassword() {
    var kf = document.forms.kf;
    var site = kf.siteName.value;
    var fmt = kf.fmt.value;

    var alpha = Alphabet.NoPunct;
    if (kf.usePunct.checked) {
	alpha = Alphabet.All;
    }

    var ctx = new KeyFish(alpha, kf.salt.value, kf.secretKey.value);

    if (kf.fmt.value != "") {
	var pw = ctx.Format(site, fmt);
    } else {
	var pw = ctx.Password(site);
    }

    var len = kf.pwLength.value;
    if (pw.length > len) {
	pw = pw.substr(0, len);
    }

    kf.password.value = pw;
    kf.password.select();
}

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
function getSetting(key) {
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


// Save the current state in local storage.
function uiSaveState(state) { saveState(currentState()); }

// Capture the savable state in local storage.
function saveState(state) {
    modifyState(function (sites) {
	sites[state.s || ""] = state;
	return true;
    });
}

var defaultState =  {s:"", n:18, t:"", f:"", u:false};

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

// Purge saved state from local storage under the current key.
function uiClearState() {
    var key = currentState().s;
    modifyState(function (sites) {
	delete sites[key];
	return true;
    });
}

// Purge all saved state from local storage.
function uiClearAllState() {
    modifyState(function (sites) {
	for (var key in sites) {
	    delete sites[key];
	}
	return true;
    });
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

// Toggle the visibility of the "advanced" controls.
function uiToggleVis() {
    var vis = document.getElementById("adv").style.display != "block";
    showAdvanced(vis);
    storeSetting("adv", vis);
}

// Check whether the current site name corresponds to one of the saved state
// values and, if so, update the rest of the state accordingly.
function uiSiteChanged() {
    var site = document.forms.kf.siteName.value;
    setState(loadState(site) || currentState(), defaultState);
}
