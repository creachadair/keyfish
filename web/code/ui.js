// One-time initialization for the main UI.
// Invoke from body.onload.
function init() {
    var kf = document.forms.kf;

    // Populate input fields from the query, if possible.
    // If not, fall back to local storage if available.
    var q = stateFromQuery();
    var s = loadState(q.s);

    kf.siteName.value   = q.s || s.s;
    kf.secretKey.value  = q.p || s.p;
    kf.pwLength.value   = q.n || s.n;
    kf.salt.value       = q.t || s.t;
    kf.fmt.value        = q.f || s.f;
    kf.usePunct.checked = q.u || s.u;

    // If we have enough information to generate a password, do it.
    if (kf.siteName.value && kf.secretKey.value) {
	computePassword();
    } else if (kf.siteName.value) {
	kf.secretKey.focus();
    } else {
	kf.siteName.focus();
    }
}

// Compute the password from the current settings and store it into the output
// text field.
function computePassword() {
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

// Capture the savable state in local storage.
function saveState(state) {
    if (state == null) {
	state = currentState();
    }
    var key = state.s || "";
    window.localStorage.setItem(key, JSON.stringify(state));
}

var defaultState =  {s:"", p:"", n:18, t:"", f:"", u:false};

// Load and return a state object for key from local storage.
// Returns defaultState if no state is found for that key.
function loadState(key) {
    var pod = window.localStorage.getItem(key || "");
    if (!pod) { return defaultState; }
    return JSON.parse(pod);
}

// Purge saved state from local storage under the given key.
// The site name from the current state is used if key is not given.
function clearState(key) {
    if (key == null) {
	key = currentState().s;
    }
    window.localStorage.removeItem(key);
}

// Purge all saved state from local storage.
function clearAllState() { window.localStorage.clear(); window.location.reload(); }

// Returns an object capturing the current state of the UI.
function currentState() {
    var kf = document.forms.kf;
    return {
	s: kf.siteName.value,
	p: kf.secretKey.value,
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
	}
	q[key] = val || true;
    }
    return q;
}

// Toggle the visibility of the "advanced" controls.
function toggleVis() {
    var div = document.getElementById("adv");
    var vis = div.style.display;
    if (vis == "block") {
      div.style.display = "none";
    } else {
      div.style.display = "block";
    }
}
