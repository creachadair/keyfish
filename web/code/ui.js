// One-time initialization for the main UI.
// Invoke from body.onload.
function init() {
    var kf = document.forms.kf;

    showAdvanced(loadSetting("adv"));

    // Populate input fields from the query, if possible.
    // If not, fall back to local storage if available.
    var q = stateFromQuery();
    var s = loadState(q.s) || loadState("") || currentState();
    setState(q, s);
    uiUpdateSiteList();

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

// Save the current state in local storage.
function uiSaveState(state) { 
    saveState(currentState()); 
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

// Update the data list used by the siteName field.
function uiUpdateSiteList() {
    var list = document.getElementById("sitelist");
    while (list.firstChild) {
	list.removeChild(list.firstChild);
    }
    var names = loadSiteNames();
    for (var i in names) {
	list.appendChild(new Option(names[i]));
    }
}
