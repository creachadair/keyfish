// One-time initialization for the main UI.  Invoke from body.onload.
function init() {
    var kf = document.forms.kf;

    // Set up handlers.
    kf.siteName.addEventListener("change", uiSiteChanged, false);
    kf.go.addEventListener("click", uiComputePassword, false);
    kf.advbtn.addEventListener("click", uiToggleVis, false);
    kf.ssbtn.addEventListener("click", uiSaveState, false);
    kf.csbtn.addEventListener("click", uiClearState, false);
    kf.cabtn.addEventListener("click", uiClearAllState, false);

    showAdvanced(loadSetting("adv"));

    // Populate input fields from the query, if possible.
    // If not, fall back to local storage if available.
    var q = stateFromQuery();
    var s = loadState(q.s) || loadState("") || currentState();
    setState(q, s);

    // Update various UI components based on saved state.
    uiUpdateSiteList();
    updateStateButtons(kf.siteName.value);

    // If we have enough information to generate a password, do it.
    if (kf.siteName.value && kf.secretKey.value) {
	uiComputePassword();
    } else if (kf.siteName.value) {
	kf.secretKey.focus();
    } else {
	kf.siteName.focus();
    }
}

// Attach the load listener to the document body.
document.addEventListener("DOMContentLoaded", function() {
    // When loading as a Chrome extension, we have to set a reasonable width or
    // the popup will get a very narrow default size.  For everything else, we
    // are happy with the device width.
    if (typeof chrome != 'undefined') {
	document.body.style.minWidth = "380px";
	getBrowserHost(function (host) {
	    document.forms.kf.siteName.value =
		trimHost(host || getPreviousHost());
	    uiSiteChanged();
	});
    }

    // Do this after checking the Chrome stuff, so settings from the page query
    // will override the defaults.
    init();
}, false);

// Compute the password from the current settings and store it into the output
// text field.
// Click handler for the "Generate" button.
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

    // If we're allowed to copy (e.g., we're in an extension with permissions
    // enabled, or similar), send the password to the system pasteboard.
    try {
	document.execCommand("Copy");
    } catch (err) {
	// Probably not allowed or supported, but that's OK.
    }
}

// Save the current state in local storage.
// Click handler for the "Save Defaults/Site" button.
function uiSaveState() { saveState(currentState()); }

// Purge saved state from local storage under the current key.
// Click handler for the "Clear Defaults/Site" button.
function uiClearState() {
    var key = currentState().s;
    modifyState(function (sites) {
	delete sites[key];
	return true;
    });
}

// Purge all saved state from local storage.
// Click handler for the "Clear All" button.
function uiClearAllState() {
    modifyState(function (sites) {
	for (var key in sites) {
	    delete sites[key];
	}
	return true;
    });
}

// Toggle the visibility of the "advanced" controls.
// Click handler for the "Advanced" button.
function uiToggleVis() {
    var vis = document.getElementById("adv").style.display != "block";
    showAdvanced(vis);
    storeSetting("adv", vis);
}

// Check whether the current site name corresponds to one of the saved state
// values and, if so, update the rest of the state accordingly.
// Change handler for the site name field.
function uiSiteChanged() {
    var site = document.forms.kf.siteName.value;
    setState(loadState(site) || currentState(), defaultState);
    updateStateButtons(site);
}

// Update the data list used by the siteName field.
function uiUpdateSiteList() {
    var list = document.getElementById("sitelist");
    removeKids(list);
    var names = loadSiteNames();
    for (var i in names) {
	list.appendChild(new Option(names[i]));
    }
}
