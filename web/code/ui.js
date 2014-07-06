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
    uiUpdateKeysMenu();
    var u = loadSetting("username");
    if (u != undefined) {
	kf.userName.value = u
    }
    uiUpdateSecret();
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

// Update the user keys menu.
function uiUpdateKeysMenu() {
    var menu = document.forms.kf.userName;
    removeKids(menu);
    modifyKeys(function (keys) {
	var names = Object.keys(keys);
	names.sort();
	for (var i in names) {
	    menu.appendChild(new Option(names[i]));
	}
	return false;
    });
}

// Populate the secret key from the selected user value, if any.
function uiUpdateSecret() {
    var kf = document.forms.kf;
    var key = loadKey(kf.userName.value);
    if (key == undefined) {
	kf.secretKey.value = "";
    } else {
	kf.secretKey.value = key;
    }
}

// Update the various state settings in response to a change in the user menu.
function uiUserChanged() {
    uiUpdateSecret();
    storeSetting("username", document.forms.kf.userName.value);
}

// Save the current master key under a (possibly new) username.
function uiSaveMaster() {
    var kf = document.forms.kf;
    var user = prompt("Enter the username to save this key for",
		      kf.userName.value);
    if (user == null) {
	return;
    }
    storeKey(user, kf.secretKey.value);
    storeSetting("username", user);
    uiUpdateKeysMenu();
}

// Clear the master key belonging to the currently-selected user.
function uiClearMaster() {
    var user = document.forms.kf.userName.value;
    removeKey(user);
    uiUpdateKeysMenu();
    uiUserChanged();
}
