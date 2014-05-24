//
// Name:     popup.js
// Purpose:  Controls the behaviour of the KeyFish popup page.
// Author:   M. J. Fromberger <michael.j.fromberger@gmail.com>
//

function updateShowSecret() {
    var show = document.forms.iomain.show_pw.checked
    document.forms.iomain.secret.type = (show ? 'text' : 'password')
}

// Select a site name from the menu.
function pickSite(site) {
    if (site)
	KeyFish.site = site
    changeSite(site)
}

// Load settings and update the menu as appropriate.
function changeSite(site) {
    if (!site || !KeyFish.loadSiteData(site))
	KeyFish.loadSiteDefaults()

    var pick = document.forms.iomain.pick
    for (var i = 0; i < pick.children.length; ++i) {
	var opt = pick.children[i]
	if (opt.innerText == site) {
	    pick.selectedIndex = i
	    return
	}
    }
    pick.selectedIndex = 0
    document.output.result.value = ''
}

function updateAdvanced(who) {
    var elt = document.getElementById("adv")
    elt.style.display = who.target.checked ? "block" : "none"
}

function saveSecret() {
    KeyFish.saveMasterKey()
    postStatus("adv", "Master key saved", 2000)
}

function clearSecret() {
    KeyFish.clearMasterKey()
    postStatus("adv", "Master key cleared", 2000)
    KeyFish.secret = ""
}

function saveSite() {
    KeyFish.saveSiteData()
    var site = KeyFish.site

    if (site) {
	postStatus("adv", 'Saved settings for "' +
		   KeyFish.site + '"', 2000)
	populatePicker()
	changeSite(KeyFish.site)
    } else {
	postStatus("adv", "Saved default settings", 2000)
    }
}

function clearSite() {
    KeyFish.clearSiteData()
    var site = KeyFish.site
    KeyFish.site = ''
    KeyFish.site = site
    KeyFish.keyFormat = ''

    if (site) {
	postStatus("adv", 'Cleared settings for "' +
		   site + '"', 2000)
	populatePicker()
    } else {
	postStatus("adv", "Cleared default settings", 2000)
    }
}

function populatePicker() {
    var keys = KeyFish.loadSiteKeys()
    var pick = document.forms.iomain.pick
    pick.options.length = 0
    pick.options[0] = new Option("(default)", "")
    for (var i = 0; i < keys.length; ++i) {
	pick.options[i+1] = new Option(keys[i], keys[i])
    }
}

// Set up event listeners for internal controls.
document.addEventListener('DOMContentLoaded', function () {
    document.forms.iomain.secret.addEventListener('change', checkEmpty);
    document.forms.ioadv.passlen.addEventListener('change', updateLabel)
    initKeyFish()
    document.forms.iomain.site.addEventListener('change', function() {
	changeSite(this.value)
    })
    document.forms.iomain.pick.addEventListener('change', function() {
	pickSite(this.value)
    })
    document.forms.iomain.fill.addEventListener('click', function() {
	KeyFish.loadBrowserSite()
    })
    document.forms.iomain.show_pw.addEventListener('change', updateShowSecret)
    document.forms.output.compute.addEventListener('click', updatePassword)
    document.forms.output.show_adv.addEventListener('change', updateAdvanced)
    document.forms.ioadv.savekey.addEventListener('click', saveSecret)
    document.forms.ioadv.clearkey.addEventListener('click', clearSecret)
    document.forms.ioadv.savesite.addEventListener('click', saveSite)
    document.forms.ioadv.clearsite.addEventListener('click', clearSite)
    updateAdvanced({target: document.forms.output.show_adv});
    populatePicker()
})
