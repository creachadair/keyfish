package service

import (
	"bytes"
	"html/template"
	"log"
	"path"
	"strings"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/js"
)

var (
	sitesList = template.Must(template.New("sites").Funcs(map[string]interface{}{
		"trimExt": func(s string) string {
			return strings.TrimSuffix(s, path.Ext(s))
		},
		"hasExt": func(s string) bool {
			ext := path.Ext(s)
			return ext != "" && len(ext) < 6
		},
	}).Parse(sitesListText))
	menuPage     = template.Must(template.New("menu").Parse(menuPageText))
	minifiedCode template.JS // populated from rawCode, see below.
)

func init() {
	const mediaType = "application/javascript"

	var buf bytes.Buffer
	m := minify.New()
	m.Add(mediaType, &js.Minifier{KeepVarNames: false})
	if err := m.Minify(mediaType, &buf, strings.NewReader(rawCode)); err != nil {
		log.Panicf("Minification failed: %v", err)
	}
	minifiedCode = template.JS(buf.String())
}

// The raw helper code for the page. This is minified and injected into the
// final output during program initialization.
const rawCode = `
void((()=>{
const doCopy = document.getElementById('authsend').value == 'local';

// Issue an HTTP GET request to the key server for the given tag.
function copyKey(tag) {
  return function() {
    const auth = localStorage.getItem(authKey);
    const doPrompt = doCopy && !auth;
    var req = new XMLHttpRequest();
    req.open('GET', '/key/'+tag+'?copy='+doCopy+'&prompt='+doPrompt, true);
    if (auth) {
        req.setRequestHeader('Authorization', 'Basic '+btoa(auth+':'));
    }
    if (!doCopy) {
       req.addEventListener('readystatechange', function() {
         if (req.readyState != XMLHttpRequest.DONE) { return; }
         if (req.status == 200) { prompt("Key", req.responseText.trim()); }
         alert("Copy failed: "+req.responseText.trim());
       })
    }
    req.send();
  }
}

function copyOTP(tag) {
  return function() {
    var req = new XMLHttpRequest();
    req.open('GET', '/otp/'+tag+'?copy='+doCopy, true);
    if (!doCopy) {
      req.addEventListener('readystatechange', function() {
        if (req.readyState != XMLHttpRequest.DONE) { return; }
        if (req.status == 200) { prompt("OTP", req.responseText.trim()); }
      })
    }
    req.send();
  }
}

function copyLogin(tag) {
  return function() {
    var req = new XMLHttpRequest();
    req.open('GET', '/login/'+tag+'?copy='+doCopy, true);
    if (!doCopy) {
      req.addEventListener('readystatechange', function() {
        if (req.readyState != XMLHttpRequest.DONE) { return; }
        if (req.status == 200) { prompt("Login", req.responseText.trim()); }
      })
    }
    req.send();
  }
}

// Update the auth key indicator.
function updateKeyTag() {
   const indicator = document.getElementById('keyflag');
   indicator.innerText = localStorage.getItem(authKey) ? '\u2705' : '';
}

// Attach event listeners to all the buttons.
for (const btn of document.getElementsByTagName('button')) {
  if (btn.className == "copy") {
    btn.addEventListener('click', copyKey(btn.value));
  } else if (btn.className == "otp") {
    btn.addEventListener('click', copyOTP(btn.value));
  } else if (btn.className == "login") {
    btn.addEventListener('click', copyLogin(btn.value));
  }
}

const authKey = 'passphrase';
const filter = document.getElementById('filter');

// Filter visible elements by containing a substring of the filter.
// Use 'display' rather than 'hidden' so that the hidden items collapse.
filter.addEventListener('input', function(e) {
   var text = e.target.value.toLowerCase();
   var numVis = 0;
   for (const row of document.getElementsByClassName('siterow')) {
      var vis = filter.value == "" || row.dataset.tag.includes(text) || row.dataset.host.includes(text);
      if (vis) { numVis += 1; }
      row.style.display = vis ? '' : 'none';
   }
})

document.getElementById('auth').addEventListener('click', function() {
   const input = prompt('Enter passphrase (empty to clear)');
   if (input === '') {
      localStorage.removeItem(authKey);
   } else if (input) {
      localStorage.setItem(authKey, btoa(input));
   }
   updateKeyTag();
})

updateKeyTag();
})())
`

// The HTML page generated by the /sites endpoint.
const sitesListText = `<html>
<head><title>Known Sites</title>
<style type="text/css">
body {
  font-family: sans-serif;
}
table.list { table-layout: auto; border-style: dotted; min-width: 50%; }
th { text-align: left; background-color: #dddddd; }
td.btn { width: auto; }
td.host { font-size: 85%; }
</style>
</head><body id=main>
<h1>Known sites:</h1>

<p>Filter: <input type=text inputmode=email id=filter size=25 autofocus /></p>
<p><button id=auth tabindex="-1">auth</button> <span id=keyflag></span></p>
<input id=authsend type=hidden value={{.Label}} />

<table class=list>
<tr>
  <th>Tag</th>
  <th>Link</th>
  <th>Host</th>
</tr>
{{range $tag, $site := .Sites}}<tr class=siterow data-tag="{{$tag}}" data-host="{{trimExt $site.Host}}">
  <td><tt>{{$tag}}</tt></td>
  <td>
    <button class=login type=button value="{{$tag}}">login</button>
    <button class=copy type=button value="{{$tag}}">copy</button>
    {{- if (index $site.OTP "")}} <button class=otp type=button value="{{$tag}}">otp</button>{{end}}</td>
  <td class=host>{{if hasExt $site.Host}}<a href="https://{{$site.Host}}" target=_blank>{{$site.Host}}</a>{{else}}{{$site.Host}}{{end}}</td>
</tr>{{end}}
</table>
<script>
{{.Code}}
</script>
</body></html>
`

// The HTML page generated by the menu ("/") endpoint.
const menuPageText = `<html>
<head><title>KeyFish key server</title>
</head><body>

<h1>KeyFish service</h1>

<p>Routes:</p>
<ul>
  <li><tt><a href="/sites">/sites</a></tt>: a list of all known sites
  <li><tt>/key/:site</tt>: return the key for site
  <li><tt>/otp/:site</tt>: return an OTP code for site
  <li><tt>/login/:site</tt>: return the login name for site
</ul>

<p>Site format:</p>
<ul>
  <li><tt>tag</tt>: a named site in the config
  <li><tt>salt@tag</tt>: a named site with a specific key salt
  <li><tt>host.com</tt>: a hostname
  <li><tt>salt@host.com</tt>: a hostname with a specific key salt
</ul>

<p>Parameters:</p>
<ul>
  <li><tt>strict=false</tt>: allow arbitrary host names
  <li><tt>copy=true</tt>: copy the key to the clipboard
  <li><tt>insert=true</tt>: insert the key as keystrokes
  <li><tt>prompt=true</tt>: prompt the local user for a passphrase
</ul>

</body></html>`
