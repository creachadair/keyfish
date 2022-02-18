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
	}).Parse(sitesListText))
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
// Issue an HTTP GET request to the key server for the given tag.
function copyKey(tag) {
  return function() {
    const auth = localStorage.getItem(authKey);
    var req = new XMLHttpRequest();
    req.open('GET', '/key/'+tag+'?copy=1', true);
    if (auth) {
        req.setRequestHeader('Authorization', 'Phrase '+auth);
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
  btn.addEventListener('click', copyKey(btn.value));
}

const authKey = 'passphrase';
const maxColumns = 4;
const columnHeight = 30;
const filter = document.getElementById('filter');

// Filter visible elements by containing a substring of the filter.
// Use 'display' rather than 'hidden' so that the hidden items collapse.
// Reduce the number of columns so the results are a little easier to read.
filter.addEventListener('input', function(e) {
   var text = e.target.value;
   var numVis = 0;
   for (const row of document.getElementsByClassName('siterow')) {
      var vis = filter.value == "" || row.dataset.tag.includes(text) || row.dataset.host.includes(text);
      if (vis) { numVis += 1; }
      row.style.display = vis ? '' : 'none';
   }
   var cols = Math.floor((numVis + columnHeight - 1) / columnHeight);
   document.getElementById('main').style.columnCount = Math.min(cols, maxColumns);
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
  column-count: 4;
  column-width: auto;
  column-fill: auto;
  font-family: sans-serif;
}
th { text-align: left; }
@media (max-width: 1000px) { body { column-count: 1; } }
td.host { font-size: 80%; }
</style>
</head><body id=main>
<h1>Known sites:</h1>

<p>Filter: <input type=text id=filter size=25 autofocus /></p>
<p><button id=auth>auth</button> <span id=keyflag></span></p>

<table>
<tr>
  <th>Tag</th>
  <th>Host</th>
  <th>Link</th>
</tr>
{{range $tag, $site := .Sites}}<tr class=siterow data-tag="{{$tag}}" data-host="{{trimExt $site.Host}}">
  <td><tt>{{$tag}}</tt></td>
  <td class=host>{{$site.Host}}</td>
  <td><button class=copy type=button value="{{$tag}}">copy</button></td>
</tr>{{end}}
</table>
<script>
{{.Code}}
</script>
</body></html>
`
