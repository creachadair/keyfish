package service

import "html/template"

const sitesListText = `<html>
<head><title>Known Sites</title>
<style type="text/css">
body {
  column-count: 4;
  column-width: auto;
  column-fill: auto;
  font-family: sans-serif;
}
@media (max-width: 1000px) { body { column-count: 1; } }
td.host { font-size: 80%; }
</style>
</head><body id=main>
<h1>Known sites:</h1>

<p>Filter: <input type=text id=filter size=25 autofocus /></p>
<table>
<tr>
  <th>Tag</th>
  <th>Host</th>
  <th>Link</th>
</tr>
{{range $tag, $site := .Sites}}<tr class=siterow data-tag="{{$tag}}">
  <td><tt>{{$tag}}</tt></td>
  <td class=host>{{$site.Host}}</td>
  <td><button class=copy type=button value="{{$tag}}">copy</button></td>
</tr>{{end}}
</table>
<script>
void((()=>{
{{/* Issue an HTTP GET request to the key server for the given tag. */-}}
function copyKey(tag) {
  return function() {
    var req = new XMLHttpRequest();
    req.open('GET', '/key/'+tag+'?copy=1', true);
    req.send();
  }
}

{{/* Attach event listeners to all the buttons. */-}}
for (const btn of document.getElementsByTagName('button')) {
  btn.addEventListener('click', copyKey(btn.value));
}

const maxColumns = 4;
const columnHeight = 30;
const filter = document.getElementById('filter');

{{/* Filter visible elements by containing a substring of the filter.
     Use 'display' rather than 'hidden' so that the hidden items collapse.
     Reduce the number of columns so the results are a little easier to read. */-}}
filter.addEventListener('input', function(e) {
   var text = e.target.value;
   var numVis = 0;
   for (const row of document.getElementsByClassName('siterow')) {
      var vis = filter.value == "" || row.dataset.tag.includes(text);
      if (vis) { numVis += 1; }
      row.style.display = vis ? '' : 'none';
   }
   var cols = Math.floor((numVis + columnHeight - 1) / columnHeight);
   document.getElementById('main').style.columnCount = Math.min(cols, maxColumns);
})
})())
</script>
</body></html>
`

var sitesList = template.Must(template.New("sites").Parse(sitesListText))
