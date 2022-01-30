package service

import "html/template"

const sitesListText = `<html>
<head><title>Known Sites</title></head><body>
<style type="text/css">
body {
  column-count: 4;
  column-width: auto;
  font-family: sans-serif;
}
@media (max-width: 1000px) { body { column-count: 1; } }
td.host { font-size: 80%; }
</style>
<h1>Known sites:</h1>

<table>
<tr>
  <th>Tag</th>
  <th>Host</th>
  <th>Link</th>
</tr>
{{range $tag, $site := .Sites}}<tr>
  <td><tt>{{$tag}}</tt></td>
  <td class=host>{{$site.Host}}</td>
  <td><button class=copy type=button value="{{$tag}}">copy</button></td>
</tr>{{end}}
</table>
<script>
void((()=>{
function copyKey(tag) {
  return function() {
    var req = new XMLHttpRequest();
    req.open('GET', '/key/'+tag+'?copy=1', true);
    req.send();
  }
}
for (const btn of document.getElementsByTagName('button')) {
  btn.addEventListener('click', copyKey(btn.value));
}
})())
</script>
</body></html>
`

var sitesList = template.Must(template.New("sites").Parse(sitesListText))
