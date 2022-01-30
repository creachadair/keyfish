package service

import "html/template"

const sitesListText = `<html>
<head><title>Known Sites</title></head><body>

<h1>Known sites:</h1>

<table>
<tr>
  <th>Tag</th>
  <th>Host</th>
  <th>Link</th>
</tr>
{{range $tag, $site := .Sites}}<tr>
  <td>{{$tag}}</td>
  <td><tt>{{$site.Host}}</tt></td>
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
