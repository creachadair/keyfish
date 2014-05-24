//
// Name:     utils.js
// Purpose:  Utility functions.
// Author:   M. J. Fromberger <michael.j.fromberger@gmail.com>
//

// Trim the leading path component from a hostname if it has more than two,
// e.g., "foo.bar.com" ==> "bar.com", "baz.org" ==> "baz.org".
function trimHostName(host) {
    var parts = host.split(".")
    if (parts.length > 2) {
	return parts.slice(1).join('.')
    }
    return host
}

// Parse a URI into an object containing fields for each of the structural
// components, without regard to scheme.
function parseURI(url) {
    var m = url.match('^(\\w+:)?' +
		      '(?://([^/?#]+))?' +
		      '([^?#]+)?' +
		      '(\\?[^#]*)?' +
		      '(#.*)?')
    if (!m) return null
    var parsed = {
	url:       m[0],
	scheme:    m[1] || "",
	authority: m[2] || "",
	path:      m[3] || "",
	query:     m[4] || "",
	fragment:  m[5] || "",
    }
    m = parsed.authority.match('(?:([^:]+)(?::(.+))?@)?' +
			       '(([^:]+)(?::(.+))?)')

    if (m) {
	parsed.user     = m[1] || ""
	parsed.pass     = m[2] || ""
	parsed.host     = m[3] || ""
	parsed.hostname = m[4] || ""
	parsed.port     = m[5] || ""
    }
    return parsed
}

// Obscures most of a password so that an observer can see only a few
// characters of it.  This permits the user to verify that it is the expected
// value, without giving the whole thing to a shoulder surfer.
function obscurePassword(pw) {
    var out = "";
    for (var i = 0; i < pw.length; i++) {
	if (i < 2 || i == pw.length - 1) {
	    out += pw[i];
	} else {
	    out += "*";
	}
    }
    return out
}
