package config

import (
	"testing"

	"github.com/creachadair/keyfish/internal/hashpass"
	gocmp "github.com/google/go-cmp/cmp"
)

func pbool(t bool) *bool { return &t }

var testConfig = &Config{
	Sites: map[string]Site{
		"alpha": {Host: "alpha", Punct: pbool(true), Length: 10, Salt: "NaCl"},
		"bravo": {Host: "bravo", Format: "******1", Login: "sam"},
		"tango": {Host: "tangy.com", Length: 45, Salt: "K2Cr2O7"},
		"oscar": {Host: "zesty.org", Length: 11, OTP: map[string]*OTP{"": {Key: []byte("foobar")}}},
		"romeo": {Host: "giant.edu", Alphabet: []string{"digit", "chars:AEIOU"}, Length: 99},
		"sigma": {Host: "far.gone", Key: "glargh"},
	},
	Default: Site{
		Host:  "mos.def",
		Punct: pbool(false),
		Login: "frodo",
	},
}

func init() {
	testConfig.Flags.Copy = true
}

func TestSiteLookup(t *testing.T) {
	tests := []struct {
		name string
		want Site
		ok   bool
	}{
		// A site that isn't found returns the default, with that site name.
		{"nonesuch", Site{Host: "nonesuch", Punct: pbool(false), Login: "frodo"}, false},

		// Defaults fill in the missing fields.
		{"alpha", Site{Host: "alpha", Length: 10, Punct: pbool(true), Login: "frodo", Salt: "NaCl"}, true},

		// A site name with a salt overrides the salt value.
		{"xyz@bravo", Site{
			Host: "bravo", Format: "******1", Login: "sam", Punct: pbool(false), Salt: "xyz",
		}, true},

		// A site that matches by host reports lookup success.
		{"hoy@tangy.com", Site{
			Host: "tangy.com", Punct: pbool(false), Length: 45, Login: "frodo", Salt: "hoy",
		}, true},
	}
	for _, test := range tests {
		got, ok := testConfig.Site(test.name)
		if diff := gocmp.Diff(test.want, got); diff != "" {
			t.Errorf("Site %q differs from expected (-want, +got)\n%s", test.name, diff)
		}
		if ok != test.ok {
			t.Errorf("Site %q in config: got %v, want %v", test.name, ok, test.ok)
		}
	}
}

func TestContext(t *testing.T) {
	pctx := func(a hashpass.Alphabet, site, salt, secret string) hashpass.Context {
		return hashpass.Context{Alphabet: a, Site: site, Salt: salt, Secret: secret}
	}
	tests := []struct {
		site, secret string
		want         hashpass.Context
	}{
		{"nonesuch", "foo", pctx(hashpass.NoPunct, "nonesuch", "", "foo")},
		{"xyz@nonesuch", "bar", pctx(hashpass.NoPunct, "nonesuch", "xyz", "bar")},
		{"alpha", "baz", pctx(hashpass.All, "alpha", "NaCl", "baz")},
		{"xyz@alpha", "frob", pctx(hashpass.All, "alpha", "xyz", "frob")},
		{"bravo", "quux", pctx(hashpass.NoPunct, "bravo", "", "quux")},
		{"romeo", "nut", pctx(hashpass.Digits+"AEIOU", "giant.edu", "", "nut")},
		{"sigma", "boozle", pctx(hashpass.NoPunct, "glargh", "", "boozle")},
	}
	for _, test := range tests {
		site, _ := testConfig.Site(test.site)
		got := site.Context(test.secret)
		if diff := gocmp.Diff(test.want, got); diff != "" {
			t.Errorf("Context %q differs from expected (-want, +got)\n%s", test.secret, diff)
		}
	}
}
