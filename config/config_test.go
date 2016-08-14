package config

import (
	"testing"

	"bitbucket.org/creachadair/keyfish/alphabet"
	"bitbucket.org/creachadair/keyfish/password"

	"github.com/kylelemons/godebug/pretty"
)

var testConfig = &Config{
	Sites: map[string]Site{
		"alpha": {Host: "alpha", Punct: true, Length: 10, Salt: "NaCl"},
		"bravo": {Host: "bravo", Format: "******1", Login: "sam"},
	},
	Default: Site{
		Host:  "mos.def",
		Punct: false,
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
	}{
		// A site that isn't found returns the default, with that site name.
		{"nonesuch", Site{Host: "nonesuch", Login: "frodo"}},

		// Defaults fill in the missing fields.
		{"alpha", Site{Host: "alpha", Length: 10, Punct: true, Login: "frodo", Salt: "NaCl"}},

		// A site name with a salt overrides the salt value.
		{"xyz@bravo", Site{Host: "bravo", Format: "******1", Login: "sam", Salt: "xyz"}},
	}
	for _, test := range tests {
		got := testConfig.Site(test.name)
		if diff := pretty.Compare(got, test.want); diff != "" {
			t.Errorf("Site %q differs from expected (-got, +want)\n%s", test.name, diff)
		}
	}
}

func TestContext(t *testing.T) {
	tests := []struct {
		site, secret string
		want         password.Context
	}{
		{"nonesuch", "foo", password.Context{alphabet.NoPunct, "", "foo"}},
		{"xyz@nonesuch", "bar", password.Context{alphabet.NoPunct, "xyz", "bar"}},
		{"alpha", "baz", password.Context{alphabet.All, "NaCl", "baz"}},
		{"xyz@alpha", "frob", password.Context{alphabet.All, "xyz", "frob"}},
		{"bravo", "quux", password.Context{alphabet.NoPunct, "", "quux"}},
	}
	for _, test := range tests {
		site := testConfig.Site(test.site)
		got := site.Context(test.secret)
		if diff := pretty.Compare(got, test.want); diff != "" {
			t.Errorf("Context %q differs from expected (-got, +want)\n%s", test.secret, diff)
		}
	}
}
