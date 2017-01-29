// Package config handles keyfish configuration settings. Configurations are
// typically stored as JSON on disk.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"bitbucket.org/creachadair/keyfish/alphabet"
	"bitbucket.org/creachadair/keyfish/password"
)

// A Config represents the contents of a keyfish config file.
type Config struct {
	// A map from site names to site configurations.
	Sites map[string]Site `json:"sites,omitempty"`

	// A default site, overrides empty fields of a named config.
	Default Site `json:"default,omitempty"`

	// Default values for flags.
	Flags struct {
		Copy    bool `json:"copy,omitempty"`
		Verbose bool `json:"verbose,omitempty"`
	} `json:"flags,omitempty"`

	// Named user configuration settings, which override missing fields of a
	// site config if a user is named.
	Users map[string]User `json:"users,omitempty"`
}

// A User represents a collection of shared login information.
type User struct {
	Login string `json:"login,omitempty"`
	EMail string `json:"email,omitempty"`
	Salt  string `json:"salt,omitempty"`
}

// A Site represents the non-secret configuration for a single site.
type Site struct {
	Host   string            `json:"host,omitempty"`
	Format string            `json:"format,omitempty"`
	Length int               `json:"length,omitempty"`
	Punct  bool              `json:"punct,omitempty"`
	Salt   string            `json:"salt,omitempty"`
	Login  string            `json:"login,omitempty"`
	EMail  string            `json:"email,omitempty"`
	User   string            `json:"user,omitempty"`
	Hints  map[string]string `json:"hints,omitempty"`
}

// Load loads the contents of the specified path into c.  If path does not
// exist, this is a no-op without error.
func (c *Config) Load(path string) error {
	data, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return json.Unmarshal(data, c)
}

// Site returns a site configuration for the given name, which has the form
// host.name or salt@host.name. If a matching entry is found in the config, the
// corresponding Site is returned; otherwise a default Site is build using the
// name to derive the host (and possibly the salt).
func (c *Config) Site(name string) Site {
	host, salt := name, ""
	if i := strings.Index(name, "@"); i >= 0 {
		host = name[i+1:]
		salt = name[:i]
	}

	// Try to find a named configuration for the host.
	site, ok := c.Sites[host]
	if !ok {
		// If we didn't find one, see if there is a named config that has this as
		// its host name.
		for _, cfg := range c.Sites {
			if cfg.Host == host {
				site = cfg
				break
			}
		}
	}
	if site.Host == "" {
		site.Host = host
	}
	if salt != "" {
		site.Salt = salt // override the salt with the user's spec.
	}
	return site.merge(c.Default, c.Users[site.User])
}

// Context returns a password generation context from s.
func (s Site) Context(secret string) password.Context {
	a := alphabet.NoPunct
	if s.Punct {
		a = alphabet.All
	}
	return password.Context{
		Alphabet: a,
		Salt:     s.Salt,
		Secret:   secret,
	}
}

// merge returns a copy of s in which non-empty fields of c are used to fill
// empty fields of s.
func (s Site) merge(c Site, u User) Site {
	s.User = ""
	if s.Host == "" {
		s.Host = c.Host
	}
	if s.Format == "" {
		s.Format = c.Format
	}
	if s.Length <= 0 {
		s.Length = c.Length
	}
	if !s.Punct && c.Punct {
		s.Punct = c.Punct
	}
	if s.Salt == "" {
		if u.Salt != "" {
			s.Salt = u.Salt
		} else {
			s.Salt = c.Salt
		}
	}
	if s.Login == "" {
		if u.Login != "" {
			s.Login = u.Login
		} else {
			s.Login = c.Login
		}
	}
	if s.EMail == "" {
		if u.EMail != "" {
			s.EMail = u.EMail
		} else {
			s.EMail = c.EMail
		}
	}
	if strings.HasPrefix(s.EMail, "+") {
		s.EMail = insertAddressTag(c.EMail, s.EMail)
	} else if strings.HasPrefix(s.EMail, "@") && s.Login != "" {
		s.EMail = s.Login + s.EMail
	}
	return s
}

// insertAddressTag inserts tag into a base e-mail address. If base has the
// form "name@addr", the result has the form "name<tag>@addr"; otherwise the
// function returns base + tag.
func insertAddressTag(base, tag string) string {
	if i := strings.Index(base, "@"); i >= 0 {
		return base[:i] + tag + base[i:]
	}
	return base + tag
}

func (s Site) String() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "host=%q", s.Host)
	if s.Format == "" {
		fmt.Fprintf(&buf, ", n=%d", s.Length)
	} else {
		fmt.Fprintf(&buf, ", fmt=%q", s.Format)
	}
	fmt.Fprintf(&buf, ", punct=%v, salt=%q", s.Punct, s.Salt)
	return buf.String()
}
