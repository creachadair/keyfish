// Package config handles keyfish configuration settings. Configurations are
// typically stored as JSON on disk.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
}

// A Site represents the non-secret configuration for a single site.
type Site struct {
	Host   string            `json:"host,omitempty"`
	Format string            `json:"format,omitempty"`
	Length int               `json:"length,omitempty"`
	Punct  *bool             `json:"punct,omitempty"`
	Salt   string            `json:"salt,omitempty"`
	Login  string            `json:"login,omitempty"`
	EMail  string            `json:"email,omitempty"`
	Hints  map[string]string `json:"hints,omitempty"`
}

// Load loads the contents of the specified path into c.  If path does not
// exist, the reported error satisfies os.IsNotExist and c is unmodified.
func (c *Config) Load(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, c)
}

// Site returns a site configuration for the given name, which has the form
// host.name or salt@host.name, and reports whether the config arose from a
// matching entry in the config. If a matching entry was found, the
// corresponding Site is returned; otherwise a default Site is built using the
// name to derive the host (and possibly the salt).
func (c *Config) Site(name string) (Site, bool) {
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
	return site.merge(c.Default), ok
}

// Context returns a password generation context from s.
func (s Site) Context(secret string) password.Context {
	a := alphabet.NoPunct
	if s.usePunct() {
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
func (s Site) merge(c Site) Site {
	if s.Host == "" {
		s.Host = c.Host
	}
	if s.Format == "" {
		s.Format = c.Format
	}
	if s.Length <= 0 {
		s.Length = c.Length
	}
	if s.Punct == nil && c.Punct != nil {
		s.Punct = c.Punct
	}
	if s.Salt == "" {
		s.Salt = c.Salt
	}
	if s.Login == "" {
		s.Login = c.Login
	}
	if s.EMail == "" {
		s.EMail = c.EMail
	}
	if strings.HasPrefix(s.EMail, "+") {
		s.EMail = insertAddressTag(c.EMail, s.EMail)
	} else if strings.HasPrefix(s.EMail, "@") && s.Login != "" {
		s.EMail = s.Login + s.EMail
	}
	if s.Login == "$EMAIL" {
		s.Login = s.EMail
	}
	return s
}

func (s Site) usePunct() bool { return s.Punct != nil && *s.Punct }

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
