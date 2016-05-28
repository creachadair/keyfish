package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"bitbucket.org/creachadair/keyfish/alphabet"
	"bitbucket.org/creachadair/keyfish/password"
)

// A Config represents the contents of a keyfish config file.
type Config struct {
	Sites   map[string]*Site `json:"sites,omitempty"`
	Default *Site            `json:"default,omitempty"`
	Flags   struct {
		Copy    bool `json:"copy,omitempty"`
		Verbose bool `json:"verbose,omitempty"`
	} `json:"flags,omitempty"`
}

// A Site represents the non-secret configuration for a single site.
type Site struct {
	Host   string `json:"host,omitempty"`
	Format string `json:"format,omitempty"`
	Length int    `json:"length,omitempty"`
	Punct  *bool  `json:"punct,omitempty"`
	Salt   string `json:"salt,omitempty"`
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

// context returns a password generation context from s.
func (s *Site) context(secret string) password.Context {
	a := alphabet.NoPunct
	if p := s.Punct; p != nil && *p {
		a = alphabet.All
	}
	return password.Context{
		Alphabet: a,
		Salt:     s.Salt,
		Secret:   secret,
	}
}

// merge copies non-empty fields from c to fill empty fields of s.
// Modifies *s in place.
func (s *Site) merge(c *Site) {
	if c == nil {
		return
	}
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
		s.Punct = new(bool)
		*s.Punct = *c.Punct
	}
	if s.Salt == "" {
		s.Salt = c.Salt
	}
}

func (s *Site) String() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "host=%q", s.Host)
	if s.Format == "" {
		fmt.Fprintf(&buf, ", n=%d", s.Length)
	} else {
		fmt.Fprintf(&buf, ", fmt=%q", s.Format)
	}
	if s.Punct != nil {
		fmt.Fprintf(&buf, ", punct=%v", *s.Punct)
	}
	fmt.Fprintf(&buf, ", salt=%q", s.Salt)
	return buf.String()
}
