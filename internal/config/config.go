// Package config handles keyfish configuration settings. Configurations are
// typically stored as JSON on disk.
package config

import (
	"bytes"
	"embed"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"

	"github.com/creachadair/keyfish/internal/hashpass"
	"github.com/creachadair/otp"
)

//go:generate rm -fr -- static static.go
//go:generate ./embed.sh

// This filesystem contains an embedded config file one exists.
// It is populated by the static.go generated by embed.sh.
// If that file does not exist, no static config is used.
var static embed.FS

// The default configuration is a variable so it can be set by the generated
// static config loader.
var defaultPath = "$HOME/.keyfish"

// A Config represents the contents of a keyfish config file.
type Config struct {
	// A map from site names to site configurations.
	Sites map[string]Site `json:"sites,omitempty"`

	// A default site, overrides empty fields of a named config.
	Default Site `json:"default,omitempty"`

	// Default values for flags.
	Flags struct {
		Copy    bool `json:"copy,omitempty"`
		OTP     bool `json:"otp,omitempty"`
		Strict  bool `json:"strict,omitempty"`
		Verbose bool `json:"verbose,omitempty"`
	} `json:"flags,omitempty"`
}

// A Site represents the non-secret configuration for a single site.
type Site struct {
	// A human-readable title for the site (optional).
	Title string `json:"title,omitempty"`

	// The hostname that identifies this site (required).
	// This can be any non-empty string, but conventionally is the domain name
	// of the site, e.g. "dartmouth.edu".
	Host string `json:"host"`

	// The hash key used to generate passwords for this site.  If empty, the
	// hostname is used.
	Key string `json:"key,omitempty"`

	// If set, this defines the alphabet used for key generation on this site.
	// This overrides the Punct setting. The entries in the slice define which
	// components to include:
	//
	//    "upper"     : uppercase letters (A..Z)
	//    "lower"     : lowercase letters (a..z)
	//    "letter"    : upper + lower
	//    "digit"     : decimal digits (0..9)
	//    "nopunct"   : upper + lower + digit
	//    "punct"     : punctuation (the built-in set)
	//    "all"       : upper + lower + digit + punct
	//    "chars:..." : the literal characters ... (order matters)
	//
	// Order is significant: For example ["digit", "chars:x"] means
	// "0123456789x"; whereas ["chars:x", "digit"] means "x0123456789".
	Alphabet []string `json:"alphabet,omitempty"`

	// If set, this defines the exact layout of the password.
	// See the Format method of hashpass.Context for details.
	Format string `json:"format,omitempty"`

	// If set, generate passwords with this many characters.
	// If zero, uses the default.
	Length int `json:"length,omitempty"`

	// If true, include punctuation in the password alphabet.  This is ignored
	// if Alphabet or Format is set.
	Punct *bool `json:"punct,omitempty"`

	// Use this string as a salt for password generation.  This can be used to
	// rotate passwords.
	Salt string `json:"salt,omitempty"`

	// The fields below are not used for password generation.

	// The login name to use for this site.
	Login string `json:"login,omitempty"`

	// The e-mail address associated with this login.
	EMail string `json:"email,omitempty"`

	// OTP configurations for this site. The map key is the salt value for which
	// each configuration applies. Use "" as the key for an unsalted host.
	OTP map[string]*OTP `json:"otp,omitempty"`

	// Alternative hostnames that should be considered aliases for this site.
	// This is useful for sites that use a different domain for authentication.
	// Aliases are only examined if there is no primary host match.
	Aliases []string `json:"aliases,omitempty"`

	// User-defined password hints, security questions, and other metadata that
	// do not affect the password but the user may need to log in.
	Hints map[string]interface{} `json:"hints,omitempty"`

	// Indicates the site entry is archived and should not be listed.
	Archived bool `json:"archived,omitempty"`
}

// An OTP represents the settings for an OTP generator.
type OTP struct {
	Key    OTPKey `json:"key"`
	Digits int    `json:"digits,omitempty"`
}

// OTPKey is the JSON encoding of an OTP secret.
type OTPKey []byte

// UnmarshalJSON decodes an OTPKey from a base32 string.
func (o *OTPKey) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	key, err := otp.ParseKey(s)
	if err != nil {
		return err
	}
	*o = key
	return nil
}

// MarshalJSON encodes an OTPKey to a base32 string.
func (o OTPKey) MarshalJSON() ([]byte, error) {
	key := strings.TrimRight(base32.StdEncoding.EncodeToString(o), "=")
	return json.Marshal(key)
}

// FilePath returns the effective configuration file path. If KEYFISH_CONFIG is
// defined in the environment, that is used; otherwise the compiled-in default
// is used.
func FilePath() string {
	if path, ok := os.LookupEnv("KEYFISH_CONFIG"); ok {
		return path
	}
	return os.ExpandEnv(defaultPath) // from static.go
}

// Load loads the contents of the specified path into c.  If path does not
// exist, the reported error satisfies os.IsNotExist and c is unmodified.
func (c *Config) Load(path string) error {
	data, err := static.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		data, err = os.ReadFile(path)
	}
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
		var cands []Site

		// If we didn't find one, see if there is a named config that has this as
		// its host name or an alias.
		for _, cfg := range c.Sites {
			if cfg.Host == host {
				site = cfg
				ok = true
				break
			}

			// Check for an alias match, but don't return immediately in case
			// there is a host match on a later entry. We prefer a direct host
			// match to an alias match.
			for _, alias := range cfg.Aliases {
				if alias == host {
					cands = append(cands, cfg)
				}
			}
		}

		// If we did not find any host matches, fall back on an alias.
		if !ok && len(cands) != 0 {
			site = cands[0]
			ok = true
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
func (s Site) Context(secret string) hashpass.Context {
	siteKey := s.Key
	if siteKey == "" {
		siteKey = s.Host
	}
	return hashpass.Context{
		Alphabet: s.alphabet(),
		Site:     siteKey,
		Salt:     s.Salt,
		Secret:   secret,
	}
}

func (s Site) alphabet() hashpass.Alphabet {
	if len(s.Alphabet) != 0 {
		var a hashpass.Alphabet

		for _, elt := range s.Alphabet {
			switch elt {
			case "upper":
				a += hashpass.Uppercase
			case "lower":
				a += hashpass.Lowercase
			case "letter":
				a += hashpass.Letters
			case "digit":
				a += hashpass.Digits
			case "nopunct":
				a += hashpass.NoPunct
			case "punct":
				a += hashpass.Puncts
			case "all":
				a += hashpass.All
			default:
				trim := strings.TrimPrefix(elt, "chars:")
				if trim != elt {
					a += hashpass.Alphabet(trim)
				} else {
					log.Printf("Warning: Unknown alphabet spec %q (ignored)", elt)
				}
			}
		}
		return a
	} else if s.usePunct() {
		return hashpass.All
	}
	return hashpass.NoPunct
}

// merge returns a copy of s in which non-empty fields of c are used to fill
// empty fields of s.
func (s Site) merge(c Site) Site {
	if s.Host == "" {
		s.Host = c.Host
	}
	if len(s.Alphabet) == 0 {
		s.Alphabet = c.Alphabet
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

// SiteCandidates returns a slice of candidate site names from base.  If base
// is structured like a host name, the candidates are the suffixes of the
// hostname having length at least 2. For example, given "x.y.z" the candidates
// are "x.y.z" and "x.y".  A salt prefix (salt@x.y) is preserved on each
// candidate, so "s@x.y.z" yields "s@x.y.z" and "s@y.z" as candidates.
//
// If base does not look like a hostname, the slice contains it alone.
func SiteCandidates(base string) []string {
	if !strings.Contains(base, ".") {
		return []string{base}
	}

	salt, label := "", base
	if ps := strings.SplitN(base, "@", 2); len(ps) == 2 {
		salt, label = ps[0]+"@", ps[1]
	}

	var cands []string
	ps := strings.Split(label, ".")
	for i := 0; i+2 <= len(ps); i++ {
		cands = append(cands, salt+strings.Join(ps[i:], "."))
	}
	return cands
}
