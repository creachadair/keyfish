// Package service implements an HTTP service to answer queries
// for keys from browser extensions and bookmarklets.
package service

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/creachadair/keyfish/clipboard"
	"github.com/creachadair/keyfish/internal/config"
	"github.com/creachadair/otp"
)

// A HostFilter is a slice of CIDR masks defining a set of addresses allowed to
// make requests of the service.
type HostFilter []*net.IPNet

// NewHostFilter constructs a host filter from the specified CIDR strings.
func NewHostFilter(masks []string) (HostFilter, error) {
	m := make(HostFilter, len(masks))
	for i, cidr := range masks {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		m[i] = ipnet
	}
	return m, nil
}

// Contains reports whether any of the masks in the filter covers host, which
// must be an IPv4 or IPv6 address without a port.  If the filter is empty,
// this is true by default.
func (h HostFilter) Contains(host string) bool {
	if len(h) == 0 {
		return true
	}
	ip := net.ParseIP(host)
	for _, m := range h {
		if m.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckAllow reports an error if the host from req.RemoteAddr is invalid or
// does not match any of the masks in h.
func (h HostFilter) CheckAllow(req *http.Request) error {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return errors.New("invalid host address")
	} else if h.Contains(host) {
		return nil
	}
	return errors.New("caller is not allowed")
}

// Config carries the settings for a keyserver. It implments http.Handler.
type Config struct {
	// The path of the keyfish configuration file.
	KeyConfigPath string

	keyConfig *config.Config
	loadedAt  time.Time

	// If set, this function is called with each inbound HTTP request.  If it
	// reports an error, the handler will report http.StatusForbidden.
	// if nil, all requests are accepted.
	CheckAllow func(*http.Request) error
}

func (c *Config) checkAllow(req *http.Request) error {
	if c.CheckAllow == nil {
		return nil
	}
	return c.CheckAllow(req)
}

func (c *Config) loadKeyConfig() (*config.Config, error) {
	if c.KeyConfigPath == "" {
		return nil, errors.New("no file path is set")
	}
	if c.keyConfig == nil || isModifiedSince(c.KeyConfigPath, c.loadedAt) {
		now := time.Now()
		var cfg config.Config
		if err := cfg.Load(c.KeyConfigPath); err != nil {
			return nil, fmt.Errorf("loading: %v", err)
		}
		c.keyConfig = &cfg
		c.loadedAt = now
	}
	return c.keyConfig, nil
}

func isModifiedSince(path string, since time.Time) bool {
	// Conservatively treat a stat error as a modification. The caller will then
	// try to (re)read the file and report any errors that result.
	fi, err := os.Stat(path)
	return err != nil || fi.ModTime().After(since)
}

// ServeHTTP implements http.Handler for the key generator service.
func (c *Config) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if code, err := c.serveInternal(w, req); err != nil {
		if code == 0 {
			code = http.StatusInternalServerError
		}
		w.WriteHeader(code)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		return
	}
}

func (c *Config) serveInternal(w http.ResponseWriter, req *http.Request) (int, error) {
	if err := c.checkAllow(req); err != nil {
		return http.StatusForbidden, fmt.Errorf("request forbidden: %w", err)
	} else if req.Method != "GET" {
		return http.StatusMethodNotAllowed, fmt.Errorf("unsupported method %q", req.Method)
	}
	if req.URL.Path == "/" {
		return c.serveMenu(w)
	}

	kc, err := c.loadKeyConfig()
	if err != nil {
		return 0, err
	}
	if req.URL.Path == "/sites" || req.URL.Path == "/remote" {
		return c.serveSites(w, kc, sourceLabel(req))
	}

	sel, key, err := pathSelector(req.URL.Path)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if err := req.ParseForm(); err != nil {
		return http.StatusBadRequest, err
	}

	kreq := parseRequest(key, req.Form)
	var site config.Site
	var ok bool
	for _, c := range config.SiteCandidates(kreq.base) {
		site, ok = kc.Site(c)
		if ok {
			break
		}
	}
	if !ok && kreq.strict {
		return http.StatusNotFound, fmt.Errorf("unknown site %q", kreq.label())
	}

	var result string
	switch sel {
	case "otp":
		otpc, ok := site.OTP[site.Salt]
		if !ok {
			return http.StatusNotFound, fmt.Errorf("no OTP key for %q", kreq.label())
		}
		result = otp.Config{Key: string(otpc.Key)}.TOTP()

	case "key":
		passphrase, err := getPassphrase(req, site)
		if err != nil {
			return 0, fmt.Errorf("reading passphrase: %w", err)
		}

		ctx := site.Context(passphrase)
		if fmt := site.Format; fmt != "" {
			result = ctx.Format(fmt)
		} else {
			result = ctx.Password(site.Length)
		}

	case "login":
		result = site.Login

	default:
		return http.StatusNotFound, fmt.Errorf("unknown operator %q", sel)
	}

	if kreq.copy {
		clipboard.WriteString(result)
	} else if kreq.insert {
		if err := insertText(result); err != nil {
			return 0, err
		}
	} else {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, result)
	}
	return 0, nil
}

func getPassphrase(req *http.Request, site config.Site) (string, error) {
	key, pass, ok := req.BasicAuth()
	if ok {
		if key == "" || pass != "" {
			return "", errors.New("invalid authorization")
		}
		return key, nil
	}

	// Check whether we should prompt the user locally.
	if pr := parseBool(req.URL.Query().Get("prompt")); pr == nil || !*pr {
		return "", errors.New("missing authorization")
	}

	// Reaching here, we should attempt to prompt the local user.
	prompt := fmt.Sprintf("Passphrase for %q", site.Host)
	pp, err := userText(prompt, "", true)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	return pp, nil
}

func (c *Config) serveMenu(w http.ResponseWriter) (int, error) {
	w.Header().Set("Content-Type", "text/html")
	return 0, menuPage.Execute(w, nil)
}

func (c *Config) serveSites(w http.ResponseWriter, kc *config.Config, label string) (int, error) {
	w.Header().Set("Content-Type", "text/html")
	return 0, sitesList.Execute(w, map[string]interface{}{
		"Sites": kc.Sites,
		"Code":  minifiedCode,
		"Label": label,
	})
}

func pathSelector(s string) (sel, rest string, err error) {
	ps := strings.SplitN(s, "/", 3)
	if len(ps) != 3 || ps[0] != "" {
		return "", "", fmt.Errorf("invalid request path: %q", s)
	} else if ps[1] == "" {
		return "", "", errors.New("invalid operation")
	} else if ps[2] == "" {
		return "", "", errors.New("empty key selector")
	}
	return ps[1], ps[2], nil
}

func parseRequest(key string, form url.Values) *keyRequest {
	kreq := &keyRequest{
		base:   key,
		strict: true,
	}

	// Check for an optional strictness parameter.
	if sp := parseBool(form.Get("strict")); sp != nil {
		kreq.strict = *sp
	}
	if cp := parseBool(form.Get("copy")); cp != nil {
		kreq.copy = *cp
	}
	if ins := parseBool(form.Get("insert")); ins != nil {
		kreq.insert = *ins
	}

	return kreq
}

func parseBool(s string) *bool {
	if s != "" {
		v, err := strconv.ParseBool(s)
		if err == nil {
			return &v
		}
	}
	return nil
}

func sourceLabel(req *http.Request) string {
	switch req.URL.Path {
	case "/sites":
		return "local"
	default:
		return "remote"
	}
}

type keyRequest struct {
	base   string
	strict bool
	copy   bool
	insert bool
}

func (r *keyRequest) label() string {
	ps := strings.SplitN(r.base, "@", 2)
	if len(ps) == 2 {
		return ps[1]
	}
	return ps[0]
}
