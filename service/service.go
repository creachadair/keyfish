// Package service implements an HTTP service to answer queries
// for keys from browser extensions and bookmarklets.
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/creachadair/keyfish/clipboard"
	"github.com/creachadair/keyfish/config"
	"github.com/creachadair/keyfish/wordhash"
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

// printErrorf reports the given HTTP status with a formatted text message in
// the body. A newline is appended if the format does not already contain one.
func (c *Config) printfError(w http.ResponseWriter, status int, msg string, args ...interface{}) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprintf(w, msg, args...)
}

// unmarshalBody fully reads and closes the body of req, and decodes it as JSON
// into v. The body is fully read even if decoding fails.
func (c *Config) unmarshalBody(req *http.Request, v interface{}) error {
	data, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// marshalBody marshals v as JSON into the response body of w.  In case of
// error, it generates an internal server error (500).
func (c *Config) marshalBody(w http.ResponseWriter, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		c.printfError(w, http.StatusInternalServerError, "encoding output: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
	w.Write([]byte("\n"))
}

// ServeHTTP implements http.Handler for the key generator service.
func (c *Config) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if err := c.checkAllow(req); err != nil {
		c.printfError(w, http.StatusForbidden, "Request fobidden: %v", err)
		return
	}
	switch req.URL.Path {
	case "/key":
		c.HandleKey(w, req)
	default:
		c.printfError(w, http.StatusNotFound, "Endpoint not found: %q", req.URL.Path)
	}
}

// HandleKey handles a key-generation request.
func (c *Config) HandleKey(w http.ResponseWriter, req *http.Request) {
	var kreq KeyRequest
	switch req.Method {
	case "GET":
		if err := req.ParseForm(); err != nil {
			c.printfError(w, http.StatusBadRequest, "Invalid request parameters: %v", err)
			return
		}
		kreq = KeyRequest{
			URL:  req.Form.Get("url"),
			Salt: req.Form.Get("salt"),
		}
		if v, err := strconv.ParseBool(req.Form.Get("punct")); err == nil {
			kreq.Punct = v
		}
		if v, err := strconv.ParseBool(req.Form.Get("strict")); err == nil {
			kreq.Strict = v
		}
	case "POST":
		if err := c.unmarshalBody(req, &kreq); err != nil {
			c.printfError(w, http.StatusBadRequest, "Invalid request body: %v", err)
			return
		}
	default:
		c.printfError(w, http.StatusMethodNotAllowed, "Unsupported method: %q", req.Method)
		return
	}

	host := kreq.URL
	if u, err := url.Parse(host); err == nil {
		if u.Host != "" {
			host = u.Host
			if ps := strings.Split(host, "."); len(ps) > 2 {
				host = strings.Join(ps[1:], ".")
			}
		} else if u.Path != "" {
			host = u.Path
		}
	}
	if host == "" {
		c.marshalBody(w, &Response{Error: "no hostname specified"})
		return
	}
	kc, err := c.loadKeyConfig()
	if err != nil {
		c.printfError(w, http.StatusInternalServerError, "Key configuration: %v", err)
		return
	}
	site, ok := kc.Site(host)
	if kreq.Strict && !ok {
		c.marshalBody(w, &Response{Error: fmt.Sprintf("unknown site %q", host)})
		return
	}
	if kreq.Salt != "" {
		site.Salt = kreq.Salt
	}

	prompt := fmt.Sprintf("Passphrase for %q", site.Host)
	passphrase, err := userText(prompt, "", true)
	if err != nil {
		c.marshalBody(w, &Response{Error: fmt.Sprintf("reading passphrase: %v", err)})
		return
	}
	ctx := site.Context(passphrase)
	var pw string
	if fmt := site.Format; fmt != "" {
		pw = ctx.Format(site.Host, fmt)
	} else {
		pw = ctx.Password(site.Host, site.Length)
	}
	var auth string
	if site.OTP != nil {
		auth = otp.Config{
			Key: string(site.OTP.Key),
		}.TOTP()
		clipboard.WriteString(auth)
	}
	c.marshalBody(w, &Response{
		Result: KeyResponse{
			Key:  pw,
			OTP:  auth,
			Hash: wordhash.String(pw),
		},
	})
}

// KeyRequest describes a key generation request.
type KeyRequest struct {
	URL    string `json:"url"`
	Salt   string `json:"salt"`
	Punct  bool   `json:"punct"`
	Strict bool   `json:"strict"`
}

// KeyResponse describes the content of a successful key generation response.
type KeyResponse struct {
	Key  string `json:"key,omitempty"`
	Hash string `json:"hash,omitempty"`
	OTP  string `json:"otp,omitempty"`
}

// Response is the top-level response wrapper.
type Response struct {
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}
