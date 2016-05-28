// The keyfish tool implements the KeyFish site-specific password generation
// algorithm.
//
// Basic usage:
//    keyfish some.site.com
//
// The tool will prompt at the terminal for a password, and will print the
// resulting password to stdout.  Use the -copy option to instead copy the
// password to the clipboard (this option currently only works in MacOS).
//
// Passwords are constructed by computing a HMAC/SHA256 of the site name and a
// salt string ("" by default, set using -salt), with the password as the key.
// The resulting digest is mapped to a password of up to 32 bytes by mapping
// the digest bytes to printable ASCII characters.
//
// Passwords may contain ASCII letters, digits, and punctuation; by default,
// letters and digits are used, but no punctuation.  Use -punct to enable
// punctuation and -format to override the password format explicitly.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"

	"bitbucket.org/creachadair/keyfish/alphabet"
	"bitbucket.org/creachadair/keyfish/password"
	"github.com/stackengine/gopass"
)

const (
	minLength = 6
	maxLength = password.MaxLength
)

var (
	base      = siteConfig{Length: 18, Punct: new(bool)}
	secretKey string
	doCopy    bool
	verbose   bool
)

func init() {
	flag.IntVar(&base.Length, "length", 18, "Password length")
	flag.BoolVar(base.Punct, "punct", false, "Use punctuation")
	flag.StringVar(&base.Format, "format", "", "Password format")
	flag.StringVar(&base.Salt, "salt", "", "Salt to hash with the site name")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")

	flag.StringVar(&secretKey, "secret", os.Getenv("KEYFISH_SECRET"), "Secret key")

	// Only enable the -copy flag if it's supported by the system.
	// Right now, that means MacOS.
	if runtime.GOOS == "darwin" {
		flag.BoolVar(&doCopy, "copy", false, "Copy to clipboard instead of printing")
	}

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: keyfish [options] <site.name>+

Generates a site-specific password based on the given site name.  The resulting
password is printed to stdout, or copied to the clipboard if --copy is set.

If --secret is set, it is used as the master key to generate passwords.  If
not, the value of the KEYFISH_SECRET environment variable is used if it is
defined.  Otherwise, the user is prompted at the terminal.

Use --format to specify an exact password layout, with "A" for an uppercase
letter, "a" for a lowercase letter, "1" for a digit, "*" for a letter of either
case, "?" for a punctuation mark.  All other non-letters are copied verbatim.
All letters are wildcards for a letter of the appropriate case, all digits are
wildcards for a digit.

Flags:`)
		flag.PrintDefaults()
	}
}

// Attempts to copy the given password to the system clipboard.
func toClipboard(pw string) error {
	cmd := exec.Command("pbcopy")
	p, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	fmt.Fprint(p, pw)

	// We must close the pipe, so the process can exit.
	if err := p.Close(); err != nil {
		log.Printf("Error closing pipe: %v", err)
	}
	return cmd.Wait()
}

type siteConfig struct {
	Host   string `json:"host,omitempty"`
	Format string `json:"format,omitempty"`
	Length int    `json:"length,omitempty"`
	Punct  *bool  `json:"punct,omitempty"`
	Salt   string `json:"salt,omitempty"`
}

func (s *siteConfig) context(secret string) password.Context {
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

func (s *siteConfig) merge(c siteConfig) siteConfig {
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
	return *s
}

func (s siteConfig) String() string {
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

func loadConfig() (map[string]siteConfig, error) {
	path := os.ExpandEnv("$HOME/.keyfish")
	bits, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	conf := make(map[string]siteConfig)
	if err := json.Unmarshal(bits, &conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// usage prints a usage message to stderr and terminates the program.
func fail(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		fail("You must specify at least one site name")
	}
	configs, err := loadConfig()
	if err != nil {
		fail("Error loading configuration: %v", err)
	}
	if secretKey == "" {
		pw, err := gopass.GetPass("Secret key: ")
		if err != nil {
			fail("Error reading secret key: %v", err)
		}
		secretKey = pw
	}

	for _, arg := range flag.Args() {
		config := base
		if c, ok := configs[arg]; ok {
			config = c.merge(base)
		} else {
			config.Host = arg
		}
		if n := config.Length; n < minLength || n > maxLength {
			fail("Password length must be ≥ %d and ≤ %d", minLength, maxLength)
		}
		if verbose {
			log.Printf("Config: %v", config)
		}

		ctx := config.context(secretKey)
		var pw string
		if fmt := config.Format; fmt != "" {
			pw = ctx.Format(config.Host, fmt)
		} else {
			pw = ctx.Password(config.Host)[:config.Length]
		}
		if !doCopy {
			fmt.Println(pw)
		} else if err := toClipboard(pw); err != nil {
			log.Printf("Error copying to clipboard: %v", err)
		}
	}
}
