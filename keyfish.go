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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"text/tabwriter"

	"bitbucket.org/creachadair/keyfish/config"
	"bitbucket.org/creachadair/keyfish/password"
	"bitbucket.org/creachadair/stringset"
	"github.com/stackengine/gopass"
)

const (
	minLength = 6
	maxLength = password.MaxLength
)

var (
	cfg       = &config.Config{Default: config.Site{Length: 18}}
	secretKey string
	doSites   bool
	doPrint   bool
)

func init() {
	flag.IntVar(&cfg.Default.Length, "length", 18, "Password length")
	flag.BoolVar(&cfg.Default.Punct, "punct", false, "Use punctuation")
	flag.StringVar(&cfg.Default.Format, "format", "", "Password format")
	flag.StringVar(&cfg.Default.Salt, "salt", "", "Salt to hash with the site name")
	flag.BoolVar(&doSites, "list", false, "List known sites and exit")
	flag.BoolVar(&doPrint, "print", false, "Print specified configurations and exit")
	flag.BoolVar(&cfg.Flags.Verbose, "v", false, "Verbose logging (includes hints with -print)")

	flag.StringVar(&secretKey, "secret", os.Getenv("KEYFISH_SECRET"), "Secret key")

	// Only enable the -copy flag if it's supported by the system.
	// Right now, that means MacOS.
	if runtime.GOOS == "darwin" {
		flag.BoolVar(&cfg.Flags.Copy, "copy", false, "Copy to clipboard instead of printing")
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

A site name has the form "host.org" or "salt@host.org". If the site matches one
of the sites named in the user's ~/.keyfish file, the corresponding settings
are used.

Flags:`)
		flag.PrintDefaults()
	}
}

// toClipboard attempts to copy the given password to the system clipboard.
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

func vcode(pw string) string {
	var vc uint16
	for _, b := range []byte(pw) {
		vc = ((vc << 3) | (vc >> 13)) + uint16(b)
	}
	return fmt.Sprintf("%04x", vc)
}

// usage prints a usage message to stderr and terminates the program.
func fail(msg string, args ...interface{}) { log.Fatalf(msg, args...) }

// listSites renders a nicely-formatted listing of sites to w.
func listSites(w io.Writer, sites stringset.Set) {
	fmt.Fprintln(w, "▷ Known sites:")
	const padding = 2
	const fieldWidth = 12 + padding
	const lineWidth = 80
	tw := tabwriter.NewWriter(w, fieldWidth, 0, padding, ' ', tabwriter.TabIndent)
	nc := 0
	for _, site := range sites.Elements() {
		fmt.Fprint(tw, site)
		nc += fieldWidth
		if nc > lineWidth {
			fmt.Fprintln(tw)
			nc = 0
		} else {
			fmt.Fprint(tw, "\t")
		}
	}
	if nc != 0 {
		fmt.Fprintln(tw)
	}
	tw.Flush()
}

func main() {
	// Load configuration settings from the user's file, if it exists.
	// Do this prior to flag parsing so that flags can override defaults.
	if err := cfg.Load(os.ExpandEnv("$HOME/.keyfish")); err != nil {
		fail("Error loading configuration: %v", err)
	}

	flag.Parse()

	// Unless we're listing sites, at least one must be requested.
	if doSites {
		listSites(os.Stdout, stringset.FromKeys(cfg.Sites))
		return
	} else if flag.NArg() == 0 {
		fail("You must specify at least one site name")
	}
	if doPrint {
		out := json.NewEncoder(os.Stdout)
		for _, arg := range flag.Args() {
			site := cfg.Site(arg)
			if !cfg.Flags.Verbose {
				site.Hints = nil
			}
			if err := out.Encode(site); err != nil {
				fail("Error encoding site %q: %v", arg, err)
			}
		}
		return
	}

	// Establish the secret key.
	if secretKey == "" {
		pw, err := gopass.GetPass("Secret key: ")
		if err != nil {
			fail("Error reading secret key: %v", err)
		}
		secretKey = pw
	}

	for _, arg := range flag.Args() {
		site := cfg.Site(arg)
		if n := site.Length; n < minLength || n > maxLength {
			fail("Password length must be ≥ %d and ≤ %d", minLength, maxLength)
		}
		if cfg.Flags.Verbose {
			log.Printf("Site: %v", site)
		}

		ctx := site.Context(secretKey)
		var pw string
		if fmt := site.Format; fmt != "" {
			pw = ctx.Format(site.Host, fmt)
		} else {
			pw = ctx.Password(site.Host)[:site.Length]
		}
		if !cfg.Flags.Copy {
			fmt.Println(pw)
		} else if err := toClipboard(pw); err != nil {
			log.Printf("Error copying to clipboard: %v", err)
		} else {
			if u := site.Login; u != "" {
				fmt.Print(u, "@")
			}
			fmt.Print(site.Host, "\t", vcode(pw), "\n")
		}
	}
}