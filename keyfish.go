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
// The resulting digest is converted to a password by mapping the digest bytes
// to printable ASCII characters.
//
// Passwords may contain letters, digits, and punctuation; by default, letters
// and digits are used, but no punctuation.  Use -punct to enable punctuation
// and -format to override the password format explicitly.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"bitbucket.org/creachadair/shell"
	"bitbucket.org/creachadair/stringset"
	"github.com/creachadair/getpass"
	"github.com/creachadair/keyfish/config"
	"github.com/creachadair/keyfish/wordhash"
	"github.com/creachadair/otp"
)

const minLength = 6 // Allow no passwords shorter than this

var (
	cfg       = &config.Config{Default: config.Site{Length: 18, Punct: new(bool)}}
	secretKey = os.Getenv("KEYFISH_SECRET")
	doOTP     bool // generate an OTP along with the passphrase
	doSites   bool // list known site configuations
	doShow    bool // show the named configurations
	doPrint   bool // print the result, overriding -copy
)

func init() {
	flag.IntVar(&cfg.Default.Length, "length", 18, "Password length")
	flag.BoolVar(cfg.Default.Punct, "punct", false, "Use punctuation")
	flag.StringVar(&cfg.Default.Format, "format", "", "Password format")
	flag.StringVar(&cfg.Default.Salt, "salt", "", "Salt to hash with the site name")
	flag.BoolVar(&doOTP, "otp", false, "Generate an OTP for the site (if configured)")
	flag.BoolVar(&doSites, "list", false, "List known sites and exit")
	flag.BoolVar(&doShow, "show", false, "Print specified configurations and exit")
	flag.BoolVar(&doPrint, "print", false, "Print the result rather than copying (overrides -copy)")
	flag.BoolVar(&cfg.Flags.Verbose, "v", false, "Verbose logging (includes hints with -print)")
	flag.BoolVar(&cfg.Flags.Copy, "copy", false, "Copy to clipboard instead of printing")

	flag.Usage = func() {
		cf := configFilePath()
		if t := strings.TrimPrefix(cf, os.Getenv("HOME")); t != cf {
			cf = "~" + t
		}
		fmt.Fprintf(os.Stderr, `Usage: %[1]s [options] <site.name>+

Generates a site-specific password based on the given site name.  The resulting
password is printed to stdout, or copied to the clipboard if --copy is set.

If the KEYFISH_SECRET environment variable is set, it is used as the passphrase
for password generation.  Otherwise, the user is prompted at the terminal.
However, if KEYFISH_SECRET ends with a "|" symbol, it is instead treated as a
command line to execute to return the passphrase.

Use --format to specify an exact password layout, with wildcards to substitute
elements of the alphabet:

  ^   for an uppercase letter
  _   for a lowercase letter
  #   for a digit
  *   for a letter of either case
  ?   for a punctuation mark
  ~   for a non-punctuation mark (* or #)

All other characters are copied verbatim.

A site name has the form "host.org" or "salt@host.org". If the site matches one
of the sites named in the user's config file, the corresponding settings are used.

By default, configuration is read from %[2]s.
If KEYFISH_CONFIG is set to a non-empty path, that path is used instead.
If KEYFISH_CONFIG is set empty, no config file is loaded.

Flags:`+"\n", filepath.Base(os.Args[0]), cf)
		flag.PrintDefaults()
	}
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
	if err := cfg.Load(configFilePath()); err != nil && !os.IsNotExist(err) {
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
	if doShow {
		out := json.NewEncoder(os.Stdout)
		if cfg.Flags.Verbose {
			out.SetIndent("", "  ")
		}
		for _, arg := range flag.Args() {
			site, _ := cfg.Site(arg)
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
		pw, err := getpass.Prompt("Secret key: ")
		if err != nil {
			fail("Error reading secret key: %v", err)
		}
		secretKey = pw
	} else if pc, ok := isPipeCommand(secretKey); ok {
		pw, err := exec.Command(pc[0], pc[1:]...).Output()
		if err != nil {
			fail("Error reading secret key: %v", err)
		}
		secretKey = strings.TrimSuffix(string(pw), "\n")
	}

	for _, arg := range flag.Args() {
		site, _ := cfg.Site(arg)

		// Check minimum length.
		if site.Length < minLength {
			fail("Password length must be ≥ %d", minLength)
		} else if site.Format != "" && len(site.Format) < minLength {
			fail("Format length must be ≥ %d", minLength)
		}
		if cfg.Flags.Verbose {
			log.Printf("Site: %v", site)
		}

		ctx := site.Context(secretKey)
		var pw string
		if fmt := site.Format; fmt != "" {
			pw = ctx.Format(site.Host, fmt)
		} else {
			pw = ctx.Password(site.Host, site.Length)
		}
		if doPrint || !cfg.Flags.Copy {
			fmt.Println(pw)
		} else if err := toClipboard(pw); err != nil {
			log.Printf("Error copying to clipboard: %v", err)
		} else {
			if u := site.Login; u != "" {
				fmt.Print(u, "@")
			}
			fmt.Print(site.Host, "\t", wordhash.String(pw))
			if doOTP && site.OTP != nil {
				fmt.Print("\t", otp.Config{Key: string(site.OTP.Key)}.TOTP())
			}
			fmt.Println()
		}
	}
}

var defaultConfig = "$HOME/.keyfish"

func configFilePath() string {
	if path, ok := os.LookupEnv("KEYFISH_CONFIG"); ok {
		return path
	}
	return os.ExpandEnv(defaultConfig)
}

func isPipeCommand(key string) ([]string, bool) {
	if t := strings.TrimSuffix(key, "|"); t != key {
		return shell.Split(t)
	}
	return nil, false
}
