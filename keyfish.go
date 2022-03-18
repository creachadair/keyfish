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
//
// To statically compile the configuration into the main package, set the
// KEYFISH_CONFIG environment variable to the path of the configuration file
// and run "go generate ./config" before building:
//
//   git clone https://github.com/creachadair/keyfish
//   cd keyfish
//   env KEYFISH_CONFIG=$HOME/my-config.json go generate ./config
//   go build
//
// You can then copy the keyfish binary where you like and it will use the
// static configuration unless you override it at runtime with KEYFISH_CONFIG.

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
	"github.com/creachadair/keyfish/clipboard"
	"github.com/creachadair/keyfish/config"
	"github.com/creachadair/keyfish/wordhash"
	"github.com/creachadair/otp"
)

const minLength = 6 // Allow no passwords shorter than this

var (
	cfg *config.Config // see init below

	secretKey = os.Getenv("KEYFISH_SECRET")
	doSites   bool // list known site configuations
	doShow    bool // show the named configurations
	doPrint   bool // print the result, overriding -copy
	doPunct   bool // enable punctuation, overriding the default
)

func init() {
	// Set up a default configuration to use if one is not loaded from a file.
	usePunct := true
	cfg = &config.Config{
		Default: config.Site{
			Length: 18, Punct: &usePunct,
		},
	}
}

func init() {
	flag.IntVar(&cfg.Default.Length, "length", 18, "Password length")

	flag.StringVar(&cfg.Default.Format, "format", "", "Password format")
	flag.StringVar(&cfg.Default.Salt, "salt", "", "Salt to hash with the site name")
	flag.BoolVar(&doSites, "list", false, "List known sites and exit")
	flag.BoolVar(&doShow, "show", false, "Print specified configurations and exit")
	flag.BoolVar(&doPrint, "print", false, "Print the result rather than copying (overrides -copy)")
	flag.BoolVar(&doPunct, "punct", false, "Use punctuation, overriding the default")
	flag.BoolVar(&cfg.Flags.Verbose, "v", false, "Verbose logging (includes hints with -print)")
	flag.BoolVar(&cfg.Flags.Copy, "copy", false, "Copy to clipboard instead of printing")
	flag.BoolVar(&cfg.Flags.OTP, "otp", false, "Generate an OTP for the site (if configured)")
	flag.BoolVar(&cfg.Flags.Strict, "strict", false, "Report an error for sites not named in the config")

	flag.Usage = func() {
		cf := config.FilePath()
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
If KEYFISH_CONFIG is set, that path is used instead.

Flags:`+"\n", filepath.Base(os.Args[0]), cf)
		flag.PrintDefaults()
	}
}

// usage prints a usage message to stderr and terminates the program.
func fail(msg string, args ...interface{}) { log.Fatalf(msg, args...) }

// listSites renders a nicely-formatted listing of sites to w.
func listSites(w io.Writer, sites stringset.Set) {
	const lineWidth = 80
	const padding = 2

	// Find the maximum-width site label and use it to compute the number of
	// columns that will fit into the designated line width.
	var maxWidth int
	for site := range sites {
		if len(site) > maxWidth {
			maxWidth = len(site)
		}
	}
	fieldWidth := maxWidth + padding
	numCols := (lineWidth + fieldWidth - 1) / fieldWidth
	numRows := sites.Len() / numCols

	// Fill columns before rows, so that the reader can scan down a column in
	// lexicographic order rather than reading across rows.
	var cols [][]string
	elts := sites.Elements() // sorted
	for i := 0; i < len(elts); {
		n := i + numRows
		if n > len(elts) {
			n = len(elts)
		}
		cols = append(cols, elts[i:n])
		i = n
	}

	fmt.Fprintln(w, "▷ Known sites:")
	tw := tabwriter.NewWriter(w, maxWidth, 0, padding, ' ', 0)
	for r := 0; r < numRows; r++ {
		var row []string
		for _, col := range cols {
			if r >= len(col) {
				break
			}
			row = append(row, col[r])
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
}

func main() {
	// Load configuration settings from the user's file, if it exists.
	// Do this prior to flag parsing so that flags can override defaults.
	if err := cfg.Load(config.FilePath()); err != nil && !os.IsNotExist(err) {
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
			var site config.Site
			var ok bool

			for _, c := range config.SiteCandidates(arg) {
				site, ok = cfg.Site(c)
				if ok {
					break
				}
			}
			if !ok && cfg.Flags.Strict {
				fail("Site %q is not known", arg)
			}
			if !cfg.Flags.Verbose {
				site.Hints = nil
			}
			if err := out.Encode(site); err != nil {
				fail("Error encoding site %q: %v", arg, err)
			}
		}
		return
	}

	// Establish the secret key, on demand.
	mustLoadKey := func() string {
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
		return secretKey
	}

	// Check all the sites before generating any secrets.
	var sites []config.Site
	for _, arg := range flag.Args() {
		var site config.Site
		var ok bool

		for _, c := range config.SiteCandidates(arg) {
			site, ok = cfg.Site(c)
			if ok {
				break
			}
		}
		if !ok && cfg.Flags.Strict {
			fail("Site %q is not known", arg)
		}
		sites = append(sites, site)
	}

	for _, site := range sites {
		// Check minimum length.
		if site.Length < minLength {
			fail("Password length must be ≥ %d", minLength)
		} else if site.Format != "" && len(site.Format) < minLength {
			fail("Format length must be ≥ %d", minLength)
		}

		if isFlagSet("punct") {
			site.Punct = &doPunct // override whatever was there
		}
		if cfg.Flags.Verbose {
			log.Printf("Site: %v", site)
		}

		ctx := site.Context(mustLoadKey())
		var pw string
		if fmt := site.Format; fmt != "" {
			pw = ctx.Format(site.Host, fmt)
		} else {
			pw = ctx.Password(site.Host, site.Length)
		}
		if doPrint || !cfg.Flags.Copy {
			fmt.Println(pw)
		} else if err := clipboard.WriteString(pw); err != nil {
			log.Printf("Error copying to clipboard: %v", err)
		} else {
			if u := site.Login; u != "" {
				fmt.Print(u, "@")
			}
			fmt.Print(site.Host, "\t", wordhash.String(pw))
			if cfg.Flags.OTP {
				otpc := site.OTP
				if site.Salt != "" && site.SaltOTP[site.Salt] != nil {
					otpc = site.SaltOTP[site.Salt]
				}
				if otpc != nil {
					fmt.Print("\t", otp.Config{Key: string(otpc.Key)}.TOTP())
				}
			}
			fmt.Println()
		}
	}
}

func isPipeCommand(key string) ([]string, bool) {
	if t := strings.TrimSuffix(key, "|"); t != key {
		return shell.Split(t)
	}
	return nil, false
}

func isFlagSet(name string) bool {
	var ok bool
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			ok = true
		}
	})
	return ok
}
