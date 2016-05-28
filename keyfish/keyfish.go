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
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"

	"bitbucket.org/creachadair/keyfish/password"
	"github.com/stackengine/gopass"
)

const (
	minLength = 6
	maxLength = password.MaxLength
)

var (
	config = &Config{
		Default: &Site{Length: 18, Punct: new(bool)},
	}
	secretKey string
)

func init() {
	flag.IntVar(&config.Default.Length, "length", 18, "Password length")
	flag.BoolVar(config.Default.Punct, "punct", false, "Use punctuation")
	flag.StringVar(&config.Default.Format, "format", "", "Password format")
	flag.StringVar(&config.Default.Salt, "salt", "", "Salt to hash with the site name")
	flag.BoolVar(&config.Flags.Verbose, "v", false, "Verbose logging")

	flag.StringVar(&secretKey, "secret", os.Getenv("KEYFISH_SECRET"), "Secret key")

	// Only enable the -copy flag if it's supported by the system.
	// Right now, that means MacOS.
	if runtime.GOOS == "darwin" {
		flag.BoolVar(&config.Flags.Copy, "copy", false, "Copy to clipboard instead of printing")
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

// usage prints a usage message to stderr and terminates the program.
func fail(msg string, args ...interface{}) { log.Fatalf(msg, args...) }

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		fail("You must specify at least one site name")
	}
	if err := config.Load(os.ExpandEnv("$HOME/.keyfish")); err != nil {
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
		site, ok := config.Sites[arg]
		if !ok {
			site = &Site{Host: arg}
		}
		site.merge(config.Default)
		if n := site.Length; n < minLength || n > maxLength {
			fail("Password length must be ≥ %d and ≤ %d", minLength, maxLength)
		}
		if config.Flags.Verbose {
			log.Printf("Site: %v", site)
		}

		ctx := site.context(secretKey)
		var pw string
		if fmt := site.Format; fmt != "" {
			pw = ctx.Format(site.Host, fmt)
		} else {
			pw = ctx.Password(site.Host)[:site.Length]
		}
		if !config.Flags.Copy {
			fmt.Println(pw)
		} else if err := toClipboard(pw); err != nil {
			log.Printf("Error copying to clipboard: %v", err)
		}
	}
}
