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

	"bitbucket.org/creachadair/keyfish/go/alphabet"
	"bitbucket.org/creachadair/keyfish/go/password"
	"code.google.com/p/gopass"
)

const (
	minLength = 6
	maxLength = password.MaxLength
)

var (
	usePunct = flag.Bool("punct", false, "Use punctuation?")
	doCopy   = flag.Bool("copy", false, "Copy to clipboard")
	format   = flag.String("format", "", "Password format")
	length   = flag.Int("length", 18, "Password length")

	context = password.Context{
		Alphabet: alphabet.NoPunct,
	}
)

func init() {
	flag.StringVar(&context.Salt, "salt", context.Salt, "Salt to hash with the site name")
	flag.StringVar(&context.Secret, "secret", "", "Secret key")

	flag.Usage = func() {
		fmt.Println("Usage: keyfish [options] <site.name>+")
		flag.PrintDefaults()
		fmt.Println(`
If the --secret flag is omitted, the value of the KEYFISH_SECRET
environment variable is used, if defined.  Otherwise, the user is
prompted at the terminal.`)
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
func fail(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}

func main() {
	flag.Parse()

	if *length < minLength || *length > maxLength {
		fail("Password length must be ≥ %d and ≤ %d", minLength, maxLength)
	}
	if flag.NArg() == 0 {
		fail("At least one site name must be given")
	}
	if context.Secret == "" {
		if pw := os.Getenv("KEYFISH_SECRET"); pw != "" {
			context.Secret = pw
		} else if pw, err := gopass.GetPass("Secret key: "); err == nil {
			context.Secret = pw
		} else {
			fail("Error reading secret key: %v", err)
		}
	}
	if *usePunct {
		context.Alphabet = alphabet.All
	}

	for _, arg := range flag.Args() {
		var pw string
		if *format != "" {
			pw = context.Format(arg, *format)
		} else {
			pw = context.Password(arg)[:*length]
		}
		if *doCopy {
			if err := toClipboard(pw); err != nil {
				log.Printf("Error copying to clipboard: %v", err)
			}
		} else {
			fmt.Println(pw)
		}
	}
}
