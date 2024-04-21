package cmdcli

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/clipboard"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/keyfish/wordhash"
	"github.com/creachadair/mds/slice"
)

var Commands = []*command.C{
	{
		Name:     "list",
		Help:     "List the entries in the database.",
		SetFlags: command.Flags(flax.MustBind, &listFlags),
		Run:      command.Adapt(runList),
	},
	{
		Name:     "print",
		Usage:    "<query>",
		Help:     "Print the password for the specified query.",
		SetFlags: command.Flags(flax.MustBind, &pwFlags),
		Run:      command.Adapt(runPW),
	},
	{
		Name:     "copy",
		Usage:    "<query>",
		Help:     "Copy the password for the specified query to the clipboard.",
		SetFlags: command.Flags(flax.MustBind, &pwFlags),
		Run:      command.Adapt(runPW),
	},
	{
		Name:  "otp",
		Usage: "<query>",
		Help: `Print a TOTP code for the specified query.

If the specified query does not match a record with an OTP code,
an error is reported. If a tag is set on the query, and the record
has a detail whose contents are an OTP URL, that URL is used to
generate a code instead of the base record's code.`,
		SetFlags: command.Flags(flax.MustBind, &otpFlags),
		Run:      command.Adapt(runOTP),
	},
	{
		Name: "random",
		Help: `Generate a cryptographically random password.

By default, a password is output as ASCII letters and digits.
Use --no-digits to exclude digits, --symbols to include punctuation.
Use --words to choose words from a word list instead.
Use --sep to choose the word separator when --words is set.

Output is written to stdout, or use --copy to send it to the
clipboard. When --copy is set, a non-cryptographic digest of the
generated value is printed to stdout as a human-readable checksum.

With --set, the password is also stored on the record matching the
given query, in addition to printing or copying it.`,
		SetFlags: command.Flags(flax.MustBind, &randFlags),
		Run:      command.Adapt(runRandom),
	},
	{
		Name:  "archive",
		Usage: "<query>",
		Help:  "Archive the specified record.",
		Run:   command.Adapt(runArchive),
	},
	{
		Name:  "unarchive",
		Usage: "<query>",
		Help:  "Unarchive the specified record.",
		Run:   command.Adapt(runArchive),
	},
}

var listFlags struct {
	All bool `flag:"a,Include archived entries in the output"`
}

// runList implements the "list" subcommand.
func runList(env *command.Env) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	db := s.DB()

	var ids []string
	var maxWidth int
	for _, r := range db.Records {
		if r.Archived {
			if !listFlags.All {
				continue
			}
			ids = append(ids, r.Label+"*")
		} else {
			ids = append(ids, r.Label)
		}
		maxWidth = max(maxWidth, len(ids[len(ids)-1]))
	}
	slices.Sort(ids)

	const lineLength = 90
	const padding = 2

	fw := maxWidth + padding
	nc := (lineLength + fw - 1) / fw
	nr := (len(ids) + nc - 1) / nc

	cols := slice.Chunks(ids, nr)
	tw := tabwriter.NewWriter(os.Stdout, maxWidth, 0, padding, ' ', 0)
	for r := 0; r < nr; r++ {
		fmt.Fprintln(tw, strings.Join(slice.Strip(cols, r), "\t"))
	}
	return tw.Flush()
}

var pwFlags struct {
	OTP bool `flag:"otp,Also generate a TOTP code if available"`
}

// runPW implements the "print" and "copy" subcommands.
func runPW(env *command.Env, query string) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	res, err := kflib.FindRecord(s.DB(), query, false)
	if err != nil {
		return err
	}

	var pw string
	if res.Record.Password != "" {
		pw = res.Record.Password
	} else if pw, err = genPassword(s.DB(), res.Tag, res.Record); err != nil {
		return err
	}
	if env.Command.Name == "copy" {
		if err := clipboard.WriteString(pw); err != nil {
			return fmt.Errorf("copying password: %w", err)
		}
		pw = wordhash.New(pw)
	}
	fmt.Print(pw)

	if pwFlags.OTP {
		otpURL := getOTPCode(res.Record, res.Tag)
		if otpURL != nil {
			otp, err := kflib.GenerateOTP(res.Record.OTP, 0)
			if err != nil {
				otp = "<invalid-otp>"
			}
			fmt.Print(" ", otp)
		}
	}
	fmt.Println()
	return nil
}

var otpFlags struct {
	Shift int `flag:"s,Shift the time step forward by s"`
}

// runOTP implements the "otp" subcommand.
func runOTP(env *command.Env, query string) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	res, err := kflib.FindRecord(s.DB(), query, false)
	if err != nil {
		return err
	}
	otpURL := getOTPCode(res.Record, res.Tag)
	if otpURL == nil {
		return fmt.Errorf("no OTP config for %q", res.Record.Label)
	}
	otp, err := kflib.GenerateOTP(otpURL, otpFlags.Shift)
	if err != nil {
		return err
	}
	fmt.Println(otp)
	return nil
}

// runArchive implements the "archive" and "unarchive" subcommands.
func runArchive(env *command.Env, query string) error {
	doArchive := env.Command.Name == "archive"

	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	db := s.DB()

	res, err := kflib.FindRecord(db, query, !doArchive)
	if err != nil {
		return err
	} else if res.Record.Archived == doArchive {
		return fmt.Errorf("record is already %sd", env.Command.Name)
	}
	res.Record.Archived = doArchive
	return config.SaveDB(env, s)
}

var randFlags struct {
	Length  int    `flag:"n,The length of the password to generate"`
	Words   bool   `flag:"words,Generate words instead of characters"`
	Copy    bool   `flag:"copy,Copy the generated password to the clipboard"`
	NoDigit bool   `flag:"no-digits,Omit digits from the generated password"`
	Symbols bool   `flag:"symbols,Include punctuation in the generated password"`
	WordSep string `flag:"sep,default='-',Word separator"`
	Set     string `flag:"set,Store the generated password in this record"`
}

func runRandom(env *command.Env) error {
	if randFlags.Length <= 0 {
		return env.Usagef("the length (-n) must be positive")
	}

	var s *kfdb.Store
	var r *kfdb.Record
	if randFlags.Set != "" {
		var err error
		s, err = config.LoadDB(env)
		if err != nil {
			return err
		}
		fr, err := kflib.FindRecord(s.DB(), randFlags.Set, false)
		if err != nil {
			return err
		}
		r = fr.Record
	}

	var pw string
	if randFlags.Words {
		pw = kflib.RandomWords(randFlags.Length, randFlags.WordSep)
	} else {
		cs := kflib.Letters
		if !randFlags.NoDigit {
			cs |= kflib.Digits
		}
		if randFlags.Symbols {
			cs |= kflib.Symbols
		}
		pw = kflib.RandomChars(randFlags.Length, cs)
	}

	if r != nil {
		r.Password = pw
		fmt.Fprintf(env, "Setting password on record %q\n", r.Label)
		if err := config.SaveDB(env, s); err != nil {
			return err
		}
	}

	if randFlags.Copy {
		if err := clipboard.WriteString(pw); err != nil {
			return fmt.Errorf("copying password: %w", err)
		}
		pw = wordhash.New(pw)
	}

	fmt.Println(pw)
	return nil
}
