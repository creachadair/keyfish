package cmdcli

import (
	"cmp"
	"fmt"
	"os"
	"slices"
	"text/tabwriter"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/clipboard"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/keyfish/wordhash"
	"github.com/creachadair/mds/value"
)

var Commands = []*command.C{
	{
		Name:     "list",
		Usage:    "[query]",
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
}

var listFlags struct {
	Arch  bool `flag:"a,Include archived entries in the output"`
	NArch bool `flag:"n,Exclude unarchived entries from the output"`
}

// runList implements the "list" subcommand.
func runList(env *command.Env, optQuery ...string) error {
	var query string // everything
	if len(optQuery) > 1 {
		return env.Usagef("extra arguments after query: %q", optQuery[1:])
	} else if len(optQuery) == 1 {
		query = optQuery[0]
	}

	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	db := s.DB()

	fr := kflib.FindRecords(db.Records, query)
	slices.SortFunc(fr, func(a, b kflib.FoundRecord) int {
		return cmp.Compare(a.Record.Label, b.Record.Label)
	})

	tw := tabwriter.NewWriter(os.Stdout, 4, 0, 1, ' ', 0)
	for _, r := range fr {
		if r.Record.Archived {
			if !(listFlags.Arch || listFlags.NArch) {
				continue
			}
		} else if listFlags.NArch {
			continue
		}
		tag := value.Cond(r.Record.Archived, "*", "-")
		title := r.Record.Title
		if title == "" && len(r.Record.Hosts) != 0 {
			title = r.Record.Hosts[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Record.Label, tag, title)
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
	} else if pw, err = kflib.GenerateHashpass(s.DB(), res.Record, res.Tag); err != nil {
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
