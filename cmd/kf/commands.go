package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/creachadair/command"
	"github.com/creachadair/keyfish/clipboard"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/keyfish/wordhash"
	"github.com/creachadair/mds/slice"
	"github.com/creachadair/otp/otpauth"
)

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
	res, err := kflib.FindRecord(s.DB(), query)
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

	if pwFlags.OTP && res.Record.OTP != nil {
		otp, err := kflib.GenerateOTP(res.Record.OTP, 0)
		if err != nil {
			otp = "<invalid-otp>"
		}
		fmt.Print(" ", otp)
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
	res, err := kflib.FindRecord(s.DB(), query)
	if err != nil {
		return err
	}
	otpURL := res.Record.OTP
	if res.Tag != "" {
		for _, d := range res.Record.Details {
			if d.Label != "tag" {
				continue
			} else if u, err := otpauth.ParseURL(d.Value); err == nil {
				otpURL = u
				break
			}
		}
	}
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

// runCreateDB implements the "create" subcommand.
func runCreateDB(env *command.Env, dbPath string) error {
	if _, err := os.Stat(dbPath); err == nil {
		return fmt.Errorf("database %q already exists", dbPath)
	}
	passphrase, err := kflib.ConfirmPassphrase("New database passphrase: ")
	if err != nil {
		return err
	}
	s, err := kfdb.New(passphrase, nil)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	if err := kflib.SaveDB(s, dbPath); err != nil {
		return err
	}
	fmt.Fprintf(env, "Created database %q\n", dbPath)
	return nil
}

// runArchive implements the "archive" subcommand.
func runArchive(env *command.Env, query string) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	db := s.DB()

	res, err := kflib.FindRecord(db, query)
	if err != nil {
		return err
	} else if res.Record.Archived {
		return errors.New("record is already archived")
	}
	res.Record.Archived = true
	return config.SaveDB(env, s)
}
