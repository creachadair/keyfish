// Package cmddb implements the "kf db" subcommand.
package cmddb

import (
	"cmp"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/slice"
)

var Command = &command.C{
	Name: "db",
	Help: "Commands to manipulate a key database.",

	Commands: []*command.C{
		{
			Name:  "create",
			Usage: "<db-path>",
			Help:  "Create a new empty database.",
			Run:   command.Adapt(runDBCreate),
		},
		{
			Name: "change-key",
			Help: "Change the access key on the database.",
			Run:  command.Adapt(runDBChangeKey),
		},
		{
			Name: "edit",
			Help: "Edit the full content of the database.",
			Run:  command.Adapt(runDBEdit),
		},
		{
			Name:  "export",
			Usage: "[query...]",
			Help: `Export the database to CSV.

With no arguments, all non-archived records are exported.  Otherwise, only
records matching the specified queries are chosen. Use "-a" to include archived
records; use "-n" to exclude non-archived records.

An --output file path is required. Caution: The output includes plaintext
passwords and OTP secrets. You may specify "-" as the output to write to
stdout, but this is not recommended unless you are piping to another program.

By default, notes are omitted; use --notes to include them.
By default, OTP codes are included; use --no-otp to exclude them.
`,
			SetFlags: command.Flags(flax.MustBind, &exportFlags),
			Run:      command.Adapt(runDBExport),
		},
	},
}

// runDBCreate implements the "db create" subcommand.
func runDBCreate(env *command.Env, dbPath string) error {
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

// runDBChangeKey implements the "db change-key" subcommand.
func runDBChangeKey(env *command.Env) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	newpp, err := kflib.ConfirmPassphrase("New passphrase: ")
	if err != nil {
		return err
	}
	s2, err := kfdb.New(newpp, s.DB())
	if err != nil {
		return err
	}
	if err := config.SaveDB(env, s2); err != nil {
		return err
	}
	fmt.Fprintf(env, "Access key updated for %q\n", config.DBPath(env))
	return nil
}

// runDBEdit implements the "db edit" subcommand.
func runDBEdit(env *command.Env) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	repl, err := kflib.Edit(env.Context(), s.DB())
	if errors.Is(err, kflib.ErrNoChange) {
		fmt.Fprintln(env, "No change")
		return nil
	} else if err != nil {
		return err
	}
	*s.DB() = *repl
	if err := config.SaveDB(env, s); err != nil {
		return err
	}
	fmt.Fprintf(env, "Edit applied to %q\n", config.DBPath(env))
	return nil
}

var exportFlags struct {
	Target string `flag:"to,Output file path (use '-' for stdout)"`
	Arch   bool   `flag:"a,Include archived entries in the export"`
	NArch  bool   `flag:"n,Exclude unarchived entries from the export"`
	Notes  bool   `flag:"notes,Include notes field in output"`
	NoOTP  bool   `flag:"no-otp,Exclude OTP settings from output"`
}

// runDBExport implements the "db export" subcommand.
func runDBExport(env *command.Env, queries ...string) error {
	if exportFlags.Target == "" {
		return env.Usagef("a --to file is required (use '-' for stdout)")
	}
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	wantArchived := exportFlags.Arch || exportFlags.NArch
	toExport := slice.Select(s.DB().Records, func(r *kfdb.Record) bool {
		return r.Archived && wantArchived || !r.Archived && !exportFlags.NArch
	})
	if len(queries) != 0 {
		var hits []*kfdb.Record
		for _, q := range queries {
			res, err := kflib.FindRecord(s.DB(), q, wantArchived)
			if err != nil {
				return err
			}
			hits = append(hits, res.Record)
		}
		toExport = slices.Values(hits)
	}
	f := os.Stdout
	if exportFlags.Target != "-" { // already checked for empty above
		f, err = os.Create(exportFlags.Target)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close() // in case of error
	}

	// TODO(creachadair): These are just the fields Apple wants.
	cw := csv.NewWriter(f)
	cw.Write([]string{"Title", "URL", "Username", "Password", "Notes", "OTPAuth"})
	var nexp int
	for r := range toExport {
		nexp++
		user := r.Username
		if user == "" && len(r.Addrs) != 0 {
			user = r.Addrs[0]
		}
		title := cmp.Or(r.Title, r.Label)
		var url, notes, otpAuth string
		if len(r.Hosts) != 0 {
			url = r.Hosts[0]
		}
		if !exportFlags.NoOTP && r.OTP != nil {
			otpAuth = r.OTP.String()
		}
		if exportFlags.Notes {
			notes = r.Notes
		}
		cw.Write([]string{title, url, user, r.Password, notes, otpAuth})
	}
	cw.Flush()
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(env, "Exported %d records\n", nexp)
	return nil
}
