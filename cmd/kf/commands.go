package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/creachadair/command"
	"github.com/creachadair/keyfish/clipboard"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/keyfish/wordhash"
	"github.com/creachadair/mds/mapset"
	"github.com/creachadair/mds/slice"
)

// runCreate implements the "create" subcommand.
func runCreate(env *command.Env, dbPath string) error {
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

// runList implements the "list" subcommand.
func runList(env *command.Env) error {
	s, err := loadDB(env)
	if err != nil {
		return err
	}
	db := s.DB()

	ids := mapset.Keys(db.Records)
	var maxWidth int
	for id := range ids {
		maxWidth = max(maxWidth, len(id))
	}

	const lineLength = 90
	const padding = 2

	fw := maxWidth + padding
	nc := (lineLength + fw - 1) / fw
	nr := len(ids) / nc

	names := ids.Slice()
	sort.Strings(names)
	cols := slice.Chunks(names, nr)

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
	s, err := loadDB(env)
	if err != nil {
		return err
	}
	res, err := findRecord(s.DB(), query)
	if err != nil {
		return err
	}

	var pw string
	if res.record.Password != "" {
		pw = res.record.Password
	} else if pw, err = genPassword(s.DB(), res.tag, res.record); err != nil {
		return err
	}
	if env.Command.Name == "copy" {
		if err := clipboard.WriteString(pw); err != nil {
			return fmt.Errorf("copying password: %w", err)
		}
		pw = wordhash.New(pw)
	}
	fmt.Print(pw)

	if pwFlags.OTP && res.record.OTP != nil {
		otp, err := kflib.GenerateOTP(res.record.OTP, 0)
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
	s, err := loadDB(env)
	if err != nil {
		return err
	}
	res, err := findRecord(s.DB(), query)
	if err != nil {
		return err
	}
	if res.record.OTP == nil {
		return fmt.Errorf("no OTP config for %q", res.label)
	}
	otp, err := kflib.GenerateOTP(res.record.OTP, otpFlags.Shift)
	if err != nil {
		return err
	}
	fmt.Println(otp)
	return nil
}

// runDebugShow implements the "debug show" subcommand.
func runDebugShow(env *command.Env, query string) error {
	s, err := loadDB(env)
	if err != nil {
		return err
	}
	res, err := findRecord(s.DB(), query)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(struct {
		Q string       `json:"query"`
		L string       `json:"label"`
		R *kfdb.Record `json:"record"`
	}{
		Q: query,
		L: res.label,
		R: res.record,
	})
	return nil
}

// runDebugEdit implements the "debug show" subcommand.
func runDebugEdit(env *command.Env, query string) error {
	s, err := loadDB(env)
	if err != nil {
		return err
	}
	res, err := findRecord(s.DB(), query)
	if err != nil {
		return err
	}
	repl, err := kflib.Edit(env.Context(), res.record)
	if err != nil {
		return err
	}
	s.DB().Records[res.label] = repl
	return saveDB(env, s)
}

// runDebugExportJSON implements the "debug export-json" subcommand.
func runDebugExportJSON(env *command.Env, dbPath string) error {
	s, err := kflib.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(s.DB())
}

// runDebugImportJSON implements the "debug import-json" subcommand.
func runDebugImportJSON(env *command.Env, dbPath, jsonPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("load JSON: %w", err)
	}
	var db kfdb.DB
	if err := json.Unmarshal(data, &db); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	s, err := kflib.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	*s.DB() = db
	if err := kflib.SaveDB(s, dbPath); err != nil {
		return err
	}
	fmt.Fprintf(env, "Imported %q into %q\n", jsonPath, dbPath)
	return nil
}

// runDebugChangeKey implements the "debug change-key" subcommand.
func runDebugChangeKey(env *command.Env, dbPath string) error {
	s, err := kflib.OpenDB(dbPath)
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
	if err := kflib.SaveDB(s2, dbPath); err != nil {
		return err
	}
	fmt.Fprintf(env, "Access key updated for %q\n", dbPath)
	return nil
}
