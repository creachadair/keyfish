package cmdrecord

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
)

var Command = &command.C{
	Name: "record",
	Help: "Commands to manipulate records.",

	Commands: []*command.C{
		{
			Name:  "show",
			Usage: "<query>",
			Help:  "Print the config record for the specified query.",
			Run:   command.Adapt(runRecordShow),
		},
		{
			Name:  "edit",
			Usage: "<query>",
			Help:  "Edit the record matching the specified query.",
			Run:   command.Adapt(runRecordEdit),
		},
		{
			Name:  "archive",
			Usage: "<query>",
			Help:  "Archive the specified record.",
			Run:   command.Adapt(runRecordArchive),
		},
		{
			Name:  "unarchive",
			Usage: "<query>",
			Help:  "Unarchive the specified record.",
			Run:   command.Adapt(runRecordArchive),
		},
	},
}

// runRecordShow implements the "record show" subcommand.
func runRecordShow(env *command.Env, query string) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	res, err := kflib.FindRecord(s.DB(), query, true)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(struct {
		Q string       `json:"query"`
		I int          `json:"index"`
		R *kfdb.Record `json:"record"`
	}{
		Q: query,
		I: res.Index,
		R: res.Record,
	})
	return nil
}

// runRecordEdit implements the "record edit" subcommand.
func runRecordEdit(env *command.Env, query string) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	res, err := kflib.FindRecord(s.DB(), query, true)
	if err != nil {
		return err
	}
	repl, err := kflib.Edit(env.Context(), res.Record)
	if errors.Is(err, kflib.ErrNoChange) {
		fmt.Fprintln(env, "No change")
		return nil
	} else if err != nil {
		return err
	}
	s.DB().Records[res.Index] = repl
	if err := config.SaveDB(env, s); err != nil {
		return err
	}
	fmt.Fprintf(env, "Record edit applied to %q\n", config.DBPath(env))
	return nil
}

// runRecordArchive implements the "archive" and "unarchive" subcommands.
func runRecordArchive(env *command.Env, query string) error {
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
