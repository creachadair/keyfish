package cmdrecord

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
)

var Command = &command.C{
	Name: "record",
	Help: "Commands to manipulate records.",

	Commands: []*command.C{
		{
			Name:     "add",
			Usage:    "<label>",
			Help:     "Add a new record with the specified label.",
			SetFlags: command.Flags(flax.MustBind, &addFlags),
			Run:      command.Adapt(runRecordAdd),
		},
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
			Usage: "<query> ...",
			Help:  "Archive the specified records.",
			Run:   command.Adapt(runRecordArchive),
		},
		{
			Name:  "unarchive",
			Usage: "<query> ...",
			Help:  "Unarchive the specified records.",
			Run:   command.Adapt(runRecordArchive),
		},
	},
}

var addFlags struct {
	Title    string `flag:"title,Specify the title of the record"`
	Username string `flag:"username,Specify the username for the record"`
	EMail    string `flag:"email,Specify an e-mail for the record"`
	Host     string `flag:"host,Specify a hostname for the record"`
	Edit     bool   `flag:"edit,Open the new record in an editor"`
}

// runRecordAdd implements the "record add" subcommand.
func runRecordAdd(env *command.Env, label string) error {
	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	db := s.DB()
	if _, err := kflib.FindRecord(db, label, true); err == nil {
		return fmt.Errorf("label %q already exists", label)
	}

	nr := &kfdb.Record{
		Label:    label,
		Title:    addFlags.Title,
		Username: addFlags.Username,
	}
	if addFlags.EMail != "" {
		nr.Addrs = append(nr.Addrs, addFlags.EMail)
	}
	if addFlags.Host != "" {
		nr.Hosts = append(nr.Hosts, addFlags.Host)
	}
	if addFlags.Edit {
		nr, err = kflib.Edit(env.Context(), nr)
		if err != nil && !errors.Is(err, kflib.ErrNoChange) {
			return err
		}
	}
	db.Records = append(db.Records, nr)
	if err := config.SaveDB(env, s); err != nil {
		return err
	}
	fmt.Fprintf(env, "Created new record %q\n", label)
	return nil
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
func runRecordArchive(env *command.Env, queries ...string) error {
	if len(queries) == 0 {
		return env.Usagef("at least one query is required")
	}
	doArchive := env.Command.Name == "archive"

	s, err := config.LoadDB(env)
	if err != nil {
		return err
	}
	db := s.DB()

	for _, query := range queries {
		res, err := kflib.FindRecord(db, query, !doArchive)
		if err != nil {
			return err
		} else if res.Record.Archived == doArchive {
			return fmt.Errorf("record is already %sd", env.Command.Name)
		}
		res.Record.Archived = doArchive
	}
	return config.SaveDB(env, s)
}
