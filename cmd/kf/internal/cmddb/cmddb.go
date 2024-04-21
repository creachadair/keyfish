package cmddb

import (
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
)

var Command = &command.C{
	Name: "db",
	Help: "Commands to manipulate a key database.",

	Commands: []*command.C{
		{
			Name:  "create",
			Usage: "<db-path>",
			Help:  "Create a new empty database.",
			Run:   command.Adapt(runCreateDB),
		},
		{
			Name: "change-key",
			Help: "Change the access key on the database.",
			Run:  command.Adapt(runChangeKey),
		},
	},
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

// runChangeKey implements the "db change-key" subcommand.
func runChangeKey(env *command.Env) error {
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
