package cmddebug

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"

	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmdconvert"
)

var Command = &command.C{
	Name: "debug",
	Help: `Debug commands (potentially dangerous).

Debug commands require specifying a database path explicitly.
Use "@" to refer to the path set via the --db flag.`,

	Unlisted: true,

	Commands: []*command.C{{
		Name:  "show-record",
		Usage: "<db-path> <query>",
		Help:  "Print the config record for the specified query.",
		Run:   command.Adapt(runDebugShowRecord),
	}, {
		Name:  "edit-record",
		Usage: "<db-path> <query>",
		Help:  "Edit the record matching the specified query.",
		Run:   command.Adapt(runDebugEditRecord),
	}, {
		Name:  "edit",
		Usage: "<db-path>",
		Help:  "Edit the full content of the database.",
		Run:   command.Adapt(runDebugEdit),
	}, {
		Name:  "export",
		Usage: "<db-path>",
		Help:  "Export the contents of a database in plaintext as JSON.",
		Run:   command.Adapt(runDebugExport),
	}, {
		Name:  "import",
		Usage: "<db-path> <json-path>",
		Help:  "Import a plaintext JSON into a database, replacing its contents.",
		Run:   command.Adapt(runDebugImport),
	},
		cmdconvert.Command,
	},
}

// runDebugShowRecord implements the "debug show-record" subcommand.
func runDebugShowRecord(env *command.Env, dbPath, query string) error {
	s, err := kflib.OpenDB(getDBPath(env, dbPath))
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

// runDebugEdit implements the "debug edit" subcommand.
func runDebugEdit(env *command.Env, dbPath string) error {
	dp := getDBPath(env, dbPath)
	s, err := kflib.OpenDB(dp)
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
	if err := kflib.SaveDB(s, dp); err != nil {
		return err
	}
	fmt.Fprintf(env, "Edit applied to %q\n", dp)
	return nil
}

// runDebugEditRecord implements the "debug edit-record" subcommand.
func runDebugEditRecord(env *command.Env, dbPath, query string) error {
	dp := getDBPath(env, dbPath)
	s, err := kflib.OpenDB(dp)
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
	if err := kflib.SaveDB(s, dp); err != nil {
		return err
	}
	fmt.Fprintf(env, "Record edit applied to %q\n", dp)
	return nil
}

// runDebugExport implements the "debug export" subcommand.
func runDebugExport(env *command.Env, dbPath string) error {
	s, err := kflib.OpenDB(getDBPath(env, dbPath))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(s.DB())
}

// runDebugImport implements the "debug import" subcommand.
func runDebugImport(env *command.Env, dbPath, jsonPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("load JSON: %w", err)
	}
	var db kfdb.DB
	if err := json.Unmarshal(data, &db); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	dp := getDBPath(env, dbPath)
	s, err := kflib.OpenDB(dp)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	*s.DB() = db
	if err := kflib.SaveDB(s, dp); err != nil {
		return err
	}
	fmt.Fprintf(env, "Imported %q into %q\n", jsonPath, dp)
	return nil
}

func getDBPath(env *command.Env, dbPath string) string {
	if dbPath == "@" {
		return config.DBPath(env)
	}
	return dbPath
}
