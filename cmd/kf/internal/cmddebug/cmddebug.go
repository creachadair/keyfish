package cmddebug

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmdconvert"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
)

var Command = &command.C{
	Name: "debug",
	Help: `Debug commands (potentially dangerous).

Debug commands require specifying a database path explicitly.
Use "@" to refer to the path set via the --db flag.`,

	Unlisted: true,

	Commands: []*command.C{{
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
