package cmddebug

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmdconvert"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/value"
)

var Command = &command.C{
	Name: "debug",
	Help: `Debug commands (potentially dangerous).

Debug commands require specifying a database path explicitly.
Use "@" to refer to the path set via the --db flag.`,

	Unlisted: true,

	Commands: []*command.C{
		{
			Name:  "export",
			Usage: "<db-path>",
			Help:  "Export the contents of a database in plaintext as JSON.",
			Run:   command.Adapt(runDebugExport),
		},
		{
			Name:  "import",
			Usage: "<db-path> <json-path>",
			Help:  "Import a plaintext JSON into a database, replacing its contents.",
			Run:   command.Adapt(runDebugImport),
		},
		{
			Name:  "hashpass",
			Usage: "[flags] [salt]@seed",
			Help: `Generate an HKDF based hashed password.

The seed is the non-secret generator seed. If provided, the salt is
mixed in to the HKDF as additional context. The user is prompted for
the HKDF secret. The output is written as a single line to stdout.`,
			SetFlags: command.Flags(flax.MustBind, &hpFlags),
			Run:      command.Adapt(runDebugHashpass),
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

var hpFlags struct {
	Length  int  `flag:"n,The length of the password to generate"`
	NoDigit bool `flag:"no-digits,Omit digits from the generated password"`
	Symbols bool `flag:"symbols,Include punctuation in the generated password"`
	Confirm bool `flag:"c,Confirm passphrase"`
}

// runDebugHashpass implements the "debug hashpass" subcommand.
func runDebugHashpass(env *command.Env, input string) error {
	if hpFlags.Length <= 0 {
		return env.Usagef("the length (-n) must be positive")
	}

	salt, seed, ok := strings.Cut(input, "@")
	if !ok {
		seed = input
	}
	pp, err := value.Cond(hpFlags.Confirm, kflib.ConfirmPassphrase, kflib.GetPassphrase)("Passphrase: ")
	if err != nil {
		return err
	}
	cs := kflib.Letters
	if !hpFlags.NoDigit {
		cs |= kflib.Digits
	}
	if hpFlags.Symbols {
		cs |= kflib.Symbols
	}
	fmt.Println(kflib.HashedChars(hpFlags.Length, cs, pp, seed, salt))
	return nil
}

func getDBPath(env *command.Env, dbPath string) string {
	if dbPath == "@" {
		return config.DBPath(env)
	}
	return dbPath
}
