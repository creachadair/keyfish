// Program kf is a keyfish command-line tool.
package main

import (
	"cmp"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"

	"github.com/creachadair/keyfish/cmd/kf/internal/cmdcli"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmddb"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmddebug"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmdrecord"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmdweb"
)

// defaultDBPath, if set, defines a default database path to use when one is
// not otherwise provided. It is exposed as a variable so the linker can set
// it. If the path begins with "$0" the path is taken relative to the directory
// containing the program executable.
var defaultDBPath string

func main() {
	var flags = struct {
		DBPath string `flag:"db,default=*,Database path (required)"`
		PFile  string `flag:"kf.pfile,PRIVATE:Read passphrase from this file path"`
	}{DBPath: cmp.Or(defaultDBPath, os.Getenv("KEYFISH_DB"))}

	root := &command.C{
		Name: command.ProgramName(),
		Help: `🐟 A command-line tool for the Keyfish password generator.

Keyfish generates and stores a database of site-specific passwords.
Site data and passwords are stored in a database encrypted with a secret
key provided by the user. Use --db to specify the database path, or set
the KEYFISH_DB environment variable.`,

		SetFlags: command.Flags(flax.MustBind, &flags),

		Init: func(env *command.Env) error {
			env.Config = &config.Settings{
				DBPath: flags.DBPath,
				PFile:  flags.PFile,
			}
			return nil
		},

		Commands: append(
			cmdcli.Commands,
			cmddb.Command,
			cmdrecord.Command,
			cmdweb.Command,
			command.HelpCommand([]command.HelpTopic{{
				Name: "query-syntax",
				Help: `Syntax of query arguments.

Various commands accept a query to identify which record or records to
operate on. A query has the form [tag@]label. The label is either the unique
label assigned to a record, a full or partial match for one of the hostnames
associated with the record, or a substring match for the title or notes
field of the record.

Matching records are ranked from most to least specific:

 1. An exact match on the record label.
 2. An exact match on a hostname of the record.
 3. A partial (suffix) match on a hostname of the record.
 4. A substring match on the title.
 5. A substring match on the label of a detail.
 6. A substring match in some other text field.

A command that requires a single record will select the highest-ranked
unique result. If no such record exists, the command will report an error
listing the candidate records that could have been chosen.`,
			}}),
			command.VersionCommand(),
			cmddebug.Command,
		),
	}
	command.RunOrFail(root.NewEnv(nil), os.Args[1:])
}
