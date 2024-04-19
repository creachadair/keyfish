// Program kf is a keyfish command-line tool.
package main

import (
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"

	"github.com/creachadair/keyfish/cmd/kf/internal/cmdcli"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmddebug"
	"github.com/creachadair/keyfish/cmd/kf/internal/cmdserver"
)

func main() {
	var flags struct {
		DBPath string `flag:"db,default=$KEYFISH_DB,Database path (required)"`
	}
	root := &command.C{
		Name: command.ProgramName(),
		Help: `🐟 A command-line tool for the Keyfish password generator.

Keyfish generates and stores a database of site-specific passwords.
Site data and passwords are stored in a database encrypted with a secret
key provided by the user. Use --db to specify the database path, or set
the KEYFISH_DB environment variable.`,

		SetFlags: command.Flags(flax.MustBind, &flags),

		Init: func(env *command.Env) error {
			env.Config = &config.Settings{DBPath: flags.DBPath}
			return nil
		},

		Commands: append(
			cmdcli.Commands,
			cmdserver.Command,
			command.HelpCommand([]command.HelpTopic{{
				Name: "query",
				Help: `Syntax of query arguments.

A query has the form [tag@]label. The label is either the unique label
assigned to the record, a full or partial match for one of the host names
associated with the record, or a substring match for the title or notes
field of the record.

A query that matches multiple records will report an error listing the
multiple candidate records that could be selected.`,
			}}),
			command.VersionCommand(),
			cmddebug.Command,
		),
	}
	command.RunOrFail(root.NewEnv(nil).MergeFlags(true), os.Args[1:])
}
