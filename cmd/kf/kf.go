// Program kf is a keyfish command-line tool.
package main

import (
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"

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

		Commands: []*command.C{
			{
				Name:     "list",
				Help:     "List the entries in the database.",
				SetFlags: command.Flags(flax.MustBind, &listFlags),
				Run:      command.Adapt(runList),
			},
			{
				Name:     "print",
				Usage:    "<query>",
				Help:     "Print the password for the specified query.",
				SetFlags: command.Flags(flax.MustBind, &pwFlags),
				Run:      command.Adapt(runPW),
			},
			{
				Name:     "copy",
				Usage:    "<query>",
				Help:     "Copy the password for the specified query to the clipboard.",
				SetFlags: command.Flags(flax.MustBind, &pwFlags),
				Run:      command.Adapt(runPW),
			},
			{
				Name:  "otp",
				Usage: "<query>",
				Help: `Print a TOTP code for the specified query.

If the specified query does not match a record with an OTP code,
an error is reported. If a tag is set on the query, and the record
has a detail whose contents are an OTP URL, that URL is used to
generate a code instead of the base record's code.`,
				SetFlags: command.Flags(flax.MustBind, &otpFlags),
				Run:      command.Adapt(runOTP),
			},
			{
				Name:  "create-db",
				Usage: "<db-path>",
				Help:  "Create a new empty database.",
				Run:   command.Adapt(runCreateDB),
			},
			{
				Name:  "archive",
				Usage: "<query>",
				Help:  "Archive the specified record.",
				Run:   command.Adapt(runArchive),
			},
			{
				Name:  "unarchive",
				Usage: "<query>",
				Help:  "Unarchive the specified record.",
				Run:   command.Adapt(runArchive),
			},
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
		},
	}
	command.RunOrFail(root.NewEnv(nil).MergeFlags(true), os.Args[1:])
}
