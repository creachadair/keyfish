// Package config contains shared configuration settings for kf subcommands.
package config

import (
	"errors"
	"fmt"

	"github.com/creachadair/command"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
)

// Settings are shared settings used by kf subcommands.
type Settings struct {
	DBPath string
}

// LoadDB opens the database specified by the DBPath setting. If the database
// does not exist, LoadDB reports an error.
func LoadDB(env *command.Env) (*kfdb.Store, error) {
	set := env.Config.(*Settings)
	if set.DBPath == "" {
		return nil, errors.New("no database path specified")
	}
	return kflib.OpenDB(set.DBPath)
}

// SaveDB saves the specified database to the DBPath.
func SaveDB(env *command.Env, s *kfdb.Store) error {
	set := env.Config.(*Settings)
	if err := kflib.SaveDB(s, set.DBPath); err != nil {
		return err
	}
	fmt.Fprintln(env, "<saved>")
	return nil
}

// DBPath returns the database path associated with env, or "".
func DBPath(env *command.Env) string { return env.Config.(*Settings).DBPath }
