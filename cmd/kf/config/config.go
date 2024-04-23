// Package config contains shared configuration settings for kf subcommands.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	path := DBPath(env)
	if path == "" {
		return nil, errors.New("no database path specified (provide --db or set KEYFISH_DB)")
	}
	return kflib.OpenDB(path)
}

// SaveDB saves the specified database to the DBPath.
func SaveDB(env *command.Env, s *kfdb.Store) error {
	if err := kflib.SaveDB(s, DBPath(env)); err != nil {
		return err
	}
	fmt.Fprintln(env, "<saved>")
	return nil
}

// DBPath returns the database path associated with env, or "".
func DBPath(env *command.Env) string {
	set := env.Config.(*Settings)
	if tail, ok := strings.CutPrefix(set.DBPath, "$0"); ok {
		ep, err := os.Executable()
		if err == nil {
			return filepath.Join(filepath.Dir(ep), tail)
		}
	}
	return set.DBPath
}
