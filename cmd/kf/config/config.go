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
	DBPath string // path of database file (overrides KEYFISH_DB)
	PFile  string // path of passphrase file
}

// LoadDB opens the database specified by the DBPath setting. If the database
// does not exist, LoadDB reports an error.
func LoadDB(env *command.Env) (*kfdb.Store, error) {
	st, _, _, err := openDBInternal(env)
	return st, err
}

// WatchDB opens a watcher for the database specified by the DBPath setting.
// If the database does not exist, WatchDB reports an error.
func WatchDB(env *command.Env) (*kflib.DBWatcher, error) {
	st, path, pp, err := openDBInternal(env)
	if err != nil {
		return nil, err
	}
	return kflib.NewDBWatcher(st, path, pp)
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

func openDBInternal(env *command.Env) (_ *kfdb.Store, path, pp string, err error) {
	path = DBPath(env)
	if path == "" {
		return nil, "", "", errors.New("no database path specified (set --db or KEYFISH_DB)")
	}

	set := env.Config.(*Settings)
	if set.PFile != "" {
		var data []byte
		data, err = os.ReadFile(set.PFile)
		pp = strings.TrimSpace(string(data))
	} else {
		pp, err = kflib.GetPassphrase("Passphrase: ")
	}
	if err != nil {
		return nil, "", "", fmt.Errorf("read passphrase: %w", err)
	}

	st, err := kflib.OpenDBWithPassphrase(path, pp)
	if err != nil {
		return nil, "", "", err
	}
	return st, path, pp, nil
}
