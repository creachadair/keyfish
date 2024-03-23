package main

import (
	"cmp"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/creachadair/command"
	"github.com/creachadair/keyfish/hashpass"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/mapset"
	"github.com/creachadair/mds/value"
)

// settings are common configuration data plumbed through to commands.
type settings struct {
	DBPath string // the path of the database file
}

// loadDB opens the database specified by the DBPath setting. If the database
// does not exist, loadDB reports an error.
func loadDB(env *command.Env) (*kfdb.Store, error) {
	set := env.Config.(*settings)
	if set.DBPath == "" {
		return nil, errors.New("no database path specified")
	}
	return kflib.OpenDB(set.DBPath)
}

// findResult is the result of a successful call to findRecord.
type findResult struct {
	tag    string       // the tag from the query, if present
	label  string       // the label matched by the query
	record *kfdb.Record // the record matched by the label
}

func findRecord(db *kfdb.DB, query string) (findResult, error) {
	if query == "" {
		return findResult{}, fmt.Errorf("no match for %q", query)
	}
	tag, rest, ok := strings.Cut(query, "@")
	if !ok {
		tag, rest = "", query
	}

	// Case 1: An exact match for the label of a record.
	if r, ok := db.Records[rest]; ok {
		return findResult{tag, rest, r}, nil
	}

	// Case 2: Look for an exact or partial host match.
	if strings.Contains(rest, ".") {
		var exact, partial []string
		for label, r := range db.Records {
			for _, h := range r.Hosts {
				if rest == h {
					exact = append(exact, label)
				} else if strings.HasSuffix(h, "."+rest) {
					partial = append(partial, label)
				}
			}
		}
		if len(exact)+len(partial) == 0 {
			return findResult{}, fmt.Errorf("no match for host %q", rest)
		} else if len(exact) == 1 {
			// Prefer a unique exact match if available.
			return findResult{tag, exact[0], db.Records[exact[0]]}, nil
		} else if len(partial) == 1 {
			// Otherwise, prefer a unique partial match if available.
			return findResult{tag, partial[0], db.Records[partial[0]]}, nil
		}
		return findResult{}, fmt.Errorf("host %q is ambiguous (%s)",
			rest, fmtStrings(append(exact, partial...)))
	}

	// Case 3: Look for other substring matches.
	sub := strings.ToLower(rest)
	var hits mapset.Set[string]
	for label, r := range db.Records {
		if strings.Contains(strings.ToLower(r.Notes), sub) ||
			strings.Contains(strings.ToLower(r.Title), sub) {
			hits.Add(label)
		}
		for _, host := range r.Hosts {
			if strings.Contains(host, rest) {
				hits.Add(label)
			}
		}
	}
	switch len(hits) {
	case 0:
		return findResult{}, fmt.Errorf("no match for %q", rest)
	case 1:
		hit := hits.Pop()
		return findResult{tag, hit, db.Records[hit]}, nil
	default:
		return findResult{}, fmt.Errorf("query %q is ambiguous (%s)",
			rest, fmtStrings(hits.Slice()))
	}
}

func fmtStrings(ss []string) string {
	sort.Strings(ss)
	if len(ss) > 5 {
		ss[5] = "..."
		ss = ss[:6]
	}
	return strings.Join(ss, ", ")
}

func genPassword(db *kfdb.DB, tag string, rec *kfdb.Record) (string, error) {
	h := value.At(rec.Hashpass)
	d := value.At(db.Defaults)

	// Use a record-specific key if one is defined.
	// Otherwise, use the default key if one is set.
	// Otherwise prompt the user.
	hkey := h.SecretKey
	if hkey == "" {
		hkey = value.At(d.Hashpass).SecretKey
	}
	if hkey == "" {
		var err error
		hkey, err = kflib.GetPassphrase("Secret key: ")
		if err != nil {
			return "", err
		}
	}
	hc := hashpass.Context{
		Alphabet: hashpass.All,
		Site:     cmp.Or(h.Seed, rec.Hosts[0]),
		Salt:     cmp.Or(tag, h.Tag),
		Secret:   hkey,
	}
	if h.Punct != nil && !*h.Punct {
		hc.Alphabet = hashpass.NoPunct
	}
	if h.Format != "" {
		return hc.Format(h.Format), nil
	}
	return hc.Password(cmp.Or(h.Length, d.PasswordLength)), nil
}
