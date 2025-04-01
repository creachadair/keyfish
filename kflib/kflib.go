// Package kflib is a support library for the KeyFish tool.
package kflib

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/getpass"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/mds/slice"
	"github.com/creachadair/mds/value"
	"github.com/creachadair/otp"
	"github.com/creachadair/otp/otpauth"
	"github.com/fsnotify/fsnotify"
)

// OpenDB opens the specified database store.
func OpenDB(dbPath string) (*kfdb.Store, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer f.Close()

	pp, err := GetPassphrase("Passphrase: ")
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return kfdb.Open(f, pp)
}

// OpenDBWithPassphrase opens the specified database store using the provided
// access key passphrase instead of prompting at the terminal.
func OpenDBWithPassphrase(dbPath, passphrase string) (*kfdb.Store, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer f.Close()
	db, err := kfdb.Open(f, passphrase)
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", dbPath, err)
	}
	return db, nil
}

// SaveDB writes the specified database store to dbPath.
func SaveDB(s *kfdb.Store, dbPath string) error {
	return atomicfile.Tx(dbPath, 0600, func(f *atomicfile.File) error {
		_, err := s.WriteTo(f)
		return err
	})
}

// GetPassphrase prompts the user at the terminal for a passphrase with echo
// disabled.  An empty passprase is permitted; the caller must check for that
// case if an empty passphrase is not wanted.
func GetPassphrase(prompt string) (string, error) {
	passphrase, err := getpass.Prompt(prompt)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return passphrase, nil
}

// ConfirmPassphrase prompts the user at the terminal for a passphrase with
// echo disabled, then prompts again for confirmation and reports an error if
// the two copies are not equal.
func ConfirmPassphrase(prompt string) (string, error) {
	passphrase, err := getpass.Prompt(prompt)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	confirm, err := getpass.Prompt("Confirm " + strings.ToLower(prompt))
	if err != nil {
		return "", fmt.Errorf("read confirmation: %w", err)
	}
	if confirm != passphrase {
		return "", errors.New("passphrases do not match")
	}
	return passphrase, nil
}

// GenerateOTP returns a TOTP code based on url.  The time code is shifted by
// offset steps (based on the size of the window specified by url).
func GenerateOTP(url *otpauth.URL, offset int) (string, error) {
	step := (time.Now().Unix() / int64(url.Period)) + int64(offset)
	cfg := otp.Config{Digits: url.Digits}
	if err := cfg.ParseKey(url.RawSecret); err != nil {
		return "", err
	}
	return cfg.HOTP(uint64(step)), nil

	// TODO(creachadair): Other algorithms, HOTP.
}

// FindResult is the result of a successful call to FindRecord.
type FindResult struct {
	Tag    string       // the tag from the query, if present
	Index  int          // offset of the record in the database
	Record *kfdb.Record // the record matched by the label
}

// MatchQuality indicates how good a match a query is for a record.
type MatchQuality int

const (
	// MatchNone means the query does not match the record at all.
	MatchNone MatchQuality = iota

	// MatchLabel means the query matches the record's label.
	MatchLabel

	// MatchHost means the query is an exact host match for the record.
	MatchHost

	// MatchHostPartial means the query is a partial host match for the record.
	MatchHostPartial

	// MatchTitle means the query is a case-insensitive substring match for the
	// title or label of the record.
	MatchTitle

	// MatchDetail means the query is a case-insensitive substring match for the
	// label of one of the details of the record.
	MatchDetail

	// MatchSubstring means the query is a case-insensitive substring match for
	// one of the text fields or host entries of the record.
	MatchSubstring
)

// MatchRecord reports how good a match query is for the specified record.
func MatchRecord(query string, r *kfdb.Record) MatchQuality {
	if r.Label != "" && query == r.Label {
		return MatchLabel
	}
	if strings.Contains(query, ".") {
		var isPartial bool
		for _, h := range r.Hosts {
			if query == h {
				return MatchHost
			} else if strings.HasSuffix(h, "."+query) {
				isPartial = true
			}
		}
		if isPartial {
			return MatchHostPartial
		}
	}

	sub := strings.ToLower(query)
	if strings.Contains(r.Label, sub) || strings.Contains(strings.ToLower(r.Title), sub) {
		return MatchTitle
	}
	for _, d := range r.Details {
		if strings.Contains(strings.ToLower(d.Label), sub) {
			return MatchDetail
		}
	}
	if strings.Contains(strings.ToLower(r.Notes), sub) {
		return MatchSubstring
	}
	for _, h := range r.Hosts {
		if strings.Contains(h, query) {
			return MatchSubstring
		}
	}
	return MatchNone
}

// FindRecord finds the unique record matching the specified query.  An exact
// match for a label is preferred; otherwise FindRecord will look for a full or
// partial match on host names, or other substrings in the title and notes. An
// error is reported if query matches no records, or more than 1.  If all is
// true, all records are considered; otherwise archived records are skipped.
//
// If the query begins with a tag (tag@label), the tag is removed and returned
// along with the result.
func FindRecord(db *kfdb.DB, query string, all bool) (FindResult, error) {
	found := FindRecords(db.Records, query)
	if !all {
		found = slice.Partition(found, func(r FoundRecord) bool {
			return !r.Record.Archived
		})
	}
	if len(found) == 0 {
		return FindResult{}, fmt.Errorf("no matches for %q", query)
	}
	tag, _, ok := strings.Cut(query, "@")
	if !ok {
		tag = ""
	}

	if best, ok := PickBest(found); ok {
		return FindResult{
			Tag:    tag,
			Index:  best.Index,
			Record: best.Record,
		}, nil
	}

	// At this point there was no unique match, report a diagnostic error.
	var hits []string
	for _, fr := range found {
		hits = append(hits, cmp.Or(fr.Record.Label, fr.Record.Title))
		if len(hits) > 5 {
			hits = append(hits, "...")
			break
		}
	}
	return FindResult{}, fmt.Errorf("found %d matches for %q (%s)",
		len(found), query, strings.Join(hits, ", "))
}

// PickBest reports whether there is a unique "best" match in a slice of found
// records, and if so returns that specific record. The records must be ordered
// in decreasing order of match quality.
func PickBest(found []FoundRecord) (FoundRecord, bool) {
	pos := 0
	for pos < len(found) {
		end := pos + 1
		for end < len(found) && found[end].Quality == found[pos].Quality {
			end++
		}
		if end-pos == 1 {
			return found[pos], true
		}
		pos = end
	}
	return FoundRecord{}, false
}

// FoundRecord is a single record reported by FindRecords.
type FoundRecord struct {
	Quality MatchQuality `json:"quality"` // how this record was matched
	Index   int          `json:"index"`   // the index of the record in the database
	Record  *kfdb.Record `json:"record"`  // the record itself
}

// FindRecords finds candidate records matching the specified query.  If the
// query begins with a tag (tag@label), the tag is removed.  Results are
// returned in order of quality from highest to lowest, with ties broken by
// index.
func FindRecords(recs []*kfdb.Record, query string) []FoundRecord {
	if _, rest, ok := strings.Cut(query, "@"); ok {
		query = rest
	}

	var out []FoundRecord
	for i, r := range recs {
		m := MatchRecord(query, r)
		if m == MatchNone {
			continue
		}
		out = append(out, FoundRecord{
			Quality: m,
			Index:   i,
			Record:  r,
		})
	}
	slices.SortFunc(out, func(a, b FoundRecord) int {
		if c := cmp.Compare(a.Quality, b.Quality); c != 0 {
			return c
		}
		return cmp.Compare(a.Index, b.Index)
	})
	return out
}

type hashpassConfig struct {
	Secret  string
	Tag     string
	Seed    string
	Length  int
	Charset Charset
}

func (h hashpassConfig) Generate() string {
	return HashedChars(h.Length, h.Charset, h.Secret, h.Seed, h.Tag)
}

func getHashpassConfig(db *kfdb.DB, rec *kfdb.Record, tag string) (out hashpassConfig, _ error) {
	out.Tag = tag

	h, d := value.At(rec.Hashpass), value.At(db.Defaults)
	dh := value.At(d.Hashpass)

	// Length
	out.Length = cmp.Or(h.Length, dh.Length)

	// Secret
	out.Secret = cmp.Or(h.SecretKey, dh.SecretKey)
	if out.Secret == "" {
		return out, errors.New("no hashpass secret is available")
	}

	// Seed
	out.Seed = h.Seed
	if out.Seed == "" && len(rec.Hosts) != 0 {
		out.Seed = rec.Hosts[0]
	}
	if out.Seed == "" {
		return out, fmt.Errorf("no hashpass seed is available")
	}

	// Charset
	out.Charset = AllChars
	if h.Punct != nil {
		if !*h.Punct {
			out.Charset &^= Symbols // punctuation is disabled for this record
		}
	} else if dh.Punct != nil && !*dh.Punct {
		out.Charset &^= Symbols // punctuation is disabled by default
	}
	return out, nil
}

// GenerateHashpass hashpass password for the specified record in the given
// database. It reports an error if no hashpass secret is available.  will be
func GenerateHashpass(db *kfdb.DB, rec *kfdb.Record, tag string) (string, error) {
	hc, err := getHashpassConfig(db, rec, tag)
	if err != nil {
		return "", err
	}
	return hc.Generate(), nil
}

// DBWatcher is a database connected with a file path watcher, that reloads the
// file when it is modified.
type DBWatcher struct {
	path       string
	fw         *fsnotify.Watcher
	passphrase string

	μ         sync.Mutex
	store     *kfdb.Store
	hasUpdate bool
}

// NewDBWatcher creates a watcher that automatically reloads the specified
// store from its original path when that path is modified.
func NewDBWatcher(s *kfdb.Store, dbPath, passphrase string) (*DBWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &DBWatcher{path: dbPath, fw: w, passphrase: passphrase, store: s}, nil
}

// Store returns the current database. If an update is available, Store tries
// to load it, but in case of error it falls back to the existing value.
func (w *DBWatcher) Store() *kfdb.Store {
	w.μ.Lock()
	defer w.μ.Unlock()

	for w.hasUpdate {
		f, err := os.Open(w.path)
		if err != nil {
			log.Printf("WARNING: Open database: %v (skipped)", err)
			w.hasUpdate = false // don't retry until it changes again
			break
		}
		defer f.Close()

		st, err := kfdb.Open(f, w.passphrase)
		if err != nil {
			log.Printf("WARNING: Load database: %v (skipped)", err)
			// N.B. Don't reset the flag; it might just be an incomplete update.
			break
		}
		log.Printf("Updated database %q", w.path)
		w.hasUpdate = false
		w.store = st
	}
	return w.store
}

// Run monitors for changes to the database path in w, and updates it when the
// underlying file is modified. Run should be run in a separate goroutine.  It
// exits when the watcher closes, or ctx ends.
func (w *DBWatcher) Run(ctx context.Context) {
	w.fw.Add(w.path)
	defer w.fw.Close()

	for {
		select {
		case evt, ok := <-w.fw.Events:
			if !ok {
				return
			}
			if evt.Op&fsnotify.Rename != 0 {
				log.Printf("Database %q has moved; stopping the watcher", w.path)
				return
			} else if evt.Op&(fsnotify.Create|fsnotify.Chmod) == 0 {
				continue // not relevant here
			}
			w.μ.Lock()
			w.hasUpdate = true // read by Store
			w.μ.Unlock()
		case e, ok := <-w.fw.Errors:
			if !ok {
				return
			}
			log.Printf("WARNING: Error watching %q: %v", w.path, e)
		case <-ctx.Done():
			return
		}
	}
}
