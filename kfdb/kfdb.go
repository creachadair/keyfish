// Package kfdb implements a database of sensitive values maintained by keyfish.
package kfdb

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/creachadair/keyfish/kfstore"
	"github.com/creachadair/otp/otpauth"
	"golang.org/x/crypto/hkdf"
)

// Store is an alias for kfstore.Store to avoid the need to import the kfstore
// package directly.
type Store = kfstore.Store[DB]

// A DB is a database of sensitive data managed by keyfish.
type DB struct {
	// Defaults are default values for certain record fields.
	Defaults *Defaults `json:"defaults,omitempty"`

	// Settings is an opaque collection of tool-specific settings.  Each tool
	// should use its own unique key in this map. The format of the value is the
	// responsibility of the tool that defines it.
	Settings map[string]json.RawMessage `json:"settings,omitempty"`

	// Records are the data records contained in the database.  Each record is
	// identified by a non-empty string label.
	Records map[string]*Record `json:"records,omitempty"`
}

// ErrNoSettings is reported by UnmarshalSettings if the requested settings key
// is not defined on the database.
var ErrNoSettings = errors.New("settings key not found")

// UnmarshalSettings unmarshals the settings corresponding to key into v.  If
// no settings for that key are available, it reports ErrNoSettings and does
// not modify v.
func (db *DB) UnmarshalSettings(key string, v any) error {
	src, ok := db.Settings[key]
	if !ok || len(src) == 0 {
		return fmt.Errorf("unmarshal %q: %w", key, ErrNoSettings)
	}
	return json.Unmarshal(src, v)
}

// MarshalSettings marshals the specified value into the settings map under
// key, replacing any existing value for that key.
func (db *DB) MarshalSettings(key string, v any) error {
	bits, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal %q: %w", key, err)
	}
	if db.Settings == nil {
		db.Settings = make(map[string]json.RawMessage)
	}
	db.Settings[key] = bits
	return nil
}

// Defaults are default values applied to records that do not define their own
// values for certain fields.
type Defaults struct {
	// Username, if set, is used as the default username for records that do not
	// provide one.
	Username string `json:"username,omitempty"`

	// Addr, if set, is used as the default e-mail address for records that do
	// not provide one.
	Addr string `json:"addr,omitempty"`

	// PasswordLength, if positive, is used as the default password length when
	// generating a password that does not specify its own length.
	PasswordLength int `json:"passwordLength,omitempty"`

	// Hashpass, if set, contains defaults for the hashpass generator.
	Hashpass *Hashpass `json:"hashpass,omitempty"`
}

// A Record records an item of interest such as a login account.
type Record struct {
	// Title is a human-readable title for this record.
	Title string `json:"title,omitempty"`

	// Username is the user name or login associated with this record.
	Username string `json:"username,omitempty"`

	// Hosts are optional hostnames associated with this record.
	Hosts Strings `json:"hosts,omitempty"`

	// Addrs are e-mail addresses associated with this record.
	Addrs Strings `json:"addrs,omitempty"`

	// Tags are optional query tags associated with this record.
	Tags []string `json:"tags,omitempty"`

	// Notes are optional human-readable notes.
	Notes string `json:"notes,omitempty"`

	// Details are optional labelled data annotations.
	Details []*Detail `json:"details,omitempty"`

	// Hashpass, if non-nil, is a configuration for a hashed password.
	Hashpass *Hashpass `json:"hashpass,omitempty"`

	// Password, if non-empty, is a generated password.
	Password string `json:"password,omitempty"`

	// OTP, if non-nil, is used to generate one-time 2FA codes.
	OTP *otpauth.URL `json:"otp,omitempty"`

	// Archived, if true, indicates the record is archived and should not be
	// shown in default listings and search results.
	Archived bool `json:"archived,omitempty"`
}

// Detail is a labelled data annotation for a record.
type Detail struct {
	// Label is a human-readable label for the detail.
	Label string `json:"label"`

	// Hidden, if true, indicates the value is sensitive and should not be
	// displayed plainly unless the user requests it.
	Hidden bool `json:"hidden,omitempty"`

	// Value is the display content of the detail.
	Value string `json:"value"`
}

// Hashpass contains settings for a "hashed" password generator.
// See [github.com/creachadair/keyfish/hashpass.Context] for details on the
// algorithm used for password generation.
type Hashpass struct {
	// SecretKey, if set, is used as the hashpass generator key.
	SecretKey string `json:"secretKey,omitempty"`

	// Seed is the seed used for password generation. If empty, the first
	// element of the Hosts for the record is used.
	Seed string `json:"seed,omitempty"`

	// Length specifies the length of the generated password in characters.
	// If zero, the default length is used.
	Length int `json:"length,omitempty"`

	// Format, if non-empty, defines the layout of the generated password.
	Format string `json:"format,omitempty"`

	// Tag, if non-empty, defines a record tag to include in the generator hash
	// if one is not provided explicitly.
	Tag string `json:"tag,omitempty"`

	// Punct, if non-nil, specifies whether punctuation should be included in
	// the generated password. This is ignored if the Format is set.
	Punct *bool `json:"punct,omitempty"`
}

// Strings is a convenience alias for an array of strings that decodes from
// JSON as either a single string or an array of multiple strings.
type Strings = array[string]

// An array represents an array of objects that encodes in JSON as either a
// single JSON value, or as a JSON array with multiple values.
type array[T any] []T

// MarshalJSON implements json.Marshaler. If len(a) == 1 it marshals the single
// value a[0] by itself; otherwise it produces an array.
func (a array[T]) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	type shim[T any] array[T]
	return json.Marshal(shim[T](a))
}

// UnmarshalJSON implements json.Unmarshaler. If the input is an array, it is
// unmarshaled normally. If the input is "null" it unmarshals to an empty
// slice.  Otherwise it unmarshals a slice of a single value.
func (a *array[T]) UnmarshalJSON(data []byte) error {
	if data[0] == '[' {
		type shim[T any] array[T]
		return json.Unmarshal(data, (*shim[T])(a))
	} else if bytes.Equal(data, []byte("null")) {
		*a = nil
		return nil
	}
	*a = make(array[T], 1)
	return json.Unmarshal(data, &(*a)[0])
}

// Open reads a DB store from r using the given passphrase to generate a store
// access key.
func Open(r io.Reader, passphrase string) (*Store, error) {
	return kfstore.Open[DB](r, deriveKey(passphrase))
}

// New creates a new DB store using the given passphrase to generate a store
// access key. If init != nil, it is used as the initial database.
func New(passphrase string, init *DB) (*Store, error) {
	buf := make([]byte, 2*kfstore.AccessKeyLen)
	accessKey, keySalt := buf[:kfstore.AccessKeyLen], buf[kfstore.AccessKeyLen:]
	if _, err := crand.Read(keySalt); err != nil {
		return nil, fmt.Errorf("generate access key salt: %w", err)
	}
	h := hkdf.New(sha256.New, []byte(passphrase), keySalt, nil)
	if _, err := io.ReadFull(h, accessKey); err != nil {
		return nil, fmt.Errorf("generate access key: %w", err)
	}
	return kfstore.New(accessKey, keySalt, init)
}

func deriveKey(passphrase string) kfstore.KeyFunc {
	return func(salt []byte) []byte {
		h := hkdf.New(sha256.New, []byte(passphrase), salt, nil)
		key := make([]byte, kfstore.AccessKeyLen)
		if _, err := io.ReadFull(h, key); err != nil {
			panic(fmt.Sprintf("derive key: %v", err))
		}
		return key
	}
}
