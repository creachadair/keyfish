// Package kfdb implements a database of sensitive values maintained by keyfish.
package kfdb

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/creachadair/keyfish/kfstore"
	"github.com/creachadair/otp/otpauth"
	"golang.org/x/crypto/hkdf"
	yaml "gopkg.in/yaml.v3"
)

// Store is an alias for kfstore.Store to avoid the need to import the kfstore
// package directly.
type Store = kfstore.Store[DB]

// A DB is a database of sensitive data managed by keyfish.
type DB struct {
	// Defaults are default values for certain record fields.
	Defaults *Defaults `json:"defaults,omitzero" yaml:"defaults,omitempty"`

	// Records are the data records contained in the database.
	Records []*Record `json:"records,omitempty" yaml:"records,omitempty"`
}

// Defaults are default values applied to records that do not define their own
// values for certain fields.
type Defaults struct {
	// WebUI, if set, contains defaults for the web UI.
	Web *WebConfig `json:"webConfig,omitzero" yaml:"web-config,omitempty"`
}

// A Record records an item of interest such as a login account.
type Record struct {
	// Label is a short identifier for this record.
	Label string `json:"label,omitzero" yaml:"label,omitempty"`

	// Title is a human-readable title for this record.
	Title string `json:"title,omitzero" yaml:"title,omitempty"`

	// Archived, if true, indicates the record is archived and should not be
	// shown in default listings and search results.
	Archived bool `json:"archived,omitzero" yaml:"archived,omitempty"`

	// Username is the user name or login associated with this record.
	Username string `json:"username,omitzero" yaml:"username,omitempty"`

	// Hosts are optional hostnames associated with this record.
	Hosts Strings `json:"hosts,omitzero" yaml:"hosts,flow,omitempty"`

	// Addrs are e-mail addresses associated with this record.
	Addrs Strings `json:"addrs,omitzero" yaml:"addrs,flow,omitempty"`

	// Tags are optional query tags associated with this record.
	Tags []string `json:"tags,omitempty" yaml:"tags,flow,omitempty"`

	// Notes are optional human-readable notes.
	Notes string `json:"notes,omitzero" yaml:"notes,omitempty"`

	// Password, if non-empty, is a generated password.
	Password string `json:"password,omitzero" yaml:"password,omitempty"`

	// OldPassword, if non-empty, is a previous generated password.  It is
	// stored so password rotation can preserve the previous value.
	OldPassword string `json:"oldPassword,omitzero" yaml:"old-password,omitempty"`

	// OTP, if non-nil, is used to generate one-time 2FA codes.
	OTP *otpauth.URL `json:"otp,omitzero" yaml:"otp,omitempty"`

	// Details are optional labelled data annotations.
	Details []*Detail `json:"details,omitempty" yaml:"details,omitempty"`
}

// Detail is a labelled data annotation for a record.
type Detail struct {
	// Label is a human-readable label for the detail.
	Label string `json:"label" yaml:"label"`

	// Hidden, if true, indicates the value is sensitive and should not be
	// displayed plainly unless the user requests it.
	Hidden bool `json:"hidden,omitzero" yaml:"hidden,omitempty"`

	// Value is the display content of the detail.
	Value string `json:"value" yaml:"value"`
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

// UnmarshalYAML implements yaml.Unmarshaler. If the input is an array, it is
// unmarshaled normally; otherwise it unmarshals a single value.
func (a *array[T]) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			*a = nil
			return nil
		}
		type shim[T any] array[T]
		return node.Decode((*shim[T])(a))

	case yaml.ScalarNode:
		if node.ShortTag() != "!!str" {
			return fmt.Errorf("invalid value %q", node.ShortTag())
		}
		*a = make(array[T], 1)
		return node.Decode(&(*a)[0])

	default:
		return fmt.Errorf("invalid node type %v", node.Kind)
	}
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

// WebConfig is a collection of settings for the web UI.
type WebConfig struct {
	// LockPIN is the code used to unlock the web UI.
	LockPIN string `json:"lockPIN,omitempty" yaml:"lock-pin,omitempty"`

	// LockTimeout, if set, is the timeout after which the web UI will
	// automatically lock itself if not accessed.
	LockTimeout Duration `json:"lockTimeout,omitempty" yaml:"lock-timeout,omitempty"`
}

// A Duration represents the encoding of a [time.Duration] in JSON using a
// string representation compatible with [time.ParseDuration].
//
// TODO(creachadair): Move this somewhere more common.
type Duration int64

// MarshalText implements [encoding.TextMarshaler], to encode d as a string in
// the standard [time.Duration] format. It never reports an error.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler], to decode d from a
// string in the standard [time.Duration] format.
func (d *Duration) UnmarshalText(text []byte) error {
	dur, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// Get returns d as a [time.Duration].
func (d Duration) Get() time.Duration { return time.Duration(d) }
