// Package kfstore provides a self-contained encrypted data store for sensitive
// data managed by keyfish. A Store is packaged as a JSON object containing an
// encrypted database packet.
//
// # Storage Format
//
// On disk, the kfstore is a single JSON object in this layout:
//
//	{
//	   "format":  "ks1",
//	   "dataKey": "<base64-encoded-data-key>",
//	   "data":    "<base64-encoded-data>",
//	   "keySalt": "<base64-encoded-key-salt>"
//	}
//
// The data value is zlib-compressed and encrypted with the data key using the
// AEAD construction over chacha20poly1305 with the format as extra data.
//
// The data key is a cryptographically randomly generated key, encrypted with a
// user-provided access key using the AEAD construction over chacha20poly1305.
//
// The key salt is a plaintext salt value provided by the caller for use in
// access key generation via a KDF. This field is optional and may be empty.
package kfstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/creachadair/mds/mbits"
)

// A Store is an encrypted store containing a user-provide DB value.
// The concrete type of DB must be JSON-marshalable.
//
// The contents of a store are encoded as a JSON object, inside which the
// database is encrypted with chacha20poly1305 using the AEAD construction and
// a randomly-generated data key. The data key is itself encrypted (using the
// same construction) with a caller-provided access key, and stored alongside
// the data.
type Store[DB any] struct {
	dataKeyEncrypted []byte // enceypted data key
	dataKeyPlain     []byte // plaintext data key
	accessKeySalt    []byte // access key generation salt (optional)
	db               *DB    // the unencrypted database
}

// New creates a new store using accessKey to encrypt the store key.
//
// If the accessKey was generated using a key-derivation function, the salt
// value for the KDF may be passed as keySalt, and it will be stored in plain
// text alongside the data. This value is made available to the caller when the
// store is reopened. The keySalt is optional and may be left nil or empty.
//
// If init != nil, it is used as the initial database for the store; otherwise
// an empty DB is created. The concrete type of DB must be JSON-marshalable.
func New[DB any](accessKey, keySalt []byte, init *DB) (*Store[DB], error) {
	if len(accessKey) != AccessKeyLen {
		return nil, fmt.Errorf("access key is %d bytes, want %d", len(accessKey), AccessKeyLen)
	}
	plain, encrypted, err := generateAndEncryptKey(accessKey)
	if err != nil {
		return nil, fmt.Errorf("data key: %w", err)
	}
	if init == nil {
		init = new(DB)
	}
	return &Store[DB]{
		dataKeyPlain:     plain,
		dataKeyEncrypted: encrypted,
		accessKeySalt:    keySalt,
		db:               init,
	}, nil
}

// Open opens a Store from the contents of r. Open calls accessKey with the
// stored key derivation salt (which may be empty) to obtain the access key,
// which is used to decrypt the stored data.
func Open[DB any](r io.Reader, accessKey KeyFunc) (*Store[DB], error) {
	// Consume the entire input so there cannot be extra junk at the end of the
	// encoding when stored in a file.
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	// Decode the wrapper {"format":"ks1","dataKey":<dk>,"data":<data>,"keySalt":<salt>}
	// The version is checked when we decrypt and authenticate the extra data.
	var s storeJSON
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("decode input: %w", err)
	}

	// Generate the access key...
	akey := accessKey(s.KeySalt)

	// Decrypt the data key with the access key.
	dataKey, err := decryptWithKey(akey, s.DataKey, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt data key: %w", err)
	}

	// Decrypt the data payload with the data key, and verify that the format
	// version matches what we encrypted with.
	data, err := decryptWithKey(dataKey, s.Data, []byte(s.Format))
	if err != nil {
		mbits.Zero(dataKey)
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	// Decode the database and discard the raw plaintext.
	var db DB
	err = json.Unmarshal(decompressData(data), &db)
	mbits.Zero(data)
	if err != nil {
		mbits.Zero(dataKey)
		return nil, fmt.Errorf("decode database: %w", err)
	}

	return &Store[DB]{
		dataKeyEncrypted: s.DataKey,
		dataKeyPlain:     dataKey,
		accessKeySalt:    s.KeySalt,
		db:               &db,
	}, nil
}

// WriteTo encodes and encrypts the current contents of s and writes it to w.
func (s *Store[DB]) WriteTo(w io.Writer) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("invalid store value")
	}

	data, err := json.Marshal(s.db)
	if err != nil {
		return 0, fmt.Errorf("encode database: %w", err)
	}
	encData, err := encryptWithKey(s.dataKeyPlain, compressData(data), []byte(Format))
	if err != nil {
		return 0, fmt.Errorf("encrypt data: %w", err)
	}
	pkt, err := json.Marshal(storeJSON{
		Format:  Format,
		DataKey: s.dataKeyEncrypted, // N.B. do not persist the plaintext
		Data:    encData,
		KeySalt: s.accessKeySalt,
	})
	if err != nil {
		mbits.Zero(data)
		return 0, fmt.Errorf("encode output: %w", err)
	}
	nw, err := w.Write(pkt)
	return int64(nw), err
}

// DB returns the database associated with s. The result is never nil.
// If s == nil or points to an invalid Store, DB panics.
func (s *Store[DB]) DB() *DB {
	if s.db == nil {
		panic("uninitialized store")
	}
	return s.db
}

// storeJSON is the JSON structure used to persist a Store.
type storeJSON struct {
	Format  string `json:"format"`            // currently kfstore.Format (ks1)
	DataKey []byte `json:"dataKey"`           // encrypted with accessKey
	Data    []byte `json:"data"`              // encrypted with D(accessKey, dataKey)
	KeySalt []byte `json:"keySalt,omitempty"` // access key derivation salt (optional)

	// The data are compressed with zlib prior to encryption.
}
