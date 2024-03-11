package kfstore

import (
	"bytes"
	"compress/zlib"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// AccessKeyLen is the required length in bytes of an access key.
const AccessKeyLen = chacha20poly1305.KeySize // 32 bytes

// Format is the storage format label supported by this package.
const Format = "ks1"

// KeyFunc is a function that takes a salt value as input and returns an
// encryption key.
type KeyFunc func(salt []byte) []byte

// AccessKey returns a KeyFunc that ignores its argument and returns the
// specified string as the key. It is a convenience wrapper for passing
// pre-generated key.
func AccessKey[S ~string | ~[]byte](key S) KeyFunc {
	return func(ignored []byte) []byte { return []byte(key) }
}

func decryptWithKey(key, data, extra []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("initialize decryption key: %w", err)
	}
	if len(data) < aead.NonceSize() {
		return nil, errors.New("malformed input: short nonce")
	}
	nonce, ctext := data[:aead.NonceSize()], data[aead.NonceSize():]
	return aead.Open(nil, nonce, ctext, extra)
}

func encryptWithKey(key, data, extra []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("initialize encryption key: %w", err)
	}
	buf := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err := crand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return aead.Seal(buf, buf, data, extra), nil
}

func generateAndEncryptKey(accessKey []byte) (plain, encrypted []byte, _ error) {
	pkey := make([]byte, AccessKeyLen)
	if _, err := crand.Read(pkey); err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	ekey, err := encryptWithKey(accessKey, pkey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt key: %w", err)
	}
	return pkey, ekey, nil
}

func compressData(data []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(data)
	if err := w.Close(); err != nil {
		panic(fmt.Sprintf("zlib close: %v", err))
	}
	return buf.Bytes()
}

func decompressData(data []byte) []byte {
	rc, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		panic(fmt.Sprintf("zlib reader: %v", err))
	}
	defer rc.Close()
	dec, err := io.ReadAll(rc)
	if err != nil {
		panic(fmt.Sprintf("zlib read: %v", err))
	}
	return dec
}
