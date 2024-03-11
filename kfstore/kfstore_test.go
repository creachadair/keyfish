package kfstore_test

import (
	"bytes"
	crand "crypto/rand"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/creachadair/keyfish/kfstore"
	"github.com/creachadair/mds/mtest"
	gocmp "github.com/google/go-cmp/cmp"
)

type testDB struct {
	V string `json:"v"`
}

func TestStore(t *testing.T) {
	// Stub out the random generator for the test so that we don't thrash the
	// system entropy pool for unit tests.
	save := crand.Reader
	crand.Reader = mrand.New(mrand.NewSource(20240309152407))
	defer func() { crand.Reader = save }()

	const testKey = "00000000000000000000000000000000"
	const altKey = "11111111111111111111111111111111"
	const keySalt = "fleur de sel"
	const testValue = "not all those who wander are lost"

	// A KeyFunc that verifies we got the expected keySalt plumbed in from a
	// store that has it set.
	testKeyGen := func(s string) kfstore.KeyFunc {
		return func(salt []byte) []byte {
			if string(salt) != keySalt {
				t.Errorf("Key salt is %q, want %q", salt, keySalt)
			}
			return []byte(s)
		}
	}

	s, err := kfstore.New[testDB]([]byte(testKey), []byte(keySalt), nil)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	s.DB().V = testValue

	var buf bytes.Buffer
	if _, err := s.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: unexpected error: %v", err)
	}
	t.Logf("Encrypted packet: %s", buf.String())

	t.Run("RoundTrip", func(t *testing.T) {
		s2, err := kfstore.Open[testDB](bytes.NewReader(buf.Bytes()), testKeyGen(testKey))
		if err != nil {
			t.Fatalf("Open: unexpected error: %v", err)
		}

		if diff := gocmp.Diff(s2.DB(), &testDB{V: testValue}); diff != "" {
			t.Errorf("Opened database (-got, +want):\n%s", diff)
		}
	})

	t.Run("WrongAccessKey", func(t *testing.T) {
		s2, err := kfstore.Open[testDB](bytes.NewReader(buf.Bytes()), kfstore.AccessKey(altKey))
		if err == nil {
			t.Fatalf("Open with bad key: got %v, want error", s2)
		} else {
			t.Logf("Open: got expected error: %v", err)
		}
	})

	t.Run("WrongVersion", func(t *testing.T) {
		bad := strings.ReplaceAll(buf.String(), kfstore.Format, "kf:v9")
		s2, err := kfstore.Open[testDB](strings.NewReader(bad), kfstore.AccessKey(testKey))
		if err == nil {
			t.Fatalf("Open with bad format: got %v, want error", s2)
		} else {
			t.Logf("Open: got expected error: %v", err)
		}
	})

	t.Run("Rekey", func(t *testing.T) {
		s2, err := kfstore.New([]byte(altKey), []byte(keySalt), s.DB())
		if err != nil {
			t.Fatalf("New: unexpected error: %v", err)
		}
		buf.Reset()
		if _, err := s2.WriteTo(&buf); err != nil {
			t.Fatalf("WriteTo: unexpected error: %v", err)
		}
		t.Logf("Encrypted packet: %s", buf.String())
	})

	t.Run("Reopen", func(t *testing.T) {
		s2, err := kfstore.Open[testDB](bytes.NewReader(buf.Bytes()), testKeyGen(altKey))
		if err != nil {
			t.Fatalf("Open: unexpected error: %v", err)
		}
		if diff := gocmp.Diff(s2.DB(), s.DB()); diff != "" {
			t.Errorf("Reopened database (-got, +want):\n%s", diff)
		}
	})

	mtest.MustPanicf(t, func() {
		var pnil *kfstore.Store[testDB]
		pnil.DB()
	}, "pnil.DB() should panic")
	mtest.MustPanicf(t, func() {
		var zero kfstore.Store[testDB]
		zero.DB()
	}, "zero.DB() should panic")
}
