package kfdb_test

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	mrand "math/rand"
	"testing"

	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/mds/mtest"
	gocmp "github.com/google/go-cmp/cmp"
)

func TestDB(t *testing.T) {
	mtest.Swap[io.Reader](t, &crand.Reader, mrand.New(mrand.NewSource(20240309152407)))

	const testPass = "full plate and packing steel"

	s, err := kfdb.New(testPass, nil)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	s.DB().Defaults = &kfdb.Defaults{
		Username: "Minsc & Boo together again",
	}

	var buf bytes.Buffer
	if _, err := s.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: unexpected error: %v", err)
	}
	t.Logf("Encrypted packet: %s", buf.String())

	t.Run("RoundTrip", func(t *testing.T) {
		s2, err := kfdb.Open(bytes.NewReader(buf.Bytes()), testPass)
		if err != nil {
			t.Fatalf("Open: unexpected error: %v", err)
		}

		if diff := gocmp.Diff(s2.DB(), s.DB()); diff != "" {
			t.Errorf("Reopened database (-got, +want):\n%s", diff)
		}
	})

	t.Run("WrongPass", func(t *testing.T) {
		s2, err := kfdb.Open(bytes.NewReader(buf.Bytes()), "wrong wrong wrong")
		if err == nil {
			t.Fatalf("Open: got %+v, want error", s2)
		} else {
			t.Logf("Open with wrong pass: got expected error: %v", err)
		}
	})
}

func TestDB_Settings(t *testing.T) {
	db := new(kfdb.DB)

	var s1 []string
	if err := db.UnmarshalSettings("s1", &s1); !errors.Is(err, kfdb.ErrNoSettings) {
		t.Errorf("Unmarshal s1: got (%+v, %v), want error %v", s1, err, kfdb.ErrNoSettings)
	}
	if err := db.MarshalSettings("s1", []string{"flying", "purple", "people"}); err != nil {
		t.Errorf("Marshal s1: got error %v, want nil", err)
	}

	type stuff struct {
		C string
		I string
	}
	input := stuff{C: "aardvark", I: "trombone"}
	if err := db.MarshalSettings("s2", input); err != nil {
		t.Errorf("Marshal s2: got error %v, want nil", err)
	}
	var s2 stuff
	if err := db.UnmarshalSettings("s2", &s2); err != nil {
		t.Errorf("Unmarshal s2: got error %v, want nil", err)
	} else if diff := gocmp.Diff(s2, input); diff != "" {
		t.Errorf("Unmarshal s2 (-got, +want):\n%s", diff)
	}

	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(db)
	t.Logf("DB: %s", buf.String())
}
