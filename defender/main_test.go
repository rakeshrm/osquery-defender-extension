package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
)

func TestKnownArgs(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("socket", "", "")
	fs.Int("timeout", 3, "")
	fs.Bool("verbose", false, "")
	got := knownArgs(fs, []string{"--socket", "/s", "--foo=bar", "--timeout", "5", "--unknown", "x", "--verbose", "--flagonly", "-x", "pos"})
	want := []string{"--socket", "/s", "--timeout", "5", "--verbose"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q want %q", got, want)
	}
	if err := fs.Parse(got); err != nil {
		t.Fatal(err)
	}
}

func TestDecryptTo(t *testing.T) {
	out := filepath.Join(t.TempDir(), "x.db")
	src := filepath.Join("internal", "mpengine", "testdata", "oracle", "known_key")
	var buf bytes.Buffer
	if err := decryptTo(&buf, src, out, mpengine.Options{}); err != nil {
		t.Fatal(err)
	}
	var info mpengine.Info
	if err := json.Unmarshal(buf.Bytes(), &info); err != nil || info.KeySource != "known:1.1.26100.4" {
		t.Fatalf("info %+v: %v", info, err)
	}
	b, err := os.ReadFile(out)
	if err != nil || !bytes.HasPrefix(b, []byte("SQLite format 3\x00")) {
		t.Fatalf("output: %v", err)
	}
	if err := decryptTo(&buf, src, out, mpengine.Options{}); err == nil {
		t.Error("overwrote existing output")
	}
}

// Finding 7: a derived keystream that yields garbage must not be written.
func TestDecryptDerivedGarbage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "mpenginedb.db")
	b := make([]byte, 128<<10)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[16], b[17] = 0x00, 0x01 // page size 65536 (two pages)
	if err := os.WriteFile(src, b, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.db")
	var buf bytes.Buffer
	err := decryptTo(&buf, src, out, mpengine.Options{DeriveKey: true})
	if err == nil {
		t.Fatal("decryptTo succeeded on random bytes")
	}
	if _, serr := os.Stat(out); !os.IsNotExist(serr) {
		t.Errorf("output written: %v (decrypt err %v)", serr, err)
	}
	if buf.Len() != 0 {
		t.Errorf("info printed: %s", buf.String())
	}
	t.Log(err)
}
