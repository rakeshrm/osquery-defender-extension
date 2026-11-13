package main

import (
	"bytes"
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
