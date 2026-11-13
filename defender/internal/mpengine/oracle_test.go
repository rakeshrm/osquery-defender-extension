package mpengine_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
)

// Fixtures in testdata/oracle were generated and self-checked by an independent
// Python implementation (see testdata/oracle/README.md).
func oracleDir(name string) string { return filepath.Join("testdata", "oracle", name) }

func TestOracleImages(t *testing.T) {
	cases := []struct {
		name    string
		sha     string
		commits int
	}{
		{"known_key", "4eb4d9ed316c11a23f4fdd1026f13c3428b45c439aa5d9543448c219c26c4dec", 4},
		{"plain", "4eb4d9ed316c11a23f4fdd1026f13c3428b45c439aa5d9543448c219c26c4dec", 4},
		{"corrupt_wal", "29e0ec0861065ac7006e75e85dba47e64a491ba3c6d7f497185a545ed1cf5e24", 3},
		{"no_wal", "0cd0bb33ec2b56902d2012b731136d25247cded525e0f071530e4d79a1f12040", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img, info, err := mpengine.Decrypt(oracleDir(tc.name), mpengine.Options{})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			sum := sha256.Sum256(img)
			if got := hex.EncodeToString(sum[:]); got != tc.sha {
				t.Errorf("image sha256 = %s, want %s", got, tc.sha)
			}
			if info.WALCommits != tc.commits {
				t.Errorf("WALCommits = %d, want %d", info.WALCommits, tc.commits)
			}
			if tc.name == "corrupt_wal" && !strings.Contains(info.WALNote, "frame 10") {
				t.Errorf("WALNote = %q, want mention of frame 10", info.WALNote)
			}
			wantProt := "rc4"
			if tc.name == "plain" {
				wantProt = "none"
			}
			if info.Protection != wantProt {
				t.Errorf("Protection = %q, want %q", info.Protection, wantProt)
			}
			compareOracleRows(t, tc.name)
		})
	}
}

func compareOracleRows(t *testing.T, name string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(oracleDir(name), "expected_rows.json"))
	if err != nil {
		t.Fatalf("read expected_rows.json: %v", err)
	}
	var expected map[string][]map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&expected); err != nil {
		t.Fatalf("parse expected_rows.json: %v", err)
	}

	snap, err := mpengine.Open(oracleDir(name), mpengine.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer snap.Close()

	var ic string
	if err := snap.DB.QueryRow("PRAGMA integrity_check").Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity_check = %q, %v", ic, err)
	}

	for table, wantRows := range expected {
		rows, err := snap.DB.Query(fmt.Sprintf(`SELECT * FROM "%s" ORDER BY ID`, table))
		if err != nil {
			t.Errorf("%s: query: %v", table, err)
			continue
		}
		cols, _ := rows.Columns()
		var got []map[string]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatalf("%s: scan: %v", table, err)
			}
			m := map[string]any{}
			for i, c := range cols {
				m[c] = normalize(vals[i])
			}
			got = append(got, m)
		}
		rows.Close()

		if len(got) != len(wantRows) {
			t.Errorf("%s: %d rows, want %d", table, len(got), len(wantRows))
			continue
		}
		for i := range wantRows {
			want := map[string]any{}
			for k, v := range wantRows[i] {
				want[k] = normalize(v)
			}
			if !reflect.DeepEqual(got[i], want) {
				t.Errorf("%s row %d:\n got  %v\n want %v", table, i, got[i], want)
			}
		}
	}
}

// normalize maps SQLite and JSON values onto a common representation:
// integers -> int64, blobs -> lowercase hex string, text -> string, NULL -> nil.
func normalize(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		return hex.EncodeToString(x)
	case int64:
		return x
	case float64:
		return x
	case string:
		return x
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	default:
		return fmt.Sprint(x)
	}
}

func TestOracleJunk(t *testing.T) {
	if _, _, err := mpengine.Decrypt(oracleDir("junk"), mpengine.Options{}); err == nil {
		t.Fatal("expected error for junk input")
	}
	if _, err := mpengine.Open(oracleDir("junk"), mpengine.Options{}); err == nil {
		t.Fatal("expected Open error for junk input")
	}
}

// A frame with a valid salt and checksum chain but pgno 0 or an absurd pgno
// must not panic or allocate unbounded memory; earlier commits still apply.
func TestWALFrameBounds(t *testing.T) {
	for _, pgno := range []uint32{0, 0x7fffffff} {
		t.Run(fmt.Sprintf("pgno_%d", pgno), func(t *testing.T) {
			dir := t.TempDir()
			db, err := os.ReadFile(filepath.Join(oracleDir("known_key"), "mpenginedb.db"))
			if err != nil {
				t.Fatal(err)
			}
			wal, err := os.ReadFile(filepath.Join(oracleDir("known_key"), "mpenginedb.db-wal"))
			if err != nil {
				t.Fatal(err)
			}
			ps := int(binary.BigEndian.Uint32(wal[8:12]))
			big := binary.BigEndian.Uint32(wal[0:4])&1 == 1
			frameSize := 24 + ps
			last := 32 + ((len(wal)-32)/frameSize-1)*frameSize
			s0 := binary.BigEndian.Uint32(wal[last+16 : last+20])
			s1 := binary.BigEndian.Uint32(wal[last+20 : last+24])

			fh := make([]byte, 24)
			binary.BigEndian.PutUint32(fh[0:4], pgno)
			binary.BigEndian.PutUint32(fh[4:8], pgno) // commit frame
			copy(fh[8:16], wal[16:24])                // salts from the WAL header
			data := append([]byte(nil), wal[last+24:last+frameSize]...)
			s0, s1 = mpengine.WalCksum(fh[:8], s0, s1, big)
			s0, s1 = mpengine.WalCksum(data, s0, s1, big)
			binary.BigEndian.PutUint32(fh[16:20], s0)
			binary.BigEndian.PutUint32(fh[20:24], s1)
			wal = append(append(wal, fh...), data...)

			if err := os.WriteFile(filepath.Join(dir, "mpenginedb.db"), db, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "mpenginedb.db-wal"), wal, 0o600); err != nil {
				t.Fatal(err)
			}

			img, info, err := mpengine.Decrypt(dir, mpengine.Options{})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if info.WALCommits != 4 {
				t.Errorf("WALCommits = %d, want 4 (crafted frame must be rejected)", info.WALCommits)
			}
			if info.WALNote == "" {
				t.Error("expected WALNote describing the rejected frame")
			}
			sum := sha256.Sum256(img)
			if got := hex.EncodeToString(sum[:]); got != "4eb4d9ed316c11a23f4fdd1026f13c3428b45c439aa5d9543448c219c26c4dec" {
				t.Errorf("image changed by crafted frame: %s", got)
			}
		})
	}
}
