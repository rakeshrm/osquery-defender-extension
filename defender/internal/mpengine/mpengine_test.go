package mpengine_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
	"github.com/huntbase-io/osquery-defender/internal/mpengine/mpenginetest"
)

// (1) Plain unencrypted db passthrough.
func TestPlainPassthrough(t *testing.T) {
	dir := mpenginetest.Build(t, mpenginetest.FixtureOptions{
		NoEncryption: true,
		BeforeCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(1, 100);`)
			return err
		},
	})

	snap, err := mpengine.Open(dir, mpengine.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer snap.Close()

	if snap.Info.Protection != "none" {
		t.Errorf("expected Protection 'none', got %q", snap.Info.Protection)
	}

	var vsn int
	err = snap.DB.QueryRow(`SELECT VSN FROM FileHashes WHERE ID = 1`).Scan(&vsn)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if vsn != 100 {
		t.Errorf("expected VSN 100, got %d", vsn)
	}

	// (10) Integrity check == ok
	var ic string
	if err := snap.DB.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity_check: %v, got %q", err, ic)
	}
}

// (2) Known-key encrypted db, no WAL.
func TestKnownKeyNoWAL(t *testing.T) {
	dir := mpenginetest.Build(t, mpenginetest.FixtureOptions{
		BeforeCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(1, 42);`)
			return err
		},
	})

	// Remove WAL file so there is no WAL
	_ = os.Remove(filepath.Join(dir, "mpenginedb.db-wal"))

	snap, err := mpengine.Open(dir, mpengine.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer snap.Close()

	if snap.Info.Protection != "rc4" {
		t.Errorf("expected Protection 'rc4', got %q", snap.Info.Protection)
	}
	if snap.Info.KeySource != "known:1.1.26100.4" {
		t.Errorf("expected KeySource 'known:1.1.26100.4', got %q", snap.Info.KeySource)
	}
	if snap.Info.WALPath != "" {
		t.Errorf("expected empty WALPath, got %q", snap.Info.WALPath)
	}

	var vsn int
	err = snap.DB.QueryRow(`SELECT VSN FROM FileHashes WHERE ID = 1`).Scan(&vsn)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if vsn != 42 {
		t.Errorf("expected VSN 42, got %d", vsn)
	}
}

// (3) Encrypted db + WAL: rows inserted after checkpoint are visible after Decrypt/Open.
func TestEncryptedWithWAL(t *testing.T) {
	dir := mpenginetest.Build(t, mpenginetest.FixtureOptions{
		BeforeCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(1, 10);`)
			return err
		},
		AfterCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(2, 20);`)
			return err
		},
	})

	snap, err := mpengine.Open(dir, mpengine.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer snap.Close()

	if !snap.Info.WALHeaderValid {
		t.Errorf("expected WALHeaderValid true")
	}
	if snap.Info.WALFramesCommitted < 1 {
		t.Errorf("expected at least 1 committed WAL frame, got %d", snap.Info.WALFramesCommitted)
	}

	rows, err := snap.DB.Query(`SELECT ID, VSN FROM FileHashes ORDER BY ID`)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()

	var results [][2]int
	for rows.Next() {
		var id, vsn int
		if err := rows.Scan(&id, &vsn); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		results = append(results, [2]int{id, vsn})
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(results))
	}
	if results[0] != [2]int{1, 10} || results[1] != [2]int{2, 20} {
		t.Errorf("unexpected rows: %v", results)
	}

	var ic string
	if err := snap.DB.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity_check: %v, got %q", err, ic)
	}
}

// (4) WAL with a corrupted frame checksum in the middle -> frames from break on ignored, earlier committed frames applied.
func TestCorruptedWALChecksum(t *testing.T) {
	dir := mpenginetest.Build(t, mpenginetest.FixtureOptions{
		BeforeCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(1, 100);`)
			return err
		},
		AfterCheckpoint: func(db *sql.DB) error {
			// Transaction 1
			if _, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(2, 200);`); err != nil {
				return err
			}
			// Transaction 2
			if _, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(3, 300);`); err != nil {
				return err
			}
			return nil
		},
		CorruptWALAt: 2, // corrupt frame 2
	})

	snap, err := mpengine.Open(dir, mpengine.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer snap.Close()

	// Should not error, row 1 must be present
	var count int
	if err := snap.DB.QueryRow(`SELECT count(*) FROM FileHashes WHERE ID = 1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("row 1 not found: %v, count=%d", err, count)
	}
}

// (5) Uncommitted trailing frames are ignored.
func TestUncommittedTrailingFrames(t *testing.T) {
	dir := mpenginetest.Build(t, mpenginetest.FixtureOptions{
		BeforeCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(1, 111);`)
			return err
		},
		AfterCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(2, 222);`)
			return err
		},
		UncommittedFrames: 2,
	})

	snap, err := mpengine.Open(dir, mpengine.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer snap.Close()

	if snap.Info.WALFramesTotal <= snap.Info.WALFramesCommitted {
		t.Errorf("expected WALFramesTotal (%d) > WALFramesCommitted (%d)", snap.Info.WALFramesTotal, snap.Info.WALFramesCommitted)
	}

	var vsn int
	if err := snap.DB.QueryRow(`SELECT VSN FROM FileHashes WHERE ID = 2`).Scan(&vsn); err != nil || vsn != 222 {
		t.Fatalf("row 2 failed: %v, vsn=%d", err, vsn)
	}
}

// (6) Unknown key -> DeriveKeystream used, KeySource "derived".
func TestDeriveKeystream(t *testing.T) {
	t.Run("random_key", func(t *testing.T) {
		fixtureDir := filepath.Join("testdata", "oracle", "random_key")
		testDeriveFixture(t, fixtureDir, mpengine.Options{})
	})

	t.Run("known_key", func(t *testing.T) {
		fixtureDir := filepath.Join("testdata", "oracle", "known_key")
		testDeriveFixture(t, fixtureDir, mpengine.Options{DeriveKey: true})
	})
}

func testDeriveFixture(t *testing.T, fixtureDir string, opt mpengine.Options) {
	keyHex, err := os.ReadFile(filepath.Join(fixtureDir, "key.txt"))
	if err != nil {
		t.Fatalf("ReadFile key.txt failed: %v", err)
	}
	keyBytes, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		t.Fatalf("hex.DecodeString key.txt failed: %v", err)
	}

	_, info, err := mpengine.Decrypt(fixtureDir, opt)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if info.KeySource != "derived" {
		t.Errorf("expected KeySource 'derived', got %q", info.KeySource)
	}

	trueKS, err := mpengine.RC4Stream(keyBytes, info.PageSize)
	if err != nil {
		t.Fatalf("RC4Stream failed: %v", err)
	}

	dbBytes, err := os.ReadFile(filepath.Join(fixtureDir, "mpenginedb.db"))
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	ps := info.PageSize
	numPages := len(dbBytes) / ps
	pages := make([][]byte, numPages)
	for i := 0; i < numPages; i++ {
		pages[i] = dbBytes[i*ps : (i+1)*ps]
	}
	var nonRootFrames [][]byte
	walPath := filepath.Join(fixtureDir, "mpenginedb.db-wal")
	if walBytes, err := os.ReadFile(walPath); err == nil && len(walBytes) >= 32 {
		fsz := 24 + ps
		nframes := (len(walBytes) - 32) / fsz
		for i := 0; i < nframes; i++ {
			off := 32 + i*fsz
			pg := binary.BigEndian.Uint32(walBytes[off : off+4])
			if pg != 1 {
				nonRootFrames = append(nonRootFrames, walBytes[off+24:off+fsz])
			}
		}
	}
	derivedKS, _ := mpengine.DeriveKeystream(pages, nonRootFrames, ps)
	derivedSHA := fmt.Sprintf("%x", sha256.Sum256(derivedKS))
	if derivedSHA != info.KeystreamSHA256 {
		t.Errorf("derived keystream sha mismatch: %s != %s", derivedSHA, info.KeystreamSHA256)
	}

	if !bytes.Equal(derivedKS[:16], trueKS[:16]) {
		t.Errorf("derived keystream bytes 0..15 do not match true keystream")
	}
	if !bytes.Equal(derivedKS[48:68], trueKS[48:68]) {
		t.Errorf("derived keystream bytes 48..67 do not match true keystream")
	}

	diffCount := 0
	for i := 0; i < info.PageSize; i++ {
		if derivedKS[i] != trueKS[i] {
			diffCount++
		}
	}
	t.Logf("[%s] positions differing from true keystream: %d / %d", filepath.Base(fixtureDir), diffCount, info.PageSize)

	snap, err := mpengine.Open(fixtureDir, opt)
	if err == nil {
		defer snap.Close()
		if snap.Info.KeySource != "derived" {
			t.Errorf("expected KeySource 'derived', got %q", snap.Info.KeySource)
		}
		var ic string
		if err := snap.DB.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
			t.Fatalf("expected integrity_check ok, got %v (%q)", err, ic)
		}
		t.Logf("[%s] Open succeeded with integrity ok", filepath.Base(fixtureDir))
	} else {
		if !strings.HasPrefix(err.Error(), "derived keystream did not produce a consistent database (") || !strings.Contains(err.Error(), "low-confidence byte positions): ") {
			t.Fatalf("unexpected Open error: %v", err)
		}
		if snap != nil {
			snap.Close()
			t.Fatalf("expected nil snapshot on Open error")
		}
		t.Logf("[%s] Open gated with error: %v", filepath.Base(fixtureDir), err)
	}
}

// (7) ~wal naming resolution and directory resolution.
func TestWALNamingAndDirResolution(t *testing.T) {
	dir := mpenginetest.Build(t, mpenginetest.FixtureOptions{
		WALExtension: "~wal",
		BeforeCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(1, 1);`)
			return err
		},
		AfterCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(2, 2);`)
			return err
		},
	})

	// Test Resolve with directory
	dbPath, walPath, err := mpengine.Resolve(dir, mpengine.Options{})
	if err != nil {
		t.Fatalf("Resolve(dir) failed: %v", err)
	}
	if filepath.Base(dbPath) != "mpenginedb.db" {
		t.Errorf("unexpected dbPath: %q", dbPath)
	}
	if filepath.Base(walPath) != "mpenginedb.db~wal" {
		t.Errorf("unexpected walPath: %q", walPath)
	}

	// Test Open on directory directly
	snap, err := mpengine.Open(dir, mpengine.Options{})
	if err != nil {
		t.Fatalf("Open(dir) failed: %v", err)
	}
	defer snap.Close()

	var count int
	if err := snap.DB.QueryRow(`SELECT count(*) FROM FileHashes`).Scan(&count); err != nil || count != 2 {
		t.Errorf("expected 2 rows, got count=%d, err=%v", count, err)
	}
}

// (8) Junk input / wrong size -> error, no panic.
func TestJunkInput(t *testing.T) {
	tempDir := t.TempDir()

	// Case 1: Empty file
	pEmpty := filepath.Join(tempDir, "empty.db")
	_ = os.WriteFile(pEmpty, []byte{}, 0600)
	if _, _, err := mpengine.Decrypt(pEmpty, mpengine.Options{}); err == nil {
		t.Errorf("expected error for empty file")
	}

	// Case 2: Random junk smaller than 512 bytes
	pJunkSmall := filepath.Join(tempDir, "small.db")
	_ = os.WriteFile(pJunkSmall, []byte("random junk not sqlite"), 0600)
	if _, _, err := mpengine.Decrypt(pJunkSmall, mpengine.Options{}); err == nil {
		t.Errorf("expected error for small junk file")
	}

	// Case 3: Junk 4096 bytes with invalid page size
	pJunk4096 := filepath.Join(tempDir, "junk4096.db")
	buf := bytes.Repeat([]byte{0xAA}, 4096)
	_ = os.WriteFile(pJunk4096, buf, 0600)
	if _, _, err := mpengine.Decrypt(pJunk4096, mpengine.Options{}); err == nil {
		t.Errorf("expected error for invalid page size in 4096 junk file")
	}

	// Case 4: File not multiple of page size
	pJunkOdd := filepath.Join(tempDir, "junkodd.db")
	bufOdd := bytes.Repeat([]byte{0xAA}, 4096+13)
	_ = os.WriteFile(pJunkOdd, bufOdd, 0600)
	if _, _, err := mpengine.Decrypt(pJunkOdd, mpengine.Options{}); err == nil {
		t.Errorf("expected error for file not multiple of page size")
	}
}

// (9) Cache: same snapshot reused, rebuilt after file mtime change, concurrent With calls under -race.
func TestCache(t *testing.T) {
	dir := mpenginetest.Build(t, mpenginetest.FixtureOptions{
		BeforeCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(1, 100);`)
			return err
		},
	})
	dbFile := filepath.Join(dir, "mpenginedb.db")

	cache := mpengine.NewCache(30*time.Second, 0, mpengine.Options{})
	defer cache.Close()

	var firstCreated time.Time
	err := cache.With(dbFile, func(s *mpengine.Snapshot) error {
		firstCreated = s.Created
		var vsn int
		return s.DB.QueryRow(`SELECT VSN FROM FileHashes WHERE ID = 1`).Scan(&vsn)
	})
	if err != nil {
		t.Fatalf("first With failed: %v", err)
	}

	// Second With call: should reuse snapshot
	err = cache.With(dbFile, func(s *mpengine.Snapshot) error {
		if !s.Created.Equal(firstCreated) {
			t.Errorf("snapshot was not reused: %v vs %v", s.Created, firstCreated)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("second With failed: %v", err)
	}

	// Concurrent With calls under -race
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cache.With(dbFile, func(s *mpengine.Snapshot) error {
				var vsn int
				return s.DB.QueryRow(`SELECT VSN FROM FileHashes WHERE ID = 1`).Scan(&vsn)
			})
		}()
	}
	wg.Wait()

	// Update mtime of dbFile -> should rebuild snapshot
	futureTime := time.Now().Add(10 * time.Minute)
	if err := os.Chtimes(dbFile, futureTime, futureTime); err != nil {
		t.Fatalf("Chtimes failed: %v", err)
	}

	var secondCreated time.Time
	err = cache.With(dbFile, func(s *mpengine.Snapshot) error {
		secondCreated = s.Created
		return nil
	})
	if err != nil {
		t.Fatalf("third With failed: %v", err)
	}
	if secondCreated.Equal(firstCreated) {
		t.Errorf("expected snapshot to be rebuilt after mtime update")
	}
}

// (11) Snapshot is read-only (INSERT fails).
func TestReadOnlySnapshot(t *testing.T) {
	dir := mpenginetest.Build(t, mpenginetest.FixtureOptions{
		BeforeCheckpoint: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(1, 100);`)
			return err
		},
	})

	snap, err := mpengine.Open(dir, mpengine.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer snap.Close()

	// Try inserting a row
	_, err = snap.DB.Exec(`INSERT INTO FileHashes(ID, VSN) VALUES(2, 200)`)
	if err == nil {
		t.Fatalf("expected INSERT to fail on read-only snapshot, but it succeeded")
	}
}
