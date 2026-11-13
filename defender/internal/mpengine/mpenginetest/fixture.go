package mpenginetest

import (
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
	_ "modernc.org/sqlite"
)

// FixtureOptions configures the database fixture generation.
type FixtureOptions struct {
	Key               []byte // if nil and !NoEncryption, use default known key
	NoEncryption      bool
	PageSize          int // default 4096
	BeforeCheckpoint  func(db *sql.DB) error
	AfterCheckpoint   func(db *sql.DB) error
	WALExtension      string // default "-wal", can be "~wal"
	CorruptWALAt      int    // 1-based frame index where checksum chain should be broken (0 = none)
	UncommittedFrames int    // number of uncommitted frames to append (commit=0)
}

// Build creates a SQLite database fixture in WAL mode, encrypts it according to opts,
// and returns the directory containing mpenginedb.db (and mpenginedb.db-wal if present).
func Build(t testing.TB, opts FixtureOptions) string {
	t.Helper()

	ps := opts.PageSize
	if ps == 0 {
		ps = 4096
	}

	srcDir := t.TempDir()
	realDBPath := filepath.Join(srcDir, "test.db")

	db, err := sql.Open("sqlite", realDBPath)
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	execPragma := func(q string) {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			t.Fatalf("pragma failed %q: %v", q, err)
		}
	}

	execPragma("PRAGMA page_size = 4096;")
	execPragma("PRAGMA journal_mode = WAL;")
	execPragma("PRAGMA wal_autocheckpoint = 0;")

	createTables := `
CREATE TABLE FileHashes(
    ID INTEGER PRIMARY KEY,
    SHA1 BLOB,
    MD5 BLOB,
    SHA256 BLOB,
    VSN INTEGER,
    FileID INTEGER,
    USN INTEGER,
    InstanceTimeStamp INTEGER
);
CREATE TABLE RollingQueuesValues(
    ID INTEGER PRIMARY KEY,
    EntryTable TEXT,
    EntryKey TEXT,
    EntryValue TEXT,
    InsertTime INTEGER,
    ExpireTime INTEGER
);
`
	if _, err := db.Exec(createTables); err != nil {
		db.Close()
		t.Fatalf("failed to create tables: %v", err)
	}

	if opts.BeforeCheckpoint != nil {
		if err := opts.BeforeCheckpoint(db); err != nil {
			db.Close()
			t.Fatalf("beforeCheckpoint failed: %v", err)
		}
	}

	execPragma("PRAGMA wal_checkpoint(TRUNCATE);")

	if opts.AfterCheckpoint != nil {
		if err := opts.AfterCheckpoint(db); err != nil {
			db.Close()
			t.Fatalf("afterCheckpoint failed: %v", err)
		}
	}

	// Read files while connection is open so WAL is preserved.
	dbBytes, err := os.ReadFile(realDBPath)
	if err != nil {
		db.Close()
		t.Fatalf("failed to read db file: %v", err)
	}

	walBytes, _ := os.ReadFile(realDBPath + "-wal")
	_ = db.Close()

	var ks []byte
	if !opts.NoEncryption {
		key := opts.Key
		if len(key) == 0 {
			key = mpengine.KnownKeys["1.1.26100.4"]
		}
		var err error
		ks, err = mpengine.RC4Stream(key, ps)
		if err != nil {
			t.Fatalf("failed to generate rc4 stream: %v", err)
		}

		// Encrypt DB pages
		numPages := len(dbBytes) / ps
		for i := 0; i < numPages; i++ {
			page := dbBytes[i*ps : (i+1)*ps]
			enc := mpengine.EncryptPage(page, i+1, ks)
			copy(page, enc)
		}
	}

	// Encrypt WAL frames and recompute checksums
	if len(walBytes) >= 32 {
		magic := binary.BigEndian.Uint32(walBytes[0:4])
		big := (magic & 1) != 0
		salt1 := binary.BigEndian.Uint32(walBytes[16:20])
		salt2 := binary.BigEndian.Uint32(walBytes[20:24])

		s0, s1 := mpengine.WalCksum(walBytes[:24], 0, 0, big)
		binary.BigEndian.PutUint32(walBytes[24:28], s0)
		binary.BigEndian.PutUint32(walBytes[28:32], s1)

		off := 32
		frameIdx := 0
		var frameOffsets []int

		for off+24+ps <= len(walBytes) {
			frameIdx++
			frameOffsets = append(frameOffsets, off)
			pg := binary.BigEndian.Uint32(walBytes[off : off+4])
			data := walBytes[off+24 : off+24+ps]

			if !opts.NoEncryption {
				enc := mpengine.EncryptPage(data, int(pg), ks)
				copy(data, enc)
			}

			if opts.CorruptWALAt > 0 && frameIdx == opts.CorruptWALAt {
				// Corrupt checksum for this frame
				badS0 := s0 ^ 0xDEADBEEF
				binary.BigEndian.PutUint32(walBytes[off+16:off+20], badS0)
				binary.BigEndian.PutUint32(walBytes[off+20:off+24], s1)
				// Still advance state so subsequent frames continue from true chain
				s0, s1 = mpengine.WalCksum(walBytes[off:off+8], s0, s1, big)
				s0, s1 = mpengine.WalCksum(data, s0, s1, big)
			} else {
				s0, s1 = mpengine.WalCksum(walBytes[off:off+8], s0, s1, big)
				s0, s1 = mpengine.WalCksum(data, s0, s1, big)
				binary.BigEndian.PutUint32(walBytes[off+16:off+20], s0)
				binary.BigEndian.PutUint32(walBytes[off+20:off+24], s1)
			}
			off += 24 + ps
		}

		for u := 0; u < opts.UncommittedFrames; u++ {
			extra := make([]byte, 24+ps)
			if len(frameOffsets) > 0 {
				lastOff := frameOffsets[len(frameOffsets)-1]
				copy(extra, walBytes[lastOff:lastOff+24+ps])
			} else {
				binary.BigEndian.PutUint32(extra[0:4], 2)
				binary.BigEndian.PutUint32(extra[8:12], salt1)
				binary.BigEndian.PutUint32(extra[12:16], salt2)
			}
			// commit = 0 makes it an uncommitted frame
			binary.BigEndian.PutUint32(extra[4:8], 0)
			s0, s1 = mpengine.WalCksum(extra[:8], s0, s1, big)
			s0, s1 = mpengine.WalCksum(extra[24:24+ps], s0, s1, big)
			binary.BigEndian.PutUint32(extra[16:20], s0)
			binary.BigEndian.PutUint32(extra[20:24], s1)
			walBytes = append(walBytes, extra...)
		}
	}

	outDir := t.TempDir()
	outDB := filepath.Join(outDir, "mpenginedb.db")
	if err := os.WriteFile(outDB, dbBytes, 0600); err != nil {
		t.Fatalf("failed to write mpenginedb.db: %v", err)
	}

	ext := opts.WALExtension
	if ext == "" {
		ext = "-wal"
	}
	if len(walBytes) > 0 {
		outWAL := filepath.Join(outDir, "mpenginedb.db"+ext)
		if err := os.WriteFile(outWAL, walBytes, 0600); err != nil {
			t.Fatalf("failed to write wal file: %v", err)
		}
	}

	return outDir
}
