package mpengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const DefaultDir = `C:\ProgramData\Microsoft\Windows Defender\Scans`

// DefaultMaxBytes is the default cap on db+wal size read by Decrypt.
const DefaultMaxBytes int64 = 1 << 30

// readAttempts bounds how often Decrypt re-reads files that changed while
// they were being read.
const readAttempts = 3

// Options controls decryption and path resolution.
type Options struct {
	DeriveKey bool   // ignore known keys, derive from evidence
	WALPath   string // explicit WAL path; default: <db>-wal, then <db>~wal
	MaxBytes  int64  // cap on db+wal bytes read; <= 0 means DefaultMaxBytes
}

func (o Options) maxBytes() int64 {
	if o.MaxBytes <= 0 {
		return DefaultMaxBytes
	}
	return o.MaxBytes
}

// Info contains metadata about the decrypted database and evidence files.
type Info struct {
	DBPath, WALPath      string
	DBSize, WALSize      int64
	DBSHA256, WALSHA256  string
	Protection           string // "none" | "rc4"
	KeySource            string // "" | "known:1.1.26100.4" | "derived"
	KeystreamSHA256      string
	DerivedLowConfidence int // byte positions with weak/no votes (derived key only)
	PageSize, DBPages    int
	WALHeaderValid       bool
	WALFramesTotal       int
	WALFramesCommitted   int
	WALCommits           int
	WALNote              string
	ReadAttempts         int    // reads needed for a stable (unchanged) copy of db+wal
	QuickCheck           string `json:",omitempty"` // PRAGMA quick_check: "ok" or its first line (set by Open)

	sig signature // file signature taken before the bytes were read
}

// Resolve accepts a file or a directory containing mpenginedb.db and returns
// db + wal paths ("" if no WAL). The database and WAL must be regular files.
func Resolve(path string, opt Options) (dbPath, walPath string, err error) {
	if path == "" {
		return "", "", errors.New("empty path")
	}
	cleanPath := filepath.Clean(path)
	fi, err := os.Stat(cleanPath)
	if err != nil {
		return "", "", err
	}

	if fi.IsDir() {
		dbPath = filepath.Join(cleanPath, "mpenginedb.db")
		if fi, err = os.Stat(dbPath); err != nil {
			return "", "", fmt.Errorf("mpenginedb.db not found in %s: %w", cleanPath, err)
		}
	} else {
		dbPath = cleanPath
	}
	if !fi.Mode().IsRegular() {
		return "", "", fmt.Errorf("%s: not a regular file", dbPath)
	}

	if opt.WALPath != "" {
		cleanWAL := filepath.Clean(opt.WALPath)
		wfi, err := os.Stat(cleanWAL)
		if err != nil {
			return "", "", fmt.Errorf("explicit WAL path not found: %w", err)
		}
		if !wfi.Mode().IsRegular() {
			return "", "", fmt.Errorf("%s: not a regular file", cleanWAL)
		}
		walPath = cleanWAL
	} else {
		for _, cand := range []string{dbPath + "-wal", dbPath + "~wal"} {
			wfi, err := os.Stat(cand)
			if err != nil {
				continue
			}
			if !wfi.Mode().IsRegular() {
				return "", "", fmt.Errorf("%s: not a regular file", cand)
			}
			walPath = cand
			break
		}
	}

	return dbPath, walPath, nil
}

type fileStat struct {
	size    int64
	modTime time.Time
}

// signature identifies the resolved files and their size+mtime. err is set
// (and the rest empty) when the path does not resolve. Comparable.
type signature struct {
	dbPath, walPath string
	db, wal         fileStat
	err             string
}

func statFile(path string) (fileStat, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStat{}, err
	}
	return fileStat{size: fi.Size(), modTime: fi.ModTime()}, nil
}

// currentSignature resolves path and stats the db and WAL files.
func currentSignature(path string, opt Options) signature {
	dbPath, walPath, err := Resolve(path, opt)
	if err != nil {
		return signature{err: err.Error()}
	}
	s := signature{dbPath: dbPath, walPath: walPath}
	if s.db, err = statFile(dbPath); err != nil {
		return signature{err: err.Error()}
	}
	if walPath != "" {
		if s.wal, err = statFile(walPath); err != nil {
			return signature{err: err.Error()}
		}
	}
	return s
}

// readFileHook reads evidence files; replaced in tests.
var readFileHook = readFile

// readStable reads db and wal, re-reading (up to readAttempts) when their
// size, mtime or WAL salts changed during the read. It returns the signature
// taken before the final read.
func readStable(path string, opt Options) (dbBytes, walBytes []byte, sig signature, attempts int, err error) {
	limit := opt.maxBytes()
	for attempts = 1; ; attempts++ {
		sig = currentSignature(path, opt)
		if sig.err != "" {
			return nil, nil, sig, attempts, errors.New(sig.err)
		}
		if total := sig.db.size + sig.wal.size; total > limit {
			return nil, nil, sig, attempts, fmt.Errorf("db+wal size %d exceeds limit %d (--max_db_bytes)", total, limit)
		}
		var salts []byte
		if sig.walPath != "" {
			salts = readWALSalts(sig.walPath)
		}
		dbBytes, err = readFileHook(sig.dbPath, limit)
		if err != nil {
			return nil, nil, sig, attempts, fmt.Errorf("read db: %w", err)
		}
		walBytes = nil
		if sig.walPath != "" {
			walBytes, err = readFileHook(sig.walPath, limit-int64(len(dbBytes)))
			if err != nil {
				return nil, nil, sig, attempts, fmt.Errorf("read wal: %w", err)
			}
		}
		stable := currentSignature(path, opt) == sig
		if stable && sig.walPath != "" {
			var got []byte
			if len(walBytes) >= 24 {
				got = walBytes[16:24]
			}
			stable = bytes.Equal(salts, got)
		}
		if stable || attempts >= readAttempts {
			return dbBytes, walBytes, sig, attempts, nil
		}
	}
}

// Decrypt returns a plaintext SQLite image with committed WAL frames applied
// and header bytes 18/19 set to 1.
func Decrypt(path string, opt Options) ([]byte, *Info, error) {
	img, info, err := decrypt(path, opt)
	if err != nil {
		return nil, nil, err
	}
	return img, info, nil
}

func decrypt(path string, opt Options) ([]byte, *Info, error) {
	dbBytes, walBytes, sig, attempts, err := readStable(path, opt)
	if err != nil {
		return nil, &Info{sig: sig}, err
	}
	img, info, err := decode(sig.dbPath, sig.walPath, dbBytes, walBytes, opt)
	if info == nil {
		info = &Info{}
	}
	info.sig, info.ReadAttempts = sig, attempts
	return img, info, err
}

// decode decrypts dbBytes and replays the committed frames of walBytes.
func decode(dbPath, walPath string, dbBytes, walBytes []byte, opt Options) ([]byte, *Info, error) {
	if len(dbBytes) < 512 {
		return nil, nil, fmt.Errorf("not a MetaVault/SQLite file: file size %d too small", len(dbBytes))
	}

	ps := int(binary.BigEndian.Uint16(dbBytes[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps > 65536 || (ps&(ps-1)) != 0 || len(dbBytes)%ps != 0 {
		return nil, nil, fmt.Errorf("not a MetaVault/SQLite file: page size field %d, file size %d", ps, len(dbBytes))
	}

	dbHash := sha256.Sum256(dbBytes)
	info := &Info{
		DBPath:   dbPath,
		DBSize:   int64(len(dbBytes)),
		DBSHA256: hex.EncodeToString(dbHash[:]),
		PageSize: ps,
		DBPages:  len(dbBytes) / ps,
	}

	if walPath != "" {
		walHash := sha256.Sum256(walBytes)
		info.WALPath = walPath
		info.WALSize = int64(len(walBytes))
		info.WALSHA256 = hex.EncodeToString(walHash[:])
	}

	pages := make([][]byte, info.DBPages)
	for i := 0; i < info.DBPages; i++ {
		pages[i] = dbBytes[i*ps : (i+1)*ps]
	}

	var whdr *walHeader
	var frames []*walFrame
	if walPath != "" {
		var note string
		whdr, frames, note = parseWAL(walBytes, ps, info.DBPages)
		info.WALNote = note
	}
	if whdr != nil {
		info.WALHeaderValid = whdr.HeaderChecksumOK
		info.WALFramesTotal = whdr.FramesTotal
		info.WALFramesCommitted = whdr.FramesCommitted
		info.WALCommits = whdr.Commits
	}

	var codec *Codec
	if bytes.Equal(dbBytes[:16], Magic) {
		info.Protection = "none"
		info.KeySource = ""
		info.KeystreamSHA256 = ""
		info.DerivedLowConfidence = 0
	} else {
		info.Protection = "rc4"
		var ks []byte
		var keySource string

		if !opt.DeriveKey {
			names := make([]string, 0, len(KnownKeys))
			for name := range KnownKeys {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				cand, err := RC4Stream(KnownKeys[name], ps)
				if err != nil {
					continue
				}
				p1 := DecryptPage(pages[0], 1, cand)
				if bytes.Equal(p1[:16], Magic) {
					ks = cand
					keySource = "known:" + name
					break
				}
			}
		}

		if ks == nil {
			var nonRootFrames [][]byte
			for _, f := range frames {
				if f.pgno != 1 {
					nonRootFrames = append(nonRootFrames, f.data)
				}
			}
			var lowConf int
			ks, lowConf = DeriveKeystream(pages, nonRootFrames, ps)
			keySource = "derived"
			info.DerivedLowConfidence = lowConf
		}

		codec = NewCodec(ks, ps)
		decP1 := codec.DecryptPage(pages[0], 1)
		if !bytes.Equal(decP1[:16], Magic) {
			return nil, nil, fmt.Errorf("decryption failed: header does not match SQLite magic")
		}

		info.KeySource = keySource
		ksHash := sha256.Sum256(ks)
		info.KeystreamSHA256 = hex.EncodeToString(ksHash[:])
	}

	plainPages := make([][]byte, len(pages))
	for i, p := range pages {
		if codec != nil {
			plainPages[i] = codec.DecryptPage(p, i+1)
		} else {
			plainPages[i] = p
		}
	}
	for _, f := range frames {
		if codec != nil {
			f.plain = codec.DecryptPage(f.data, int(f.pgno))
		} else {
			f.plain = f.data
		}
	}

	cur := make([]byte, 0, len(dbBytes))
	for _, p := range plainPages {
		cur = append(cur, p...)
	}

	maxPages := info.DBPages + info.WALFramesTotal
	for _, f := range frames {
		if !f.valid || f.pgno == 0 || int(f.pgno) > maxPages || int(f.commit) > maxPages {
			continue
		}
		need := int(f.pgno) * ps
		if len(cur) < need {
			cur = append(cur, make([]byte, need-len(cur))...)
		}
		copy(cur[(int(f.pgno)-1)*ps:int(f.pgno)*ps], f.plain)
		if f.commit > 0 {
			commitBytes := int(f.commit) * ps
			if len(cur) > commitBytes {
				cur = cur[:commitBytes]
			} else if len(cur) < commitBytes {
				cur = append(cur, make([]byte, commitBytes-len(cur))...)
			}
		}
	}

	if len(cur) >= 20 {
		cur[18] = 1
		cur[19] = 1
	}

	return cur, info, nil
}
