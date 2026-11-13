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
)

const DefaultDir = `C:\ProgramData\Microsoft\Windows Defender\Scans`

// Options controls decryption and path resolution.
type Options struct {
	DeriveKey bool   // ignore known keys, derive from evidence
	WALPath   string // explicit WAL path; default: <db>-wal, then <db>~wal
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
}

// Resolve accepts a file or a directory containing mpenginedb.db and returns db + wal paths ("" if no WAL).
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
		candidate := filepath.Join(cleanPath, "mpenginedb.db")
		if _, err := os.Stat(candidate); err != nil {
			return "", "", fmt.Errorf("mpenginedb.db not found in %s: %w", cleanPath, err)
		}
		dbPath = candidate
	} else {
		dbPath = cleanPath
	}

	if opt.WALPath != "" {
		cleanWAL := filepath.Clean(opt.WALPath)
		if _, err := os.Stat(cleanWAL); err != nil {
			return "", "", fmt.Errorf("explicit WAL path not found: %w", err)
		}
		walPath = cleanWAL
	} else {
		cand1 := dbPath + "-wal"
		cand2 := dbPath + "~wal"
		if _, err := os.Stat(cand1); err == nil {
			walPath = cand1
		} else if _, err := os.Stat(cand2); err == nil {
			walPath = cand2
		}
	}

	return dbPath, walPath, nil
}

// Decrypt returns a plaintext SQLite image with committed WAL frames applied
// and header bytes 18/19 set to 1.
func Decrypt(path string, opt Options) ([]byte, *Info, error) {
	dbPath, walPath, err := Resolve(path, opt)
	if err != nil {
		return nil, nil, err
	}

	dbBytes, err := readFile(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read db: %w", err)
	}

	var walBytes []byte
	if walPath != "" {
		walBytes, err = readFile(walPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read wal: %w", err)
		}
	}

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
