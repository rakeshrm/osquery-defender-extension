package mpengine

import (
	"encoding/binary"
	"fmt"
)

const (
	walMagicLE = 0x377F0682
	walMagicBE = 0x377F0683
)

type walHeader struct {
	Magic            uint32
	Version          uint32
	PageSize         int
	CheckpointSeq    uint32
	Salt1            uint32
	Salt2            uint32
	HeaderChecksumOK bool
	BigEndianCksum   bool
	FramesTotal      int
	FramesCommitted  int
	Commits          int
}

type walFrame struct {
	idx    int
	pgno   uint32
	commit uint32
	data   []byte
	plain  []byte
	valid  bool
	offset int
}

// WalCksum computes SQLite WAL checksums over data.
// Exported for use in tests / fixture building.
func WalCksum(data []byte, s0, s1 uint32, big bool) (uint32, uint32) {
	for i := 0; i+8 <= len(data); i += 8 {
		var v0, v1 uint32
		if big {
			v0 = binary.BigEndian.Uint32(data[i : i+4])
			v1 = binary.BigEndian.Uint32(data[i+4 : i+8])
		} else {
			v0 = binary.LittleEndian.Uint32(data[i : i+4])
			v1 = binary.LittleEndian.Uint32(data[i+4 : i+8])
		}
		s0 += v0 + s1
		s1 += v1 + s0
	}
	return s0, s1
}

// parseWAL parses, validates, and chains the SQLite WAL.
// dbPages is the number of database pages in the main db.
// If WAL is missing, < 32 bytes, has bad magic, or page size differs, it returns (nil, nil, note).
func parseWAL(wal []byte, ps int, dbPages int) (*walHeader, []*walFrame, string) {
	if len(wal) < 32 {
		return nil, nil, "too short"
	}

	magic := binary.BigEndian.Uint32(wal[0:4])
	if magic != walMagicLE && magic != walMagicBE {
		return nil, nil, "bad magic"
	}

	wps := int(binary.BigEndian.Uint32(wal[8:12]))
	if wps != ps {
		return nil, nil, fmt.Sprintf("page size %d != db page size %d", wps, ps)
	}

	ver := binary.BigEndian.Uint32(wal[4:8])
	ckpt := binary.BigEndian.Uint32(wal[12:16])
	salt1 := binary.BigEndian.Uint32(wal[16:20])
	salt2 := binary.BigEndian.Uint32(wal[20:24])
	c1 := binary.BigEndian.Uint32(wal[24:28])
	c2 := binary.BigEndian.Uint32(wal[28:32])

	big := (magic & 1) != 0
	s0, s1 := WalCksum(wal[:24], 0, 0, big)
	hdrOK := s0 == c1 && s1 == c2

	hdr := &walHeader{
		Magic:            magic,
		Version:          ver,
		PageSize:         wps,
		CheckpointSeq:    ckpt,
		Salt1:            salt1,
		Salt2:            salt2,
		HeaderChecksumOK: hdrOK,
		BigEndianCksum:   big,
	}

	var note string
	if !hdrOK {
		note = "header checksum invalid"
	}

	fsz := 24 + wps
	totalFrames := (len(wal) - 32) / fsz
	maxPages := dbPages + totalFrames

	var frames []*walFrame
	off := 32
	chainOK := hdrOK
	idx := 0

	for off+24+wps <= len(wal) {
		idx++
		pg := binary.BigEndian.Uint32(wal[off : off+4])
		commit := binary.BigEndian.Uint32(wal[off+4 : off+8])
		fs1 := binary.BigEndian.Uint32(wal[off+8 : off+12])
		fs2 := binary.BigEndian.Uint32(wal[off+12 : off+16])
		k1 := binary.BigEndian.Uint32(wal[off+16 : off+20])
		k2 := binary.BigEndian.Uint32(wal[off+20 : off+24])
		data := wal[off+24 : off+24+wps]

		if chainOK {
			if fs1 != salt1 || fs2 != salt2 {
				chainOK = false
				if note == "" {
					note = fmt.Sprintf("frame %d invalid: salt mismatch", idx)
				}
			} else {
				s0, s1 = WalCksum(wal[off:off+8], s0, s1, big)
				s0, s1 = WalCksum(data, s0, s1, big)
				if s0 != k1 || s1 != k2 {
					chainOK = false
					if note == "" {
						note = fmt.Sprintf("frame %d invalid: checksum mismatch", idx)
					}
				} else if pg == 0 {
					chainOK = false
					if note == "" {
						note = fmt.Sprintf("frame %d invalid: pgno 0", idx)
					}
				} else if int(pg) > maxPages {
					chainOK = false
					if note == "" {
						note = fmt.Sprintf("frame %d invalid: pgno %d > max %d", idx, pg, maxPages)
					}
				} else if int(commit) > maxPages {
					chainOK = false
					if note == "" {
						note = fmt.Sprintf("frame %d invalid: commit %d > max %d", idx, commit, maxPages)
					}
				}
			}
		}

		frames = append(frames, &walFrame{
			idx:    idx,
			pgno:   pg,
			commit: commit,
			data:   data,
			valid:  chainOK,
			offset: off,
		})
		off += 24 + wps
	}

	// Frames after the last valid commit are uncommitted.
	lastCommit := 0
	for _, f := range frames {
		if f.valid && f.commit > 0 {
			if f.idx > lastCommit {
				lastCommit = f.idx
			}
		}
	}
	for _, f := range frames {
		if f.valid && f.idx > lastCommit {
			f.valid = false
		}
	}

	hdr.FramesTotal = len(frames)
	for _, f := range frames {
		if f.valid {
			hdr.FramesCommitted++
			if f.commit > 0 {
				hdr.Commits++
			}
		}
	}

	if note == "" && hdr.FramesCommitted < hdr.FramesTotal {
		note = fmt.Sprintf("%d uncommitted trailing frames", hdr.FramesTotal-hdr.FramesCommitted)
	}

	return hdr, frames, note
}
