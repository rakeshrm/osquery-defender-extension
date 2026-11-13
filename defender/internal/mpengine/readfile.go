package mpengine

import (
	"bytes"
	"fmt"
	"io"
)

// readFile reads a regular file of at most limit bytes. The buffer is sized
// from the file's current size; growth past limit while reading is detected
// by reading at most limit+1 bytes.
func readFile(path string, limit int64) ([]byte, error) {
	f, err := openShared(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s: size %d exceeds limit %d (--max_db_bytes)", path, fi.Size(), limit)
	}
	var buf bytes.Buffer
	buf.Grow(int(fi.Size()) + 1)
	n, err := buf.ReadFrom(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, fmt.Errorf("%s: grew past limit %d (--max_db_bytes) while reading", path, limit)
	}
	return buf.Bytes(), nil
}

// readWALSalts returns WAL header bytes 16..24 (salt-1, salt-2), or nil if
// the file is shorter than a header or cannot be read.
func readWALSalts(path string) []byte {
	f, err := openShared(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil
	}
	return hdr[16:24]
}
