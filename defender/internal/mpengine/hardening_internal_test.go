package mpengine

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// plainDB writes an unencrypted rollback-journal mpenginedb.db with nRows
// rows in table T into a new temp dir and returns the dir.
func plainDB(t *testing.T, nRows int) string {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "mpenginedb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE T (ID INTEGER PRIMARY KEY, V TEXT)`); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= nRows; i++ {
		if _, err := db.Exec(`INSERT INTO T VALUES (?, ?)`, i, fmt.Sprint("v", i)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// countingOpen replaces c.open with the real open plus a per-path build counter.
func countingOpen(c *Cache) *sync.Map {
	var counts sync.Map
	c.open = func(p string, o Options) (*Snapshot, signature, error) {
		n, _ := counts.LoadOrStore(p, new(atomic.Int64))
		n.(*atomic.Int64).Add(1)
		return open(p, o)
	}
	return &counts
}

func builds(m *sync.Map, p string) int64 {
	n, ok := m.Load(filepath.Clean(p))
	if !ok {
		return 0
	}
	return n.(*atomic.Int64).Load()
}

func rowCount(t *testing.T, s *Snapshot) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT count(*) FROM T`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// Finding 2: different paths build in parallel; one path builds once.
func TestCacheSingleFlightPerPath(t *testing.T) {
	a, b, same := plainDB(t, 1), plainDB(t, 1), plainDB(t, 1)
	c := NewCache(time.Minute, 0, Options{})
	defer c.Close()

	bStarted := make(chan struct{})
	release := make(chan struct{})
	var sameBuilds atomic.Int64
	c.open = func(p string, o Options) (*Snapshot, signature, error) {
		switch p {
		case a: // a's build can only finish once b's build has started
			select {
			case <-bStarted:
			case <-time.After(10 * time.Second):
				return nil, signature{}, fmt.Errorf("b did not build while a was building")
			}
		case b:
			close(bStarted)
		case same:
			sameBuilds.Add(1)
			<-release
		}
		return open(p, o)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for _, p := range []string{a, b} {
		wg.Go(func() { errs <- c.With(p, func(*Snapshot) error { return nil }) })
	}
	const n = 10
	for range n {
		wg.Go(func() {
			errs <- c.With(same, func(s *Snapshot) error {
				var got int
				if err := s.DB.QueryRow(`SELECT count(*) FROM T`).Scan(&got); err != nil || got != 1 {
					return fmt.Errorf("rows %d: %v", got, err)
				}
				return nil
			})
		})
	}
	// Release the shared build once at least one caller is building it.
	for sameBuilds.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := sameBuilds.Load(); got != 1 {
		t.Errorf("same path built %d times, want 1", got)
	}
}

// Finding 3: a pooled connection discarded by database/sql is replaced by an
// empty :memory: database; the cache must notice and rebuild.
func TestCacheRebuildsDroppedConnection(t *testing.T) {
	dir := plainDB(t, 3)
	c := NewCache(time.Minute, 0, Options{})
	defer c.Close()
	counts := countingOpen(c)

	var old *Snapshot
	err := c.With(dir, func(s *Snapshot) error {
		old = s
		conn, err := s.DB.Conn(context.Background())
		if err != nil {
			return err
		}
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close() // already closed by the ErrBadConn
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The old snapshot now silently serves an empty database.
	if err := old.DB.QueryRow(`SELECT count(*) FROM T`).Scan(new(int)); err == nil {
		t.Fatal("connection was not discarded; test premise broken")
	}
	err = c.With(dir, func(s *Snapshot) error {
		if got := rowCount(t, s); got != 3 {
			t.Errorf("rows %d, want 3", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := builds(counts, dir); got != 2 {
		t.Errorf("builds %d, want 2", got)
	}
}

// Finding 5: expired unused entries are swept; the LRU cap is enforced.
func TestCacheSweepAndLRU(t *testing.T) {
	a, b, d := plainDB(t, 1), plainDB(t, 1), plainDB(t, 1)
	use := func(c *Cache, p string) *Snapshot {
		var snap *Snapshot
		if err := c.With(p, func(s *Snapshot) error { snap = s; return nil }); err != nil {
			t.Fatal(err)
		}
		return snap
	}
	closed := func(s *Snapshot) bool { return s.DB.Ping() != nil }

	t.Run("sweep", func(t *testing.T) {
		c := NewCache(time.Minute, 0, Options{})
		defer c.Close()
		sa := use(c, a)
		c.mu.Lock()
		c.entries[filepath.Clean(a)].created = time.Now().Add(-time.Hour)
		c.mu.Unlock()
		use(c, b)
		c.mu.Lock()
		_, still := c.entries[filepath.Clean(a)]
		n := len(c.entries)
		c.mu.Unlock()
		if still || n != 1 || !closed(sa) {
			t.Errorf("expired entry kept=%v entries=%d closed=%v", still, n, closed(sa))
		}
	})

	t.Run("lru", func(t *testing.T) {
		c := NewCache(time.Minute, 2, Options{})
		defer c.Close()
		sa := use(c, a)
		sb := use(c, b)
		use(c, a) // a is now more recently used than b
		use(c, d)
		c.mu.Lock()
		n := len(c.entries)
		c.mu.Unlock()
		if n != 2 || !closed(sb) || closed(sa) {
			t.Errorf("entries=%d b closed=%v a closed=%v", n, closed(sb), closed(sa))
		}
	})
}

// Finding 6: ttl 0 means no caching.
func TestCacheTTLZeroBuildsEveryCall(t *testing.T) {
	dir := plainDB(t, 1)
	c := NewCache(0, 0, Options{})
	defer c.Close()
	counts := countingOpen(c)
	var snaps []*Snapshot
	for range 3 {
		if err := c.With(dir, func(s *Snapshot) error { snaps = append(snaps, s); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if got := builds(counts, dir); got != 3 {
		t.Errorf("builds %d, want 3", got)
	}
	for _, s := range snaps {
		if s.DB.Ping() == nil {
			t.Error("per-call snapshot left open")
		}
	}
	if len(c.entries) != 0 {
		t.Errorf("%d cached entries", len(c.entries))
	}
}

// Finding 6: the cache signature is taken before reading, so a write during
// decryption is picked up on the next call.
func TestCacheSignatureIsPreRead(t *testing.T) {
	dir := plainDB(t, 1)
	dbFile := filepath.Join(dir, "mpenginedb.db")
	t.Cleanup(func() { readFileHook = readFile })
	var n atomic.Int64
	readFileHook = func(p string, limit int64) ([]byte, error) {
		b, err := readFile(p, limit)
		if n.Add(1) <= readAttempts { // "write" during every read of the first build
			mt := time.Now().Add(time.Duration(n.Load()) * time.Hour)
			_ = os.Chtimes(dbFile, mt, mt)
		}
		return b, err
	}
	c := NewCache(time.Minute, 0, Options{})
	defer c.Close()
	counts := countingOpen(c)
	for range 2 {
		if err := c.With(dir, func(*Snapshot) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if got := builds(counts, dir); got != 2 {
		t.Errorf("builds %d, want 2 (rebuild after a write during the first build)", got)
	}
}

// Finding 8: failed opens are cached for the TTL while the files are unchanged.
func TestCacheCachesErrors(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "mpenginedb.db")
	if err := os.WriteFile(junk, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	c := NewCache(time.Minute, 0, Options{})
	defer c.Close()
	counts := countingOpen(c)
	for range 5 {
		for _, p := range []string{junk, missing} {
			if err := c.With(p, func(*Snapshot) error { return nil }); err == nil {
				t.Fatalf("%s: no error", p)
			}
		}
	}
	if builds(counts, junk) != 1 || builds(counts, missing) != 1 {
		t.Errorf("builds junk=%d missing=%d, want 1 each", builds(counts, junk), builds(counts, missing))
	}
	mt := time.Now().Add(time.Hour)
	if err := os.Chtimes(junk, mt, mt); err != nil {
		t.Fatal(err)
	}
	_ = c.With(junk, func(*Snapshot) error { return nil })
	if got := builds(counts, junk); got != 2 {
		t.Errorf("builds after change %d, want 2", got)
	}
}

// Finding 4: files that change while being read are re-read (at most
// readAttempts times), including a WAL whose salts change at the same size
// and mtime.
func TestReadStableRetries(t *testing.T) {
	t.Cleanup(func() { readFileHook = readFile })
	dir := plainDB(t, 1)
	dbFile := filepath.Join(dir, "mpenginedb.db")

	var dbReads atomic.Int64
	hook := func(change func(n int64)) {
		dbReads.Store(0)
		readFileHook = func(p string, limit int64) ([]byte, error) {
			b, err := readFile(p, limit)
			if p == dbFile {
				change(dbReads.Add(1))
			}
			return b, err
		}
	}

	hook(func(n int64) {
		if n == 1 {
			mt := time.Now().Add(time.Hour)
			_ = os.Chtimes(dbFile, mt, mt)
		}
	})
	_, info, err := Decrypt(dir, Options{})
	if err != nil || info.ReadAttempts != 2 || dbReads.Load() != 2 {
		t.Errorf("changed once: attempts=%v reads=%d err=%v", info, dbReads.Load(), err)
	}

	hook(func(n int64) {
		mt := time.Now().Add(time.Duration(n) * time.Hour)
		_ = os.Chtimes(dbFile, mt, mt)
	})
	_, info, err = Decrypt(dir, Options{})
	if err != nil || info.ReadAttempts != readAttempts || dbReads.Load() != readAttempts {
		t.Errorf("always changing: info=%+v reads=%d err=%v", info, dbReads.Load(), err)
	}

	// WAL salts change without a size or mtime change.
	wal := dbFile + "-wal"
	hdr := make([]byte, 32)
	if err := os.WriteFile(wal, hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	walFi, _ := os.Stat(wal)
	hook(func(n int64) {
		if n == 1 {
			hdr[16] = 0xAB
			_ = os.WriteFile(wal, hdr, 0o600)
			_ = os.Chtimes(wal, walFi.ModTime(), walFi.ModTime())
		}
	})
	_, info, err = Decrypt(dir, Options{})
	if err != nil || info.ReadAttempts != 2 {
		t.Errorf("salt change: info=%+v err=%v", info, err)
	}
}

// Finding 2: non-regular files are refused; size is capped.
func TestResolveAndSizeLimits(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "mpenginedb.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(dir, Options{}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory as db: %v", err)
	}

	ok := plainDB(t, 1)
	if err := os.Mkdir(filepath.Join(ok, "mpenginedb.db-wal"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(ok, Options{}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory as wal: %v", err)
	}

	small := plainDB(t, 1)
	if _, _, err := Decrypt(small, Options{MaxBytes: 1024}); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("max bytes: %v", err)
	}
	if _, err := readFile(filepath.Join(small, "mpenginedb.db"), 100); err == nil {
		t.Error("readFile ignored its limit")
	}
	if _, _, err := Decrypt(small, Options{}); err != nil {
		t.Errorf("default limit: %v", err)
	}
}

// A hostile generated column producing a huge blob must fail with
// SQLITE_TOOBIG instead of allocating unbounded memory.
func TestValueLengthLimit(t *testing.T) {
	src := filepath.Join(t.TempDir(), "mpenginedb.db")
	db, err := sql.Open("sqlite", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE FileHashes(ID INTEGER PRIMARY KEY, Big BLOB GENERATED ALWAYS AS (zeroblob(100000000)) VIRTUAL); INSERT INTO FileHashes(ID) VALUES(1);`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	snap, err := Open(src, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer snap.Close()
	var n int
	err = snap.DB.QueryRow(`SELECT length(Big) FROM FileHashes`).Scan(&n)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "too big") {
		t.Fatalf("expected string-or-blob-too-big error, got n=%d err=%v", n, err)
	}
}
