package mpengine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"modernc.org/sqlite"
)

const (
	// sqliteLimitLength is SQLITE_LIMIT_LENGTH (sqlite3.h).
	sqliteLimitLength = 0
	// maxValueBytes caps a single string/blob value. Real MpEngineDb values
	// are small (paths, hashes, short JSON); 16 MiB leaves ample headroom.
	maxValueBytes = 16 << 20
)

// DefaultCacheEntries is the default LRU cap of a Cache.
const DefaultCacheEntries = 8

// Snapshot represents a read-only in-memory SQLite database created from decrypted evidence.
type Snapshot struct {
	DB      *sql.DB
	Info    *Info
	Created time.Time

	pages int64 // PRAGMA page_count right after loading; see valid
}

// Open decrypts the database (and committed WAL frames) at path and loads it into
// an in-memory read-only SQLite database. PRAGMA quick_check runs on every
// open (Info.QuickCheck); a failure with a known key or a plaintext image is
// retried once (torn read) and then served anyway. A derived keystream must
// pass PRAGMA integrity_check.
func Open(path string, opt Options) (*Snapshot, error) {
	s, _, err := open(path, opt)
	return s, err
}

// open is Open that also returns the pre-read file signature (on error too).
func open(path string, opt Options) (*Snapshot, signature, error) {
	s, sig, err := openOnce(path, opt)
	if err != nil || s.Info.QuickCheck == "ok" || s.Info.KeySource == "derived" {
		return s, sig, err
	}
	if s2, sig2, err2 := openOnce(path, opt); err2 == nil {
		s.Close()
		return s2, sig2, nil
	}
	return s, sig, nil
}

func openOnce(path string, opt Options) (*Snapshot, signature, error) {
	img, info, err := decrypt(path, opt)
	if err != nil {
		return nil, info.sig, err
	}
	db, err := load(img)
	if err != nil {
		return nil, info.sig, err
	}
	ctx := context.Background()
	info.QuickCheck = firstLine(ctx, db, "PRAGMA quick_check")
	if info.KeySource == "derived" {
		if ic := firstLine(ctx, db, "PRAGMA integrity_check"); ic != "ok" {
			db.Close()
			return nil, info.sig, fmt.Errorf("derived keystream did not produce a consistent database (%d low-confidence byte positions): %s", info.DerivedLowConfidence, ic)
		}
	}
	var pages int64
	if err := db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		db.Close()
		return nil, info.sig, fmt.Errorf("page_count: %w", err)
	}
	return &Snapshot{DB: db, Info: info, Created: time.Now(), pages: pages}, info.sig, nil
}

// load deserializes img into a single-connection in-memory database with
// query_only=1, trusted_schema=OFF and temp_store=MEMORY (decrypted data
// never spills to temp files).
func load(img []byte) (*sql.DB, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	defer conn.Close()

	err = conn.Raw(func(dc any) error {
		d, ok := dc.(interface{ Deserialize([]byte) error })
		if !ok {
			return errors.New("driver connection does not implement Deserialize")
		}
		return d.Deserialize(img)
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite deserialize: %w", err)
	}
	for _, p := range []string{"PRAGMA trusted_schema = OFF", "PRAGMA temp_store = MEMORY", "PRAGMA query_only = 1"} {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	// Cap any single string/blob value so hostile content (e.g. a generated
	// column using zeroblob) cannot allocate unbounded memory.
	if _, err := sqlite.Limit(conn, sqliteLimitLength, maxValueBytes); err != nil {
		db.Close()
		return nil, fmt.Errorf("set SQLITE_LIMIT_LENGTH: %w", err)
	}
	return db, nil
}

// firstLine returns the first result row of a check pragma, or the error text.
func firstLine(ctx context.Context, db *sql.DB, q string) string {
	var s string
	if err := db.QueryRowContext(ctx, q).Scan(&s); err != nil {
		return err.Error()
	}
	return s
}

// IntegrityCheck loads img into a temporary in-memory database and returns
// the first line of PRAGMA integrity_check ("ok" when consistent).
func IntegrityCheck(img []byte) (string, error) {
	db, err := load(img)
	if err != nil {
		return "", err
	}
	defer db.Close()
	return firstLine(context.Background(), db, "PRAGMA integrity_check"), nil
}

// valid reports whether the pooled connection still holds the loaded image.
// database/sql silently replaces a connection it discarded (driver.ErrBadConn)
// with a fresh, empty :memory: database. It waits for the single connection
// like any other query on the snapshot would.
func (s *Snapshot) valid() bool {
	var n int64
	return s.DB.QueryRow("PRAGMA page_count").Scan(&n) == nil && n == s.pages
}

// Close closes the in-memory database.
func (s *Snapshot) Close() error {
	if s != nil && s.DB != nil {
		return s.DB.Close()
	}
	return nil
}

type cacheEntry struct {
	path     string
	ready    chan struct{} // closed once snapshot/err/sig are set
	snapshot *Snapshot     // nil for a cached error
	err      error
	sig      signature // pre-read signature of the build
	created  time.Time
	lastUsed time.Time
	refs     int
	closed   bool // removed from the cache; close the snapshot at refs == 0
}

func (e *cacheEntry) isReady() bool {
	select {
	case <-e.ready:
		return true
	default:
		return false
	}
}

// Cache caches decrypted snapshots keyed by cleaned path, reusing them while
// DB and WAL size and modification times are unchanged and age is below ttl.
// Failed opens are cached the same way, so a bad file is not re-decrypted by
// every table of a pack. ttl <= 0 disables caching (every With builds and
// closes its own snapshot). At most maxEntries snapshots are kept (LRU).
//
// Builds are single-flight per path: concurrent callers for one path share
// one build; different paths build in parallel. The mutex only guards the
// map.
type Cache struct {
	ttl        time.Duration
	maxEntries int
	opt        Options
	open       func(string, Options) (*Snapshot, signature, error) // tests replace it

	mu      sync.Mutex
	entries map[string]*cacheEntry
	closed  bool
}

// NewCache creates a Cache. maxEntries <= 0 means DefaultCacheEntries.
func NewCache(ttl time.Duration, maxEntries int, opt Options) *Cache {
	if maxEntries <= 0 {
		maxEntries = DefaultCacheEntries
	}
	return &Cache{
		ttl:        ttl,
		maxEntries: maxEntries,
		opt:        opt,
		open:       open,
		entries:    make(map[string]*cacheEntry),
	}
}

// With runs fn with a cached (or freshly built) snapshot for path. Safe for
// concurrent use; a snapshot is never closed while fn is running on it.
func (c *Cache) With(path string, fn func(*Snapshot) error) error {
	if path == "" {
		return errors.New("empty path")
	}
	cleanPath := filepath.Clean(path)

	if c.ttl <= 0 {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return errors.New("cache is closed")
		}
		s, _, err := c.open(cleanPath, c.opt)
		if err != nil {
			return err
		}
		defer s.Close()
		return fn(s)
	}

	e, err := c.acquire(cleanPath)
	if err != nil {
		return err
	}
	defer c.release(e)
	return fn(e.snapshot)
}

// acquire returns a ready entry holding a snapshot, with a reference taken.
func (c *Cache) acquire(path string) (*cacheEntry, error) {
	for attempt := 0; ; attempt++ {
		// Stat outside the lock; the lock only guards the map.
		cur := currentSignature(path, c.opt)
		now := time.Now()

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, errors.New("cache is closed")
		}
		c.sweepLocked(now)
		e := c.entries[path]
		if e != nil && e.isReady() && (now.Sub(e.created) >= c.ttl || e.sig != cur) {
			c.removeLocked(e)
			e = nil
		}
		building := e == nil
		if building {
			e = &cacheEntry{path: path, ready: make(chan struct{})}
			c.entries[path] = e
			c.evictLocked()
		}
		e.refs++
		e.lastUsed = now
		c.mu.Unlock()

		if building {
			s, sig, err := c.open(path, c.opt)
			c.mu.Lock()
			e.snapshot, e.sig, e.err, e.created = s, sig, err, time.Now()
			close(e.ready) // if the entry was removed meanwhile, release closes s
			c.mu.Unlock()
		} else {
			<-e.ready
		}

		if e.err != nil {
			c.release(e)
			return nil, e.err
		}
		// A replaced (empty) connection is rebuilt; retry once at most.
		if attempt == 0 && !building && !e.snapshot.valid() {
			c.mu.Lock()
			c.removeLocked(e)
			c.mu.Unlock()
			c.release(e)
			continue
		}
		return e, nil
	}
}

func (c *Cache) release(e *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.refs--
	if e.closed && e.refs == 0 && e.snapshot != nil {
		e.snapshot.Close()
	}
}

// removeLocked drops e from the map; its snapshot is closed once unused.
func (c *Cache) removeLocked(e *cacheEntry) {
	if c.entries[e.path] == e {
		delete(c.entries, e.path)
	}
	if e.closed {
		return
	}
	e.closed = true
	if e.refs == 0 && e.snapshot != nil {
		e.snapshot.Close()
	}
}

// sweepLocked closes unused entries whose TTL has expired.
func (c *Cache) sweepLocked(now time.Time) {
	for _, e := range c.entries {
		if e.refs == 0 && e.isReady() && now.Sub(e.created) >= c.ttl {
			c.removeLocked(e)
		}
	}
}

// evictLocked removes least recently used unused entries above maxEntries.
func (c *Cache) evictLocked() {
	for len(c.entries) > c.maxEntries {
		var lru *cacheEntry
		for _, e := range c.entries {
			if e.refs == 0 && e.isReady() && (lru == nil || e.lastUsed.Before(lru.lastUsed)) {
				lru = e
			}
		}
		if lru == nil {
			return // everything is in use or building
		}
		c.removeLocked(lru)
	}
}

// Close closes all cached snapshots that are not in use. Snapshots currently in use
// will be closed when their callers finish.
func (c *Cache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for _, e := range c.entries {
		c.removeLocked(e)
	}
}
