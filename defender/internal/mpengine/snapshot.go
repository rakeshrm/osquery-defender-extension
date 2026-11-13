package mpengine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Snapshot represents a read-only in-memory SQLite database created from decrypted evidence.
type Snapshot struct {
	DB      *sql.DB
	Info    *Info
	Created time.Time
}

// Open decrypts the database (and committed WAL frames) at path and loads it into
// an in-memory read-only SQLite database.
func Open(path string, opt Options) (*Snapshot, error) {
	img, info, err := Decrypt(path, opt)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

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

	if _, err := conn.ExecContext(ctx, "PRAGMA query_only = 1;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set query_only: %w", err)
	}

	if info.KeySource == "derived" {
		var firstLine string
		rows, err := conn.QueryContext(ctx, "PRAGMA integrity_check;")
		if err != nil {
			firstLine = err.Error()
		} else {
			if rows.Next() {
				if err := rows.Scan(&firstLine); err != nil {
					firstLine = err.Error()
				}
			}
			_ = rows.Close()
			if err := rows.Err(); err != nil && firstLine == "" {
				firstLine = err.Error()
			}
		}
		if firstLine != "ok" {
			_ = conn.Close()
			_ = db.Close()
			return nil, fmt.Errorf("derived keystream did not produce a consistent database (%d low-confidence byte positions): %s", info.DerivedLowConfidence, firstLine)
		}
	}

	return &Snapshot{
		DB:      db,
		Info:    info,
		Created: time.Now(),
	}, nil
}

// Close closes the in-memory database.
func (s *Snapshot) Close() error {
	if s.DB != nil {
		return s.DB.Close()
	}
	return nil
}

type fileStat struct {
	size    int64
	modTime time.Time
}

func statFile(path string) (fileStat, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStat{}, err
	}
	return fileStat{
		size:    fi.Size(),
		modTime: fi.ModTime(),
	}, nil
}

type cacheEntry struct {
	snapshot *Snapshot
	dbPath   string
	walPath  string
	dbStat   fileStat
	walStat  fileStat
	hasWal   bool
	created  time.Time
	refs     int
	closed   bool
}

// Cache caches decrypted snapshots keyed by cleaned path, reusing them while DB and WAL
// size and modification times are unchanged and age is within ttl.
type Cache struct {
	ttl     time.Duration
	opt     Options
	mu      sync.Mutex
	entries map[string]*cacheEntry
	closed  bool
}

// NewCache creates a new Cache with the given TTL and decryption options.
func NewCache(ttl time.Duration, opt Options) *Cache {
	return &Cache{
		ttl:     ttl,
		opt:     opt,
		entries: make(map[string]*cacheEntry),
	}
}

func (c *Cache) isEntryValidLocked(entry *cacheEntry, path string) bool {
	if entry == nil || entry.closed {
		return false
	}
	if c.ttl > 0 && time.Since(entry.created) >= c.ttl {
		return false
	}
	dbPath, walPath, err := Resolve(path, c.opt)
	if err != nil {
		return false
	}
	if dbPath != entry.dbPath {
		return false
	}
	stDB, err := statFile(dbPath)
	if err != nil || stDB.size != entry.dbStat.size || !stDB.modTime.Equal(entry.dbStat.modTime) {
		return false
	}
	if (walPath != "") != entry.hasWal {
		return false
	}
	if walPath != "" {
		stWAL, err := statFile(walPath)
		if err != nil || stWAL.size != entry.walStat.size || !stWAL.modTime.Equal(entry.walStat.modTime) {
			return false
		}
	}
	return true
}

// With runs fn with a cached (or freshly built) snapshot for path. Safe for
// concurrent use; a snapshot is never closed while fn is running on it.
func (c *Cache) With(path string, fn func(*Snapshot) error) error {
	if path == "" {
		return errors.New("empty path")
	}
	cleanPath := filepath.Clean(path)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("cache is closed")
	}

	entry := c.entries[cleanPath]
	if !c.isEntryValidLocked(entry, cleanPath) {
		if entry != nil {
			entry.closed = true
			if entry.refs == 0 {
				entry.snapshot.Close()
			}
			delete(c.entries, cleanPath)
		}

		snap, err := Open(cleanPath, c.opt)
		if err != nil {
			c.mu.Unlock()
			return err
		}

		dbStat, _ := statFile(snap.Info.DBPath)
		var walStat fileStat
		hasWal := snap.Info.WALPath != ""
		if hasWal {
			walStat, _ = statFile(snap.Info.WALPath)
		}

		entry = &cacheEntry{
			snapshot: snap,
			dbPath:   snap.Info.DBPath,
			walPath:  snap.Info.WALPath,
			dbStat:   dbStat,
			walStat:  walStat,
			hasWal:   hasWal,
			created:  time.Now(),
		}
		c.entries[cleanPath] = entry
	}

	entry.refs++
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		entry.refs--
		if entry.closed && entry.refs == 0 {
			entry.snapshot.Close()
		}
		c.mu.Unlock()
	}()

	return fn(entry.snapshot)
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
	for k, entry := range c.entries {
		entry.closed = true
		if entry.refs == 0 {
			entry.snapshot.Close()
		}
		delete(c.entries, k)
	}
}
