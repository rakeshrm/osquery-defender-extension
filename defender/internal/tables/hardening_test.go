package tables

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rakeshrm/osquery-defender-extension/internal/mpengine"
)

// sqliteDir writes a plain mpenginedb.db built from stmts into a temp dir.
func sqliteDir(t *testing.T, stmts ...string) string {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "mpenginedb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return dir
}

// Finding 1: a view (here: an infinite recursive CTE) or virtual table
// posing as a Defender table is treated as missing.
func TestHostileSchemaIgnored(t *testing.T) {
	dir := sqliteDir(t,
		`CREATE VIEW RollingQueuesValues AS WITH RECURSIVE c(x) AS (SELECT 'x' UNION ALL SELECT x FROM c) SELECT x AS EntryTable FROM c`,
		`CREATE VIEW RollingQueuesTables AS WITH RECURSIVE c(x) AS (SELECT 'x' UNION ALL SELECT x FROM c) SELECT x AS Name FROM c`,
		`CREATE VIRTUAL TABLE FileHashes USING fts5(SHA256)`,
		`INSERT INTO FileHashes VALUES ('a')`,
	)
	cfg := testConfig(t)
	cfg.QueryTimeout = 20 * time.Second // backstop only; must not be reached
	start := time.Now()
	if rows := genPath(t, cfg, "defender_mpengine_rolling_queues", dir); len(rows) != 0 {
		t.Errorf("rolling_queues: %d rows", len(rows))
	}
	if rows := genPath(t, cfg, "defender_mpengine_file_hashes", dir); len(rows) != 0 {
		t.Errorf("file_hashes from a virtual table: %d rows", len(rows))
	}
	for _, r := range genPath(t, cfg, "defender_mpengine_tables", dir) {
		if r["table_name"] == "RollingQueuesValues" || r["table_name"] == "FileHashes" {
			t.Errorf("tables lists %s", r["table_name"])
		}
	}
	if raw := genPath(t, cfg, "defender_mpengine_raw", dir); len(raw) != 0 {
		for _, r := range raw {
			if r["table_name"] == "RollingQueuesValues" || r["table_name"] == "FileHashes" {
				t.Fatalf("raw reads %s", r["table_name"])
			}
		}
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
	}
}

// Finding 1: the per-generate deadline interrupts a runaway query.
func TestQueryDeadline(t *testing.T) {
	dir := sqliteDir(t, `CREATE TABLE T (x)`)
	cfg := testConfig(t)
	err := cfg.Cache.With(dir, func(s *mpengine.Snapshot) error {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, _, err := query(ctx, s.DB, 0, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x FROM c) SELECT count(*) FROM c`)
		return err
	})
	if err == nil {
		t.Fatal("runaway query was not interrupted")
	}
	// The snapshot still works afterwards.
	if rows := genPath(t, cfg, "defender_mpengine_tables", dir); len(rows) != 1 {
		t.Errorf("after interrupt: %v", rows)
	}
}

// Finding 1: --max_rows truncates per table per path.
func TestMaxRows(t *testing.T) {
	dir := sqliteDir(t,
		`CREATE TABLE FileHashes (ID INTEGER PRIMARY KEY, SHA256 BLOB)`,
		`WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 10) INSERT INTO FileHashes SELECT i, NULL FROM c`,
	)
	cfg := testConfig(t)
	cfg.MaxRows = 3
	if rows := genPath(t, cfg, "defender_mpengine_file_hashes", dir); len(rows) != 3 {
		t.Errorf("file_hashes: %d rows, want 3", len(rows))
	}
	raw := gen(t, cfg, "defender_mpengine_raw", qc(map[string][]string{"path": {dir}, "table_name": {"FileHashes"}}))
	if len(raw) != 3*2 {
		t.Errorf("raw: %d cells, want 6", len(raw))
	}
	cfg.MaxRows = 0
	if rows := genPath(t, cfg, "defender_mpengine_file_hashes", dir); len(rows) != 10 {
		t.Errorf("unlimited: %d rows", len(rows))
	}
}

// Finding 9: TEXT in DATE/TIME-declared columns is returned as stored.
func TestDateColumnsVerbatim(t *testing.T) {
	dir := sqliteDir(t,
		`CREATE TABLE SQLiteGlobals (ID INTEGER PRIMARY KEY, Version INTEGER, Current INTEGER, LastUpdated DATETIME)`,
		`INSERT INTO SQLiteGlobals VALUES (1, 5, 1, '2024-05-06T07:08:09Z'), (2, 6, 0, 1700000000)`,
		`CREATE TABLE AmsiFileCache (ID INTEGER PRIMARY KEY, ExpirationDate timestamp)`,
		`INSERT INTO AmsiFileCache VALUES (1, '2024-05-06 07:08:09.5+02:00')`,
	)
	cfg := testConfig(t)
	sh := genPath(t, cfg, "defender_mpengine_schema_history", dir)
	if r := byID(sh, "1"); r["last_updated"] != "2024-05-06T07:08:09Z" {
		t.Errorf("last_updated %q", r["last_updated"])
	}
	if r := byID(sh, "2"); r["last_updated"] != "1700000000" {
		t.Errorf("integer last_updated %q", r["last_updated"])
	}
	if r := byID(genPath(t, cfg, "defender_mpengine_amsi_file_cache", dir), "1"); r["expiration_date"] != "2024-05-06 07:08:09.5+02:00" {
		t.Errorf("expiration_date %q", r["expiration_date"])
	}
	raw := gen(t, cfg, "defender_mpengine_raw", qc(map[string][]string{"path": {dir}, "table_name": {"SQLiteGlobals"}}))
	for _, r := range raw {
		if r["column_name"] != "LastUpdated" {
			continue
		}
		want := map[string][2]string{"1": {"2024-05-06T07:08:09Z", "text"}, "2": {"1700000000", "integer"}}[r["row_id"]]
		if [2]string{r["value"], r["value_type"]} != want {
			t.Errorf("raw row %s: %q %q", r["row_id"], r["value"], r["value_type"])
		}
	}
}

// Finding 10: UNC / device paths and non-mpenginedb file names are rejected.
func TestPathRejection(t *testing.T) {
	dir := sqliteDir(t, `CREATE TABLE SQLiteGlobals (ID INTEGER PRIMARY KEY)`, `INSERT INTO SQLiteGlobals VALUES (1)`)
	db := filepath.Join(dir, "mpenginedb.db")
	b, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.sqlite")
	upper := filepath.Join(dir, "MPENGINEDB.db.bak")
	for _, p := range []string{other, upper} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := testConfig(t)
	for p, ok := range map[string]bool{
		dir: true, db: true, upper: true, other: false,
		`\\server\share\Scans`: false, `//server/share/Scans`: false, `\\.\C:\x\mpenginedb.db`: false,
		`\\?\C:\x\mpenginedb.db`: false, `\??\C:\x\mpenginedb.db`: false,
	} {
		rows := genPath(t, cfg, "defender_mpengine_schema_history", p)
		if ok != (len(rows) == 1) {
			t.Errorf("%s: %d rows, accepted want %v", p, len(rows), ok)
		}
		st := genPath(t, cfg, "defender_mpengine_status", p)
		rejected := len(st) == 1 && strings.HasPrefix(st[0]["error"], "path rejected: ")
		if rejected == ok || st[0]["path"] != p {
			t.Errorf("%s: status %v", p, st)
		}
	}

	// The operator's --mpengine_path is trusted.
	cfg.DefaultPath = other
	if rows := gen(t, cfg, "defender_mpengine_schema_history", qc(nil)); len(rows) != 1 {
		t.Errorf("default path: %d rows", len(rows))
	}

	cfg.AllowUNCPaths = true
	st := genPath(t, cfg, "defender_mpengine_status", `//server/share/Scans`)
	if strings.HasPrefix(st[0]["error"], "path rejected") {
		t.Errorf("--allow_unc_paths: %v", st[0]["error"])
	}
}
