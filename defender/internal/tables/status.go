package tables

import (
	"context"
	"strconv"
	"strings"

	"github.com/rakeshrm/osquery-defender-extension/internal/mpengine"
	"github.com/osquery/osquery-go/plugin/table"
)

// statusCols lists defender_mpengine_status columns ("+" = BIGINT).
var statusCols = []string{
	"db_path", "wal_path", "+db_size", "+wal_size", "db_sha256", "wal_sha256",
	"protection", "key_source", "keystream_sha256", "+derived_low_confidence",
	"+page_size", "+db_pages", "+wal_header_valid", "+wal_frames_total",
	"+wal_frames_committed", "+wal_commits", "wal_note", "quick_check", "integrity_check",
	"+table_count", "error", "path",
}

// defender_mpengine_status: one row per path; failures are reported in
// `error` instead of being dropped.
func (cfg Config) statusGen(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	ctx, cancel := cfg.deadline(ctx)
	defer cancel()
	var out []map[string]string
	for _, p := range cfg.paths(qc) {
		row := map[string]string{}
		err := cfg.with(p, func(s *mpengine.Snapshot) error {
			i := s.Info
			itoa := strconv.Itoa
			row = map[string]string{
				"db_path": i.DBPath, "wal_path": i.WALPath,
				"db_size": strconv.FormatInt(i.DBSize, 10), "wal_size": strconv.FormatInt(i.WALSize, 10),
				"db_sha256": i.DBSHA256, "wal_sha256": i.WALSHA256,
				"protection": i.Protection, "key_source": i.KeySource, "keystream_sha256": i.KeystreamSHA256,
				"derived_low_confidence": itoa(i.DerivedLowConfidence),
				"page_size":              itoa(i.PageSize), "db_pages": itoa(i.DBPages),
				"wal_header_valid": itoa(boolInt(i.WALHeaderValid)),
				"wal_frames_total": itoa(i.WALFramesTotal), "wal_frames_committed": itoa(i.WALFramesCommitted),
				"wal_commits": itoa(i.WALCommits), "wal_note": i.WALNote,
				"quick_check": i.QuickCheck, "integrity_check": "ok",
			}
			_, rows, err := query(ctx, s.DB, 0, "PRAGMA integrity_check")
			if err != nil {
				row["integrity_check"] = err.Error()
			} else if len(rows) > 0 {
				row["integrity_check"] = text(rows[0][0])
			}
			var n int64
			if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type = 'table'").Scan(&n); err == nil {
				row["table_count"] = strconv.FormatInt(n, 10)
			}
			return nil
		})
		if err != nil {
			row = map[string]string{"error": err.Error()}
		}
		for _, c := range statusCols {
			if c = strings.TrimPrefix(c, "+"); row[c] == "" {
				row[c] = ""
			}
		}
		row["path"] = p
		out = append(out, row)
	}
	return out, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
