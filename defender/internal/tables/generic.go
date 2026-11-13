package tables

import (
	"context"
	"database/sql"
	"encoding/hex"
	"slices"
	"strconv"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
	"github.com/osquery/osquery-go/plugin/table"
)

func tableNames(ctx context.Context, db *sql.DB) ([]string, []string, error) {
	_, rows, err := query(ctx, db, `SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	names, sqls := make([]string, len(rows)), make([]string, len(rows))
	for i, r := range rows {
		names[i], sqls[i] = text(r[0]), text(r[1])
	}
	return names, sqls, err
}

// defender_mpengine_tables: every table in the snapshot with its row count.
func (cfg Config) tablesGen(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	var out []map[string]string
	cfg.each(qc, "defender_mpengine_tables", func(p string, s *mpengine.Snapshot) error {
		names, sqls, err := tableNames(ctx, s.DB)
		if err != nil {
			return err
		}
		for i, n := range names {
			var count int64
			if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+quoteIdent(n)).Scan(&count); err != nil {
				return err
			}
			out = append(out, map[string]string{
				"table_name": n, "row_count": strconv.FormatInt(count, 10), "sql": sqls[i], "path": p,
			})
		}
		return nil
	})
	return out, nil
}

// defender_mpengine_raw: one row per cell, optionally limited by `table_name =`.
func (cfg Config) rawGen(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	want := constraintValues(qc, "table_name")
	var out []map[string]string
	cfg.each(qc, "defender_mpengine_raw", func(p string, s *mpengine.Snapshot) error {
		names, _, err := tableNames(ctx, s.DB)
		if err != nil {
			return err
		}
		for _, n := range names {
			if len(want) > 0 && !slices.Contains(want, n) {
				continue
			}
			q := "SELECT * FROM " + quoteIdent(n)
			cols, rows, err := query(ctx, s.DB, q+" ORDER BY rowid")
			if err != nil { // WITHOUT ROWID table: natural order
				if cols, rows, err = query(ctx, s.DB, q); err != nil {
					return err
				}
			}
			for i, r := range rows {
				for j, c := range cols {
					v, typ := rawValue(r[j])
					out = append(out, map[string]string{
						"table_name": n, "row_id": strconv.Itoa(i + 1), "column_name": c,
						"value": v, "value_type": typ, "path": p,
					})
				}
			}
		}
		return nil
	})
	return out, nil
}

func rawValue(v any) (string, string) {
	switch x := v.(type) {
	case nil:
		return "", "null"
	case int64:
		return text(x), "integer"
	case float64:
		return text(x), "real"
	case []byte:
		return hex.EncodeToString(x), "blob"
	default: // string, or time.Time from DATE/DATETIME columns
		return text(x), "text"
	}
}
