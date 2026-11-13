package tables

import (
	"context"
	"database/sql"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
	"github.com/osquery/osquery-go/plugin/table"
)

// tableNames lists the ordinary tables (no views or virtual tables).
func tableNames(ctx context.Context, db *sql.DB) ([]string, []string, error) {
	_, rows, err := query(ctx, db, 0, `SELECT name, sql FROM sqlite_master WHERE type = 'table'
		AND rootpage > 0 AND upper(ltrim(sql)) NOT LIKE 'CREATE VIRTUAL%' ORDER BY name`)
	names, sqls := make([]string, len(rows)), make([]string, len(rows))
	for i, r := range rows {
		names[i], sqls[i] = text(r[0]), text(r[1])
	}
	return names, sqls, err
}

// defender_mpengine_tables: every table in the snapshot with its row count.
func (cfg Config) tablesGen(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	ctx, cancel := cfg.deadline(ctx)
	defer cancel()
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
	ctx, cancel := cfg.deadline(ctx)
	defer cancel()
	want := constraintValues(qc, "table_name")
	var out []map[string]string
	cfg.each(qc, "defender_mpengine_raw", func(p string, s *mpengine.Snapshot) error {
		rd := cfg.reader(p, s)
		names, _, err := tableNames(ctx, s.DB)
		if err != nil {
			return err
		}
		for _, n := range names {
			if len(want) > 0 && !slices.Contains(want, n) {
				continue
			}
			sel, err := selectList(ctx, s.DB, n)
			if err != nil {
				return err
			}
			if len(sel) == 0 {
				continue
			}
			q := "SELECT " + strings.Join(sel, ", ") + " FROM " + quoteIdent(n)
			cols, rows, err := rd.query(ctx, n, q+" ORDER BY rowid")
			if err != nil { // WITHOUT ROWID table: natural order
				if cols, rows, err = rd.query(ctx, n, q); err != nil {
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
	default: // string
		return text(x), "text"
	}
}
