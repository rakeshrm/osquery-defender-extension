// Package tables exposes a decrypted mpenginedb.db snapshot as osquery tables.
//
// Typed tables are declared as data (Spec/Col); the engine reads each source
// table schema-tolerantly (only columns that exist, missing table = no rows)
// and renders every value according to its column Kind.
package tables

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/osquery/osquery-go/plugin/table"
)

// Kind selects how a source value is rendered and which osquery type it has.
type Kind int

const (
	Text     Kind = iota // TEXT; blobs holding text are rendered as text
	Int                  // BIGINT; non-numeric values render as ""
	FileTime             // BIGINT <name> (unix seconds, "" if implausible) + BIGINT <name>_raw
	Hex                  // TEXT; lowercase hex of the bytes
	GUIDLE               // TEXT; 16-byte blob as little-endian Windows GUID, otherwise hex
	Hex32                // TEXT; %08X of v & 0xFFFFFFFF
	CStr                 // TEXT; bytes up to the first NUL
)

// FILETIME plausibility window: 1980-01-01 <= t < 2107-01-01.
const (
	ftMin          = 119600064000000000
	ftMax          = 159793632000000000
	ftUnixEpochSec = 11644473600
)

// Row is one source row keyed by source column name (plus keys added by
// From.Set or Spec.Prep). Values are int64, float64, string, []byte,
// time.Time or nil.
type Row map[string]any

// Col maps one output column. The value is Fn(row) when Fn is set (a computed
// column), otherwise row[Src]; it is then rendered according to Kind.
type Col struct {
	Name string
	Src  string
	Kind Kind
	Fn   func(Row) any
}

// From is one source table; Set adds constant keys to each of its rows.
type From struct {
	Table string
	Set   Row
}

// Spec declares one typed osquery table.
type Spec struct {
	Name string
	From []From
	Cols []Col
	// Prep optionally loads auxiliary data (joins) once per snapshot query
	// and returns a function that enriches each source row.
	Prep func(ctx context.Context, db *sql.DB) (func(Row), error)
}

func (s Spec) columns() []table.ColumnDefinition {
	var defs []table.ColumnDefinition
	for _, c := range s.Cols {
		switch c.Kind {
		case Int:
			defs = append(defs, table.BigIntColumn(c.Name))
		case FileTime:
			defs = append(defs, table.BigIntColumn(c.Name), table.BigIntColumn(c.Name+"_raw"))
		default:
			defs = append(defs, table.TextColumn(c.Name))
		}
	}
	return append(defs, table.TextColumn("path"))
}

func (s Spec) rows(ctx context.Context, db *sql.DB) ([]map[string]string, error) {
	var enrich func(Row)
	if s.Prep != nil {
		var err error
		if enrich, err = s.Prep(ctx, db); err != nil {
			return nil, err
		}
	}
	var out []map[string]string
	for _, f := range s.From {
		src, err := readTable(ctx, db, f.Table)
		if err != nil {
			return nil, err
		}
		for _, r := range src {
			maps.Copy(r, f.Set)
			if enrich != nil {
				enrich(r)
			}
			o := make(map[string]string, len(s.Cols)+4)
			for _, c := range s.Cols {
				c.emit(r, o)
			}
			out = append(out, o)
		}
	}
	return out, nil
}

func (c Col) emit(r Row, o map[string]string) {
	v := r[c.Src]
	if c.Fn != nil {
		v = c.Fn(r)
	}
	switch c.Kind {
	case Text:
		o[c.Name] = text(v)
	case Int:
		o[c.Name] = ""
		if n, ok := toInt(v); ok {
			o[c.Name] = strconv.FormatInt(n, 10)
		}
	case FileTime:
		o[c.Name], o[c.Name+"_raw"] = "", ""
		if n, ok := toInt(v); ok {
			o[c.Name+"_raw"] = strconv.FormatInt(n, 10)
			if n >= ftMin && n < ftMax {
				o[c.Name] = strconv.FormatInt(n/10_000_000-ftUnixEpochSec, 10)
			}
		}
	case Hex:
		o[c.Name] = hex.EncodeToString(toBytes(v))
	case GUIDLE:
		o[c.Name] = guidLE(toBytes(v))
	case Hex32:
		o[c.Name] = ""
		if n, ok := toInt(v); ok {
			o[c.Name] = fmt.Sprintf("%08X", uint32(n))
		}
	case CStr:
		b := toBytes(v)
		if i := strings.IndexByte(string(b), 0); i >= 0 {
			b = b[:i]
		}
		o[c.Name] = string(b)
	}
}

// --- value helpers ---

func text(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case time.Time: // modernc parses TEXT in DATE/DATETIME/TIMESTAMP columns
		if x.Location() == time.UTC {
			return x.Format("2006-01-02 15:04:05.999999999")
		}
		return x.Format("2006-01-02 15:04:05.999999999-07:00")
	default:
		return fmt.Sprint(x)
	}
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		if x == float64(int64(x)) {
			return int64(x), true
		}
	case string, []byte:
		n, err := strconv.ParseInt(strings.TrimSpace(text(x)), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func toBytes(v any) []byte {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		return x
	default:
		return []byte(text(x))
	}
}

// guidLE renders a 16-byte Windows GUID (Data1-3 little-endian); other
// lengths fall back to hex. Empty input gives "".
func guidLE(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%x-%x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8:10], b[10:16])
}

// --- schema-tolerant reading ---

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// readTable returns all rows of tbl, selecting only the columns that exist
// (per pragma table_info). A missing table yields no rows and no error.
func readTable(ctx context.Context, db *sql.DB, tbl string) ([]Row, error) {
	_, names, err := query(ctx, db, `SELECT name FROM pragma_table_info(?)`, tbl)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	sel := make([]string, len(names))
	for i, n := range names {
		sel[i] = quoteIdent(text(n[0]))
	}
	cols, vals, err := query(ctx, db, "SELECT "+strings.Join(sel, ", ")+" FROM "+quoteIdent(tbl))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tbl, err)
	}
	rows := make([]Row, len(vals))
	for i, v := range vals {
		r := make(Row, len(cols))
		for j, c := range cols {
			r[c] = v[j]
		}
		rows[i] = r
	}
	return rows, nil
}

// query runs q and returns the column names and all row values.
func query(ctx context.Context, db *sql.DB, q string, args ...any) ([]string, [][]any, error) {
	rs, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rs.Close()
	cols, err := rs.Columns()
	if err != nil {
		return nil, nil, err
	}
	var out [][]any
	for rs.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rs.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		out = append(out, vals)
	}
	return cols, out, rs.Err()
}
