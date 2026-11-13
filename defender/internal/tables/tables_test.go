package tables

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/rakeshrm/osquery-defender-extension/internal/mpengine"
	"github.com/osquery/osquery-go/plugin/table"
)

const oracle = "../mpengine/testdata/oracle"

var knownKey = filepath.Join(oracle, "known_key")

func testConfig(t *testing.T) Config {
	t.Helper()
	c := mpengine.NewCache(time.Minute, 0, mpengine.Options{})
	t.Cleanup(c.Close)
	return Config{Cache: c, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func qc(cols map[string][]string) table.QueryContext {
	q := table.QueryContext{Constraints: map[string]table.ConstraintList{}}
	for col, vals := range cols {
		var cl table.ConstraintList
		for _, v := range vals {
			cl.Constraints = append(cl.Constraints, table.Constraint{Operator: table.OperatorEquals, Expression: v})
		}
		q.Constraints[col] = cl
	}
	return q
}

// gen runs table name against path and checks every row has exactly the
// declared columns.
func gen(t *testing.T, cfg Config, name string, q table.QueryContext) []map[string]string {
	t.Helper()
	for _, d := range cfg.defs() {
		if d.name != name {
			continue
		}
		rows, err := d.gen(context.Background(), q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var want []string
		for _, c := range d.cols {
			want = append(want, c.Name)
		}
		slices.Sort(want)
		for _, r := range rows {
			if got := slices.Sorted(maps.Keys(r)); !slices.Equal(got, want) {
				t.Fatalf("%s: row columns %v, declared %v", name, got, want)
			}
		}
		return rows
	}
	t.Fatalf("no table %s", name)
	return nil
}

func genPath(t *testing.T, cfg Config, name, path string) []map[string]string {
	return gen(t, cfg, name, qc(map[string][]string{"path": {path}}))
}

// expected loads expected_rows.json with exact integers.
func expected(t *testing.T) map[string][]map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(knownKey, "expected_rows.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.UseNumber()
	var m map[string][]map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func num(t *testing.T, v any) int64 {
	t.Helper()
	n, err := v.(json.Number).Int64()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func byID(rows []map[string]string, id string) map[string]string {
	for _, r := range rows {
		if r["id"] == id {
			return r
		}
	}
	return nil
}

func TestRowCounts(t *testing.T) {
	cfg, exp := testConfig(t), expected(t)
	for name, src := range map[string][]string{
		"defender_mpengine_rolling_queues":        {"RollingQueuesValues"},
		"defender_mpengine_persist_context":       {"AttributePersistContext"},
		"defender_mpengine_file_hashes":           {"FileHashes"},
		"defender_mpengine_backup_process_info":   {"BackupProcessInfo"},
		"defender_mpengine_lowfi_async":           {"FileLowFiAsync"},
		"defender_mpengine_process_block_history": {"ProcessBlockHistory"},
		"defender_mpengine_bm_process_info":       {"BmProcessInfo"},
		"defender_mpengine_ransomware_detections": {"RansomwareDetections"},
		"defender_mpengine_firewall_rules":        {"NetworkIpFirewallRules", "NetworkIpFirewallRulesOutgoing"},
		"defender_mpengine_atomic_counters":       {"AtomicCounters"},
		"defender_mpengine_folder_guard_paths":    {"FolderGuardPaths"},
		"defender_mpengine_amsi_file_cache":       {"AmsiFileCache"},
		"defender_mpengine_schema_history":        {"SQLiteGlobals"},
		"defender_mpengine_inventory_identifiers": {"MetaInventoryIdentifiers"},
	} {
		want := 0
		for _, s := range src {
			want += len(exp[s])
		}
		rows := genPath(t, cfg, name, knownKey)
		if len(rows) != want || want == 0 {
			t.Errorf("%s: %d rows, want %d", name, len(rows), want)
		}
		for _, r := range rows {
			if r["path"] != knownKey {
				t.Fatalf("%s: path %q", name, r["path"])
			}
		}
	}
	if n := len(specs) + 3; len(Plugins(cfg)) != n {
		t.Errorf("Plugins: %d, want %d", len(Plugins(cfg)), n)
	}
}

func TestFileHashes(t *testing.T) {
	cfg, exp := testConfig(t), expected(t)
	var src map[string]string
	b, err := os.ReadFile(filepath.Join(knownKey, "hash_sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &src); err != nil {
		t.Fatal(err)
	}
	rows := genPath(t, cfg, "defender_mpengine_file_hashes", knownKey)
	sawNegCRC := false
	for _, e := range exp["FileHashes"] {
		id := e["ID"].(json.Number).String()
		r := byID(rows, id)
		content, ok := src[id]
		if r == nil || !ok {
			t.Fatalf("FileHashes %s: row %v source %v", id, r != nil, ok)
		}
		m, s1, s256 := md5.Sum([]byte(content)), sha1.Sum([]byte(content)), sha256.Sum256([]byte(content))
		if r["md5"] != hex.EncodeToString(m[:]) || r["sha1"] != hex.EncodeToString(s1[:]) || r["sha256"] != hex.EncodeToString(s256[:]) {
			t.Errorf("FileHashes %s hashes: %s %s %s", id, r["md5"], r["sha1"], r["sha256"])
		}
		fid := uint64(num(t, e["FileID"]))
		if r["file_id"] != strconv.FormatInt(int64(fid), 10) ||
			r["mft_entry"] != strconv.FormatUint(fid&0xFFFFFFFFFFFF, 10) ||
			r["mft_sequence"] != strconv.FormatUint(fid>>48, 10) {
			t.Errorf("FileHashes %s mft: %s %s %s", id, r["file_id"], r["mft_entry"], r["mft_sequence"])
		}
		vsn := num(t, e["VSN"])
		if want := fmt.Sprintf("%04X-%04X", vsn>>16&0xFFFF, vsn&0xFFFF); r["volume_serial"] != want {
			t.Errorf("FileHashes %s volume_serial %s want %s", id, r["volume_serial"], want)
		}
		for col, srcCol := range map[string]string{"partial_crc1": "PartialCRC1", "partial_crc2": "PartialCRC2", "kcrc3": "KCRC3", "kcrc3n": "KCRC3n"} {
			v := num(t, e[srcCol])
			sawNegCRC = sawNegCRC || v < 0
			if want := fmt.Sprintf("%08X", uint32(v)); r[col] != want {
				t.Errorf("FileHashes %s %s=%s want %s", id, col, r[col], want)
			}
		}
		if r["ssdeep"] == "" || slices.Contains([]byte(r["ssdeep"]), 0) {
			t.Errorf("FileHashes %s ssdeep %q", id, r["ssdeep"])
		}
	}
	if !sawNegCRC {
		t.Error("fixture has no negative CRC")
	}
	if r := byID(rows, "1"); r["partial_crc2"] != "B5BF992D" || r["ssdeep"] != "3:288b8e049c9ab542847ccb:a67caacfd0" {
		t.Errorf("row 1: crc2 %s ssdeep %q", r["partial_crc2"], r["ssdeep"])
	}

	// The plain (codec disabled) fixture yields the same rows.
	plain := genPath(t, cfg, "defender_mpengine_file_hashes", filepath.Join(oracle, "plain"))
	strip := func(rs []map[string]string) []map[string]string {
		out := make([]map[string]string, len(rs))
		for i, r := range rs {
			out[i] = maps.Clone(r)
			delete(out[i], "path")
		}
		return out
	}
	if !slices.EqualFunc(strip(rows), strip(plain), maps.Equal) {
		t.Error("plain fixture file_hashes differ from known_key")
	}
}

func TestRollingQueues(t *testing.T) {
	rows := genPath(t, testConfig(t), "defender_mpengine_rolling_queues", knownKey)
	r := byID(rows, "1")
	want := map[string]string{
		"queue_type": "techniques", "technique_id": "T1547.001", "pid": "4312",
		"process_start_raw": "134382852170000000", "process_start": "1793811617",
		"queue_capacity": "64", "queue_ttl": "3600", "insert_time_raw": "134382858000000000",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("row 1 %s=%q want %q", k, r[k], v)
		}
	}
	for id, w := range map[string][3]string{ // queue_type, technique_id, pid
		"3": {"tactics", "", "4312"},
		"4": {"recent_threats", "", "4312"}, // pid from EntryValue
		"5": {"tracked_pids", "", "7788"},   // pid from EntryKey
		"6": {"dropped_executable", "", ""},
		"7": {"techniques", "T1003.001", "9120"},
	} {
		r := byID(rows, id)
		if got := [3]string{r["queue_type"], r["technique_id"], r["pid"]}; got != w {
			t.Errorf("row %s: %v want %v", id, got, w)
		}
	}
	// Namespace "BM" makes the join key "BMTact-pid:...", which does not match.
	if r := byID(rows, "3"); r["queue_capacity"] != "" {
		t.Errorf("row 3 capacity %q", r["queue_capacity"])
	}
}

func TestPersistContext(t *testing.T) {
	rows := genPath(t, testConfig(t), "defender_mpengine_persist_context", knownKey)
	r := byID(rows, "5")
	if r["record_kind"] != "asr_rule_state" || r["asr_rule_id"] != "d4f940ab-401b-4efc-aadc-ad5f3c50688a" ||
		r["asr_rule_name"] != "Block all Office applications from creating child processes" || r["context"] != "2" {
		t.Errorf("asr row: %v", r)
	}
	r = byID(rows, "3")
	if r["record_kind"] != "path_tag" || r["asr_rule_id"] != "" || r["file_path"] != `C:\Users\jörg\Desktop\файл.exe` {
		t.Errorf("path tag row (non-ASCII): %v", r)
	}
}

func TestProcessBlockHistory(t *testing.T) {
	rows := genPath(t, testConfig(t), "defender_mpengine_process_block_history", knownKey)
	r := byID(rows, "1")
	if r["rule_id"] != "d4f940ab-401b-4efc-aadc-ad5f3c50688a" || r["asr_rule_name"] != "Block all Office applications from creating child processes" {
		t.Errorf("row 1: %v", r)
	}
	if r := byID(rows, "2"); r["rule_id"] != "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" || r["target_path"] != `C:\Windows\System32\lsass.exe` {
		t.Errorf("row 2: %v", r)
	}
}

func TestBackupProcessInfo(t *testing.T) {
	rows := genPath(t, testConfig(t), "defender_mpengine_backup_process_info", knownKey)
	if r := byID(rows, "1"); r["first_start_is_time"] != "1" || r["first_start_time"] == "" {
		t.Errorf("row 1: %v", r)
	}
	if r := byID(rows, "2"); r["first_start_is_time"] != "0" || r["first_start_time"] != "" || r["first_start_time_raw"] != "42" ||
		r["impacted_cbp_namespaces"] != "" {
		t.Errorf("row 2: %v", r)
	}
}

func TestOtherTables(t *testing.T) {
	cfg := testConfig(t)
	inv := genPath(t, cfg, "defender_mpengine_inventory_identifiers", knownKey)
	for _, r := range inv {
		switch r["identifier"] {
		case "pkg:generic/openssl@3.0.1":
			if r["kind_name"] != "purl" || r["vulnerabilities"] != "CVE-2022-3602,CVE-2022-3786,CVE-2023-0286" {
				t.Errorf("openssl: %v", r)
			}
		default:
			if r["kind_name"] != "cpe" || r["vulnerabilities"] == "" {
				t.Errorf("cpe: %v", r)
			}
		}
	}
	fw := genPath(t, cfg, "defender_mpengine_firewall_rules", knownKey)
	dirs := map[string]int{}
	for _, r := range fw {
		dirs[r["direction"]]++
	}
	if dirs["incoming"] != 2 || dirs["outgoing"] != 2 {
		t.Errorf("firewall directions %v", dirs)
	}
	fg := genPath(t, cfg, "defender_mpengine_folder_guard_paths", knownKey)
	if r := byID(fg, "3"); r["guid"] != "12345678-9abc-4def-8123-456789abcdef" || r["folder_path"] != `D:\Backups` {
		t.Errorf("folder guard: %v", r)
	}
	if r := byID(fg, "2"); r["folder_path"] != `C:\Users\jörg\Pictures\Фото` {
		t.Errorf("folder guard non-ASCII: %v", r)
	}
	rd := genPath(t, cfg, "defender_mpengine_ransomware_detections", knownKey)
	if r := byID(rd, "2"); r["last_known_good_time"] != "" || r["last_known_good_time_raw"] != "0" || r["detection_time"] == "" {
		t.Errorf("ransomware: %v", r)
	}
	sh := genPath(t, cfg, "defender_mpengine_schema_history", knownKey)
	if r := byID(sh, "1"); r["last_updated"] != "2026-11-12 09:30:00" || r["current"] != "1" {
		t.Errorf("schema history: %v", r)
	}
}

func TestStatus(t *testing.T) {
	cfg := testConfig(t)
	missing := filepath.Join(t.TempDir(), "nope")
	rows := gen(t, cfg, "defender_mpengine_status", qc(map[string][]string{
		"path": {knownKey, filepath.Join(oracle, "junk"), missing},
	}))
	if len(rows) != 3 {
		t.Fatalf("%d rows", len(rows))
	}
	r := rows[0]
	for k, v := range map[string]string{
		"protection": "rc4", "key_source": "known:1.1.26100.4", "wal_commits": "4", "integrity_check": "ok", "quick_check": "ok",
		"table_count": "17", "wal_header_valid": "1", "error": "", "path": knownKey,
	} {
		if r[k] != v {
			t.Errorf("known_key %s=%q want %q", k, r[k], v)
		}
	}
	for _, r := range rows[1:] {
		if r["error"] == "" || r["protection"] != "" || r["path"] == "" {
			t.Errorf("error row: %v", r)
		}
	}
	// No path constraint and no default: nothing (non-Windows) or the default dir row.
	if rows := gen(t, cfg, "defender_mpengine_status", qc(nil)); len(rows) > 1 {
		t.Errorf("default: %v", rows)
	}
}

func TestGeneric(t *testing.T) {
	cfg, exp := testConfig(t), expected(t)
	tbls := genPath(t, cfg, "defender_mpengine_tables", knownKey)
	if len(tbls) != len(exp) {
		t.Errorf("tables: %d want %d", len(tbls), len(exp))
	}
	for _, r := range tbls {
		if want := strconv.Itoa(len(exp[r["table_name"]])); r["row_count"] != want || r["sql"] == "" {
			t.Errorf("tables %s: %v want count %s", r["table_name"], r, want)
		}
	}

	raw := gen(t, cfg, "defender_mpengine_raw", qc(map[string][]string{"path": {knownKey}, "table_name": {"SQLiteGlobals"}}))
	if len(raw) != 2*4 {
		t.Fatalf("raw: %d cells", len(raw))
	}
	types := map[string]string{"ID": "integer", "Version": "integer", "Current": "integer", "LastUpdated": "text"}
	for _, r := range raw {
		if r["table_name"] != "SQLiteGlobals" || types[r["column_name"]] != r["value_type"] || (r["row_id"] != "1" && r["row_id"] != "2") {
			t.Errorf("raw cell %v", r)
		}
	}
	all := gen(t, cfg, "defender_mpengine_raw", qc(map[string][]string{"path": {knownKey}}))
	seen := map[string]bool{}
	for _, r := range all {
		seen[r["value_type"]] = true
		if r["value_type"] == "null" && r["value"] != "" {
			t.Errorf("null cell %v", r)
		}
	}
	for _, typ := range []string{"integer", "text", "blob", "null"} {
		if !seen[typ] {
			t.Errorf("raw: no %s cells", typ)
		}
	}
}

// A plain SQLite DB with a stripped-down FileHashes and nothing else.
func TestSchemaTolerance(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "mpenginedb.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE FileHashes (ID INTEGER PRIMARY KEY, SHA256 BLOB, CTPH TEXT)`,
		`INSERT INTO FileHashes VALUES (1, x'0102ff', 'abc'), (2, NULL, NULL)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	cfg := testConfig(t)
	rows := genPath(t, cfg, "defender_mpengine_file_hashes", dir)
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
	r := byID(rows, "1")
	if r["sha256"] != "0102ff" || r["ssdeep"] != "abc" || r["md5"] != "" || r["instance_time"] != "" || r["volume_serial"] != "" || r["mft_entry"] != "" {
		t.Errorf("row 1: %v", r)
	}
	for _, s := range specs {
		if s.Name == "defender_mpengine_file_hashes" {
			continue
		}
		if rows := genPath(t, cfg, s.Name, dir); len(rows) != 0 {
			t.Errorf("%s: %d rows", s.Name, len(rows))
		}
	}
	// A failing path is skipped, not fatal.
	if rows := genPath(t, cfg, "defender_mpengine_file_hashes", filepath.Join(oracle, "junk")); len(rows) != 0 {
		t.Errorf("junk: %d rows", len(rows))
	}
}

func TestPathsUnion(t *testing.T) {
	cfg := testConfig(t)
	rows := gen(t, cfg, "defender_mpengine_schema_history", qc(map[string][]string{
		"path": {knownKey, filepath.Join(oracle, "plain"), knownKey},
	}))
	if len(rows) != 4 {
		t.Errorf("union: %d rows", len(rows))
	}
}

func TestGUIDLE(t *testing.T) {
	b, _ := hex.DecodeString("ab40f9d41b40fc4eaadcad5f3c50688a")
	if g := guidLE(b); g != "d4f940ab-401b-4efc-aadc-ad5f3c50688a" {
		t.Error(g)
	}
	if g := guidLE([]byte{1, 2}); g != "0102" {
		t.Error(g)
	}
}
