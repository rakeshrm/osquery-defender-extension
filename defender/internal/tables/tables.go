package tables

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

// Config is shared by all table plugins.
type Config struct {
	Cache       *mpengine.Cache // shared snapshot cache (required)
	DefaultPath string          // --mpengine_path; "" = mpengine.DefaultDir on Windows, none elsewhere
	Logger      *slog.Logger    // nil = slog.Default()
}

type tableDef struct {
	name string
	cols []table.ColumnDefinition
	gen  table.GenerateFunc
}

// Plugins returns every defender_mpengine_* table plugin.
func Plugins(cfg Config) []osquery.OsqueryPlugin {
	var ps []osquery.OsqueryPlugin
	for _, d := range cfg.defs() {
		ps = append(ps, table.NewPlugin(d.name, d.cols, d.gen))
	}
	return ps
}

func (cfg Config) defs() []tableDef {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	var defs []tableDef
	for _, s := range specs {
		defs = append(defs, tableDef{s.Name, s.columns(), cfg.typed(s)})
	}
	return append(defs,
		tableDef{"defender_mpengine_tables", textCols("table_name", "+row_count", "sql", "path"), cfg.tablesGen},
		tableDef{"defender_mpengine_raw", textCols("table_name", "+row_id", "column_name", "value", "value_type", "path"), cfg.rawGen},
		tableDef{"defender_mpengine_status", textCols(statusCols...), cfg.statusGen},
	)
}

// textCols builds column definitions; a "+" prefix marks a BIGINT column.
func textCols(names ...string) []table.ColumnDefinition {
	defs := make([]table.ColumnDefinition, len(names))
	for i, n := range names {
		if b, ok := strings.CutPrefix(n, "+"); ok {
			defs[i] = table.BigIntColumn(b)
		} else {
			defs[i] = table.TextColumn(n)
		}
	}
	return defs
}

// constraintValues returns the distinct values of `col = ...` constraints.
func constraintValues(qc table.QueryContext, col string) []string {
	var vals []string
	for _, c := range qc.Constraints[col].Constraints {
		if c.Operator == table.OperatorEquals && !slices.Contains(vals, c.Expression) {
			vals = append(vals, c.Expression)
		}
	}
	return vals
}

// paths returns the sources to read: `path =` constraints, else the default.
func (cfg Config) paths(qc table.QueryContext) []string {
	if ps := constraintValues(qc, "path"); len(ps) > 0 {
		return ps
	}
	if cfg.DefaultPath != "" {
		return []string{cfg.DefaultPath}
	}
	if runtime.GOOS == "windows" {
		return []string{mpengine.DefaultDir}
	}
	return nil
}

// each runs fn on the snapshot of every selected path, logging and skipping
// paths that fail.
func (cfg Config) each(qc table.QueryContext, name string, fn func(path string, s *mpengine.Snapshot) error) {
	for _, p := range cfg.paths(qc) {
		if err := cfg.Cache.With(p, func(s *mpengine.Snapshot) error { return fn(p, s) }); err != nil {
			cfg.Logger.Warn("query failed", "table", name, "path", p, "err", err)
		}
	}
}

func (cfg Config) typed(s Spec) table.GenerateFunc {
	return func(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
		var out []map[string]string
		cfg.each(qc, s.Name, func(p string, snap *mpengine.Snapshot) error {
			rows, err := s.rows(ctx, snap.DB)
			for _, r := range rows {
				r["path"] = p
			}
			out = append(out, rows...)
			return err
		})
		return out, nil
	}
}

// --- typed tables (docs/DESIGN.md "Tables") ---

func from(tbl string) []From { return []From{{Table: tbl}} }

var (
	pidRe       = regexp.MustCompile(`pid:(\d+),ProcessStart:(\d+)`)
	techniqueRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?`)
)

const asrPrefix = "AsrRuleStateChangeFor:"

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func queueType(t string) string {
	for _, q := range [...]struct{ prefix, typ string }{
		{"Tech-pid:", "techniques"},
		{"Tact-pid:", "tactics"},
		{"InheritedTech-pid:", "inherited_techniques"},
		{"InheritedTact-pid:", "inherited_tactics"},
		{"RQ_RecentExecDropped", "dropped_executable"},
	} {
		if hasPrefixFold(t, q.prefix) {
			return q.typ
		}
	}
	switch t {
	case "gPidsTable":
		return "tracked_pids"
	case "gTechniquesTable":
		return "machine_techniques"
	case "gTacticsTable":
		return "machine_tactics"
	case "RecentThreatsOnMachine":
		return "recent_threats"
	}
	return "named"
}

// prepRollingQueues joins RollingQueuesTables (on ifnull(Namespace,”)||Name)
// and parses pid/ProcessStart from EntryTable, EntryKey or EntryValue.
func prepRollingQueues(ctx context.Context, db *sql.DB) (func(Row), error) {
	qs, err := readTable(ctx, db, "RollingQueuesTables")
	if err != nil {
		return nil, err
	}
	byName := make(map[string]Row, len(qs))
	for _, q := range qs {
		if q["Name"] != nil {
			byName[text(q["Namespace"])+text(q["Name"])] = q
		}
	}
	return func(r Row) {
		if q, ok := byName[text(r["EntryTable"])]; ok {
			r["_capacity"], r["_ttl"] = q["Capacity"], q["TimeToLive"]
		}
		for _, k := range []string{"EntryTable", "EntryKey", "EntryValue"} {
			if m := pidRe.FindStringSubmatch(text(r[k])); m != nil {
				r["_pid"], r["_process_start"] = m[1], m[2]
				break
			}
		}
	}, nil
}

// prepInventory attaches the sorted, comma-joined vulnerability IDs.
func prepInventory(ctx context.Context, db *sql.DB) (func(Row), error) {
	vs, err := readTable(ctx, db, "MetaInventoryIdentifierVulnerabilities")
	if err != nil {
		return nil, err
	}
	vulns := map[string][]string{}
	for _, v := range vs {
		id := text(v["Identifier"])
		if vid := text(v["VulnerabilityId"]); vid != "" && !slices.Contains(vulns[id], vid) {
			vulns[id] = append(vulns[id], vid)
		}
	}
	for _, l := range vulns {
		sort.Strings(l)
	}
	return func(r Row) { r["_vulns"] = strings.Join(vulns[text(r["Identifier"])], ",") }, nil
}

func asrID(r Row) string {
	if p := text(r["FilePath"]); hasPrefixFold(p, asrPrefix) {
		return strings.ToLower(p[len(asrPrefix):])
	}
	return ""
}

func id() Col { return Col{Name: "id", Src: "ID", Kind: Int} }

var specs = []Spec{
	{
		Name: "defender_mpengine_rolling_queues", From: from("RollingQueuesValues"), Prep: prepRollingQueues,
		Cols: []Col{
			id(),
			{Name: "queue", Src: "EntryTable"},
			{Name: "queue_type", Fn: func(r Row) any { return queueType(text(r["EntryTable"])) }},
			{Name: "entry_key", Src: "EntryKey"},
			{Name: "entry_value", Src: "EntryValue"},
			{Name: "technique_id", Fn: func(r Row) any {
				if k := text(r["EntryKey"]); techniqueRe.MatchString(k) {
					return k
				}
				return nil
			}},
			{Name: "pid", Src: "_pid", Kind: Int},
			{Name: "process_start", Src: "_process_start", Kind: FileTime},
			{Name: "insert_time", Src: "InsertTime", Kind: FileTime},
			{Name: "expire_time", Src: "ExpireTime", Kind: FileTime},
			{Name: "queue_capacity", Src: "_capacity", Kind: Int},
			{Name: "queue_ttl", Src: "_ttl", Kind: Int},
		},
	},
	{
		Name: "defender_mpengine_persist_context", From: from("AttributePersistContext"),
		Cols: []Col{
			id(),
			{Name: "file_path", Src: "FilePath"},
			{Name: "context", Src: "Context"},
			{Name: "record_kind", Fn: func(r Row) any {
				if hasPrefixFold(text(r["FilePath"]), asrPrefix) {
					return "asr_rule_state"
				}
				return "path_tag"
			}},
			{Name: "asr_rule_id", Fn: func(r Row) any { return asrID(r) }},
			{Name: "asr_rule_name", Fn: func(r Row) any { return asrRules[asrID(r)] }},
			{Name: "insert_time", Src: "InsertTime", Kind: FileTime},
			{Name: "expire_time", Src: "ExpireTime", Kind: FileTime},
		},
	},
	{
		Name: "defender_mpengine_file_hashes", From: from("FileHashes"),
		Cols: []Col{
			id(),
			{Name: "instance_time", Src: "InstanceTimeStamp", Kind: FileTime},
			{Name: "volume_serial", Fn: func(r Row) any {
				if v, ok := toInt(r["VSN"]); ok {
					return fmt.Sprintf("%04X-%04X", (v>>16)&0xFFFF, v&0xFFFF)
				}
				return nil
			}},
			{Name: "file_id", Src: "FileID", Kind: Int},
			{Name: "mft_entry", Kind: Int, Fn: func(r Row) any {
				if v, ok := toInt(r["FileID"]); ok {
					return int64(uint64(v) & 0xFFFFFFFFFFFF)
				}
				return nil
			}},
			{Name: "mft_sequence", Kind: Int, Fn: func(r Row) any {
				if v, ok := toInt(r["FileID"]); ok {
					return int64(uint64(v) >> 48 & 0xFFFF)
				}
				return nil
			}},
			{Name: "usn", Src: "USN", Kind: Int},
			{Name: "md5", Src: "SHA1", Kind: Hex}, // Defender stores MD5 in column SHA1 ...
			{Name: "sha1", Src: "MD5", Kind: Hex}, // ... and SHA-1 in column MD5
			{Name: "sha256", Src: "SHA256", Kind: Hex},
			{Name: "ssdeep", Src: "CTPH", Kind: CStr},
			{Name: "lshash", Src: "LSHASH", Kind: Hex},
			{Name: "lshashs", Src: "LSHASHS", Kind: Hex},
			{Name: "partial_crc1", Src: "PartialCRC1", Kind: Hex32},
			{Name: "partial_crc2", Src: "PartialCRC2", Kind: Hex32},
			{Name: "partial_crc3", Src: "PartialCRC3", Kind: Hex32},
			{Name: "kcrc1", Src: "KCRC1", Kind: Hex32},
			{Name: "kcrc2", Src: "KCRC2", Kind: Hex32},
			{Name: "kcrc3", Src: "KCRC3", Kind: Hex32},
			{Name: "kcrc3n", Src: "KCRC3n", Kind: Hex32},
		},
	},
	{
		Name: "defender_mpengine_backup_process_info", From: from("BackupProcessInfo"),
		Cols: []Col{
			id(),
			{Name: "instance_time", Src: "InstanceTimeStamp", Kind: FileTime},
			{Name: "file_path", Src: "FilePath"},
			{Name: "first_start_time", Src: "FirstStartTime", Kind: FileTime},
			{Name: "first_start_is_time", Kind: Int, Fn: func(r Row) any {
				if v, ok := toInt(r["FirstStartTime"]); ok {
					if v >= ftMin && v < ftMax {
						return int64(1)
					}
					return int64(0)
				}
				return nil
			}},
			{Name: "next_usn", Src: "NextUSN", Kind: Int},
			{Name: "automatic_removal_policy", Src: "AutomaticRemovalPolicy", Kind: Int},
			{Name: "impacted_cbp_namespaces", Src: "ImpactedCBPNameSpaces"},
		},
	},
	{
		Name: "defender_mpengine_lowfi_async", From: from("FileLowFiAsync"),
		Cols: []Col{
			id(),
			{Name: "instance_time", Src: "InstanceTimeStamp", Kind: FileTime},
			{Name: "file_name", Src: "FileName"},
			{Name: "sig_seq", Src: "SigSeq", Kind: Int},
			{Name: "sig_sha", Src: "SigSha", Kind: Hex},
			{Name: "sig_is_sync", Src: "SigIsSync", Kind: Int},
		},
	},
	{
		Name: "defender_mpengine_process_block_history", From: from("ProcessBlockHistory"),
		Cols: []Col{
			id(),
			{Name: "time", Src: "TimeStamp", Kind: FileTime},
			{Name: "process_path", Src: "ProcessPath"},
			{Name: "target_path", Src: "TargetPath"},
			{Name: "rule_id", Src: "RuleId", Kind: GUIDLE},
			{Name: "asr_rule_name", Fn: func(r Row) any { return asrRules[guidLE(toBytes(r["RuleId"]))] }},
			{Name: "is_audit", Src: "IsAudit", Kind: Int},
			{Name: "action", Src: "Action", Kind: Int},
			{Name: "process_taint_reason", Src: "ProcessTaintReason", Kind: Int},
			{Name: "process_integrity", Src: "ProcessIntegrity", Kind: Int},
		},
	},
	{
		Name: "defender_mpengine_bm_process_info", From: from("BmProcessInfo"),
		Cols: []Col{
			id(),
			{Name: "process_start_time", Src: "ProcessStartTime", Kind: FileTime},
			{Name: "pid", Src: "PID", Kind: Int},
			{Name: "image_file_name", Src: "ImageFileName"},
			{Name: "command_line_args", Src: "CommandLineArgs"},
			{Name: "ppid_hash", Src: "PPIDHash", Kind: Int},
			{Name: "flags", Src: "Flags", Kind: Int},
			{Name: "monitoring_flags", Src: "MonitoringFlags_Flags", Kind: Int},
			{Name: "hips_injection_id", Src: "HipsInjectionId", Kind: GUIDLE},
			{Name: "folder_guard_id", Src: "FolderGuardId", Kind: GUIDLE},
			{Name: "lsass_read_mem_id", Src: "LsassReadMemId", Kind: GUIDLE},
		},
	},
	{
		Name: "defender_mpengine_ransomware_detections", From: from("RansomwareDetections"),
		Cols: []Col{
			id(),
			{Name: "detection_guid", Src: "DetectionGuid", Kind: GUIDLE},
			{Name: "detection_time", Src: "DetectionTS", Kind: FileTime},
			{Name: "last_known_good_time", Src: "LkgTS", Kind: FileTime},
			{Name: "provisional_remediation_time", Src: "ProvisionalRemedComplTS", Kind: FileTime},
			{Name: "remediation_complete_time", Src: "RemedComplTS", Kind: FileTime},
			{Name: "instance_time", Src: "InstanceTimeStamp", Kind: FileTime},
			{Name: "next_usn", Src: "NextUSN", Kind: Int},
			{Name: "impacted_cbp_namespaces", Src: "ImpactedCBPNameSpaces"},
		},
	},
	{
		Name: "defender_mpengine_firewall_rules",
		From: []From{
			{Table: "NetworkIpFirewallRules", Set: Row{"_direction": "incoming"}},
			{Table: "NetworkIpFirewallRulesOutgoing", Set: Row{"_direction": "outgoing"}},
		},
		Cols: []Col{
			{Name: "direction", Src: "_direction"},
			id(),
			{Name: "expiry_time", Src: "ExpiryTime", Kind: FileTime},
			{Name: "key", Src: "Key"},
			{Name: "firewall_rule_name", Src: "FirewallRuleName"},
		},
	},
	{
		Name: "defender_mpengine_atomic_counters", From: from("AtomicCounters"),
		Cols: []Col{
			id(),
			{Name: "insert_time", Src: "InsertTime", Kind: FileTime},
			{Name: "update_time", Src: "UpdateTime", Kind: FileTime},
			{Name: "expire_time", Src: "ExpireTime", Kind: FileTime},
			{Name: "namespace", Src: "Namespace"},
			{Name: "name", Src: "Name"},
			{Name: "count", Src: "Count", Kind: Int},
			{Name: "high_count", Src: "HighCount", Kind: Int},
		},
	},
	{
		Name: "defender_mpengine_folder_guard_paths", From: from("FolderGuardPaths"),
		Cols: []Col{
			id(),
			{Name: "user_id", Src: "UserId"},
			{Name: "guid", Src: "GUID", Kind: GUIDLE},
			{Name: "folder_path", Src: "Path"},
		},
	},
	{
		Name: "defender_mpengine_amsi_file_cache", From: from("AmsiFileCache"),
		Cols: []Col{
			id(),
			{Name: "expiration_date", Src: "ExpirationDate"},
			{Name: "persist_id", Src: "PersistId", Kind: Int},
			{Name: "persist_id_blob", Src: "PersistIdBlob", Kind: Hex},
		},
	},
	{
		Name: "defender_mpengine_schema_history", From: from("SQLiteGlobals"),
		Cols: []Col{
			id(),
			{Name: "version", Src: "Version", Kind: Int},
			{Name: "current", Src: "Current", Kind: Int},
			{Name: "last_updated", Src: "LastUpdated"},
		},
	},
	{
		Name: "defender_mpengine_inventory_identifiers", From: from("MetaInventoryIdentifiers"), Prep: prepInventory,
		Cols: []Col{
			{Name: "identifier", Src: "Identifier"},
			{Name: "kind", Src: "Kind", Kind: Int},
			{Name: "kind_name", Fn: func(r Row) any {
				k, _ := toInt(r["Kind"])
				return map[int64]string{1: "cpe", 2: "purl"}[k]
			}},
			{Name: "vulnerabilities", Src: "_vulns"},
		},
	},
}
