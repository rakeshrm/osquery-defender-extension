package tables

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Typed tables for the system-file / registry remediation caches and the
// behaviour-monitoring (Bm*) tables. Schemas were captured from live
// databases (Windows Server 2022/2025, engine 1.1.26100.x); every column is
// still read schema-tolerantly.

func init() {
	specs = append(specs, remediationSpecs...)
}

// prepJoin indexes table by its ID column and copies the listed columns
// (src -> dst key) into each row whose fk column matches.
func prepJoin(table, fk string, copyCols map[string]string) func(context.Context, reader) (func(Row), error) {
	return func(ctx context.Context, rd reader) (func(Row), error) {
		rows, err := readTable(ctx, rd, table)
		if err != nil {
			return nil, err
		}
		byID := make(map[int64]Row, len(rows))
		for _, r := range rows {
			if n, ok := toInt(r["ID"]); ok {
				byID[n] = r
			}
		}
		return func(r Row) {
			n, ok := toInt(r[fk])
			if !ok {
				return
			}
			if p, ok := byID[n]; ok {
				for src, dst := range copyCols {
					r[dst] = p[src]
				}
			}
		}, nil
	}
}

// textOrHex renders text as is and binary blobs (invalid UTF-8 or control
// characters) as lowercase hex.
func textOrHex(v any) any {
	b, ok := v.([]byte)
	if !ok {
		return v
	}
	if utf8.Valid(b) && !strings.ContainsFunc(string(b), func(r rune) bool { return unicode.IsControl(r) }) {
		return string(b)
	}
	return hex.EncodeToString(b)
}

var regTypeNames = map[int64]string{
	0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
	5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST",
	9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}

func regTypeName(v any) any {
	if n, ok := toInt(v); ok {
		return regTypeNames[n]
	}
	return nil
}

// utf16Strings decodes UTF-16LE and splits it at NULs (empty parts dropped).
func utf16Strings(b []byte) []string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	var out []string
	for _, s := range strings.Split(string(utf16.Decode(u)), "\x00") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// regData decodes registry value data by its REG_* type the way Windows
// stores it: strings as UTF-16LE (REG_SZ/EXPAND_SZ/LINK up to the first NUL,
// REG_MULTI_SZ joined with ","), REG_DWORD/QWORD as unsigned decimal.
// Other types, or data too short for its type, give "" (the hex column
// always has the bytes).
func regData(typ, data any) any {
	t, ok := toInt(typ)
	b := toBytes(data)
	if !ok || len(b) == 0 {
		return nil
	}
	switch t {
	case 1, 2, 6:
		if s := utf16Strings(b); len(s) > 0 {
			return s[0]
		}
		return ""
	case 7:
		return strings.Join(utf16Strings(b), ",")
	case 4:
		if len(b) >= 4 {
			return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b)), 10)
		}
	case 5:
		if len(b) >= 4 {
			return strconv.FormatUint(uint64(binary.BigEndian.Uint32(b)), 10)
		}
	case 11:
		if len(b) >= 8 {
			return strconv.FormatUint(binary.LittleEndian.Uint64(b), 10)
		}
	}
	return nil
}

func regCols(prefix, typeSrc, dataSrc string) []Col {
	return []Col{
		{Name: prefix + "_type", Src: typeSrc, Kind: Int},
		{Name: prefix + "_type_name", Fn: func(r Row) any { return regTypeName(r[typeSrc]) }},
		{Name: prefix + "_data", Fn: func(r Row) any { return regData(r[typeSrc], r[dataSrc]) }},
		{Name: prefix + "_data_hex", Src: dataSrc, Kind: Hex},
	}
}

var remediationSpecs = []Spec{
	{
		Name: "defender_mpengine_system_file_cache", From: from("SystemFileCache"),
		Cols: []Col{
			id(),
			{Name: "instance_time", Src: "InstanceTimeStamp", Kind: FileTime},
			{Name: "system_file_path", Src: "SystemFilePath"},
			{Name: "infected_file_sha", Fn: func(r Row) any { return textOrHex(r["InfectedFileSHA"]) }},
			{Name: "clean_file_sha", Fn: func(r Row) any { return textOrHex(r["CleanFileSha"]) }},
			{Name: "proc_file_id", Src: "ProcFileId", Kind: Hex},
			{Name: "infected_file_sha_hash", Src: "InfectedFileSHAHash", Kind: Int},
			{Name: "clean_file_sha_hash", Src: "CleanFileShaHash", Kind: Int},
			{Name: "proc_file_id_system_file_hash", Src: "ProcFileIDSystemFileHash", Kind: Int},
		},
	},
	{
		Name: "defender_mpengine_system_registry_cache", From: from("SystemRegistryCache"),
		Cols: slices.Concat(
			[]Col{
				id(),
				{Name: "instance_time", Src: "InstanceTimeStamp", Kind: FileTime},
				{Name: "reg_path", Src: "RegPath"},
				{Name: "reg_operation", Src: "RegOperation", Kind: Int},
			},
			regCols("old", "OldRegType", "OldRegData"),
			regCols("new", "NewRegType", "NewRegData"),
			[]Col{
				{Name: "key", Src: "Key", Kind: Int},
				{Name: "file_id_hash", Src: "FileIDHash", Kind: Int},
			},
		),
	},
	{
		Name: "defender_mpengine_bm_file_info", From: from("BmFileInfo"),
		Cols: []Col{
			id(),
			{Name: "dos_path", Src: "DosPath"},
			{Name: "normalized_path", Src: "NormalizedPath"},
			{Name: "is_from_web", Src: "IsFromWeb", Kind: Int},
			{Name: "is_executable", Src: "IsExecutable", Kind: Int},
			{Name: "struct_version", Src: "StructVersion", Kind: Int},
			{Name: "dos_path_hash", Src: "DosPathHash", Kind: Int},
			{Name: "normalized_path_hash", Src: "NormalizedPathHash", Kind: Int},
			{Name: "wow64_context", Src: "Wow64Context", Kind: Hex},
			{Name: "meta_context", Src: "MetaContext", Kind: Hex},
		},
	},
	{
		Name: "defender_mpengine_bm_file_actions", From: from("BmFileActions"),
		Prep: prepJoin("BmFileInfo", "FileInfoId", map[string]string{"DosPath": "_dos_path"}),
		Cols: []Col{
			id(),
			{Name: "file_info_id", Src: "FileInfoId", Kind: Int},
			{Name: "dos_path", Src: "_dos_path"},
			{Name: "threat_record_id", Src: "ThreatRecordId", Kind: Int},
			{Name: "action", Src: "Action", Kind: Int},
		},
	},
	{
		Name: "defender_mpengine_bm_file_startup_actions", From: from("BmFileStartupActions"),
		Cols: []Col{
			id(),
			{Name: "file_path", Src: "FilePath"},
			{Name: "action_flags", Src: "ActionFlags", Kind: Int},
			{Name: "process_start_count", Src: "ProcessStartCount", Kind: Int},
			{Name: "fdr_flags", Src: "FdrFlags", Kind: Int},
			{Name: "fdr_threat_record_id", Src: "FdrThreatRecordId", Kind: Int},
			{Name: "evaluator_threat_record_id", Src: "EvaluatorThreatRecordId", Kind: Int},
			{Name: "trusted_installer_threat_record_id", Src: "TrustedInstallerThreatRecordId", Kind: Int},
			{Name: "lfr_threat_record_id", Src: "LFRThreatRecordId", Kind: Int},
			{Name: "file_path_hash", Src: "FilePathHash", Kind: Int},
		},
	},
	{
		Name: "defender_mpengine_bm_hips_rules", From: from("BmHipsRuleInfo"),
		Prep: prepJoin("BmProcessInfo", "ProcessInfoId", map[string]string{"PID": "_pid", "ImageFileName": "_image"}),
		Cols: []Col{
			id(),
			{Name: "process_info_id", Src: "ProcessInfoId", Kind: Int},
			{Name: "pid", Src: "_pid", Kind: Int},
			{Name: "image_file_name", Src: "_image"},
			{Name: "rule_id", Src: "RuleId", Kind: GUIDLE},
			{Name: "asr_rule_name", Fn: func(r Row) any { return asrRules[guidLE(toBytes(r["RuleId"]))] }},
			{Name: "rule_action", Src: "RuleAction", Kind: Int},
			{Name: "is_audit", Src: "IsAudit", Kind: Int},
			{Name: "is_inherited", Src: "IsInherited", Kind: Int},
			{Name: "state", Src: "State", Kind: Int},
		},
	},
}
