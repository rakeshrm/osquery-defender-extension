package tables

import (
	"testing"
)

// Schemas captured verbatim from live Defender databases (Windows Server
// 2022/2025, engine 1.1.26100.x). The rows are synthetic.
const (
	systemFileCacheDDL      = `CREATE TABLE SystemFileCache(ID INTEGER PRIMARY KEY NOT NULL, InfectedFileSHAHash INTEGER NULL, InfectedFileSHA NVARCHAR NULL, ProcFileIDSystemFileHash INTEGER NULL, ProcFileId BLOB NULL, SystemFilePath NVARCHAR NULL, CleanFileSha NVARCHAR NULL, CleanFileShaHash INTEGER NULL, InstanceTimeStamp INTEGER NULL)`
	systemRegistryCacheDDL  = `CREATE TABLE SystemRegistryCache(ID INTEGER PRIMARY KEY NOT NULL, Key INTEGER NULL, FileIDHash INTEGER NULL, RegPath NVARCHAR NULL, RegOperation INTEGER NULL, NewRegType INTEGER NULL, OldRegType INTEGER NULL, OldRegData BLOB NULL, NewRegData BLOB NULL, InstanceTimeStamp INTEGER NULL)`
	bmFileInfoDDL           = `CREATE TABLE BmFileInfo(ID INTEGER PRIMARY KEY NOT NULL, NormalizedPathHash INTEGER, DosPathHash INTEGER, StructVersion INTEGER NOT NULL, NormalizedPath NVARCHAR NOT NULL, DosPath NVARCHAR NOT NULL, Wow64Context BLOB, MetaContext BLOB, IsFromWeb TINYINT DEFAULT 0, IsExecutable TINYINT DEFAULT 0)`
	bmFileActionsDDL        = `CREATE TABLE BmFileActions(ID INTEGER PRIMARY KEY NOT NULL, FileInfoId INTEGER NOT NULL, ThreatRecordId INTEGER, Action INTEGER)`
	bmFileStartupActionsDDL = `CREATE TABLE BmFileStartupActions(ID INTEGER PRIMARY KEY NOT NULL, FilePathHash INTEGER NULL, FilePath NVARCHAR NULL, ActionFlags INTEGER NULL, ProcessStartCount INTEGER NULL, FdrFlags INTEGER NULL, FdrThreatRecordId INTEGER NULL, EvaluatorThreatRecordId INTEGER NULL, TrustedInstallerThreatRecordId INTEGER NULL, LFRThreatRecordId INTEGER NULL)`
	bmHipsRuleInfoDDL       = `CREATE TABLE BmHipsRuleInfo(ID INTEGER PRIMARY KEY NOT NULL, ProcessInfoId INTEGER NOT NULL, RuleAction INTEGER NOT NULL, RuleId BLOB, IsAudit INTEGER NOT NULL DEFAULT 0, IsInherited INTEGER NOT NULL DEFAULT 0, State INTEGER NULL)`
)

func want(t *testing.T, r map[string]string, kv ...string) {
	t.Helper()
	for i := 0; i < len(kv); i += 2 {
		if got := r[kv[i]]; got != kv[i+1] {
			t.Errorf("%s = %q, want %q", kv[i], got, kv[i+1])
		}
	}
}

func TestSystemFileCache(t *testing.T) {
	// 134064288000000000 is 2025-11-01 00:00:00 UTC as FILETIME.
	dir := sqliteDir(t, systemFileCacheDDL,
		`INSERT INTO SystemFileCache VALUES
		  (1, -42, 'AABBCCDD', 7, x'0102030405060708', 'C:\Windows\System32\drivers\etc\hosts', '11223344', 99, 134064288000000000),
		  (2, NULL, x'00ff10', NULL, NULL, NULL, NULL, NULL, NULL)`)
	rows := genPath(t, testConfig(t), "defender_mpengine_system_file_cache", dir)
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	want(t, byID(rows, "1"),
		"instance_time", "1761955200", "instance_time_raw", "134064288000000000",
		"system_file_path", `C:\Windows\System32\drivers\etc\hosts`,
		"infected_file_sha", "AABBCCDD", "clean_file_sha", "11223344",
		"proc_file_id", "0102030405060708",
		"infected_file_sha_hash", "-42", "clean_file_sha_hash", "99", "proc_file_id_system_file_hash", "7",
		"path", dir)
	// A binary blob in a text column is rendered as hex, NULLs as "".
	want(t, byID(rows, "2"), "infected_file_sha", "00ff10", "clean_file_sha", "", "instance_time", "", "proc_file_id", "")
}

func TestSystemRegistryCache(t *testing.T) {
	dir := sqliteDir(t, systemRegistryCacheDDL,
		// Run value hijacked: REG_SZ "C:\a.exe" -> REG_EXPAND_SZ "%TEMP%\x.exe".
		`INSERT INTO SystemRegistryCache VALUES (1, 5, 6, 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x', 2, 2, 1,
		  x'43003a005c0061002e006500780065000000', x'2500540045004d00500025005c0078002e006500780065000000', 134064288000000000)`,
		// REG_DWORD 1 -> 0xFFFFFFFF; REG_MULTI_SZ a,b -> REG_QWORD 2^40.
		`INSERT INTO SystemRegistryCache VALUES (2, NULL, NULL, 'HKLM\x\d', 1, 4, 4, x'01000000', x'ffffffff', NULL)`,
		`INSERT INTO SystemRegistryCache VALUES (3, NULL, NULL, 'HKLM\x\q', 1, 11, 7, x'610000006200000000000000', x'0000000000010000', NULL)`,
		// Binary, unknown type, truncated DWORD, no data.
		`INSERT INTO SystemRegistryCache VALUES (4, NULL, NULL, 'HKLM\x\b', 3, 3, 99, x'0102', x'dead', NULL)`,
		`INSERT INTO SystemRegistryCache VALUES (5, NULL, NULL, 'HKLM\x\t', 3, 4, NULL, NULL, x'01', NULL)`)
	rows := genPath(t, testConfig(t), "defender_mpengine_system_registry_cache", dir)
	if len(rows) != 5 {
		t.Fatalf("%d rows, want 5", len(rows))
	}
	want(t, byID(rows, "1"),
		"instance_time", "1761955200", "reg_path", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x`,
		"reg_operation", "2", "key", "5", "file_id_hash", "6",
		"old_type", "1", "old_type_name", "REG_SZ", "old_data", `C:\a.exe`,
		"new_type", "2", "new_type_name", "REG_EXPAND_SZ", "new_data", `%TEMP%\x.exe`,
		"new_data_hex", "2500540045004d00500025005c0078002e006500780065000000")
	want(t, byID(rows, "2"), "old_data", "1", "new_data", "4294967295", "old_type_name", "REG_DWORD")
	want(t, byID(rows, "3"), "old_type_name", "REG_MULTI_SZ", "old_data", "a,b", "new_type_name", "REG_QWORD", "new_data", "1099511627776")
	want(t, byID(rows, "4"),
		"old_type_name", "", "old_data", "", "old_data_hex", "0102",
		"new_type_name", "REG_BINARY", "new_data", "", "new_data_hex", "dead")
	want(t, byID(rows, "5"), "old_type", "", "old_data", "", "old_data_hex", "", "new_data", "", "new_data_hex", "01")
}

func TestBmFileTables(t *testing.T) {
	dir := sqliteDir(t, bmFileInfoDDL, bmFileActionsDDL, bmFileStartupActionsDDL,
		`INSERT INTO BmFileInfo VALUES (10, 111, 222, 3, '\Device\HarddiskVolume3\Users\u\Downloads\x.exe', 'C:\Users\u\Downloads\x.exe', x'0a0b', NULL, 1, 1)`,
		`INSERT INTO BmFileActions VALUES (1, 10, 77, 2), (2, 999, NULL, 1)`,
		`INSERT INTO BmFileStartupActions VALUES (1, -5, 'C:\Users\u\AppData\Roaming\run.exe', 3, 4, 5, 6, 7, 8, 9)`)
	cfg := testConfig(t)

	info := genPath(t, cfg, "defender_mpengine_bm_file_info", dir)
	if len(info) != 1 {
		t.Fatalf("bm_file_info: %d rows", len(info))
	}
	want(t, info[0], "id", "10", "dos_path", `C:\Users\u\Downloads\x.exe`,
		"normalized_path", `\Device\HarddiskVolume3\Users\u\Downloads\x.exe`,
		"is_from_web", "1", "is_executable", "1", "struct_version", "3",
		"dos_path_hash", "222", "normalized_path_hash", "111", "wow64_context", "0a0b", "meta_context", "")

	acts := genPath(t, cfg, "defender_mpengine_bm_file_actions", dir)
	if len(acts) != 2 {
		t.Fatalf("bm_file_actions: %d rows", len(acts))
	}
	want(t, byID(acts, "1"), "file_info_id", "10", "dos_path", `C:\Users\u\Downloads\x.exe`, "threat_record_id", "77", "action", "2")
	want(t, byID(acts, "2"), "file_info_id", "999", "dos_path", "", "threat_record_id", "")

	st := genPath(t, cfg, "defender_mpengine_bm_file_startup_actions", dir)
	if len(st) != 1 {
		t.Fatalf("bm_file_startup_actions: %d rows", len(st))
	}
	want(t, st[0], "file_path", `C:\Users\u\AppData\Roaming\run.exe`, "action_flags", "3", "process_start_count", "4",
		"fdr_flags", "5", "fdr_threat_record_id", "6", "evaluator_threat_record_id", "7",
		"trusted_installer_threat_record_id", "8", "lfr_threat_record_id", "9", "file_path_hash", "-5")
}

func TestBmHipsRules(t *testing.T) {
	dir := sqliteDir(t, bmHipsRuleInfoDDL,
		`CREATE TABLE BmProcessInfo (ID INTEGER PRIMARY KEY, PID INTEGER, ImageFileName TEXT)`,
		`INSERT INTO BmProcessInfo VALUES (4, 4312, 'C:\Windows\System32\rundll32.exe')`,
		// RuleId: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 (Block credential stealing from LSASS), little-endian.
		`INSERT INTO BmHipsRuleInfo VALUES (1, 4, 1, x'1f4e6c9e607d2f47ba1aa39ef669e4b2', 1, 0, 2)`,
		`INSERT INTO BmHipsRuleInfo VALUES (2, 5, 2, NULL, 0, 1, NULL)`)
	rows := genPath(t, testConfig(t), "defender_mpengine_bm_hips_rules", dir)
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	want(t, byID(rows, "1"), "process_info_id", "4", "pid", "4312", "image_file_name", `C:\Windows\System32\rundll32.exe`,
		"rule_id", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
		"asr_rule_name", asrRules["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"],
		"rule_action", "1", "is_audit", "1", "is_inherited", "0", "state", "2")
	want(t, byID(rows, "2"), "pid", "", "image_file_name", "", "rule_id", "", "asr_rule_name", "", "is_inherited", "1", "state", "")
	if asrRules["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"] == "" {
		t.Error("ASR name map lacks the LSASS rule")
	}
}

// Missing source tables give zero rows, not errors.
func TestRemediationTablesMissing(t *testing.T) {
	dir := sqliteDir(t, `CREATE TABLE Other (ID INTEGER)`)
	cfg := testConfig(t)
	for _, s := range remediationSpecs {
		if rows := genPath(t, cfg, s.Name, dir); len(rows) != 0 {
			t.Errorf("%s: %d rows", s.Name, len(rows))
		}
	}
}
