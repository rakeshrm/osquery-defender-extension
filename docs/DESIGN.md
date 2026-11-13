# osq-defender-ext — design

An osquery extension (Go) that exposes Microsoft Defender's `mpenginedb.db`
("MetaVault") as osquery tables.

Background: <https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html>
Reference implementations (MIT): `github.com/Protokol-7/mpenginedb_parser`
(Python) and `github.com/Protokol-7/MpEngineDb_SQLECmd` (SQLECmd map + PS1).

## The file

```
C:\ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db
C:\ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db-wal   (also seen as "mpenginedb.db~wal" in collections)
```

SQLite in WAL mode, every page RC4-encrypted:

* Keystream = first `page_size` bytes of RC4(key), where key is a fixed 256-byte
  array from mpengine.dll (known key for engine 1.1.26100.4 below). RC4 is
  **restarted for every page**, so every page is XORed with the same keystream.
* Page 1: bytes 0..15 XOR ks[0..15]; bytes 16..23 are **plaintext** (page size
  etc.); bytes 24..end XOR ks[0..page_size-24-1] (note: keystream restarts at 0
  for the tail, it is NOT ks[24..]).
* Other pages: page XOR ks[0..page_size-1].
* Page size is read in clear from db[16:18] big-endian (1 => 65536).
* If db[0:16] == "SQLite format 3\0" the codec is off (`MpSqliteCodecDisable=1`):
  pass through.
* Key selection: try each known key; a key matches if decrypting db[0:16]
  yields the SQLite magic. If none match, derive the keystream from the
  evidence (known plaintext header + zero-filled free space voting) — port of
  `derive_keystream()` in the reference parser. Report low-confidence positions.
* WAL: 32-byte header and 24-byte frame headers are plaintext; only frame page
  data is encrypted (same codec, using the frame's pgno; pgno 1 gets the page-1
  treatment). **WAL checksums are computed over the stored (encrypted) bytes**,
  so validate the salt + checksum chain on the raw bytes, then decrypt. Apply
  only frames up to and including the last valid commit frame; truncate the
  image to `commit * page_size` at that commit.
* Output image: set header bytes 18 and 19 to 1 (rollback journal) so SQLite
  does not look for a -wal.

Known key (engine 1.1.26100.4, mpengine.dll RVA 0xE31A10), hex:

```
1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54fa
a21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c9cbce48e23d053
71ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe
3c8a775233557dde13a8b14087cc1bc8f10f6ecdd083a959cff84a9d1d50755e
3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd029
1771861a54b4c285a9a3db7aca6d224aeacd621db9f2a22ed1e9e11d75bed7dc
0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429b
a495676b8398db2f35d3c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253
```

## Architecture

```
defender/                         Go module github.com/huntbase-io/osquery-defender
  main.go                         flags, osquery extension server, --decrypt CLI mode
  internal/mpengine/              decryption + snapshot (no osquery dependency)
    codec.go       RC4 keystream, page codec, known keys, key derivation
    wal.go         WAL parse, checksum-chain validation, frame application
    decrypt.go     Decrypt(): file/dir resolution, assemble plaintext image, Info
    snapshot.go    Open(): Deserialize image into in-memory modernc sqlite; Cache
    readfile_windows.go / readfile_other.go   share-friendly reads of locked files
  internal/tables/                osquery table plugins
    spec.go        declarative column specs + decoders
    tables.go      the typed tables
    generic.go     defender_mpengine_tables / _raw
    status.go      defender_mpengine_status
```

Key decisions:

* **Pure Go** (`modernc.org/sqlite`, no cgo) so it cross-compiles for
  windows/amd64, windows/arm64 and for darwin/linux (offline analysis of
  collected evidence).
* **Never write decrypted data to disk.** The plaintext image is loaded with
  modernc's `conn.Deserialize` into an in-memory, read-only connection.
* **Never write to the evidence.** Files are read-only; on Windows they are
  opened with `FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE` (and
  `FILE_FLAG_BACKUP_SEMANTICS`) because MsMpEng.exe holds them open.
  DB and WAL are each read in one pass; a torn read surfaces as a broken WAL
  checksum chain (frames after the break are ignored), never as bad data.
* **Snapshot cache.** One decrypted snapshot per source path, reused while DB
  and WAL size+mtime are unchanged and younger than `--cache_ttl` (default
  30s), so a pack hitting 10 tables decrypts once.
* **Schema-tolerant.** Each typed table reads `pragma table_info` and selects
  only the columns that exist; missing columns yield empty values and a
  missing table yields zero rows. Engine builds can change the schema.
* **`path` column on every table.** `WHERE path = '<file or Scans dir>'`
  selects the source (e.g. a collected copy). Without it the default is
  `C:\ProgramData\Microsoft\Windows Defender\Scans` on Windows, overridable
  with `--mpengine_path`; on other OSes a path constraint is required (zero
  rows otherwise). Multiple `=` constraints / `IN` are supported.

## Public API contract — `internal/mpengine`

```go
const DefaultDir = `C:\ProgramData\Microsoft\Windows Defender\Scans`

type Options struct {
    DeriveKey bool   // ignore known keys, derive from evidence
    WALPath   string // explicit WAL path; default: <db>-wal, then <db>~wal
}

type Info struct {
    DBPath, WALPath           string
    DBSize, WALSize           int64
    DBSHA256, WALSHA256       string
    Protection                string // "none" | "rc4"
    KeySource                 string // "" | "known:1.1.26100.4" | "derived"
    KeystreamSHA256           string
    DerivedLowConfidence      int    // byte positions with weak/no votes (derived key only)
    PageSize, DBPages         int
    WALHeaderValid            bool
    WALFramesTotal            int
    WALFramesCommitted        int
    WALCommits                int
    WALNote                   string
}

// Resolve accepts a file or a directory containing mpenginedb.db and returns db + wal paths ("" if no WAL).
func Resolve(path string, opt Options) (dbPath, walPath string, err error)
// Decrypt returns a plaintext SQLite image with committed WAL frames applied
// and header bytes 18/19 set to 1.
func Decrypt(path string, opt Options) ([]byte, *Info, error)

type Snapshot struct {
    DB      *sql.DB   // in-memory, read-only, MaxOpenConns(1)
    Info    *Info
    Created time.Time
}
func Open(path string, opt Options) (*Snapshot, error)
func (s *Snapshot) Close() error

type Cache struct{ /* … */ }
func NewCache(ttl time.Duration, opt Options) *Cache
// With runs fn with a cached (or freshly built) snapshot for path. Safe for
// concurrent use; a snapshot is never closed while fn is running on it.
func (c *Cache) With(path string, fn func(*Snapshot) error) error
func (c *Cache) Close()
```

## Tables

Conventions: snake_case columns. FILETIME columns produce `<name>` (unix
seconds, BIGINT; empty if outside 1980..2107) and `<name>_raw` (BIGINT
FILETIME). Blobs are lowercase hex. GUID blobs (16 bytes) are decoded
little-endian (Windows GUID layout) to lowercase `8-4-4-4-12`. Every table
also has `path` (TEXT).

| osquery table | source | columns |
|---|---|---|
| `defender_mpengine_rolling_queues` | `RollingQueuesValues v LEFT JOIN RollingQueuesTables t ON v.EntryTable = ifnull(t.Namespace,'')||t.Name` | id, queue (EntryTable), queue_type, entry_key, entry_value, technique_id, pid, process_start (+_raw), insert_time (+_raw), expire_time (+_raw), queue_capacity (t.Capacity), queue_ttl (t.TimeToLive, seconds) |
| `defender_mpengine_persist_context` | `AttributePersistContext` | id, file_path, context, record_kind, asr_rule_id, asr_rule_name, insert_time (+_raw), expire_time (+_raw) |
| `defender_mpengine_file_hashes` | `FileHashes` | id, instance_time (+_raw), volume_serial, file_id, mft_entry, mft_sequence, usn, md5 (**from column SHA1**), sha1 (**from column MD5**), sha256, ssdeep, lshash, lshashs, partial_crc1, partial_crc2, partial_crc3, kcrc1, kcrc2, kcrc3, kcrc3n |
| `defender_mpengine_backup_process_info` | `BackupProcessInfo` | id, instance_time (+_raw), file_path, first_start_time (+_raw), first_start_is_time, next_usn, automatic_removal_policy, impacted_cbp_namespaces |
| `defender_mpengine_lowfi_async` | `FileLowFiAsync` | id, instance_time (+_raw), file_name, sig_seq, sig_sha, sig_is_sync |
| `defender_mpengine_process_block_history` | `ProcessBlockHistory` | id, time (+_raw) (TimeStamp), process_path, target_path, rule_id, asr_rule_name, is_audit, action, process_taint_reason, process_integrity |
| `defender_mpengine_bm_process_info` | `BmProcessInfo` | id, process_start_time (+_raw), pid, image_file_name, command_line_args, ppid_hash, flags, monitoring_flags (MonitoringFlags_Flags), hips_injection_id, folder_guard_id, lsass_read_mem_id |
| `defender_mpengine_ransomware_detections` | `RansomwareDetections` | id, detection_guid, detection_time, last_known_good_time, provisional_remediation_time, remediation_complete_time, instance_time (each +_raw), next_usn, impacted_cbp_namespaces |
| `defender_mpengine_firewall_rules` | `NetworkIpFirewallRules` (direction=incoming) ∪ `NetworkIpFirewallRulesOutgoing` (outgoing) | direction, id, expiry_time (+_raw), key, firewall_rule_name |
| `defender_mpengine_atomic_counters` | `AtomicCounters` | id, insert_time, update_time, expire_time (each +_raw), namespace, name, count, high_count |
| `defender_mpengine_folder_guard_paths` | `FolderGuardPaths` | id, user_id, guid, folder_path (Path) |
| `defender_mpengine_amsi_file_cache` | `AmsiFileCache` | id, expiration_date (text as stored), persist_id, persist_id_blob |
| `defender_mpengine_schema_history` | `SQLiteGlobals` | id, version, current, last_updated (text as stored) |
| `defender_mpengine_inventory_identifiers` | `MetaInventoryIdentifiers` + `MetaInventoryIdentifierVulnerabilities(Identifier, VulnerabilityId)` | identifier, kind, kind_name (1=cpe, 2=purl), vulnerabilities (comma-joined, sorted) |
| `defender_mpengine_tables` | `sqlite_master` | table_name, row_count, sql |
| `defender_mpengine_raw` | any table | table_name, row_id (ordinal), column_name, value (text; blob=hex), value_type. Honors `table_name =` constraint. |
| `defender_mpengine_status` | `Info` + `pragma integrity_check` | db_path, wal_path, db_size, wal_size, db_sha256, wal_sha256, protection, key_source, keystream_sha256, derived_low_confidence, page_size, db_pages, wal_header_valid, wal_frames_total, wal_frames_committed, wal_commits, integrity_check, table_count, error |

Decoding details (match the reference parser / smap):

* Rolling queues: `queue_type` from EntryTable: `Tech-pid:%`→`techniques`, `Tact-pid:%`→`tactics`, `InheritedTech-pid:%`→`inherited_techniques`, `InheritedTact-pid:%`→`inherited_tactics`, `gPidsTable`→`tracked_pids`, `gTechniquesTable`→`machine_techniques`, `gTacticsTable`→`machine_tactics`, `RecentThreatsOnMachine`→`recent_threats`, `RQ_RecentExecDropped%`→`dropped_executable`, else `named`. `pid`/`process_start` parsed from the first of EntryTable, EntryKey, EntryValue containing `pid:<n>,ProcessStart:<filetime>`. `technique_id` = EntryKey when it matches `^T\d{4}(\.\d{3})?`.
* Persist context: FilePath `AsrRuleStateChangeFor:<guid>` → record_kind `asr_rule_state`, asr_rule_id `<guid>` lowercased; else `path_tag`. ASR GUID→name from the Microsoft list (embedded map, see smap).
* FileHashes: volume_serial `%04X-%04X` of (VSN>>16)&0xFFFF, VSN&0xFFFF; mft_entry = FileID & 0xFFFFFFFFFFFF, mft_sequence = (FileID>>48)&0xFFFF (FileID as uint64); CRC columns `%08X` of value & 0xFFFFFFFF; ssdeep = CTPH up to first NUL.
* BackupProcessInfo: first_start_is_time = 1 if FirstStartTime is a plausible FILETIME.

## CLI

```
defender-mpengine.ext --socket <p> [--timeout s] [--interval s] [--verbose]
                      [--mpengine_path <file|dir>] [--cache_ttl 30s] [--derive_key]
defender-mpengine.ext --decrypt <file|dir> --out <plain.db> [--wal <file>] [--derive_key]   # offline helper
defender-mpengine.ext --version
```

## Testing

* Synthetic fixtures: a plain SQLite DB with the Defender schema + rows,
  encrypted with the known key (and a second fixture with a random key to
  exercise derivation), with an encrypted WAL containing committed frames,
  plus an uncommitted tail and a corrupted-checksum variant.
* Cross-validation: the reference Python parser decrypts the same fixtures;
  our decrypted image must be byte-identical to its `mpenginedb_decrypted.db`.
