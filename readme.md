# Defender MpEngineDb osquery extension

An osquery extension (pure Go) that exposes Microsoft Defender's hidden engine
database, `mpenginedb.db` ("MetaVault"), as osquery tables:

```
C:\ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db
C:\ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db-wal
```

The database is a flight recorder of what the Defender engine saw: per-process
MITRE ATT&CK attack scoring, behaviour detections, dropped executables, path
tags (side-loading, unsigned PEs), ASR rule state and blocks, ransomware
detections and rollback tracking, the real-time protection hash cache and the
software inventory with CVEs. Every page is RC4-encrypted, so standard SQLite
tooling cannot read it; this extension decrypts it in memory and serves it as
SQL.

## Credits

The format research and the RC4 key are the work of Protokol-7 (MIT licensed):

- Article: [Defender's hidden flight recorder: mpenginedb](https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html)
- [Protokol-7/mpenginedb_parser](https://github.com/Protokol-7/mpenginedb_parser) (Python, MIT)
- [Protokol-7/MpEngineDb_SQLECmd](https://github.com/Protokol-7/MpEngineDb_SQLECmd) (SQLECmd map + PowerShell decryptor, MIT)

This project is an independent Go implementation; its decoding matches the
reference parser and SQLECmd map.

## How it works

1. **RC4 page codec.** The keystream is the first `page_size` bytes of RC4 with
   a fixed 256-byte key from `mpengine.dll`; RC4 restarts for every page.
   Page 1 keeps bytes 16..23 (page size etc.) in clear. A known key (engine
   1.1.26100.4) is tried first; an unencrypted DB (`MpSqliteCodecDisable=1`)
   passes through.
2. **WAL replay with checksum validation.** WAL checksums cover the stored
   (encrypted) bytes, so the salt + checksum chain is validated on the raw
   frames, then frame pages are decrypted. Only frames up to the last valid
   commit are applied; a torn read or corruption simply ends the chain.
3. **In-memory snapshot.** The plaintext image is loaded into a read-only,
   in-memory SQLite (`modernc.org/sqlite`, no cgo). Nothing decrypted is
   written to disk.
4. **Cache.** One snapshot per source path is reused while the DB and WAL
   size+mtime are unchanged and it is younger than `--cache_ttl` (default
   30s), so a pack hitting many tables decrypts once. Failed opens are cached
   too; at most `--cache_entries` snapshots are kept.

## Tables

Every table has a `path` column (see [offline evidence](#offline-evidence)).
FILETIME columns are exposed as unix seconds plus a `<name>_raw` FILETIME
column; blobs are lowercase hex; GUIDs are decoded to `8-4-4-4-12`.

| Table | Source | Purpose |
|---|---|---|
| `defender_mpengine_rolling_queues` | RollingQueuesValues + RollingQueuesTables | attack-scoring techniques/tactics per process and machine, recent threats, dropped executables, named queues; `queue_type`, `technique_id`, `pid`, `process_start` decoded |
| `defender_mpengine_persist_context` | AttributePersistContext | path tags set by signatures, ASR rule state changes (`record_kind`, `asr_rule_id`, `asr_rule_name`) |
| `defender_mpengine_file_hashes` | FileHashes | real-time protection hash cache: file reference (volume serial, MFT entry/sequence, USN), MD5/SHA-1/SHA-256, ssdeep, CRCs |
| `defender_mpengine_backup_process_info` | BackupProcessInfo | files/processes tracked for ransomware rollback |
| `defender_mpengine_lowfi_async` | FileLowFiAsync | LowFi signature hits sent for async cloud lookup |
| `defender_mpengine_process_block_history` | ProcessBlockHistory | processes blocked/audited by ASR rules |
| `defender_mpengine_bm_process_info` | BmProcessInfo | behaviour-monitored processes (image, command line, flags) |
| `defender_mpengine_ransomware_detections` | RansomwareDetections | ransomware detections and remediation timeline |
| `defender_mpengine_firewall_rules` | NetworkIpFirewallRules(Outgoing) | firewall rules created by network protection |
| `defender_mpengine_atomic_counters` | AtomicCounters | counters set by signatures |
| `defender_mpengine_folder_guard_paths` | FolderGuardPaths | Controlled Folder Access paths |
| `defender_mpengine_amsi_file_cache` | AmsiFileCache | AMSI scan result cache |
| `defender_mpengine_schema_history` | SQLiteGlobals | schema version history (creation and upgrades) |
| `defender_mpengine_inventory_identifiers` | MetaInventoryIdentifiers(+Vulnerabilities) | software inventory (CPE / purl) with associated vulnerability IDs |
| `defender_mpengine_tables` | sqlite_master | every table in the DB with row count and DDL |
| `defender_mpengine_raw` | any table | generic dump, one row per cell; honours `table_name =` |
| `defender_mpengine_status` | decryptor + `pragma quick_check` / `integrity_check` | source files and hashes, protection, key source, WAL replay stats, quick_check (at decrypt time), integrity_check, table_count, error |

Column lists: [docs/DESIGN.md](docs/DESIGN.md#tables).

## Example queries

```sql
-- Is it working? (key_source, integrity_check, WAL replay)
SELECT protection, key_source, integrity_check, wal_commits, error
FROM defender_mpengine_status;

-- ATT&CK techniques Defender attributed to running / recent processes
SELECT r.technique_id, r.pid, datetime(r.process_start, 'unixepoch') AS started, p.name, p.path
FROM defender_mpengine_rolling_queues r
LEFT JOIN processes p ON p.pid = r.pid
WHERE r.queue_type IN ('techniques', 'inherited_techniques');

-- Potential DLL side-loading and unsigned PEs
SELECT file_path, context, datetime(insert_time, 'unixepoch') AS tagged
FROM defender_mpengine_persist_context
WHERE context IN ('BM_IsPotentialSideLoad', 'NewPECreatedNoCert', 'ExecutedPENoCert');

-- ASR blocks
SELECT datetime(time, 'unixepoch') AS t, process_path, target_path, asr_rule_name, is_audit
FROM defender_mpengine_process_block_history;

-- Software with CVEs
SELECT identifier, kind_name, vulnerabilities
FROM defender_mpengine_inventory_identifiers WHERE vulnerabilities != '';
```

### Offline evidence

Point any table at a collected copy (a `Scans` folder or the `.db` file; the
WAL is found as `<db>-wal` or `<db>~wal`). On macOS/Linux a `path` constraint
is required.

```sql
SELECT * FROM defender_mpengine_status WHERE path = 'D:\case\Scans';
SELECT queue_type, entry_key, pid FROM defender_mpengine_rolling_queues WHERE path = 'D:\case\Scans';
```

To get a plain SQLite copy (WAL applied) for SQLECmd with the
MpEngineDb map, `sqlite3` or a DB browser:

```
defender-mpengine-windows-amd64.ext.exe --decrypt D:\case\Scans --out D:\case\mpenginedb_decrypted.db
```

## Flags

```
--socket <path>              osquery extension socket (set by osquery)
--timeout <s>, --interval <s> extension server timeout / ping interval
--verbose                    verbose logging
--mpengine_path <file|dir>   default source (default on Windows: C:\ProgramData\Microsoft\Windows Defender\Scans)
--cache_ttl 30s              snapshot (and failed-open) cache lifetime; 0 = no caching
--cache_entries 8            max cached snapshots (LRU)
--query_timeout 30s          deadline per table query; 0 = none
--max_rows 500000            max rows read per source table per path (warning logged); 0 = unlimited
--max_db_bytes 1073741824    refuse db+wal larger than this (also for --decrypt)
--allow_unc_paths            allow UNC / device paths (\\server\share, \\.\, \\?\) in path =
--derive_key                 ignore known keys; derive the keystream from the evidence
--decrypt <file|dir> --out <plain.db> [--wal <file>] [--derive_key]   offline decrypt, then exit
--version                    print version and exit
```

## Running

Interactive:

```
osqueryi --extension bin\defender-mpengine-windows-amd64.ext.exe --allow-unsafe
```

When passing a query on the command line, add
`--extensions_require=defender_mpengine` so osqueryi waits for the extension
to register before running it:

```
osqueryi --extension bin\defender-mpengine-windows-amd64.ext.exe --allow-unsafe ^
  --extensions_require=defender_mpengine ^
  "SELECT * FROM defender_mpengine_status;"
```

Autoload with osqueryd: list the binary's absolute path in `extensions.load`
and start osqueryd with `--extensions_autoload=<path to extensions.load>`.
osquery only autoloads a binary that is owned by Administrators/SYSTEM and not
writable by users, and whose name ends in `.ext.exe` on Windows (`.ext`
elsewhere).

A ready-made Windows pack is in [pack/defender_mpengine.conf](pack/defender_mpengine.conf).

## Security notes

- **Read-only evidence.** The DB and WAL are opened read-only; on Windows with
  full share mode (`FILE_SHARE_READ|WRITE|DELETE`) because `MsMpEng.exe` holds
  them open. The extension never writes to them.
- **Decrypted data stays in memory.** It is never written to disk, except the
  explicit `--decrypt` output, which is created with mode 0600 and never
  overwrites an existing file.
- **Privileges.** Reading the `Scans` folder requires SYSTEM/administrator;
  osqueryd runs as SYSTEM.
- **Derived keys are verified.** A keystream derived from the evidence is only
  accepted if the decrypted DB passes `pragma integrity_check`; `--decrypt`
  writes nothing and exits non-zero otherwise.
- **`path` is restricted.** Queries run as SYSTEM, so a `path =` constraint
  may not be a UNC or device path (`\\server\share`, `//server/share`, `\\.\`,
  `\\?\`, `\??\` — opening one would also send the machine's NTLM credentials
  to that host) unless `--allow_unc_paths` is set, and a file must be named
  `mpenginedb*` (directories resolve to `mpenginedb.db`). Rejected paths
  return no rows (status: `error = 'path rejected: ...'`). `--mpengine_path`
  is trusted.
- **Untrusted evidence.** Only ordinary tables are read (views/virtual tables
  count as missing), with `trusted_schema=OFF` and in-memory temp storage.
  Each table query is bounded by `--query_timeout` and `--max_rows`, input
  size by `--max_db_bytes`, and only regular files are read.

## Limitations

- The format is verified for engine 1.1.26100.4. Other engine builds fall back
  to best-effort keystream derivation (known header plaintext + zero-filled
  free space voting), which may leave low-confidence bytes and be rejected —
  check `key_source` and `derived_low_confidence` in `defender_mpengine_status`.
- Defender's schema can change between builds. Tables select only the columns
  that exist; a missing column is empty and a missing table yields zero rows.
- Defender keeps roughly two weeks of data (attack-scoring queues about one
  hour; `ProcessBlockHistory` about 90 days).
- Defender stores MD5 in the column named `SHA1` and SHA-1 in `MD5`;
  `defender_mpengine_file_hashes` swaps them back.
- Only the current state (DB + committed WAL) is exposed. No deleted-row
  carving and no per-commit WAL history — use
  [mpenginedb_parser.py](https://github.com/Protokol-7/mpenginedb_parser) for that.

## Development

```bash
./build.sh                        # all platforms -> bin/, plus bin/SHA256SUMS
cd defender && go vet ./... && go test -race ./...
```

Tests run against independent oracle fixtures in
`defender/internal/mpengine/testdata/oracle/` (known key, plain, corrupt WAL,
no WAL, random key, junk), generated by a stdlib-only Python script that does
not share code with the Go implementation. Regenerate them with:

```bash
cd defender/internal/mpengine/testdata/oracle && python3 -I make_fixtures.py
```

`self_check.py` there is a second independent decryptor used to validate the
fixtures; see its [README](defender/internal/mpengine/testdata/oracle/README.md).

