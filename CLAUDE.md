# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

osquery extension (Go) exposing Microsoft Defender's RC4-encrypted
`mpenginedb.db` ("MetaVault") as `defender_mpengine_*` tables.
`docs/DESIGN.md` is authoritative for the format, table columns, CLI and API.

## Commands

```bash
./build.sh                                   # all 6 platforms -> bin/ + bin/SHA256SUMS (VERSION=x.y.z to override)
cd defender && go vet ./... && go test -race ./...
cd defender && go build -o defender-mpengine.ext .   # local single build
```

## Layout

- `defender/main.go` — flags, osquery extension server, `--decrypt` CLI; `var Version` set via `-X main.Version=`
- `defender/internal/mpengine/` — RC4 codec, key derivation, WAL replay, `Decrypt`, in-memory `Snapshot`, `Cache` (no osquery dependency)
- `defender/internal/tables/` — table plugins: `spec.go` (declarative column specs + decoders), `tables.go`, `generic.go`, `status.go`
- `defender/internal/mpengine/testdata/oracle/` — independent Python-generated fixtures + expected results
- `pack/defender_mpengine.conf` — osquery pack (use only columns that exist)

## Conventions

- Pure Go, `CGO_ENABLED=0` (`modernc.org/sqlite`). No cgo dependencies.
- Never write decrypted data to disk (the only exception is the explicit
  `--decrypt --out` file: 0600, never overwrite). Never write to the evidence.
- Tables are schema-tolerant: select only columns present in `pragma table_info`;
  missing column = empty value, missing table = zero rows. Every table has `path`.
- Add a new Defender table via the declarative `Col` spec in
  `internal/tables/spec.go`, then update the table list in `docs/DESIGN.md` and `readme.md`.
- Oracle fixtures are the ground truth. Do not edit expected values to make
  tests pass; regenerate with `python3 -I make_fixtures.py` (run in the oracle dir)
  only when the fixture design changes.
- FileHashes stores MD5 in column `SHA1` and SHA-1 in `MD5` — keep the swap.

## `.ref/`

Gitignored local copies of the reference implementations (Protokol-7, MIT):
`mpenginedb_parser.py`, `Decrypt-MpEngineDb.ps1`,
`Windows_MicrosoftDefender_MpEngineDb.smap`. Use them to check decoding
behaviour; do not commit them. Never commit real evidence (`mpenginedb.db*`).
