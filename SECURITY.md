# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/rakeshrm/osquery-defender-extension/security/advisories/new),
not in a public issue. Include the version (`--version`), the platform, and
steps or a file that reproduces the problem. Do not attach real Defender
databases (`mpenginedb.db*`); they contain data about the host they came from.

You should get a reply within a week. Fixes are released as a new version and
announced in a GitHub security advisory.

## Supported versions

Only the latest release gets security fixes.

## Scope

The extension runs as SYSTEM under osqueryd and parses untrusted input (the
database files and query constraints). Of particular interest:

- anything that makes it write to disk, write to the evidence, or open paths
  that the `path` checks should reject (UNC, device paths, non-`mpenginedb*`
  files);
- crafted databases or WAL files that cause crashes, hangs or memory
  exhaustion despite `--query_timeout`, `--max_rows` and `--max_db_bytes`;
- issues in the release process or published binaries.

See [Security notes](readme.md#security-notes) for the intended guarantees.

## Verifying releases

Every release has `SHA256SUMS`. Releases after v0.2.0 also have a signed build
provenance attestation:

```
gh attestation verify <file> -R rakeshrm/osquery-defender-extension
```
