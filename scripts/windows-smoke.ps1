<#
.SYNOPSIS
  Smoke-test the extension against the LIVE Defender database on this host.

.DESCRIPTION
  Collects diagnostics only - never row contents and never the decrypted DB:
    identity.txt     who ran the test (SYSTEM vs admin)
    defender.json    Defender engine/platform versions and protection state
    scans.json       names/sizes/mtimes of files in the Scans folder
    decrypt.json     --decrypt Info (key source, WAL state, quick_check, hashes)
    status.json      defender_mpengine_status via osqueryi (default path)
    tables.json      Defender's table list, row counts and schema SQL
    counts.json      row counts of every typed table
    summary.json     pass/fail verdict

  Exit code 0 = extension loaded and the status table answered; 1 otherwise.
  Decryption problems (e.g. an unknown engine key) are reported, not fatal.
#>
param(
  [Parameter(Mandatory)] [string] $Ext,
  [Parameter(Mandatory)] [string] $OsqueryI,
  [Parameter(Mandatory)] [string] $OutDir
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$scans = 'C:\ProgramData\Microsoft\Windows Defender\Scans'

function Save($name, $obj) {
  $obj | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $OutDir $name)
}

function OsqueryJson($sql) {
  $db = Join-Path $OutDir 'osqdb'
  $out = & $OsqueryI --extension $Ext --allow_unsafe `
           --extensions_require=defender_mpengine --extensions_timeout=30 `
           --database_path=$db --json $sql 2>&1
  $text = ($out | Where-Object { $_ -is [string] }) -join "`n"
  try { return ($text | ConvertFrom-Json) } catch { return @{ error = $text } }
}

whoami /all | Set-Content (Join-Path $OutDir 'identity.txt')

try {
  Save 'defender.json' (Get-MpComputerStatus | Select-Object AMEngineVersion,
    AMProductVersion, AMServiceVersion, AntivirusSignatureVersion,
    RealTimeProtectionEnabled, IsTamperProtected, AMRunningMode)
} catch { Save 'defender.json' @{ error = "$_" } }

try {
  Save 'scans.json' (Get-ChildItem -Force $scans -ErrorAction Stop |
    Select-Object Name, Length, @{n='LastWriteTimeUtc'; e={$_.LastWriteTimeUtc.ToString('o')}})
} catch { Save 'scans.json' @{ error = "$_" } }

# --decrypt writes a plaintext copy; keep it only long enough to prove it works.
$plain = Join-Path $env:TEMP ("mpdb-smoke-" + [guid]::NewGuid() + ".db")
$dec = & $Ext --decrypt $scans --out $plain 2>&1
$decExit = $LASTEXITCODE
$decText = ($dec | ForEach-Object { "$_" }) -join "`n"
$magic = $null
if (Test-Path $plain) {
  $bytes = [System.IO.File]::ReadAllBytes($plain)
  $magic = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 15)
  Remove-Item -Force $plain
}
try { $decObj = $decText | ConvertFrom-Json } catch { $decObj = $null }
Save 'decrypt.json' @{ exit = $decExit; output = $(if ($decObj) { $decObj } else { $decText }); header = $magic }

$status = OsqueryJson 'SELECT * FROM defender_mpengine_status;'
Save 'status.json' $status
Save 'tables.json' (OsqueryJson 'SELECT table_name, row_count, sql FROM defender_mpengine_tables;')

$typed = 'rolling_queues','persist_context','file_hashes','backup_process_info',
  'lowfi_async','process_block_history','bm_process_info','ransomware_detections',
  'firewall_rules','atomic_counters','folder_guard_paths','amsi_file_cache',
  'schema_history','inventory_identifiers'
$union = ($typed | ForEach-Object {
  "SELECT '$_' AS t, count(*) AS n FROM defender_mpengine_$_" }) -join ' UNION ALL '
Save 'counts.json' (OsqueryJson "$union;")

$row = @($status)[0]
# Any status row (even one carrying a decrypt error) proves the extension
# registered and answered; an osqueryi failure yields a hashtable without 'path'.
$loaded = $row -and ($row.PSObject.Properties.Name -contains 'path')
$summary = [ordered]@{
  user            = (whoami)
  extension_ok    = [bool]$loaded
  status_error    = $(if ($row) { $row.error } else { 'no status row' })
  key_source      = $(if ($row) { $row.key_source } else { $null })
  quick_check     = $(if ($row) { $row.quick_check } else { $null })
  decrypt_exit    = $decExit
  decrypt_header  = $magic
}
Save 'summary.json' $summary
$summary | Format-List | Out-String | Write-Output
if ($summary.extension_ok) { exit 0 } else { exit 1 }
