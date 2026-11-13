# GCE windows-startup-script-ps1 for the multi-day soak test (runs as SYSTEM
# on every boot). __BUCKET__ is replaced by gce-soak.sh.
#
# First boot: installs osquery, autoloads the extension in osqueryd (as in
# production, with the extensions watchdog on), schedules the pack at soak
# intervals, and registers three SYSTEM tasks from soak-agent.ps1:
#   monitor  every 5 min  - process/memory/handles, DB file state, Defender errors
#   activity every 60 min - EICAR, new zip, unsigned exe, scan, signature update
#   upload   every 30 min - zip C:\osqdef\soak and upload to the bucket
# Later boots (e.g. Windows Update reboots) only make sure osqueryd is running.
$ErrorActionPreference = 'Continue'
$bucket = '__BUCKET__'
$root = 'C:\osqdef'
$soak = "$root\soak"
$osq = 'C:\Program Files\osquery'
New-Item -ItemType Directory -Force -Path $root, $soak, "$soak\osquery" | Out-Null
Add-Content "$soak\boots.log" ("{0:o} boot" -f (Get-Date).ToUniversalTime())

if (Test-Path "$root\installed.marker") {
  Start-Service osqueryd -ErrorAction SilentlyContinue
  Write-Host 'SOAK: already installed; osqueryd started'
  exit 0
}

function Token {
  (Invoke-RestMethod -Headers @{ 'Metadata-Flavor' = 'Google' } `
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token').access_token
}
function Get-Obj($name, $dest) {
  $u = "https://storage.googleapis.com/storage/v1/b/$bucket/o/$([uri]::EscapeDataString($name))?alt=media"
  Invoke-WebRequest -UseBasicParsing -Headers @{ Authorization = "Bearer $(Token)" } $u -OutFile $dest
}

Write-Host 'SOAK: downloading artifacts'
Set-Content "$root\bucket.txt" $bucket
Get-Obj 'soak/defender-mpengine.ext.exe' "$root\defender-mpengine.ext.exe"
Get-Obj 'soak/defender_mpengine.conf' "$root\defender_mpengine.conf"
Get-Obj 'soak/soak-agent.ps1' "$root\soak-agent.ps1"

Write-Host 'SOAK: installing osquery'
Invoke-WebRequest -UseBasicParsing 'https://pkg.osquery.io/windows/osquery-5.20.0.msi' -OutFile "$root\osquery.msi"
Start-Process msiexec.exe -Wait -ArgumentList '/i', "$root\osquery.msi", '/qn', '/norestart'
$osqd = Get-ChildItem -Recurse -Filter osqueryd.exe $osq | Select-Object -First 1 -ExpandProperty FullName
Write-Host "SOAK: osqueryd=$osqd"
Stop-Service osqueryd -ErrorAction SilentlyContinue

# Extension in an admin-only location so osquery's autoload permission check passes.
New-Item -ItemType Directory -Force -Path "$osq\extensions" | Out-Null
Copy-Item -Force "$root\defender-mpengine.ext.exe" "$osq\extensions\defender-mpengine.ext.exe"
Set-Content -Encoding ascii "$osq\extensions.load" "$osq\extensions\defender-mpengine.ext.exe"

# Schedule: every pack query at min(interval, 5 min), plus a status snapshot
# every minute and an all-tables row count every 15 min.
$pack = Get-Content -Raw "$root\defender_mpengine.conf" | ConvertFrom-Json
$schedule = [ordered]@{}
foreach ($p in $pack.queries.PSObject.Properties) {
  $q = $p.Value
  $schedule[$p.Name] = [ordered]@{ query = $q.query; interval = [Math]::Min([int]$q.interval, 300); removed = [bool]$q.removed }
}
$schedule['soak_status'] = [ordered]@{ query = 'SELECT * FROM defender_mpengine_status;'; interval = 60; snapshot = $true }
$typed = 'rolling_queues','persist_context','file_hashes','backup_process_info','lowfi_async',
  'process_block_history','bm_process_info','ransomware_detections','firewall_rules',
  'atomic_counters','folder_guard_paths','amsi_file_cache','schema_history','inventory_identifiers'
$union = ($typed | ForEach-Object { "SELECT '$_' AS t, count(*) AS n FROM defender_mpengine_$_" }) -join ' UNION ALL '
$schedule['soak_counts'] = [ordered]@{ query = "$union;"; interval = 900; snapshot = $true }
$schedule['soak_tables'] = [ordered]@{ query = 'SELECT table_name, row_count FROM defender_mpengine_tables;'; interval = 21600; snapshot = $true }
@{ options = @{ schedule_splay_percent = 10 }; schedule = $schedule } |
  ConvertTo-Json -Depth 6 | Set-Content -Encoding ascii "$osq\osquery.conf"

@"
--config_plugin=filesystem
--config_path=$osq\osquery.conf
--logger_plugin=filesystem
--logger_path=$soak\osquery
--database_path=$osq\osquery.db
--extensions_autoload=$osq\extensions.load
--extensions_require=defender_mpengine
--extensions_timeout=30
--extensions_interval=5
--enable_extensions_watchdog=true
--watchdog_level=0
--host_identifier=hostname
--logger_min_status=0
"@ | Set-Content -Encoding ascii "$osq\osquery.flags"

if (-not (Get-Service osqueryd -ErrorAction SilentlyContinue)) {
  New-Service -Name osqueryd -StartupType Automatic -BinaryPathName "`"$osqd`" --flagfile=`"$osq\osquery.flags`"" | Out-Null
} else {
  & sc.exe config osqueryd binPath= "`"$osqd`" --flagfile=`"$osq\osquery.flags`"" start= auto | Out-Null
}
Start-Service osqueryd

function Register-SoakTask($name, $mode, $minutes) {
  $a = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$root\soak-agent.ps1`" -Mode $mode"
  $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
    -RepetitionInterval (New-TimeSpan -Minutes $minutes) -RepetitionDuration (New-TimeSpan -Days 14)
  $s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -MultipleInstances IgnoreNew -StartWhenAvailable
  Register-ScheduledTask -TaskName "osqdef-soak-$name" -Action $a -Trigger $t -Settings $s `
    -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest -Force | Out-Null
}
Register-SoakTask monitor monitor 5
Register-SoakTask activity activity 60
Register-SoakTask upload upload 30

Set-Content "$soak\started_utc.txt" ((Get-Date).ToUniversalTime().ToString('o'))
Set-Content "$root\installed.marker" 'installed'
Write-Host 'SOAK-STARTED'
