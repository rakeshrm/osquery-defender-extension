# Soak-test agent, run as SYSTEM by scheduled tasks created in soak-startup.ps1.
#   -Mode monitor   append one sample to monitor.csv (+ Defender warnings/errors)
#   -Mode activity  generate Defender activity so the database keeps changing
#   -Mode upload    zip C:\osqdef\soak and upload it to the soak bucket
param([Parameter(Mandatory)][ValidateSet('monitor', 'activity', 'upload')] [string] $Mode)

$ErrorActionPreference = 'Continue'
$root = 'C:\osqdef'
$soak = "$root\soak"
$scans = 'C:\ProgramData\Microsoft\Windows Defender\Scans'
$now = (Get-Date).ToUniversalTime()

function Iso($t) { if ($t) { $t.ToUniversalTime().ToString('o') } else { '' } }

# GCE instance name: unique, unlike COMPUTERNAME (NetBIOS, truncated to 15 chars).
$hostId = try {
  Invoke-RestMethod -Headers @{ 'Metadata-Flavor' = 'Google' } 'http://metadata.google.internal/computeMetadata/v1/instance/name'
} catch { $env:COMPUTERNAME }

switch ($Mode) {
  'monitor' {
    $ext = Get-Process -Name 'defender-mpengine.ext' -ErrorAction SilentlyContinue | Select-Object -First 1
    $osqd = Get-Process -Name 'osqueryd' -ErrorAction SilentlyContinue |
      Sort-Object WorkingSet64 -Descending | Select-Object -First 1
    $db = Get-Item -Force "$scans\mpenginedb.db" -ErrorAction SilentlyContinue
    $wal = Get-Item -Force "$scans\mpenginedb.db-wal" -ErrorAction SilentlyContinue
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue

    # Defender warnings/errors since the previous sample, with messages kept
    # separately so Monday's analysis can see what (if anything) went wrong.
    $stateFile = "$soak\monitor.last"
    $since = if (Test-Path $stateFile) { [datetime]::Parse((Get-Content $stateFile), $null, 'RoundtripKind') } else { $now.AddMinutes(-5) }
    $events = @(Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'; Level = 1, 2, 3; StartTime = $since.ToLocalTime() })
    foreach ($e in $events) {
      $msg = ($e.Message -split "`r?`n" | Where-Object { $_ } | Select-Object -First 3) -join ' | '
      Add-Content "$soak\defender-events.log" ("{0} id={1} level={2} {3}" -f (Iso $e.TimeCreated), $e.Id, $e.LevelDisplayName, $msg)
    }
    Set-Content $stateFile ($now.ToString('o'))

    $row = [ordered]@{
      ts_utc         = $now.ToString('o')
      host           = $hostId
      ext_pid        = $ext.Id
      ext_start_utc  = Iso $ext.StartTime
      ext_ws_mb      = if ($ext) { [math]::Round($ext.WorkingSet64 / 1MB, 2) } else { '' }
      ext_private_mb = if ($ext) { [math]::Round($ext.PrivateMemorySize64 / 1MB, 2) } else { '' }
      ext_handles    = $ext.HandleCount
      ext_threads    = if ($ext) { $ext.Threads.Count } else { '' }
      ext_cpu_s      = if ($ext) { [math]::Round($ext.TotalProcessorTime.TotalSeconds, 1) } else { '' }
      osqd_pid       = $osqd.Id
      osqd_start_utc = Iso $osqd.StartTime
      osqd_ws_mb     = if ($osqd) { [math]::Round($osqd.WorkingSet64 / 1MB, 2) } else { '' }
      db_size        = $db.Length
      db_mtime_utc   = Iso $db.LastWriteTime
      wal_size       = $wal.Length
      wal_mtime_utc  = Iso $wal.LastWriteTime
      engine         = $mp.AMEngineVersion
      platform       = $mp.AMProductVersion
      signatures     = $mp.AntivirusSignatureVersion
      rtp            = $mp.RealTimeProtectionEnabled
      def_events_new = $events.Count
      def_errors_new = @($events | Where-Object { $_.Level -le 2 }).Count
    }
    $csv = "$soak\monitor.csv"
    $line = [pscustomobject]$row | ConvertTo-Csv -NoTypeInformation
    if (-not (Test-Path $csv)) { $line | Set-Content -Encoding utf8 $csv } else { $line | Select-Object -Skip 1 | Add-Content -Encoding utf8 $csv }
  }

  'activity' {
    $act = "$root\act"
    New-Item -ItemType Directory -Force -Path $act | Out-Null
    $stamp = $now.ToString('yyyyMMddHHmm')
    # EICAR test string (harmless standard AV test file) -> detection + RecentThreatsOnMachine
    $e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' + '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    Set-Content -NoNewline -Path "$act\eicar-$stamp.com" -Value $e -ErrorAction SilentlyContinue
    # New zip; new unsigned PE created and executed (the extension binary is unsigned)
    Compress-Archive -Force -Path "$root\soak-agent.ps1" -DestinationPath "$act\new-$stamp.zip"
    Copy-Item -Force "$root\defender-mpengine.ext.exe" "$act\unsigned-$stamp.exe"
    & "$act\unsigned-$stamp.exe" --version | Out-Null
    Start-MpScan -ScanType CustomScan -ScanPath $act -ErrorAction SilentlyContinue
    # Exercise signature/engine updates (the database is rewritten around them).
    if ($now.Hour % 6 -eq 0) { Update-MpSignature -ErrorAction SilentlyContinue }
    # Keep the folder small.
    Get-ChildItem $act | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-6) } | Remove-Item -Force -ErrorAction SilentlyContinue
    Add-Content "$soak\activity.log" ("{0} activity" -f $now.ToString('o'))
  }

  'upload' {
    $bucket = (Get-Content "$root\bucket.txt").Trim()
    $zip = "$root\upload.zip"
    Compress-Archive -Force -Path "$soak\*" -DestinationPath $zip
    $token = (Invoke-RestMethod -Headers @{ 'Metadata-Flavor' = 'Google' } `
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token').access_token
    foreach ($name in "soak/results/$hostId/latest.zip",
                      "soak/results/$hostId/$($now.ToString('yyyyMMdd-HH')).zip") {
      $u = "https://storage.googleapis.com/upload/storage/v1/b/$bucket/o?uploadType=media&name=$([uri]::EscapeDataString($name))"
      Invoke-RestMethod -Method Post -Headers @{ Authorization = "Bearer $token" } -InFile $zip `
        -ContentType 'application/zip' $u | Out-Null
    }
    # Rotate osquery result logs locally so uploads stay small.
    Get-ChildItem "$soak\osquery" -Filter '*.log' | Where-Object { $_.Length -gt 50MB } |
      ForEach-Object { Move-Item -Force $_.FullName ($_.FullName + '.1') }
  }
}
