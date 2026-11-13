# GCE windows-startup-script-ps1 (runs as SYSTEM). Template: __BUCKET__ is
# replaced by scripts/gce-smoke.sh. Downloads the extension + smoke script
# from the bucket, installs osquery, generates a little Defender activity,
# runs the smoke test and uploads diagnostics (never the decrypted DB).
$ErrorActionPreference = 'Continue'
$bucket = '__BUCKET__'
$root = 'C:\osqdef'
if (Test-Path "$root\done.marker") { Write-Host 'SMOKE: already ran'; exit 0 }
New-Item -ItemType Directory -Force -Path $root, "$root\act" | Out-Null

function Token {
  (Invoke-RestMethod -Headers @{ 'Metadata-Flavor' = 'Google' } `
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token').access_token
}
function Get-Obj($name, $dest) {
  $u = "https://storage.googleapis.com/storage/v1/b/$bucket/o/$([uri]::EscapeDataString($name))?alt=media"
  Invoke-WebRequest -UseBasicParsing -Headers @{ Authorization = "Bearer $(Token)" } $u -OutFile $dest
}
function Put-Obj($src, $name) {
  $u = "https://storage.googleapis.com/upload/storage/v1/b/$bucket/o?uploadType=media&name=$([uri]::EscapeDataString($name))"
  Invoke-RestMethod -Method Post -Headers @{ Authorization = "Bearer $(Token)" } -InFile $src -ContentType 'application/octet-stream' $u | Out-Null
}

Write-Host 'SMOKE: downloading artifacts'
Get-Obj 'defender-mpengine.ext.exe' "$root\defender-mpengine.ext.exe"
Get-Obj 'windows-smoke.ps1' "$root\windows-smoke.ps1"

Write-Host 'SMOKE: installing osquery'
Invoke-WebRequest -UseBasicParsing 'https://pkg.osquery.io/windows/osquery-5.20.0.msi' -OutFile "$root\osquery.msi"
Start-Process msiexec.exe -Wait -ArgumentList '/i', "$root\osquery.msi", '/qn', '/norestart'
$osqi = Get-ChildItem -Recurse -Filter osqueryi.exe 'C:\Program Files\osquery' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
Write-Host "SMOKE: osqueryi=$osqi"

# Baseline before generating activity.
& powershell -NoProfile -ExecutionPolicy Bypass -File "$root\windows-smoke.ps1" -Ext "$root\defender-mpengine.ext.exe" -OsqueryI $osqi -OutDir "$root\out\1-baseline"

Write-Host 'SMOKE: generating Defender activity'
# EICAR test string (harmless, standard AV test file) -> detection
$e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' + '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -NoNewline -Path "$root\act\eicar.com" -Value $e -ErrorAction SilentlyContinue
# New zip + unsigned PE created and executed (extension binary is unsigned)
Compress-Archive -Force -Path "$root\windows-smoke.ps1" -DestinationPath "$root\act\new.zip"
Copy-Item "$root\defender-mpengine.ext.exe" "$root\act\unsigned-tool.exe"
& "$root\act\unsigned-tool.exe" --version | Out-Null
Start-MpScan -ScanType CustomScan -ScanPath "$root\act" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 120

& powershell -NoProfile -ExecutionPolicy Bypass -File "$root\windows-smoke.ps1" -Ext "$root\defender-mpengine.ext.exe" -OsqueryI $osqi -OutDir "$root\out\2-after-activity"
$rc = $LASTEXITCODE

# Remove osquery's local DB dirs before packaging; upload diagnostics only.
Get-ChildItem -Recurse -Directory "$root\out" -Filter osqdb | Remove-Item -Recurse -Force
Compress-Archive -Force -Path "$root\out\*" -DestinationPath "$root\results.zip"
Put-Obj "$root\results.zip" 'results/results.zip'
Set-Content "$root\done.marker" 'done'
Write-Host "SMOKE-DONE rc=$rc"
