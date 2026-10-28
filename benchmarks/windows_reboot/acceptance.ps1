$ErrorActionPreference = 'Stop'
$env:TF_POWER_ROOT = 'C:\coordination-reboot'
New-Item -ItemType Directory -Path $env:TF_POWER_ROOT -Force | Out-Null
$phase = if (Test-Path "$env:TF_POWER_ROOT\ready") { 'windows_after_reboot' } else { 'windows_before_reboot' }
$log = "$env:TF_POWER_ROOT\$phase.log"
try {
    & C:\OEM\coordination_power.exe --exact $phase --ignored --nocapture *> $log
    if ($LASTEXITCODE -ne 0) { throw "Fixture exited $LASTEXITCODE" }
    if ($phase -ne 'windows_after_reboot' -or !(Test-Path "$env:TF_POWER_ROOT\verified")) { throw 'Missing post-reboot verification' }
    $result = @{ status = 'passed'; phase = $phase; log = (Get-Content $log -Raw) }
} catch {
    $result = @{ status = 'failed'; phase = $phase; error = $_.ToString(); log = (Get-Content $log -Raw -ErrorAction SilentlyContinue) }
}
# The Linux controller shares the container's network namespace. QEMU's
# user-network gateway reaches it without guest credentials or open RDP ports.
$gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    try {
        Invoke-RestMethod -Uri "http://${gateway}:8765/result" -Method Post -ContentType 'application/json' -Body ($result | ConvertTo-Json) | Out-Null
        exit 0
    } catch { Start-Sleep -Seconds 2 }
}
throw 'Could not deliver acceptance result to the CI controller'
