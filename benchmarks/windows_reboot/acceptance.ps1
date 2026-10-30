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
}
catch {
	$result = @{ status = 'failed'; phase = $phase; error = $_.ToString(); log = (Get-Content $log -Raw -ErrorAction SilentlyContinue) }
}
$result | ConvertTo-Json | Set-Content -Encoding UTF8 "$env:TF_POWER_ROOT\result.json"
# QEMU user networking reaches the Linux controller through Docker's bridge
# gateway without exposing RDP or depending on a guest-agent installation.
$gateway = (Get-Content C:\OEM\controller.txt -Raw).Trim()
for ($attempt = 0; $attempt -lt 60; $attempt++) {
	try {
		Invoke-RestMethod -Uri "http://${gateway}:8765/result" -Method Post -ContentType 'application/json' -Body ($result | ConvertTo-Json) |
			Out-Null
		exit 0
	}
	catch { Start-Sleep -Seconds 2 }
}
# Preserve evidence even if guest-to-host delivery fails. A clean shutdown
# lets the controller read the result from the retained NTFS disk.
shutdown.exe /s /t 0 /f
