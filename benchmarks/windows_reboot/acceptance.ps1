$ErrorActionPreference = 'Stop'
$env:TF_POWER_ROOT = 'C:\coordination-reboot'
New-Item -ItemType Directory -Path $env:TF_POWER_ROOT -Force | Out-Null
$phase = if (Test-Path "$env:TF_POWER_ROOT\ready") { 'windows_after_reboot' } else { 'windows_before_reboot' }
$log = "$env:TF_POWER_ROOT\$phase.log"
try {
	& C:\OEM\coordination_power.exe --exact $phase --ignored --nocapture *> $log
	if ($LASTEXITCODE -ne 0) { throw "Fixture exited $LASTEXITCODE" }
	if ($phase -ne 'windows_after_reboot' -or !(Test-Path "$env:TF_POWER_ROOT\verified")) { throw 'Missing post-reboot verification' }
	$sessions = & C:\OEM\sessions.ps1
	if ($sessions.status -ne 'passed') { throw 'Missing real-session verification' }
	# Windows PowerShell 5.1 serializes provider metadata attached by
	# Get-Content. Read plain strings so reports contain only fixture output.
	$result = @{ status = 'passed'; phase = $phase; log = [System.IO.File]::ReadAllText($log); sessions = $sessions }
}
catch {
	$result = @{ status = 'failed'; phase = $phase; error = $_.ToString(); stack = $_.ScriptStackTrace }
	if (Test-Path $log) { $result.log = [System.IO.File]::ReadAllText($log) }
	if (Test-Path 'C:\coordination-sessions') {
		$result.sessionLogs = @{}
		foreach ($sessionLog in Get-ChildItem 'C:\coordination-sessions\*.log') {
			$result.sessionLogs[$sessionLog.Name] = [System.IO.File]::ReadAllText($sessionLog.FullName)
		}
	}
}
$result | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 "$env:TF_POWER_ROOT\result.json"
# QEMU user networking reaches the Linux controller through Docker's bridge
# gateway. RDP is forwarded only on the controller's loopback interface.
$gateway = (Get-Content C:\OEM\controller.txt -Raw).Trim()
for ($attempt = 0; $attempt -lt 60; $attempt++) {
	try {
		Invoke-RestMethod -Uri "http://${gateway}:8765/result" -Method Post -ContentType 'application/json' -Body ($result | ConvertTo-Json -Depth 6) |
			Out-Null
		exit 0
	}
	catch { Start-Sleep -Seconds 2 }
}
# Preserve evidence even if guest-to-host delivery fails. A clean shutdown
# lets the controller read the result from the retained NTFS disk.
shutdown.exe /s /t 0 /f
