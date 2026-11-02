param(
	[Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]+$')][string]$Name,
	[Parameter(Mandatory)][ValidateSet('hold', 'probe', 'observe', 'denied', 'appcontainer')][string]$Mode,
	[Parameter(Mandatory)][string]$Scope
)
$ErrorActionPreference = 'Stop'
$env:TF_SESSION_ROOT = 'C:\coordination-sessions'
$env:TF_SESSION_NAME = $Name
trap {
	$_ | Out-String | Add-Content "$env:TF_SESSION_ROOT\$Name.log"
	exit 1
}
$env:TF_SESSION_MODE = $Mode
$env:TF_SESSION_CONTEXT = 'normal'
$env:TF_SESSION_SCOPE = if ($Scope.StartsWith('local:')) {
	Join-Path $env:LOCALAPPDATA ('tree-fucker-fixture-' + $Scope.Substring(6))
}
else { $Scope }
if ($Scope -eq 'mapped') {
	New-PSDrive -Name Z -PSProvider FileSystem -Root '\\localhost\CoordinationFixture' -Persist -Scope Global | Out-Null
	$env:TF_SESSION_SCOPE = 'Z:\scope'
}
if ($Mode -eq 'appcontainer') {
	$env:TF_SESSION_MODE = 'denied'
	$env:TF_SESSION_CONTEXT = 'appcontainer'
	Add-Type -Path C:\OEM\session-native.cs
	exit ([SessionNative]::RunContainer("$env:TF_SESSION_ROOT\$Name.log"))
}
# Native stderr must bypass PowerShell 5.1's terminating NativeCommandError.
$fixture = Start-Process -FilePath C:\OEM\coordination_power.exe -ArgumentList @('--exact', 'windows_sessions::interactive_session_fixture', '--ignored', '--nocapture') -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TF_SESSION_ROOT\$Name.log" -RedirectStandardError "$env:TF_SESSION_ROOT\$Name.stderr.log"
$result = $fixture.ExitCode
if ($Scope -eq 'mapped') { Remove-PSDrive -Name Z -Force }
exit $result
