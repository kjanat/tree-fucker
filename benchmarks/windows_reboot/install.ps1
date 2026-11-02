$ErrorActionPreference = 'Stop'
. C:\OEM\accounts.ps1
foreach ($role in @('standard', 'admin')) {
	$account = $Accounts[$role]
	$password = ConvertTo-SecureString $account.Password -AsPlainText -Force
	$created = New-LocalUser -Name $account.Name -Password $password -PasswordNeverExpires
	if (!(Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object SID -EQ $created.SID)) {
		Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account.Name
	}
	Add-LocalGroupMember -SID 'S-1-5-32-555' -Member $account.Name
	if ($role -eq 'admin') { Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $account.Name }
}
# These changes apply only inside the disposable guest. The existing reboot
# phase activates UAC before the actual session/elevation acceptance begins.
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1
$terminalPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
New-Item -Path $terminalPolicy -Force | Out-Null
Set-ItemProperty $terminalPolicy -Name fSingleSessionPerUser -Value 0
& icacls.exe C:\OEM /grant '*S-1-15-2-1:RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot grant AppContainer traversal to its fixture executable' }
& icacls.exe C:\OEM\coordination_power.exe /grant '*S-1-15-2-1:RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot grant AppContainer fixture execute access' }
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\acceptance.ps1'
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 25) -StartWhenAvailable
Register-ScheduledTask -TaskName 'CoordinationRebootAcceptance' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force |
	Out-Null
Start-ScheduledTask -TaskName 'CoordinationRebootAcceptance'
