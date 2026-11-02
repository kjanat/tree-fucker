$ErrorActionPreference = 'Stop'
$root = 'C:\coordination-sessions'
New-Item -ItemType Directory -Path $root -Force | Out-Null
& icacls.exe $root /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot grant disposable users fixture report access' }
& icacls.exe $root /grant '*S-1-15-2-1:(OI)(CI)M' /setintegritylevel '(OI)(CI)L' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot grant the AppContainer access to its report directory' }
Add-Type -Path C:\OEM\session-native.cs
$gateway = (Get-Content C:\OEM\controller.txt -Raw).Trim()
$workers = [System.Collections.Generic.List[System.IDisposable]]::new()
$evidence = @{}

function New-FixtureVolume([string]$Name, [string]$Letter, [string]$Filesystem, [bool]$ReadOnly) {
	if (Test-Path "${Letter}:\") { throw "Fixture drive $Letter is already occupied" }
	$disk = "$root\$Name.vhdx"
	if (Test-Path $disk) { throw 'Volume fixture requires a fresh guest' }
	$commands = @(
		"create vdisk file=`"$disk`" maximum=128 type=expandable",
		"select vdisk file=`"$disk`"", 'attach vdisk', 'create partition primary',
		"format fs=$Filesystem quick", "assign letter=$Letter"
	)
	if ($ReadOnly) { $commands += 'attributes disk set readonly' }
	$commands | Set-Content "$root\$Name.diskpart"
	& diskpart.exe /s "$root\$Name.diskpart" *> "$root\$Name.log"
	if ($LASTEXITCODE -ne 0) { throw "Creating $Name volume failed" }
	$volume = Get-Volume -DriveLetter $Letter
	if ($volume.FileSystem -ne $Filesystem) { throw "Wrong filesystem for $Name" }
	if ($ReadOnly -and !(Get-Partition -DriveLetter $Letter | Get-Disk).IsReadOnly) { throw 'Read-only fixture is writable' }
}

function Assert-True([bool]$Condition, [string]$Message) {
	if (!$Condition) { throw $Message }
}
function Connect-User([string]$Role, [int]$Count) {
	Invoke-RestMethod -Uri "http://${gateway}:8765/rdp" -Method Post -ContentType 'application/json' -Body (@{ role = $Role; count = $Count } | ConvertTo-Json) |
		Out-Null
}
function Wait-Sessions([string]$User, [int]$Count) {
	$deadline = [DateTime]::UtcNow.AddMinutes(3)
	do {
		$found = @([SessionNative]::Sessions() | Where-Object User -EQ $User)
		if ($found.Count -eq $Count) { return $found }
		Start-Sleep -Milliseconds 200
	} while ([DateTime]::UtcNow -lt $deadline)
	throw "Expected $Count actual interactive sessions for $User"
}
function Start-Fixture([int]$Session, [bool]$Elevated, [string]$Name, [string]$Mode, [string]$Scope = 'discover') {
	$worker = [SessionNative]::Launch($Session, $Elevated, $Name, $Mode, $Scope)
	$workers.Add($worker)
	$deadline = [DateTime]::UtcNow.AddMinutes(2)
	while (!(Test-Path "$root\$Name.ready")) {
		if (!$worker.Running -and !(Test-Path "$root\$Name.ready")) { throw "Fixture $Name exited before readiness; see $root\$Name.log" }
		Assert-True ([DateTime]::UtcNow -lt $deadline) "Fixture $Name never became ready; see $root\$Name.log"
		Start-Sleep -Milliseconds 50
	}
	if (Test-Path "$root\$Name.report") {
		$report = @{}
		foreach ($line in Get-Content "$root\$Name.report") {
			$pair = $line.Split('=', 2)
			Assert-True ($pair.Count -eq 2) 'Invalid session report'
			$report[$pair[0]] = $pair[1]
		}
		$evidence[$Name] = $report
	}
	return $worker
}
function Finish-Fixture($Worker, [string]$Name) {
	New-Item -ItemType File -Path "$root\$Name.release" -Force | Out-Null
	Assert-True ($Worker.Wait() -eq 0) "Fixture $Name failed"
}
function Observe([int]$Session, [string]$Name, [string]$Scope = 'discover') {
	$worker = Start-Fixture $Session $false $Name 'observe' $Scope
	Assert-True ($worker.Wait() -eq 0) "Observer $Name failed"
	return $evidence[$Name]
}

try {
	New-FixtureVolume 'fat-volume' 'T' 'FAT32' $false
	New-FixtureVolume 'readonly-volume' 'U' 'NTFS' $true
	New-Item -ItemType Directory -Path "$root\remote" | Out-Null
	$everyone = ([System.Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([System.Security.Principal.NTAccount]).Value
	New-SmbShare -Name 'CoordinationFixture' -Path "$root\remote" -FullAccess $everyone | Out-Null
	Connect-User 'standard' 2
	$sessions = @(Wait-Sessions 'CoordinationUser' 2)
	$first = Start-Fixture $sessions[0].Id $false 'user-first' 'hold'
	$second = Start-Fixture $sessions[1].Id $false 'user-second' 'hold'
	$a = $evidence['user-first']; $b = $evidence['user-second']
	Assert-True ($a.session -ne $b.session -and $a.logon -ne $b.logon) 'Need distinct actual sessions and logons'
	Assert-True ($a.elevated -eq '0' -and $b.elevated -eq '0') 'Standard-user fixtures must not be elevated'
	Assert-True ($a.user -eq $b.user -and $a.generation -eq $b.generation -and $a.path -eq $b.path) 'Same user sessions split their discovered authority'
	$probe = Start-Fixture $sessions[0].Id $false 'user-full' 'probe'
	Assert-True ($probe.Wait() -eq 0 -and $evidence['user-full'].physical -eq '2') 'Cross-session physical ceiling failed'
	[SessionNative]::Logoff($sessions[0].Id)
	$first.Wait() | Out-Null
	$recovered = Observe $sessions[1].Id 'user-recovered'
	Assert-True ($recovered.physical -eq '1' -and $recovered.generation -eq $a.generation) 'Logoff released the wrong owner or reset the authority'
	Assert-True ([decimal]$recovered.charged -ge [decimal]$b.charged -and [decimal]$recovered.surcharged -eq 1000000) 'Logoff lost debt or charged failure more than once'
	Connect-User 'standard' 1
	$current = @(Wait-Sessions 'CoordinationUser' 2)
	$new = @($current | Where-Object Id -NE $sessions[1].Id)[0]
	$rejoined = Observe $new.Id 'user-new-logon'
	Assert-True ($rejoined.logon -ne $a.logon -and $rejoined.generation -eq $a.generation) 'New logon did not retain the old authority'
	Assert-True ([decimal]$rejoined.charged -ge [decimal]$recovered.charged -and $rejoined.surcharged -eq $recovered.surcharged) 'New logon reset debt or repeated recovery'
	$third = Start-Fixture $new.Id $false 'user-third' 'hold'
	Finish-Fixture $second 'user-second'
	Finish-Fixture $third 'user-third'
	$closed = Observe $new.Id 'user-closed'
	$reopened = Observe $new.Id 'user-reopened'
	Assert-True ($closed.physical -eq '0' -and $reopened.physical -eq '0' -and $closed.charged -eq $reopened.charged -and $closed.surcharged -eq $reopened.surcharged) 'Final participant close changed retained accounting'
	$container = Start-Fixture $new.Id $false 'appcontainer' 'appcontainer'
	Assert-True ($container.Wait() -eq 0 -and $evidence['appcontainer'].appcontainer -eq '1') 'AppContainer must explicitly fall back or error before joining'
	foreach ($storage in @(@('fat-storage', 'T:\scope'), @('readonly-storage', 'U:\scope'), @('remote-storage', 'mapped'))) {
		$deniedStorage = Start-Fixture $new.Id $false $storage[0] 'denied' $storage[1]
		Assert-True ($deniedStorage.Wait() -eq 0) "Unsupported storage $($storage[0]) did not produce the documented outcome"
	}
	foreach ($session in $current) { [SessionNative]::Logoff($session.Id) }

	Connect-User 'admin' 1
	$admin = @(Wait-Sessions 'CoordinationAdmin' 1)[0]
	$other = Observe $admin.Id 'other-principal'
	Assert-True ($other.user -ne $a.user -and $other.path -ne $a.path) 'Different principals shared an authority'
	$denied = Start-Fixture $admin.Id $false 'foreign-authority' 'denied' $a.path
	Assert-True ($denied.Wait() -eq 0) 'Another principal improperly opened private authority storage'
	foreach ($elevatedFirst in @($true, $false)) {
		$prefix = if ($elevatedFirst) { 'high-first' } else { 'medium-first' }
		$scope = "local:$prefix"
		$one = Start-Fixture $admin.Id $elevatedFirst "$prefix-one" 'hold' $scope
		$two = Start-Fixture $admin.Id (!$elevatedFirst) "$prefix-two" 'hold' $scope
		$high = $evidence["$prefix-one"]; $low = $evidence["$prefix-two"]
		Assert-True ($high.elevated -ne $low.elevated -and $high.user -eq $low.user -and $high.generation -eq $low.generation) 'UAC tokens did not share one authority in both creation orders'
		$probe = Start-Fixture $admin.Id $false "$prefix-full" 'probe' $scope
		Assert-True ($probe.Wait() -eq 0 -and $evidence["$prefix-full"].physical -eq '2') 'UAC physical ceiling split'
		Finish-Fixture $one "$prefix-one"
		Finish-Fixture $two "$prefix-two"
		$last = Observe $admin.Id "$prefix-closed" $scope
		Assert-True ($last.physical -eq '0' -and [decimal]$last.charged -gt 0) 'UAC completion lost accounting'
	}
	[SessionNative]::Logoff($admin.Id)
	$evidence | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 "$root\evidence.json"
	return @{ status = 'passed'; histories = $evidence }
}
finally {
	foreach ($worker in $workers) { $worker.Dispose() }
}
