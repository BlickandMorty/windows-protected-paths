[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string[]]$Path,
    [ValidateSet('IntegrityOnly', 'ReadOnlyForUser', 'SystemManaged')][string]$Mode = 'IntegrityOnly',
    [string]$Root,
    [switch]$Apply,
    [string]$Acknowledgement,
    [string]$RecoveryPhrase
)

. (Join-Path $PSScriptRoot 'Common.ps1')

$resolved = @($Path | ForEach-Object { Get-ResolvedLiteralPath $_ } | Sort-Object -Unique)
foreach ($target in $resolved) { Assert-SafeTarget $target }
if (-not $Root) {
    $setId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $Root = Join-Path $env:ProgramData "ProtectedPaths\$setId"
}
$Root = [IO.Path]::GetFullPath($Root)
if ($Root -match '(?i)\\WindowsLockdownKit(?:\\|$)') { throw 'The permanent lockdown root is reserved.' }

$entries = foreach ($target in $resolved) {
    $item = Get-Item -LiteralPath $target -Force
    $acl = Get-Acl -LiteralPath $target
    [ordered]@{
        target = $item.FullName
        kind = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
        mode = $Mode
        bytes = if ($item.PSIsContainer) { $null } else { $item.Length }
        originalSddl = $acl.Sddl
        initialSha256 = if ($item.PSIsContainer) { $null } else { (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        canonical = $null
    }
}

$planRoot = Join-Path $env:TEMP 'ProtectedPaths-Plans'
New-Item -ItemType Directory -Path $planRoot -Force | Out-Null
$planPath = Join-Path $planRoot ("plan-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$plan = [ordered]@{
    generatedAt = (Get-Date).ToString('o')
    mode = $Mode
    root = $Root
    applyRequested = [bool]$Apply
    administrator = Test-IsAdministrator
    warning = 'Administrators can ultimately take ownership. SYSTEM-managed is strong friction, not mathematical irreversibility.'
    entries = @($entries)
}
Write-JsonAtomic -Path $planPath -Value $plan

if (-not $Apply) {
    Write-Host 'Audit complete. No permissions were changed.'
    Write-Host "Plan: $planPath"
    return
}

Assert-Administrator
if ($Acknowledgement -cne 'PROTECT THESE PATHS') { throw "Apply requires -Acknowledgement 'PROTECT THESE PATHS'" }
if (-not $PSCmdlet.ShouldProcess(($resolved -join ', '), "Apply $Mode protection")) { return }

if (-not $RecoveryPhrase) {
    $bytes = [byte[]]::new(24)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $RecoveryPhrase = [Convert]::ToBase64String($bytes).TrimEnd('=')
}
$recoveryHash = Get-Sha256Text -Text $RecoveryPhrase

$canonicalRoot = Join-Path $Root 'Canonical'
New-Item -ItemType Directory -Path $canonicalRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Common.ps1') -Destination (Join-Path $Root 'Common.ps1') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'PathGuardian.ps1') -Destination (Join-Path $Root 'PathGuardian.ps1') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Restore-PathAccess.ps1') -Destination (Join-Path $Root 'Restore-PathAccess.ps1') -Force

for ($index = 0; $index -lt $entries.Count; $index++) {
    if ($entries[$index].kind -eq 'File' -and $Mode -eq 'SystemManaged') {
        $canonicalName = '{0:D4}-{1}' -f $index, [IO.Path]::GetFileName($entries[$index].target)
        $canonicalPath = Join-Path $canonicalRoot $canonicalName
        Copy-Item -LiteralPath $entries[$index].target -Destination $canonicalPath -Force
        $entries[$index].canonical = "Canonical\$canonicalName"
    }
}

$manifest = [ordered]@{
    schemaVersion = 1
    createdAt = (Get-Date).ToString('o')
    setId = Split-Path -Leaf $Root
    recoverySha256 = $recoveryHash
    permanentBoundary = $false
    entries = @($entries)
}
Write-JsonAtomic -Path (Join-Path $Root 'manifest.json') -Value $manifest

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'PathGuardian.ps1') -Root $Root
if ($LASTEXITCODE -ne 0) { throw "Initial guardian pass failed: $LASTEXITCODE" }

$taskName = "ProtectedPaths $($manifest.setId)"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Root "{1}"' -f
    (Join-Path $Root 'PathGuardian.ps1'), $Root
)
$trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Set-SystemReadOnlyAcl -Path $Root

Write-Host 'Protection applied.'
Write-Host "Guardian root: $Root"
Write-Host "Task: $taskName"
Write-Warning "RECOVERY PHRASE (store with a trusted person): $RecoveryPhrase"

