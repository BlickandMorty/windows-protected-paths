[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$RecoveryPhrase,
    [switch]$Apply
)

. (Join-Path $PSScriptRoot 'Common.ps1')
$Root = [IO.Path]::GetFullPath($Root)
$manifest = Get-Content -LiteralPath (Join-Path $Root 'manifest.json') -Raw | ConvertFrom-Json
if ([bool]$manifest.permanentBoundary) { throw 'Permanent-boundary sets cannot be restored by this utility.' }
if ((Get-Sha256Text -Text $RecoveryPhrase) -ne [string]$manifest.recoverySha256) { throw 'Recovery phrase did not match.' }

foreach ($entry in @($manifest.entries)) {
    Assert-SafeTarget ([string]$entry.target)
    Write-Host "Would restore access: $($entry.target)"
}
if (-not $Apply) {
    Write-Host 'Audit only. Add -Apply after reviewing every target.'
    return
}

Assert-Administrator
if (-not $PSCmdlet.ShouldProcess($manifest.setId, 'Stop its guardian and restore recorded access')) { return }
$taskName = "ProtectedPaths $($manifest.setId)"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

foreach ($entry in @($manifest.entries)) {
    $target = [string]$entry.target
    & icacls.exe $target /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
    if ($entry.kind -eq 'Directory') {
        $acl = Get-Acl -LiteralPath $target
        $acl.SetSecurityDescriptorSddlForm([string]$entry.originalSddl)
        Set-Acl -LiteralPath $target -AclObject $acl
        & icacls.exe $target /reset /T /C /Q | Out-Null
    } else {
        $acl = Get-Acl -LiteralPath $target
        $acl.SetSecurityDescriptorSddlForm([string]$entry.originalSddl)
        Set-Acl -LiteralPath $target -AclObject $acl
    }
}
Write-Host 'Recorded access was restored for this ordinary ProtectedPaths set.'

