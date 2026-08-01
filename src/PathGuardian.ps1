[CmdletBinding()]
param([Parameter(Mandatory)][string]$Root)

. (Join-Path $Root 'Common.ps1')
Assert-Administrator
$manifest = Get-Content -LiteralPath (Join-Path $Root 'manifest.json') -Raw | ConvertFrom-Json
$report = [Collections.Generic.List[object]]::new()

foreach ($entry in @($manifest.entries)) {
    $target = [string]$entry.target
    $state = 'Healthy'
    $detail = ''
    try {
        Assert-SafeTarget $target
        if ($entry.kind -eq 'File') {
            $actualHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -ne [string]$entry.initialSha256) {
                if ($entry.mode -eq 'SystemManaged' -and $entry.canonical) {
                    $canonical = Join-Path $Root ([string]$entry.canonical)
                    if ((Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$entry.initialSha256) {
                        throw 'Canonical copy hash mismatch.'
                    }
                    Copy-Item -LiteralPath $canonical -Destination $target -Force
                    $state = 'RepairedContent'
                } else {
                    $state = 'ContentDrift'
                }
            }
        }
        if ($entry.mode -in @('ReadOnlyForUser', 'SystemManaged')) {
            Set-SystemReadOnlyAcl -Path $target
        }
    }
    catch {
        $state = 'Error'
        $detail = $_.Exception.Message
    }
    $report.Add([pscustomobject]@{ target = $target; state = $state; detail = $detail })
}

$reportRoot = Join-Path $env:ProgramData 'ProtectedPaths-Reports'
New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
Write-JsonAtomic -Path (Join-Path $reportRoot ("$($manifest.setId)-latest.json")) -Value ([ordered]@{
    generatedAt = (Get-Date).ToString('o')
    setId = [string]$manifest.setId
    results = @($report)
})
if (@($report | Where-Object state -eq 'Error').Count) { exit 2 }

