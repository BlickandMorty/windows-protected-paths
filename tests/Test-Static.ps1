$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scripts = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.ps1' -File
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "$($script.Name): $($errors -join '; ')" }
}
. (Join-Path $root 'src\Common.ps1')
if (-not (Test-ReservedOrBroadPath $env:SystemRoot)) { throw 'Windows root safety test failed.' }
if (-not (Test-ReservedOrBroadPath (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'))) { throw 'Hosts safety test failed.' }
if (-not (Test-ReservedOrBroadPath 'C:\ProgramData\WindowsLockdownKit\Guardian')) { throw 'Permanent-boundary safety test failed.' }
Write-Host "Static checks passed for $($scripts.Count) scripts."

