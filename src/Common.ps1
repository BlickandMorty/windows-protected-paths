Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) { throw 'Run this command from an elevated PowerShell session.' }
}

function Get-ResolvedLiteralPath {
    param([Parameter(Mandatory)][string]$Path)
    (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\')
}

function Test-ReservedOrBroadPath {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $reserved = @(
        [IO.Path]::GetPathRoot($full).TrimEnd('\'),
        $env:SystemRoot.TrimEnd('\'),
        $env:ProgramFiles.TrimEnd('\'),
        ${env:ProgramFiles(x86)}.TrimEnd('\'),
        $env:ProgramData.TrimEnd('\'),
        $env:USERPROFILE.TrimEnd('\'),
        (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts')
    ) | Where-Object { $_ }
    if ($full -in $reserved) { return $true }
    if ($full -match '(?i)\\WindowsLockdownKit(?:\\|$)') { return $true }
    if ([IO.Path]::GetFileName($full) -match '^(?i:AGENTS\.md|PERMANENT-HARD-RULE\.md)$') { return $true }
    return $false
}

function Assert-SafeTarget {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-ReservedOrBroadPath $Path) { throw "Reserved or dangerously broad target refused: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Reparse-point targets are refused by default: $Path"
    }
}

function Get-Sha256Text {
    param([Parameter(Mandatory)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Set-SystemReadOnlyAcl {
    param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    & icacls.exe $item.FullName /setowner '*S-1-5-18' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set SYSTEM owner: $($item.FullName)" }
    $grants = if ($item.PSIsContainer) {
        @('*S-1-5-18:(OI)(CI)(F)', '*S-1-5-32-544:(OI)(CI)(RX)', '*S-1-5-32-545:(OI)(CI)(RX)')
    } else {
        @('*S-1-5-18:(F)', '*S-1-5-32-544:(RX)', '*S-1-5-32-545:(RX)')
    }
    & icacls.exe $item.FullName /inheritance:r /grant:r $grants /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set protected ACL: $($item.FullName)" }
}

function Write-JsonAtomic {
    param([string]$Path, $Value)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temp = Join-Path $parent ('.tmp-' + [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temp -Destination $Path -Force
    } finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
}

