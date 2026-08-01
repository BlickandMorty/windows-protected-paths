[CmdletBinding()]
param(
    [ValidateSet('IntegrityOnly', 'ReadOnlyForUser', 'SystemManaged')][string]$Mode = 'SystemManaged'
)

Add-Type -AssemblyName System.Windows.Forms
$choice = [Windows.Forms.MessageBox]::Show(
    'Choose Yes for one or more files/ZIPs, No for one folder, or Cancel to exit.',
    'Windows Protected Paths',
    [Windows.Forms.MessageBoxButtons]::YesNoCancel,
    [Windows.Forms.MessageBoxIcon]::Information
)
if ($choice -eq [Windows.Forms.DialogResult]::Cancel) { return }

$paths = @()
if ($choice -eq [Windows.Forms.DialogResult]::Yes) {
    $dialog = [Windows.Forms.OpenFileDialog]::new()
    $dialog.Multiselect = $true
    $dialog.Title = 'Select files or ZIP archives to protect'
    $dialog.Filter = 'All files (*.*)|*.*|ZIP archives (*.zip)|*.zip'
    if ($dialog.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { return }
    $paths = @($dialog.FileNames)
} else {
    $dialog = [Windows.Forms.FolderBrowserDialog]::new()
    $dialog.Description = 'Select one folder to protect'
    $dialog.ShowNewFolderButton = $false
    if ($dialog.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { return }
    $paths = @($dialog.SelectedPath)
}

$installer = Join-Path $PSScriptRoot 'Install-PathGuardian.ps1'
$quoted = @($paths | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ', '
$command = "& '$installer' -Path @($quoted) -Mode $Mode"
Set-Clipboard -Value $command
[Windows.Forms.MessageBox]::Show(
    "An audit command was copied to the clipboard. Paste it into PowerShell. It will create a plan and make no changes until you add -Apply and the required acknowledgement.`r`n`r`n$command",
    'Audit command copied',
    [Windows.Forms.MessageBoxButtons]::OK,
    [Windows.Forms.MessageBoxIcon]::Information
) | Out-Null

