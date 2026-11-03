<#
.SYNOPSIS
    Clears the 24-hour event retention database (tools/db/events.db).

.DESCRIPTION
    Wipes all past captured events, resets SQLite sequences, vacuums the file to minimum size,
    and flushes the alert deduplication cache so future test runs start with a clean slate.

.EXAMPLE
    .\tools\db\clear_events.ps1
    .\tools\db\clear_events.ps1 -DeleteFile
#>

[CmdletBinding()]
param (
    [switch]$DeleteFile
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

$PyScript = Join-Path $ScriptDir "clear_events.py"
$ArgsList = @("$PyScript")
if ($DeleteFile) {
    $ArgsList += "--delete-file"
}

& $PythonExe @ArgsList

