# ==============================================================================
# setup.ps1 - BlueTeamAI PowerShell Setup Script
# ==============================================================================
[CmdletBinding()]
param(
    [switch]$SkipAzure = $true
)

$RootDir = $PSScriptRoot
$SetupScript = Join-Path $RootDir "setup\setup.ps1"

if (Test-Path $SetupScript) {
    if ($SkipAzure) {
        & $SetupScript -SkipAzure
    } else {
        & $SetupScript
    }
} else {
    Write-Host "Running setup.sh via bash..." -ForegroundColor Yellow
    bash (Join-Path $RootDir "setup.sh")
}
