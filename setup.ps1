# ==============================================================================
# setup.ps1 - BlueTeamAI PowerShell Setup & Runner Entry Point
# ==============================================================================
[CmdletBinding(PositionalBinding=$false)]
param(
    [string]$Scenario   = "",
    [switch]$NoWatch    = $false,
    [switch]$SkipAzure  = $true
)

$RootDir = $PSScriptRoot
$SetupScript = Join-Path $RootDir "setup\setup.ps1"

if (Test-Path $SetupScript) {
    & $SetupScript -Scenario $Scenario -NoWatch:$NoWatch -SkipAzure:$SkipAzure @args
} else {
    $BashArgs = @()
    if ($NoWatch) { $BashArgs += "--no-watch" }
    if ($Scenario) { $BashArgs += "--scenario", $Scenario }
    bash (Join-Path $RootDir "setup.sh") @BashArgs @args
}
