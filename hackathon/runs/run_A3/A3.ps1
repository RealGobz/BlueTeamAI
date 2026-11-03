<#
.SYNOPSIS
    Simulates Scenario A3: Obfuscated PowerShell Execution (T1059.001 + T1027).
    Harmless simulation confined strictly to the local script folder.

.DESCRIPTION
    MITRE ATT&CK Techniques:
      - T1059.001: Command and Scripting Interpreter (PowerShell)
      - T1027:     Obfuscated Files or Information (Base64 Encoded Command)

    Scenario Mechanics:
      1. Hard Confinement Guard: Ensures execution only inside the dedicated 'run_a3' directory.
      2. Neutral Payload Creation: Drops a benign script (files\lib\update-check.ps1) that only
         writes a single timestamped status line to files\state\marker.txt and exits.
      3. Obfuscated Invocation: Constructs the invocation command, encodes it into UTF-16LE
         Base64, and launches a background PowerShell process using -EncodedCommand. The plaintext
         command never appears in the process command-line arguments.
      4. Live Process Inspection Window: The spawned PowerShell process idles (Start-Sleep)
         for a configurable duration so BlueTeamAI forensic tools can observe process tree,
         detect liveness, and test process termination response.
      5. Proof of Execution: Verifies and prints the marker file output and child PID.
      6. Containment & Cleanup: Confined 100% to .\files\. Offers optional cleanup on completion.

    SAFETY NOTICE:
      This script touches NO registry keys, NO %TEMP%, NO %APPDATA%, NO Startup folders,
      and makes NO network calls. Everything is strictly confined to .\files\.
#>

[CmdletBinding()]
param (
    [int]$KeepAliveSeconds = 300
)

# ==============================================================================
# SECTION 1: HARD CONFINEMENT GUARD
# ==============================================================================
$ScriptPath = $MyInvocation.MyCommand.Path
$Root = if ($ScriptPath) { Split-Path -Parent $ScriptPath } else { (Get-Location).Path }

# 1.1 Verify folder name is run_a3
$LeafName = (Split-Path -Leaf $Root).ToLower()
if ($LeafName -ne "run_a3") {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Current folder '$LeafName' does not end in 'run_a3'." -ForegroundColor Yellow
    Write-Host "    Path: $Root" -ForegroundColor Yellow
    exit 1
}

# 1.2 Verify path is within authorized project root or USERPROFILE
$NormRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$AllowedRoots = @(
    [System.IO.Path]::GetFullPath("F:\Projects\BlueTeamingAI\hackathon\runs\run_A3").TrimEnd('\', '/'),
    [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\', '/')
)

$IsAllowed = $false
foreach ($allowed in $AllowedRoots) {
    if ($NormRoot -eq $allowed -or $NormRoot.StartsWith("$allowed\")) {
        $IsAllowed = $true
        break
    }
}

if (-not $IsAllowed) {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    $NormRoot is not in an authorized project or profile location." -ForegroundColor Yellow
    exit 1
}

# 1.3 Ensure files subfolder can be created inside the script root
$FilesDir = Join-Path $Root "files"
try {
    if (-not (Test-Path $FilesDir)) {
        New-Item -ItemType Directory -Path $FilesDir -Force -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Failed to create 'files' subfolder: $_" -ForegroundColor Yellow
    exit 1
}

# ==============================================================================
# SECTION 2: NEUTRAL DIRECTORY & BENIGN PAYLOAD SETUP
# (No attack, malicious, A3, simulate, or BlueTeam in names under files\)
# ==============================================================================
$LibDir = Join-Path $FilesDir "lib"
$StateDir = Join-Path $FilesDir "state"

if (-not (Test-Path $LibDir))   { New-Item -ItemType Directory -Path $LibDir -Force | Out-Null }
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

$PayloadScript = Join-Path $LibDir "update-check.ps1"
$MarkerFile    = Join-Path $StateDir "marker.txt"

# Remove any stale marker file from prior test runs
if (Test-Path $MarkerFile) {
    Remove-Item -Path $MarkerFile -Force -ErrorAction SilentlyContinue
}

# Write benign payload: ONLY writes timestamp + marker line to marker.txt and exits
$PayloadBody = @"
`$UtcTimestamp = (Get-Date).ToUniversalTime().ToString("o")
`$MarkerEntry = "`$UtcTimestamp | harmless simulation marker"
Set-Content -Path '$MarkerFile' -Value `$MarkerEntry -Encoding utf8 -Force
exit 0
"@
Set-Content -Path $PayloadScript -Value $PayloadBody -Encoding utf8 -Force

# ==============================================================================
# SECTION 3: BASE64 OBFUSCATION (MITRE T1027)
# ==============================================================================
# The plaintext command that executes the local script and keeps the process alive
# Plaintext command structure:
# $ScriptPath = '<path>\files\lib\update-check.ps1'; & $ScriptPath; Start-Sleep -Seconds 300
$PlaintextCmd = "`$ScriptPath = '$PayloadScript'; & `$ScriptPath; Start-Sleep -Seconds $KeepAliveSeconds"

# Encode as UTF-16LE Base64 string for PowerShell's -EncodedCommand parameter
$UnicodeBytes = [System.Text.Encoding]::Unicode.GetBytes($PlaintextCmd)
$EncodedCmd = [System.Convert]::ToBase64String($UnicodeBytes)

# ==============================================================================
# SECTION 4: LAUNCH HIDDEN PROCESS (MITRE T1059.001)
# ==============================================================================
$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("o")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario A3: Encoded PowerShell Execution" -ForegroundColor Yellow
Write-Host " MITRE ATT&CK: T1059.001 (PowerShell) & T1027 (Obfuscation)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[1/4] Started at UTC: $StartTimeUtc" -ForegroundColor Gray
Write-Host "[*] Desktop Safety Constraint: Local file execution only (no network cradle)." -ForegroundColor DarkYellow
Write-Host "[*] Confinement Root: $Root" -ForegroundColor DarkGray
Write-Host "[*] Neutral Payload:  $PayloadScript" -ForegroundColor DarkGray
Write-Host "[*] Neutral Marker:   $MarkerFile" -ForegroundColor DarkGray

# Launch hidden background process with -EncodedCommand
Write-Host "`n[2/4] Spawning hidden PowerShell process via -EncodedCommand..." -ForegroundColor Yellow
$ProcessArgs = "-NoProfile -WindowStyle Hidden -EncodedCommand $EncodedCmd"

$Proc = Start-Process -FilePath "powershell.exe" -ArgumentList $ProcessArgs -PassThru

Write-Host "      Spawned Process ID:  $($Proc.Id)" -ForegroundColor Green
Write-Host "      Process Keep-Alive:  $KeepAliveSeconds seconds (for live agent forensic inspection)" -ForegroundColor DarkGray

# ==============================================================================
# SECTION 5: PROOF OF EXECUTION
# ==============================================================================
# Allow brief moment for child process to write marker before checking
Start-Sleep -Seconds 2

$MarkerExists = Test-Path $MarkerFile
$MarkerContent = if ($MarkerExists) { (Get-Content -Path $MarkerFile -Raw).Trim() } else { "(not found)" }

Write-Host "`n[3/4] Execution Verification:" -ForegroundColor Cyan
Write-Host "      UTC Start Time:      $StartTimeUtc" -ForegroundColor Gray
Write-Host "      Marker File Path:    $MarkerFile" -ForegroundColor Gray
Write-Host "      Marker File Exists:  $MarkerExists" -ForegroundColor $(if ($MarkerExists) { "Green" } else { "Red" })
Write-Host "      Marker Content:      $MarkerContent" -ForegroundColor Green
Write-Host "      Process Running:     $(-not $Proc.HasExited) (PID: $($Proc.Id))" -ForegroundColor Green

Write-Host "`n[4/4] Investigation Active. Observe detection in BlueTeamAI UI: http://127.0.0.1:8766" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# ==============================================================================
# SECTION 6: OPTIONAL CONTAINMENT CLEANUP
# ==============================================================================
Write-Host ""
$Cleanup = Read-Host "Do you want to clean up and delete the entire 'files' folder? (y/N)"
if ($Cleanup -match "^[Yy]$") {
    if ($Proc -and -not $Proc.HasExited) {
        Write-Host "[*] Stopping background test process (PID $($Proc.Id))..." -ForegroundColor Yellow
        Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $FilesDir) {
        Remove-Item -Path $FilesDir -Recurse -Force
        Write-Host "[+] Cleaned up $FilesDir successfully." -ForegroundColor Green
    }
} else {
    Write-Host "[*] Preserving $FilesDir for forensic review and telemetry recording." -ForegroundColor Yellow
}
