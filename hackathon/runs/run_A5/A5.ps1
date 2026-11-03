<#
.SYNOPSIS
    Simulates Scenario A5: Inhibiting System Recovery via Shadow Copies Deletion (MITRE T1490).
    Harmless simulation strictly confined to the local script directory.

.DESCRIPTION
    MITRE ATT&CK Technique:
      - T1490: Inhibit System Recovery (Volume Shadow Copy Deletion)

    Scenario Mechanics:
      1. Hard Confinement Guard: Ensures execution only inside the dedicated 'run_a5' directory.
      2. Neutral Worker Setup: Drops a benign worker script (files\lib\backup-cleaner.ps1)
         that writes a harmless timestamp marker to files\state\marker.txt and idles.
      3. Live Worker Process: Spawns a background worker process (powershell.exe) running the script
         that remains active for $KeepAliveSeconds so BlueTeamAI can inspect process trees,
         verify process presence, and test remediation.
      4. Safe OS Utility Invocation: Executes Windows built-in vssadmin.exe with shadow deletion parameters:
           vssadmin.exe delete shadows /for=C: /shadow={00000000-0000-0000-0000-000000000000} /quiet
         This command triggers Sigma rule proc_creation_win_susp_shadow_copies_deletion.yml while
         targeting a non-existent GUID, safely guaranteeing ZERO actual shadow copies or user backups are deleted.
      5. Proof of Execution: Displays the command line, worker process ID, and verification status.
      6. Containment & Cleanup: Confined 100% to .\files\. Offers optional interactive cleanup on completion.

    SAFETY NOTICE:
      This script touches NO registry keys, NO %TEMP%, NO %APPDATA%, NO Startup folders,
      and makes NO network calls. It deletes NO legitimate volume shadow copies, backups,
      or system restore points. Everything is strictly confined to .\files\.
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

# 1.1 Verify folder name is run_a5
$LeafName = (Split-Path -Leaf $Root).ToLower()
if ($LeafName -ne "run_a5") {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Current folder '$LeafName' does not end in 'run_a5'." -ForegroundColor Yellow
    Write-Host "    Path: $Root" -ForegroundColor Yellow
    exit 1
}

# 1.2 Verify path is within authorized project root or USERPROFILE
$NormRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$AllowedRoots = @(
    [System.IO.Path]::GetFullPath("F:\Projects\BlueTeamingAI\hackathon\runs\run_A5").TrimEnd('\', '/'),
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
# SECTION 2: NEUTRAL DIRECTORY & BENIGN WORKER SETUP
# (No attack, malicious, A5, simulate, or BlueTeam in names under files\)
# ==============================================================================
$LibDir = Join-Path $FilesDir "lib"
$StateDir = Join-Path $FilesDir "state"

if (-not (Test-Path $LibDir))   { New-Item -ItemType Directory -Path $LibDir -Force | Out-Null }
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

$WorkerScript = Join-Path $LibDir "backup-cleaner.ps1"
$MarkerFile   = Join-Path $StateDir "marker.txt"

# Remove any stale marker file from prior test runs
if (Test-Path $MarkerFile) {
    Remove-Item -Path $MarkerFile -Force -ErrorAction SilentlyContinue
}

# Write benign worker script: writes a harmless timestamp marker and sleeps
$WorkerContent = @"
param([int]`$KeepAlive = 300)
`$StartTime = (Get-Date).ToUniversalTime().ToString("o")
`$MarkerEntry = "`$StartTime | harmless simulation worker active"
Set-Content -Path '$MarkerFile' -Value `$MarkerEntry -Encoding utf8 -Force
Start-Sleep -Seconds `$KeepAlive
exit 0
"@
Set-Content -Path $WorkerScript -Value $WorkerContent -Encoding utf8 -Force

# ==============================================================================
# SECTION 3: SPAWN WORKER PROCESS
# ==============================================================================
$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("o")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario A5: Shadow Copies Deletion (T1490)" -ForegroundColor Yellow
Write-Host " MITRE ATT&CK: T1490 (Inhibit System Recovery: Volume Shadow Copy)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[1/4] Started at UTC: $StartTimeUtc" -ForegroundColor Gray
Write-Host "[*] Desktop Safety Constraint: Targets non-existent GUID (no real backups deleted)." -ForegroundColor DarkYellow
Write-Host "[*] Confinement Root: $Root" -ForegroundColor DarkGray
Write-Host "[*] Neutral Worker:   $WorkerScript" -ForegroundColor DarkGray
Write-Host "[*] Neutral Marker:   $MarkerFile" -ForegroundColor DarkGray

# Spawn harmless background worker process
Write-Host "`n[2/4] Spawning background worker process..." -ForegroundColor Yellow
$WorkerProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -File `"$WorkerScript`" -KeepAlive $KeepAliveSeconds" -PassThru
$WorkerPid = $WorkerProc.Id
Write-Host "      Spawned Worker PID:       $WorkerPid" -ForegroundColor Green
Write-Host "      Worker Keep-Alive:        $KeepAliveSeconds seconds" -ForegroundColor DarkGray

# Give process brief moment to initialize
Start-Sleep -Seconds 1

# ==============================================================================
# SECTION 4: EXECUTE VSSADMIN SHADOW DELETION (MITRE T1490)
# ==============================================================================
Write-Host "`n[3/4] Executing harmless vssadmin shadow deletion command..." -ForegroundColor Yellow

$VssArgs = "delete shadows /for=C: /shadow={00000000-0000-0000-0000-000000000000} /quiet"
Write-Host "      Command: vssadmin.exe $VssArgs" -ForegroundColor DarkCyan

# Execute vssadmin.exe with shadow deletion parameters to trigger Sigma detection
$VssProc = Start-Process -FilePath "vssadmin.exe" -ArgumentList $VssArgs -PassThru -Wait

Write-Host "      vssadmin execution completed (ExitCode: $($VssProc.ExitCode))." -ForegroundColor Green

# ==============================================================================
# SECTION 5: PROOF OF EXECUTION
# ==============================================================================
$MarkerExists = Test-Path $MarkerFile
$MarkerContent = if ($MarkerExists) { (Get-Content -Path $MarkerFile -Raw).Trim() } else { "(not found)" }

Write-Host "`n[4/4] Execution Verification:" -ForegroundColor Cyan
Write-Host "      UTC Start Time:      $StartTimeUtc" -ForegroundColor Gray
Write-Host "      Worker Process PID:  $WorkerPid" -ForegroundColor Gray
Write-Host "      Worker Still Alive:  $(-not $WorkerProc.HasExited)" -ForegroundColor Green
Write-Host "      Marker File Path:    $MarkerFile" -ForegroundColor Gray
Write-Host "      Marker File Exists:  $MarkerExists" -ForegroundColor $(if ($MarkerExists) { "Green" } else { "Yellow" })
Write-Host "      Marker Content:      $MarkerContent" -ForegroundColor Green
Write-Host "      Target Shadow GUID:  {00000000-0000-0000-0000-000000000000} (harmless mock)" -ForegroundColor DarkGray
Write-Host "      Sigma Detection:     proc_creation_win_susp_shadow_copies_deletion.yml" -ForegroundColor Green

Write-Host "`nInvestigation Active. Observe detection in BlueTeamAI UI: http://127.0.0.1:8766" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# ==============================================================================
# SECTION 6: OPTIONAL CONTAINMENT CLEANUP
# ==============================================================================
Write-Host ""
$Cleanup = Read-Host "Do you want to clean up and delete the entire 'files' folder? (y/N)"
if ($Cleanup -match "^[Yy]$") {
    if ($WorkerProc -and -not $WorkerProc.HasExited) {
        Write-Host "[*] Stopping background worker process (PID $($WorkerProc.Id))..." -ForegroundColor Yellow
        Stop-Process -Id $WorkerProc.Id -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $FilesDir) {
        Remove-Item -Path $FilesDir -Recurse -Force
        Write-Host "[+] Cleaned up $FilesDir successfully." -ForegroundColor Green
    }
} else {
    Write-Host "[*] Preserving $FilesDir for forensic review and telemetry recording." -ForegroundColor Yellow
}
