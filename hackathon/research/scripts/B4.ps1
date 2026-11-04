<#
.SYNOPSIS
    Simulates Scenario B4: False Positive Test - Benign Software Updater Scheduled Task Creation.
    Harmless simulation strictly confined to the local script directory.

.DESCRIPTION
    MITRE ATT&CK Technique:
      - T1053.005: Scheduled Task/Job: Scheduled Task
      - T1543: Create or Modify System Process

    Sigma Detection Rule Triggered:
      - proc_creation_win_schtasks_schedule_type.yml (HIGH)
      - Title: Suspicious Schtasks Schedule Types
      - Trigger: schtasks.exe executed with a suspicious one-off schedule type (' ONCE ').

    Why This Is A Benign False Positive:
      - Software installers, update assistants, and system utilities frequently schedule
        a delayed or one-time maintenance check (e.g., checking for updates or cleaning up installers)
        using built-in schtasks.exe with the '/sc ONCE' schedule.
      - Although adversaries use scheduled tasks for persistence and lateral execution,
        the target here is a benign Microsoft-signed binary (notepad.exe).
      - Zero network calls, zero credential access, zero payload downloads.
      - The script automatically deletes the task immediately after execution, leaving 0 persistence.
      - Triagent should inspect the scheduled binary path and signature, verify lack of malicious
        network or process behavior, ask the user ("Yes, I did this"), and correctly conclude 'false_positive'.

    SAFETY NOTICE:
      This script touches NO registry keys, NO %APPDATA%, NO Startup folders,
      and makes NO network calls. The scheduled task is automatically deleted upon test completion.
#>

[CmdletBinding()]
param (
    [int]$TaskRetentionSeconds = 5
)

# ==============================================================================
# SECTION 1: HARD CONFINEMENT GUARD
# ==============================================================================
$ScriptPath = $MyInvocation.MyCommand.Path
$Root = if ($ScriptPath) { Split-Path -Parent $ScriptPath } else { (Get-Location).Path }

# 1.1 Verify folder name is run_b4
$LeafName = (Split-Path -Leaf $Root).ToLower()
if ($LeafName -ne "run_b4") {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Current folder '$LeafName' does not end in 'run_b4'." -ForegroundColor Yellow
    Write-Host "    Path: $Root" -ForegroundColor Yellow
    exit 1
}

# 1.2 Verify path is within authorized project root or USERPROFILE
$NormRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$AllowedRoots = @(
    [System.IO.Path]::GetFullPath("F:\Projects\BlueTeamingAI\hackathon\runs\run_B4").TrimEnd('\', '/'),
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
    Write-Host "    Path is outside authorized workspace root." -ForegroundColor Yellow
    Write-Host "    Path: $NormRoot" -ForegroundColor Yellow
    exit 1
}

# ==============================================================================
# SECTION 2: TRIGGER BENIGN SCHEDULED TASK CREATION
# ==============================================================================
$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
$TaskName = "B4_AppUpdater"
$TargetBinary = "$env:SystemRoot\System32\notepad.exe"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario B4: Benign Scheduled Task (Benign FP)" -ForegroundColor Yellow
Write-Host " Sigma Rule: proc_creation_win_schtasks_schedule_type.yml" -ForegroundColor Cyan
Write-Host " Expected Verdict: false_positive" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[1/3] Started at UTC: $StartTimeUtc" -ForegroundColor Gray
Write-Host "[*] Confinement Root: $Root" -ForegroundColor DarkGray
Write-Host "[*] Task Name:        $TaskName" -ForegroundColor DarkGray
Write-Host "[*] Target Binary:    $TargetBinary" -ForegroundColor DarkGray

# Command that triggers the Sigma rule:
# proc_creation_win_schtasks_schedule_type.yml triggers on CommandLine containing ' ONCE '
$SchtasksPath = "$env:SystemRoot\System32\schtasks.exe"
$CreateArgs = "/create /tn `"$TaskName`" /tr `"$TargetBinary`" /sc ONCE /st 23:59 /f"

Write-Host "`n[2/3] Creating one-time scheduled maintenance task..." -ForegroundColor Yellow
Write-Host "      Command: $SchtasksPath $CreateArgs" -ForegroundColor Cyan

$Proc = Start-Process -FilePath $SchtasksPath -ArgumentList $CreateArgs -PassThru -NoNewWindow -Wait

Write-Host "`n[+] Creation completed with exit code $($Proc.ExitCode)." -ForegroundColor Green
Write-Host "[+] Detection rule 'Suspicious Schtasks Schedule Types' should fire momentarily." -ForegroundColor Green
Write-Host "    Triagent should identify this as a benign false positive." -ForegroundColor Cyan
Write-Host "    Scripted human answer if asked: 'Yes, I did this.'" -ForegroundColor DarkYellow

# ==============================================================================
# SECTION 3: AUTOMATIC CLEANUP (LEAVE ZERO PERSISTENCE)
# ==============================================================================
Write-Host "`n[3/3] Preserving task for $TaskRetentionSeconds seconds for detection telemetry..." -ForegroundColor DarkGray
Start-Sleep -Seconds $TaskRetentionSeconds

Write-Host "[*] Cleaning up scheduled task '$TaskName' to leave zero persistence..." -ForegroundColor Yellow
$DeleteArgs = "/delete /tn `"$TaskName`" /f"
$DelProc = Start-Process -FilePath $SchtasksPath -ArgumentList $DeleteArgs -PassThru -NoNewWindow -Wait

if ($DelProc.ExitCode -eq 0) {
    Write-Host "[+] Scheduled task successfully removed. Desktop remains 100% clean." -ForegroundColor Green
} else {
    Write-Host "[-] Note: Task cleanup returned exit code $($DelProc.ExitCode)." -ForegroundColor DarkGray
}

