<#
.SYNOPSIS
    Simulates Scenario B1: False Positive Test - Program Compatibility Assistant (Pcalua) LOLBin Execution.
    Harmless simulation strictly confined to the local script directory.

.DESCRIPTION
    MITRE ATT&CK Technique:
      - T1059: Command and Scripting Interpreter
      - T1202: Indirect Command Execution (LOLBin: Pcalua)

    Sigma Detection Rule:
      - proc_creation_win_lolbin_pcalua.yml (Use of Pcalua For Execution - MEDIUM)
      - Matches: Image ends with '\pcalua.exe' AND CommandLine contains ' -a'

    Why This Is A Benign False Positive:
      - Pcalua.exe (Program Compatibility Assistant) is a legitimate Microsoft Windows binary.
      - Here it indirectly launches calc.exe (Windows Calculator).
      - Both pcalua.exe and calc.exe are valid Microsoft-signed binaries.
      - There are 0 network connections, 0 persistence mechanisms, 0 credential access, and 0 dropped malware.
      - Triagent should inspect the process tree, verify signatures, check network sockets, ask the user if needed ("Yes, I did this"), and correctly conclude 'false_positive'.

    SAFETY NOTICE:
      This script touches NO registry keys, NO %TEMP%, NO %APPDATA%, NO Startup folders,
      and makes NO network calls. It merely launches the built-in Windows Calculator via Pcalua.
#>

[CmdletBinding()]
param (
    [switch]$NoWait,
    [int]$AutoCloseSeconds = 0
)

# ==============================================================================
# SECTION 1: HARD CONFINEMENT GUARD
# ==============================================================================
$ScriptPath = $MyInvocation.MyCommand.Path
$Root = if ($ScriptPath) { Split-Path -Parent $ScriptPath } else { (Get-Location).Path }

# 1.1 Verify folder name is run_b1
$LeafName = (Split-Path -Leaf $Root).ToLower()
if ($LeafName -ne "run_b1") {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Current folder '$LeafName' does not end in 'run_b1'." -ForegroundColor Yellow
    Write-Host "    Path: $Root" -ForegroundColor Yellow
    exit 1
}

# 1.2 Verify path is within authorized project root or USERPROFILE
$NormRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$AllowedRoots = @(
    [System.IO.Path]::GetFullPath("F:\Projects\BlueTeamingAI\hackathon\runs\run_B1").TrimEnd('\', '/'),
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
# SECTION 2: TRIGGER BENIGN LOLBIN COMMAND
# ==============================================================================
$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("o")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario B1: Pcalua LOLBin Execution (Benign FP)" -ForegroundColor Yellow
Write-Host " Sigma Rule: proc_creation_win_lolbin_pcalua.yml" -ForegroundColor Cyan
Write-Host " Expected Verdict: false_positive" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[1/2] Started at UTC: $StartTimeUtc" -ForegroundColor Gray
Write-Host "[*] Confinement Root: $Root" -ForegroundColor DarkGray

# The exact command triggering the Sigma rule:
# proc_creation_win_lolbin_pcalua.yml triggers when Image is pcalua.exe and CommandLine contains ' -a'
$PcaluaPath = Join-Path $env:SystemRoot "System32\pcalua.exe"
$TargetApp = "calc.exe"

Write-Host "`n[2/2] Launching benign target via Pcalua..." -ForegroundColor Yellow
Write-Host "      Command: $PcaluaPath -a $TargetApp" -ForegroundColor Cyan

# Execute pcalua with -a flag to trigger the rule
$Proc = Start-Process -FilePath $PcaluaPath -ArgumentList "-a $TargetApp" -PassThru

$PcaluaPid = $Proc.Id
Write-Host "      Pcalua Process ID:        $PcaluaPid" -ForegroundColor Green

# Brief pause to allow process creation event to record in Sysmon
Start-Sleep -Seconds 2

# Check if Calculator is running
$CalcProc = Get-Process -Name "CalculatorApp", "win32calc", "calc" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($CalcProc) {
    Write-Host "      Child Process (calc):     PID $($CalcProc.Id) ($($CalcProc.ProcessName))" -ForegroundColor Green
} else {
    Write-Host "      Child Process:            Spawned" -ForegroundColor DarkGray
}

Write-Host "`n[+] Trigger complete. Detection rule 'Use of Pcalua For Execution' should fire momentarily." -ForegroundColor Green
Write-Host "    Triagent should identify this as a benign false positive." -ForegroundColor Cyan
Write-Host "    Scripted human answer if asked: 'Yes, I did this.'" -ForegroundColor DarkYellow

if ($AutoCloseSeconds -gt 0) {
    Write-Host "`n[*] Auto-closing calculator in $AutoCloseSeconds seconds..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $AutoCloseSeconds
    Get-Process -Name "CalculatorApp", "win32calc", "calc" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Calculator closed." -ForegroundColor DarkGray
}

