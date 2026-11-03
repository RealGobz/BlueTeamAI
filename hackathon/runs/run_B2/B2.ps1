<#
.SYNOPSIS
    Simulates Scenario B2: False Positive Test - Encoded Administrative PowerShell Command.
    Harmless simulation strictly confined to the local script directory.

.DESCRIPTION
    MITRE ATT&CK Technique:
      - T1059.001: PowerShell
      - T1027: Obfuscated Files or Information (Base64 Command Line)

    Sigma Detection Rules Triggered:
      - proc_creation_win_powershell_base64_encoded_cmd_patterns.yml (HIGH)
      - proc_creation_win_powershell_base64_encoded_cmd.yml (HIGH)
      - Trigger: PowerShell launched with '-enc' flag and a base64-encoded string starting with 'JAB'.

    Why This Is A Benign False Positive:
      - System administrators and IT tools frequently use base64 encoding (-enc / -EncodedCommand)
        to pass complex commands through CLI wrappers without quoting or escape issues.
      - The decoded command strictly executes:
          $status = 'System maintenance health check: all services normal'; Write-Host $status
      - 0 network connections, 0 dropped executables, 0 persistence, 0 credential access.
      - Triagent must inspect the command, decode the base64 payload, observe that it is a harmless
        status print, optionally ask the user ("Yes, I did this"), and correctly conclude 'false_positive'.

    SAFETY NOTICE:
      This script touches NO registry keys, NO %TEMP%, NO %APPDATA%, NO Startup folders,
      and makes NO network calls. Everything is strictly confined to .\run_b2\.
#>

[CmdletBinding()]
param (
    [switch]$KeepAlive
)

# ==============================================================================
# SECTION 1: HARD CONFINEMENT GUARD
# ==============================================================================
$ScriptPath = $MyInvocation.MyCommand.Path
$Root = if ($ScriptPath) { Split-Path -Parent $ScriptPath } else { (Get-Location).Path }

# 1.1 Verify folder name is run_b2
$LeafName = (Split-Path -Leaf $Root).ToLower()
if ($LeafName -ne "run_b2") {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Current folder '$LeafName' does not end in 'run_b2'." -ForegroundColor Yellow
    Write-Host "    Path: $Root" -ForegroundColor Yellow
    exit 1
}

# 1.2 Verify path is within authorized project root or USERPROFILE
$NormRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$AllowedRoots = @(
    [System.IO.Path]::GetFullPath("F:\Projects\BlueTeamingAI\hackathon\runs\run_B2").TrimEnd('\', '/'),
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
# SECTION 2: CONSTRUCT & ENCODE BENIGN IT MAINTENANCE COMMAND
# ==============================================================================
$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("o")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario B2: Encoded PowerShell Command (Benign FP)" -ForegroundColor Yellow
Write-Host " Sigma Rules: proc_creation_win_powershell_base64_encoded_cmd_patterns.yml" -ForegroundColor Cyan
Write-Host "              proc_creation_win_powershell_base64_encoded_cmd.yml" -ForegroundColor Cyan
Write-Host " Expected Verdict: false_positive" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[1/3] Started at UTC: $StartTimeUtc" -ForegroundColor Gray
Write-Host "[*] Confinement Root: $Root" -ForegroundColor DarkGray

# Benign administrative command
$ClearScript = "`$status = 'System maintenance health check: all services normal'; Write-Host `$status"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($ClearScript)
$EncodedCommand = [Convert]::ToBase64String($Bytes)

Write-Host "`n[2/3] Payload Preparation:" -ForegroundColor Yellow
Write-Host "      Plaintext:   $ClearScript" -ForegroundColor DarkGray
Write-Host "      Base64 Enc:  $EncodedCommand" -ForegroundColor DarkGray
Write-Host "      Prefix:      $($EncodedCommand.Substring(0, 4)) (matches Sigma pattern 'JAB')" -ForegroundColor Cyan

# ==============================================================================
# SECTION 3: SPAWN ENCODED POWERSHELL PROCESS
# ==============================================================================
Write-Host "`n[3/3] Executing encoded PowerShell process..." -ForegroundColor Yellow

$PowerShellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -enc $EncodedCommand"

# Execute as child process so Sysmon catches process creation
$Proc = Start-Process -FilePath $PowerShellPath -ArgumentList $Arguments -PassThru -NoNewWindow -Wait

Write-Host "`n[+] Execution completed with exit code $($Proc.ExitCode)." -ForegroundColor Green
Write-Host "[+] Detection rule 'Suspicious PowerShell Encoded Command Patterns' should fire momentarily." -ForegroundColor Green
Write-Host "    Triagent should identify this as a benign false positive." -ForegroundColor Cyan
Write-Host "    Scripted human answer if asked: 'Yes, I did this.'" -ForegroundColor DarkYellow

