<#
.SYNOPSIS
    Simulates Scenario B3: False Positive Test - Developer Privileges & Token Discovery.
    Harmless simulation strictly confined to the local script directory.

.DESCRIPTION
    MITRE ATT&CK Technique:
      - T1033: System Owner/User Discovery
      - T1082: System Information Discovery

    Sigma Detection Rule Triggered:
      - proc_creation_win_whoami_priv_discovery.yml (HIGH)
      - Title: Security Privileges Enumeration Via Whoami.EXE
      - Trigger: whoami.exe executed with the '/priv' command-line flag.

    Why This Is A Benign False Positive:
      - Developers, build runners, and administrators routinely execute 'whoami /priv'
        during build pre-flight checks to determine whether their shell has elevated privileges
        (e.g., SeDebugPrivilege, SeImpersonatePrivilege, or UAC high integrity) before
        installing packages or compiling system drivers.
      - Although adversaries use this for post-exploitation privilege discovery, the action
        here is standalone, safe, and confined.
      - 'whoami.exe' is a genuine Microsoft-signed utility in System32.
      - 0 network connections, 0 persistence mechanisms, 0 memory injection, 0 dropped files.
      - Triagent should inspect the binary signature, process lineage, live network state,
        optionally ask the user ("Yes, I did this"), and correctly conclude 'false_positive'.

    SAFETY NOTICE:
      This script touches NO registry keys, NO %TEMP%, NO %APPDATA%, NO Startup folders,
      and makes NO network calls. It only inspects local token privilege flags.
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

# 1.1 Verify folder name is run_b3
$LeafName = (Split-Path -Leaf $Root).ToLower()
if ($LeafName -ne "run_b3") {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Current folder '$LeafName' does not end in 'run_b3'." -ForegroundColor Yellow
    Write-Host "    Path: $Root" -ForegroundColor Yellow
    exit 1
}

# 1.2 Verify path is within authorized project root or USERPROFILE
$NormRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$AllowedRoots = @(
    [System.IO.Path]::GetFullPath("F:\Projects\BlueTeamingAI\hackathon\runs\run_B3").TrimEnd('\', '/'),
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
# SECTION 2: TRIGGER BENIGN DEVELOPER PRE-FLIGHT PRIVILEGE CHECK
# ==============================================================================
$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("o")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario B3: Developer Privilege Check (Benign FP)" -ForegroundColor Yellow
Write-Host " Sigma Rule: proc_creation_win_whoami_priv_discovery.yml" -ForegroundColor Cyan
Write-Host " Expected Verdict: false_positive" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[1/2] Started at UTC: $StartTimeUtc" -ForegroundColor Gray
Write-Host "[*] Confinement Root: $Root" -ForegroundColor DarkGray

# Command that triggers the Sigma rule
$WhoamiPath = "$env:SystemRoot\System32\whoami.exe"
$Arguments = "/priv"

Write-Host "`n[2/2] Running developer privilege enumeration..." -ForegroundColor Yellow
Write-Host "      Command: $WhoamiPath $Arguments" -ForegroundColor Cyan

# Execute whoami.exe /priv
$Proc = Start-Process -FilePath $WhoamiPath -ArgumentList $Arguments -PassThru -NoNewWindow -Wait

Write-Host "`n[+] Execution completed with exit code $($Proc.ExitCode)." -ForegroundColor Green
Write-Host "[+] Detection rule 'Security Privileges Enumeration Via Whoami.EXE' should fire momentarily." -ForegroundColor Green
Write-Host "    Triagent should identify this as a benign false positive." -ForegroundColor Cyan
Write-Host "    Scripted human answer if asked: 'Yes, I did this.'" -ForegroundColor DarkYellow

