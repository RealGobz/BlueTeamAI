<#
.SYNOPSIS
    Simulates Scenario B5: False Positive Test - Startup & Shell Folders Registry Configuration.
    Harmless simulation strictly confined to the local script directory.

.DESCRIPTION
    MITRE ATT&CK Technique:
      - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
      - T1112: Modify Registry

    Sigma Detection Rule Triggered:
      - proc_creation_win_user_shell_folders_registry_modification.yml (HIGH)
      - Title: User Shell Folders Registry Modification via CommandLine
      - Trigger: reg.exe or powershell modifying the 'User Shell Folders' registry key with 'Startup'.

    Why This Is A Benign False Positive:
      - Software installers, desktop management scripts, and profile setup tools
        routinely ensure that the user's Startup shell folder path is correctly mapped
        and configured in HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders.
      - Although adversaries modify User Shell Folders to hijack startup folders or redirect execution,
        the command here explicitly writes the genuine, standard Windows default path:
          %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
      - 'reg.exe' is a genuine Microsoft-signed system utility in System32.
      - 0 network connections, 0 downloaded payloads, 0 suspicious binary paths.
      - Triagent should inspect the process line, verify the target registry key and harmless default path,
        optionally ask the user ("Yes, I did this"), and correctly conclude 'false_positive'.

    SAFETY NOTICE:
      This script touches NO %APPDATA% binaries, drops NO files, and makes NO network calls.
      It sets the User Shell Folders Startup value to the standard Windows default location.
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

# 1.1 Verify folder name is run_b5
$LeafName = (Split-Path -Leaf $Root).ToLower()
if ($LeafName -ne "run_b5") {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Current folder '$LeafName' does not end in 'run_b5'." -ForegroundColor Yellow
    Write-Host "    Path: $Root" -ForegroundColor Yellow
    exit 1
}

# 1.2 Verify path is within authorized project root or USERPROFILE
$NormRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$AllowedRoots = @(
    [System.IO.Path]::GetFullPath("F:\Projects\BlueTeamingAI\hackathon\runs\run_B5").TrimEnd('\', '/'),
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
# SECTION 2: TRIGGER BENIGN STARTUP SHELL FOLDERS CONFIGURATION
# ==============================================================================
$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("o")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario B5: Startup Registry Config (Benign FP)" -ForegroundColor Yellow
Write-Host " Sigma Rule: proc_creation_win_user_shell_folders_registry_modification.yml" -ForegroundColor Cyan
Write-Host " Expected Verdict: false_positive" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[1/2] Started at UTC: $StartTimeUtc" -ForegroundColor Gray
Write-Host "[*] Confinement Root: $Root" -ForegroundColor DarkGray

# Command that triggers the Sigma rule
$RegExe = "$env:SystemRoot\System32\reg.exe"
$RegKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$ValName = "Startup"
$ValData = "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

Write-Host "`n[2/2] Configuring standard User Shell Folders Startup path via reg.exe..." -ForegroundColor Yellow
Write-Host "      Key:   $RegKey" -ForegroundColor DarkGray
Write-Host "      Value: $ValName = $ValData" -ForegroundColor DarkGray

$Arguments = "add `"$RegKey`" /v `"$ValName`" /t REG_EXPAND_SZ /d `"$ValData`" /f"
Write-Host "      Command: $RegExe $Arguments" -ForegroundColor Cyan

$Proc = Start-Process -FilePath $RegExe -ArgumentList $Arguments -PassThru -NoNewWindow -Wait

Write-Host "`n[+] Execution completed with exit code $($Proc.ExitCode)." -ForegroundColor Green
Write-Host "[+] Detection rule 'User Shell Folders Registry Modification via CommandLine' should fire momentarily." -ForegroundColor Green
Write-Host "    Triagent should identify this as a benign false positive." -ForegroundColor Cyan
Write-Host "    Scripted human answer if asked: 'Yes, I did this.'" -ForegroundColor DarkYellow

