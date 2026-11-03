<#
.SYNOPSIS
    Simulates Scenario A4: OS Credential Dumping via comsvcs.dll (T1003.001).
    Harmless simulation strictly confined to the local script directory.

.DESCRIPTION
    MITRE ATT&CK Technique:
      - T1003.001: OS Credential Dumping (LSASS Memory)

    Scenario Mechanics:
      1. Hard Confinement Guard: Ensures execution only inside the dedicated 'run_a4' directory.
      2. Neutral Target Setup: Spawns a harmless background worker process (files\lib\sync-host.ps1)
         that idles for a configurable duration.
      3. LOLBin Memory Dump Invocation: Executes the exact command-line pattern used by attackers
         abusing Windows built-in comsvcs.dll via rundll32.exe:
           rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <TargetPID> <DumpPath>\lsass.dmp full
         This mimics the classic living-off-the-land credential theft command line.
      4. Live Forensic Window: The target process remains active for $KeepAliveSeconds so BlueTeamAI
         can inspect live process trees, verify process presence, and test remediation.
      5. Proof of Execution: Displays the command line, process ID, and verification status.
      6. Containment & Cleanup: Confined 100% to .\files\. Offers optional cleanup at the end.

    SAFETY NOTICE:
      This script touches NO registry keys, NO %TEMP%, NO %APPDATA%, NO Startup folders,
      and makes NO network calls. The memory dump targets only the local dummy process,
      protecting operating system credentials and secrets.
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

# 1.1 Verify folder name is run_a4
$LeafName = (Split-Path -Leaf $Root).ToLower()
if ($LeafName -ne "run_a4") {
    Write-Host "[!] CONFINEMENT GUARD REJECTED EXECUTION:" -ForegroundColor Red
    Write-Host "    Current folder '$LeafName' does not end in 'run_a4'." -ForegroundColor Yellow
    Write-Host "    Path: $Root" -ForegroundColor Yellow
    exit 1
}

# 1.2 Verify path is within authorized project root or USERPROFILE
$NormRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
$AllowedRoots = @(
    [System.IO.Path]::GetFullPath("F:\Projects\BlueTeamingAI\hackathon\runs\run_A4").TrimEnd('\', '/'),
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
# SECTION 2: NEUTRAL DIRECTORY & DUMMY TARGET SETUP
# ==============================================================================
$LibDir   = Join-Path $FilesDir "lib"
$StateDir = Join-Path $FilesDir "state"

if (-not (Test-Path $LibDir))   { New-Item -ItemType Directory -Path $LibDir -Force | Out-Null }
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

$WorkerScript = Join-Path $LibDir "sync-host.ps1"
$DumpFile     = Join-Path $StateDir "lsass.dmp"

# Remove any stale dump file from prior runs
if (Test-Path $DumpFile) {
    Remove-Item -Path $DumpFile -Force -ErrorAction SilentlyContinue
}

# Write benign worker script that simply idles
$WorkerContent = @"
`$StartTime = (Get-Date).ToUniversalTime().ToString("o")
Write-Host "Worker initialized at `$StartTime"
Start-Sleep -Seconds $KeepAliveSeconds
exit 0
"@
Set-Content -Path $WorkerScript -Value $WorkerContent -Encoding utf8 -Force

# ==============================================================================
# SECTION 3: SPAWN TARGET PROCESS
# ==============================================================================
$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("o")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario A4: OS Credential Dumping (LSASS Memory)" -ForegroundColor Yellow
Write-Host " MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[1/4] Started at UTC: $StartTimeUtc" -ForegroundColor Gray
Write-Host "[*] Desktop Safety Constraint: Targets dummy worker process inside files\ (no OS LSASS access)." -ForegroundColor DarkYellow
Write-Host "[*] Confinement Root: $Root" -ForegroundColor DarkGray

# Spawn harmless background target process
$TargetProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -File `"$WorkerScript`"" -PassThru
$TargetPid = $TargetProc.Id
Write-Host "      Spawned Dummy Target PID: $TargetPid" -ForegroundColor Green
Write-Host "      Target Keep-Alive:        $KeepAliveSeconds seconds" -ForegroundColor DarkGray

# Give process brief moment to initialize
Start-Sleep -Seconds 1

# ==============================================================================
# SECTION 4: EXECUTE COMSVCS MINIDUMP LOLBIN (MITRE T1003.001)
# ==============================================================================
Write-Host "`n[2/4] Executing comsvcs.dll MiniDump command line via rundll32.exe..." -ForegroundColor Yellow

$DumpArgs = "C:\Windows\System32\comsvcs.dll, MiniDump $TargetPid `"$DumpFile`" full"
Write-Host "      Command: rundll32.exe $DumpArgs" -ForegroundColor DarkCyan

# Execute rundll32.exe with the classic credential theft arguments
$DumpProc = Start-Process -FilePath "rundll32.exe" -ArgumentList $DumpArgs -PassThru -Wait

Write-Host "      rundll32 execution completed." -ForegroundColor Green

# ==============================================================================
# SECTION 5: PROOF OF EXECUTION
# ==============================================================================
Write-Host "`n[3/4] Execution Verification:" -ForegroundColor Cyan
Write-Host "      UTC Start Time:      $StartTimeUtc" -ForegroundColor Gray
Write-Host "      Target Process PID:  $TargetPid" -ForegroundColor Gray
Write-Host "      Target Still Alive:  $(-not $TargetProc.HasExited)" -ForegroundColor Green
Write-Host "      Dump Target Path:    $DumpFile" -ForegroundColor Gray
Write-Host "      Dump File Created:   $(Test-Path $DumpFile)" -ForegroundColor $(if (Test-Path $DumpFile) { "Green" } else { "Yellow" })

Write-Host "`n[4/4] Investigation Active. Observe detection in BlueTeamAI UI: http://127.0.0.1:8766" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# ==============================================================================
# SECTION 6: OPTIONAL CONTAINMENT CLEANUP
# ==============================================================================
Write-Host ""
$Cleanup = Read-Host "Do you want to clean up and delete the entire 'files' folder? (y/N)"
if ($Cleanup -match "^[Yy]$") {
    if ($TargetProc -and -not $TargetProc.HasExited) {
        Write-Host "[*] Stopping background target process (PID $TargetPid)..." -ForegroundColor Yellow
        Stop-Process -Id $TargetPid -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $FilesDir) {
        Remove-Item -Path $FilesDir -Recurse -Force
        Write-Host "[+] Cleaned up $FilesDir successfully." -ForegroundColor Green
    }
} else {
    Write-Host "[*] Preserving $FilesDir for forensic review and telemetry recording." -ForegroundColor Yellow
}
