<#
.SYNOPSIS
    Simulates Scenario A1: Spearphishing Trojan Dropper with Double Extension (.pdf.exe)
    MITRE ATT&CK: T1204.002 (User Execution), T1547.001 (Persistence: Registry Run Keys)

.DESCRIPTION
    Harmlessly simulates an employee double-clicking a fake PDF invoice attachment:
    1. Copies Windows cmd.exe to Downloads\Invoice_Payment_Due.pdf.exe
    2. Launches the disguised executable
    3. Simulates dropper behavior: drops a dummy script into %TEMP% and adds a Run key
    4. Runs a background loop (ping) for 30s so the agent has time to inspect process liveness and kill it
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario A1: Trojan Dropper (.pdf.exe)" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

$DownloadsDir = Join-Path $env:USERPROFILE "Downloads"
$DisguisedExe = Join-Path $DownloadsDir "Invoice_Payment_Due.pdf.exe"

# 1. Create disguised executable
Write-Host "[1/3] Creating disguised dummy invoice executable in Downloads..." -ForegroundColor Gray
Copy-Item "C:\Windows\System32\cmd.exe" $DisguisedExe -Force
Write-Host "      Created: $DisguisedExe" -ForegroundColor Green

# 2. Command to drop payload and simulate persistence
$PayloadScript = Join-Path $env:TEMP "svchost_updater.bat"
$CmdArgs = "/c `"echo @echo Harmless simulation > `"$PayloadScript`" & reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SystemUpdaterService /t REG_SZ /d `"$PayloadScript`" /f & ping 127.0.0.1 -n 301 >nul`""

# 3. Launch
Write-Host "[2/3] Launching disguised file (triggers Sysmon & Sigma rule)..." -ForegroundColor Yellow
Start-Process -FilePath $DisguisedExe -ArgumentList $CmdArgs -WindowStyle Minimized

Write-Host "[3/3] Execution launched! Check your BlueTeamAI Web UI at: http://127.0.0.1:8766" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
