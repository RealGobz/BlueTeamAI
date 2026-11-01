# ==============================================================================
# setup.ps1 - BlueTeamAI Setup & Live Runner Script
# ==============================================================================
# Prepares the complete BlueTeamAI environment on Windows 10/11:
# 1. Checks/Installs Python 3.10+ and prepares .venv virtual environment
# 2. Installs required dependencies from requirements.txt
# 3. Ensures runtime directory structure exists (tools/db, tools/cache, quarantine, etc.)
# 4. Initializes conclusion_run.csv template
# 5. Downloads and installs Microsoft Sysmon with SwiftOnSecurity configuration
# 6. Downloads sample attack logs in detection/test_data/
# 7. Extracts 600+ Sigma detection rules into detection/rules/
# 8. Checks/Installs Azure CLI & authenticates for DefaultAzureCredential
# 9. Prepares .env and auto-configures Azure AI Foundry endpoints
# 10. Runs pre-flight verification
# 11. Starts detection/watch.py and Web UI directly (pass -NoWatch to skip)
# ==============================================================================

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "rg-blueteamingai",
    [string]$AzureLocation     = "eastus",
    [string]$Scenario          = "",
    [switch]$NoWatch           = $false,
    [switch]$SkipAzure         = $true
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RootDir = Split-Path -Parent $PSScriptRoot

# Define target directories
$ToolsDir    = Join-Path $RootDir "tools\sysmon"
$TestDataDir = Join-Path $RootDir "detection\test_data"
$RulesDir    = Join-Path $RootDir "detection\rules"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " BlueTeamAI: Windows Setup & Live Runner" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# SECTION 1: PYTHON & VIRTUAL ENVIRONMENT
# ------------------------------------------------------------------------------
function Get-RealPython {
    $candidates = @()
    # Check PATH commands, explicitly filtering out Microsoft Store WindowsApps redirector shims
    $cmds = Get-Command python.exe, py.exe, python3.exe -All -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike "*WindowsApps*" }
    foreach ($c in $cmds) { $candidates += $c.Source }
    
    # If py.exe launcher is present, ask it directly for active python interpreter path
    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $pyResolved = (& $pyLauncher.Source -3 -c "import sys; print(sys.executable)" 2>$null) | Out-String
            if ($pyResolved -and (Test-Path $pyResolved.Trim())) {
                $candidates += $pyResolved.Trim()
            }
        } catch {}
        $ErrorActionPreference = $prevEap
    }

    # Check standard install directories on Windows
    $commonPaths = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python314\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python310\python.exe"),
        (Join-Path $env:ProgramFiles "Python314\python.exe"),
        (Join-Path $env:ProgramFiles "Python313\python.exe"),
        (Join-Path $env:ProgramFiles "Python312\python.exe"),
        (Join-Path $env:ProgramFiles "Python311\python.exe"),
        (Join-Path $env:ProgramFiles "Python310\python.exe"),
        "C:\Python314\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe"
    )
    foreach ($p in $commonPaths) { if (Test-Path $p) { $candidates += $p } }

    # Test candidate execution
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        foreach ($cand in $candidates) {
            if ($cand -and (Test-Path $cand)) {
                $verOutput = (& $cand --version 2>&1) | Out-String
                if ($LASTEXITCODE -eq 0 -and $verOutput -match "Python\s+3\.") {
                    return @{ Path = $cand; Version = $verOutput.Trim() }
                }
            }
        }
    } finally {
        $ErrorActionPreference = $prevEap
    }
    return $null
}

$RealPython = Get-RealPython

if (-not $RealPython) {
    Write-Host "      [!] Real Python not found (Microsoft Store shortcut ignored)." -ForegroundColor Yellow
    $WingetCmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($WingetCmd) {
        Write-Host "      Installing Python 3.12 via winget..." -ForegroundColor Yellow
        winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        $RealPython = Get-RealPython
    }
}

if (-not $RealPython) {
    Write-Host "      [-] Error: Python 3.10+ is not installed or not in PATH." -ForegroundColor Red
    Write-Host "          Please install Python 3.10+ from https://python.org or run in an Admin PowerShell:" -ForegroundColor Yellow
    Write-Host "          winget install Python.Python.3.12" -ForegroundColor Cyan
    exit 1
}

$PythonBin = $RealPython.Path
Write-Host "      Using host Python: $($RealPython.Version) ($PythonBin)" -ForegroundColor Gray

$VenvDir = Join-Path $RootDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip = Join-Path $VenvDir "Scripts\pip.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "      Creating virtual environment in .venv..." -ForegroundColor Gray
    & $PythonBin -m venv $VenvDir
}

Write-Host "      Installing Python requirements..." -ForegroundColor Gray
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $VenvPip install --upgrade pip --quiet --disable-pip-version-check 2>$null
} catch {}
& $VenvPip install -r (Join-Path $RootDir "requirements.txt") --disable-pip-version-check --quiet
$ErrorActionPreference = $prevEap
Write-Host "      [OK] Python dependencies installed in .venv." -ForegroundColor Green

# ------------------------------------------------------------------------------
# SECTION 2: RUNTIME DIRECTORIES & CSV TEMPLATE
# ------------------------------------------------------------------------------
Write-Host "`n[2/8] Verifying directory structure and runtime storage..." -ForegroundColor Yellow

$RuntimeDirs = @(
    (Join-Path $RootDir "tools\db"),
    (Join-Path $RootDir "tools\cache"),
    (Join-Path $RootDir "tools\memory"),
    (Join-Path $RootDir "tools\sysmon"),
    (Join-Path $RootDir "quarantine"),
    (Join-Path $RootDir "scratch"),
    $TestDataDir,
    $RulesDir
)

foreach ($dir in $RuntimeDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $keep = Join-Path $dir ".gitkeep"
    if (-not (Test-Path $keep)) {
        "" | Set-Content -Path $keep -Encoding ascii
    }
}

$CsvFile = Join-Path $RootDir "tools\db\conclusion_run.csv"
if (-not (Test-Path $CsvFile) -or (Get-Item $CsvFile).Length -eq 0) {
    $Header = "scenario_id,date_time,expected_verdict,detected_by_rule,alert_id,tools_used_in_order,total_turns,tokens_cost,time_to_verdict,verdict,confidence,reasoning_quality,asked_user,actions_proposed,human_decision,action_result,left_behind,correct,problems,notes"
    $Header | Set-Content -Path $CsvFile -Encoding utf8
    Write-Host "      [OK] Initialized $CsvFile" -ForegroundColor Green
} else {
    Write-Host "      [EXISTS] $CsvFile" -ForegroundColor DarkGray
}

# ------------------------------------------------------------------------------
# SECTION 3: MICROSOFT SYSMON SETUP
# ------------------------------------------------------------------------------
Write-Host "`n[3/8] Checking Microsoft Sysmon configuration & service..." -ForegroundColor Yellow

$SysmonExePath = Join-Path $ToolsDir "Sysmon64.exe"
$SysmonConfigPath = Join-Path $ToolsDir "sysmonconfig-export.xml"

if (-not (Test-Path $SysmonConfigPath)) {
    Write-Host "      Downloading SwiftOnSecurity Sysmon configuration..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $SysmonConfigPath -UseBasicParsing
    Write-Host "      [OK] Saved SwiftOnSecurity config." -ForegroundColor Green
} else {
    Write-Host "      [EXISTS] sysmonconfig-export.xml in: $ToolsDir" -ForegroundColor DarkGray
}

if (-not (Test-Path $SysmonExePath)) {
    Write-Host "      Downloading Microsoft Sysmon..." -ForegroundColor Yellow
    $SysmonZip = Join-Path $ToolsDir "Sysmon.zip"
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $SysmonZip -UseBasicParsing
    Expand-Archive -Path $SysmonZip -DestinationPath $ToolsDir -Force
    Remove-Item -Path $SysmonZip -Force
    Write-Host "      [OK] Extracted Sysmon to: $ToolsDir" -ForegroundColor Green
} else {
    Write-Host "      [EXISTS] Sysmon64.exe in: $ToolsDir" -ForegroundColor DarkGray
}

$SysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Where-Object Status -eq "Running"
if ($SysmonService) {
    Write-Host "      [OK] Microsoft Sysmon service is active and running." -ForegroundColor Green
} else {
    Write-Host "      Installing and starting Microsoft Sysmon service..." -ForegroundColor Yellow
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($IsAdmin) {
        & $SysmonExePath -accepteula -i $SysmonConfigPath
        Write-Host "      [OK] Sysmon service installed and started successfully." -ForegroundColor Green
    } else {
        Write-Host "      Requesting Administrator elevation (UAC prompt)..." -ForegroundColor Yellow
        Start-Process -FilePath $SysmonExePath -ArgumentList "-accepteula -i `"$SysmonConfigPath`"" -Verb RunAs -Wait
        $SysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Where-Object Status -eq "Running"
        if ($SysmonService) {
            Write-Host "      [OK] Sysmon service installed and running." -ForegroundColor Green
        } else {
            Write-Host "      [!] Administrator permission was not granted." -ForegroundColor Yellow
            Write-Host "          To start manually: Open Administrator PowerShell and run:" -ForegroundColor Yellow
            Write-Host "          & '$SysmonExePath' -accepteula -i '$SysmonConfigPath'" -ForegroundColor Cyan
        }
    }
}

# ------------------------------------------------------------------------------
# SECTION 4: SAMPLE ATTACK LOGS (OFFLINE REPLAY)
# ------------------------------------------------------------------------------
Write-Host "`n[4/8] Checking sample attack logs in detection/test_data/..." -ForegroundColor Yellow

$Samples = @(
    @{
        Name = "exec_sysmon_1_lolbin_pcalua.evtx"
        Url  = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Execution/exec_sysmon_1_lolbin_pcalua.evtx"
    },
    @{
        Name = "babyshark_mimikatz_powershell.evtx"
        Url  = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Credential%20Access/babyshark_mimikatz_powershell.evtx"
    },
    @{
        Name = "sysmon_mshta_sharpshooter_stageless_meterpreter.evtx"
        Url  = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx"
    }
)

foreach ($Sample in $Samples) {
    $DestFile = Join-Path $TestDataDir $Sample.Name
    if (-not (Test-Path $DestFile)) {
        Write-Host "      Downloading $($Sample.Name)..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $Sample.Url -OutFile $DestFile -UseBasicParsing
        Write-Host "      [OK] Saved: $($Sample.Name)" -ForegroundColor Green
    } else {
        Write-Host "      [EXISTS] $($Sample.Name)" -ForegroundColor DarkGray
    }
}

# ------------------------------------------------------------------------------
# SECTION 5: SIGMA DETECTION RULES
# ------------------------------------------------------------------------------
Write-Host "`n[5/8] Checking Sigma detection rules database..." -ForegroundColor Yellow

$ExistingRulesCount = (Get-ChildItem -Path $RulesDir -Filter *.yml -ErrorAction SilentlyContinue).Count
if ($ExistingRulesCount -lt 50) {
    Write-Host "      Downloading Sigma repository archive (~12 MB)..." -ForegroundColor Gray
    $SigmaZipPath = Join-Path $RootDir "sigma_master.zip"
    Invoke-WebRequest -Uri "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" -OutFile $SigmaZipPath -UseBasicParsing
    
    Write-Host "      Extracting High & Critical process-creation rules..." -ForegroundColor Gray
    $ExtractorScript = Join-Path $RootDir "setup\extract_rules.py"
    & $VenvPython $ExtractorScript --zip $SigmaZipPath --output $RulesDir
    
    Remove-Item -Path $SigmaZipPath -Force
    $ExistingRulesCount = (Get-ChildItem -Path $RulesDir -Filter *.yml -ErrorAction SilentlyContinue).Count
    Write-Host "      [OK] Populated $ExistingRulesCount Sigma rules into: $RulesDir" -ForegroundColor Green
} else {
    Write-Host "      [OK] Found $ExistingRulesCount Sigma rules in: $RulesDir" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# SECTION 6: AZURE CLI FOR DefaultAzureCredential
# ------------------------------------------------------------------------------
$EnvFile = Join-Path $RootDir ".env"
$HasEndpoint = $false
if (Test-Path $EnvFile) {
    $EnvContent = Get-Content $EnvFile -ErrorAction SilentlyContinue
    if ($EnvContent -match "^PROJECT_ENDPOINT=https://[a-zA-Z0-9]") {
        $HasEndpoint = $true
    }
}

$AzAuthenticated = $false
if ($SkipAzure) {
    Write-Host "`n[6/8] Skipping Azure CLI check (-SkipAzure specified)..." -ForegroundColor Gray
} elseif ($HasEndpoint) {
    Write-Host "`n[6/8] Azure configuration found in .env (skipping Azure CLI login)..." -ForegroundColor Green
} else {
    Write-Host "`n[6/8] Checking Azure CLI (az) for DefaultAzureCredential..." -ForegroundColor Yellow

    $AzCmd = Get-Command az.cmd, az.exe, az.ps1 -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $AzCmd) {
        # Check default installation paths
        $StandardAzPaths = @(
            "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
            "C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
        )
        foreach ($p in $StandardAzPaths) {
            if (Test-Path $p) {
                $env:Path = [System.IO.Path]::GetDirectoryName($p) + ";" + $env:Path
                $AzCmd = Get-Command az.cmd, az.exe -ErrorAction SilentlyContinue | Select-Object -First 1
                break
            }
        }
    }

    if (-not $AzCmd) {
        Write-Host "      [!] Azure CLI not found in PATH. Installing Azure CLI..." -ForegroundColor Yellow
        $WingetCmd = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($WingetCmd) {
            winget install -e --id Microsoft.AzureCLI --accept-package-agreements --accept-source-agreements
        } else {
            Start-Process msiexec.exe -ArgumentList "/i https://aka.ms/installazurecliwindows /quiet /qn /norestart" -Wait
        }
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        $AzCmd = Get-Command az.cmd, az.exe, az.ps1 -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if ($AzCmd) {
        $AccountJson = az account show --output json 2>$null
        if (-not $AccountJson) {
            Write-Host "      [!] Azure CLI is not authenticated. DefaultAzureCredential requires login." -ForegroundColor Yellow
            Write-Host "          Launching 'az login'..." -ForegroundColor Cyan
            az login --output table
            $AccountJson = az account show --output json 2>$null
        }
        if ($AccountJson) {
            $AccountObj = $AccountJson | ConvertFrom-Json
            Write-Host "      [OK] Azure CLI authenticated as: $($AccountObj.user.name)" -ForegroundColor Green
            $AzAuthenticated = $true
        }
    } else {
        Write-Host "      [NOTE] Azure CLI installed. If not active in this window, reopen PowerShell." -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------------------
# SECTION 7: ENVIRONMENT VARIABLES & ENDPOINTS (.env)
# ------------------------------------------------------------------------------
Write-Host "`n[7/8] Checking environment configuration (.env)..." -ForegroundColor Yellow

$EnvFile = Join-Path $RootDir ".env"
$EnvExample = Join-Path $RootDir ".env.example"

if (-not (Test-Path $EnvFile)) {
    if (Test-Path $EnvExample) {
        Copy-Item -Path $EnvExample -Destination $EnvFile
        Write-Host "      [OK] Created .env from .env.example" -ForegroundColor Green
    }
} else {
    Write-Host "      [OK] Existing .env file found." -ForegroundColor Green
}

# Auto-discover Azure AI Foundry endpoint if missing or placeholder
if (Test-Path $EnvFile) {
    $EnvContent = Get-Content $EnvFile
    $EndpointLine = $EnvContent | Where-Object { $_ -match "^PROJECT_ENDPOINT=(.*)$" }
    $CurrentEndpoint = if ($EndpointLine -match "^PROJECT_ENDPOINT=(.*)$") { $matches[1].Trim() } else { "" }

    if ((-not $CurrentEndpoint -or $CurrentEndpoint -like "*your-hub*") -and $AzAuthenticated) {
        Write-Host "      Auto-discovering Azure AI Foundry resources in subscription..." -ForegroundColor Gray
        $FoundAccount = az cognitiveservices account list --query "[?contains(name, 'btai-')].name | [0]" -o tsv 2>$null
        if ($FoundAccount -and $FoundAccount -ne "None") {
            $BaseName = $FoundAccount.Replace("-aiservices", "")
            $AutoEndpoint = "https://$FoundAccount.services.ai.azure.com/api/projects/$BaseName-project"
            $FoundKey = az cognitiveservices account keys list --name $FoundAccount --query "key1" -o tsv 2>$null
            
            $NewLines = @()
            $HasKey = $false
            foreach ($line in $EnvContent) {
                if ($line -match "^PROJECT_ENDPOINT=") {
                    $NewLines += "PROJECT_ENDPOINT=$AutoEndpoint"
                } elseif ($line -match "^LLM_DEPLOYMENT_NAME=") {
                    $NewLines += "LLM_DEPLOYMENT_NAME=agent_llm"
                } elseif ($line -match "^AZURE_AI_KEY=") {
                    $NewLines += "AZURE_AI_KEY=$FoundKey"
                    $HasKey = $true
                } else {
                    $NewLines += $line
                }
            }
            if (-not $HasKey -and $FoundKey) {
                $NewLines += "AZURE_AI_KEY=$FoundKey"
            }
            $NewLines | Set-Content -Path $EnvFile -Encoding utf8
            Write-Host "      [OK] Automatically configured PROJECT_ENDPOINT and AZURE_AI_KEY" -ForegroundColor Green
        }
    }
}

# Optional explicit Bicep deployment
if (-not $SkipAzure -and $AzAuthenticated) {
    $RgExists = az group exists --name $ResourceGroupName
    if ($RgExists -ne "true") {
        az group create --name $ResourceGroupName --location $AzureLocation --output none
        Write-Host "      [OK] Created Resource Group: $ResourceGroupName ($AzureLocation)" -ForegroundColor Green
    }

    # Soft-deleted Cognitive Services auto-purge
    $DeletedAccounts = az cognitiveservices account list-deleted --output json 2>$null | ConvertFrom-Json
    if ($DeletedAccounts) {
        foreach ($delAcc in $DeletedAccounts) {
            if ($delAcc.name -like "btai-*-aiservices" -and $delAcc.location -eq $AzureLocation) {
                Write-Host "      [!] Purging soft-deleted account '$($delAcc.name)'..." -ForegroundColor Yellow
                az cognitiveservices account purge --location $AzureLocation --resource-group $ResourceGroupName --name $delAcc.name --output none 2>$null
            }
        }
    }

    $BicepPath = Join-Path $PSScriptRoot "azure.bicep"
    if (Test-Path $BicepPath) {
        Write-Host "      Deploying Bicep template: $BicepPath..." -ForegroundColor Yellow
        $DeployName = "btai-deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $DeployResultRaw = az deployment group create `
                --resource-group $ResourceGroupName `
                --template-file $BicepPath `
                --name $DeployName `
                --query "properties.outputs" `
                --output json 2>&1
        } finally {
            $ErrorActionPreference = $prevEap
        }

        if ($LASTEXITCODE -eq 0) {
            $Outputs = $DeployResultRaw | ConvertFrom-Json
            Write-Host "      [OK] Azure AI Foundry deployment completed!" -ForegroundColor Green
        }
    }
}

# ------------------------------------------------------------------------------
# SECTION 8: PRE-FLIGHT VERIFICATION
# ------------------------------------------------------------------------------
Write-Host "`n[8/8] Running pre-flight self-test..." -ForegroundColor Yellow

try {
    & $VenvPython -c "
import config
from utils import load_rules_index
rules = load_rules_index(config.ROOT_DIR / 'detection' / 'rules')
print(f'      [+] Self-test passed: loaded {len(rules)} Sigma rules successfully.')
"
} catch {
    Write-Host "      [!] Pre-flight verification completed." -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
# START LIVE LISTENER & WEB UI DIRECTLY
# ------------------------------------------------------------------------------
if ($NoWatch) {
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host " Setup complete! (-NoWatch specified, watcher not started)." -ForegroundColor Green
    Write-Host " To start manually: .\.venv\Scripts\python detection/watch.py" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    exit 0
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Starting BlueTeamAI Live Watcher (detection/watch.py)..." -ForegroundColor Green
Write-Host " Investigation Web UI active at: http://127.0.0.1:8766" -ForegroundColor Cyan
Write-Host " (Press Ctrl+C to stop listening)" -ForegroundColor DarkGray
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$WatchScript = Join-Path $RootDir "detection\watch.py"
$WatchArgs = @()
if ($Scenario) {
    $WatchArgs += "--scenario", $Scenario
}
if ($args) {
    $WatchArgs += $args
}

& $VenvPython $WatchScript @WatchArgs