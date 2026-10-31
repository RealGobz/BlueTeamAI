# ==============================================================================
# setup.ps1 - BlueTeamAI Setup & Provisioning Script
# ==============================================================================
# Prepares the complete BlueTeamAI environment on Windows 10/11:
# 1. Checks/Installs Python 3.10+ and prepares .venv virtual environment
# 2. Installs required dependencies from requirements.txt
# 3. Ensures runtime directory structure exists (tools/db, tools/cache, quarantine, etc.)
# 4. Initializes conclusion_run.csv template
# 5. Downloads and installs Microsoft Sysmon with SwiftOnSecurity configuration
# 6. Downloads sample attack logs in detection/test_data/
# 7. Extracts 600+ Sigma detection rules into detection/rules/
# 8. Prepares .env from .env.example
# 9. Optionally provisions Azure AI Foundry infrastructure (setup/azure.bicep)
# 10. Runs pre-flight verification
# ==============================================================================

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "rg-blueteamingai",
    [string]$AzureLocation     = "eastus",
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
Write-Host " BlueTeamAI: Windows Environment Setup" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# SECTION 1: PYTHON & VIRTUAL ENVIRONMENT
# ------------------------------------------------------------------------------
Write-Host "`n[1/7] Checking Python virtual environment (.venv)..." -ForegroundColor Yellow

$PythonCmd = Get-Command python.exe, py.exe, python3.exe -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $PythonCmd) {
    $WingetCmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($WingetCmd) {
        Write-Host "      [!] Python not found. Installing Python 3.12 via winget..." -ForegroundColor Yellow
        winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        $PythonCmd = Get-Command python.exe, py.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    }
}

if (-not $PythonCmd) {
    Write-Host "      [-] Error: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "          Please install Python 3.10+ from https://python.org or run:" -ForegroundColor Yellow
    Write-Host "          winget install Python.Python.3.12" -ForegroundColor Cyan
    exit 1
}

$PythonVersion = & $PythonCmd.Source --version 2>&1
Write-Host "      Using host Python: $PythonVersion" -ForegroundColor Gray

$VenvDir = Join-Path $RootDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip = Join-Path $VenvDir "Scripts\pip.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "      Creating virtual environment in .venv..." -ForegroundColor Gray
    & $PythonCmd.Source -m venv $VenvDir
}

Write-Host "      Upgrading pip and installing requirements.txt..." -ForegroundColor Gray
& $VenvPip install --upgrade pip --quiet
& $VenvPip install -r (Join-Path $RootDir "requirements.txt") --quiet
Write-Host "      [OK] Python dependencies installed in .venv." -ForegroundColor Green

# ------------------------------------------------------------------------------
# SECTION 2: RUNTIME DIRECTORIES & CSV TEMPLATE
# ------------------------------------------------------------------------------
Write-Host "`n[2/7] Verifying directory structure and runtime storage..." -ForegroundColor Yellow

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
Write-Host "`n[3/7] Checking Microsoft Sysmon configuration & service..." -ForegroundColor Yellow

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
Write-Host "`n[4/7] Checking sample attack logs in detection/test_data/..." -ForegroundColor Yellow

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
Write-Host "`n[5/7] Checking Sigma detection rules database..." -ForegroundColor Yellow

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
# SECTION 6: ENVIRONMENT VARIABLES & AZURE AI FOUNDRY
# ------------------------------------------------------------------------------
Write-Host "`n[6/7] Checking environment configuration (.env)..." -ForegroundColor Yellow

$EnvFile = Join-Path $RootDir ".env"
$EnvExample = Join-Path $RootDir ".env.example"

if (-not (Test-Path $EnvFile)) {
    if (Test-Path $EnvExample) {
        Copy-Item -Path $EnvExample -Destination $EnvFile
        Write-Host "      [OK] Created .env from .env.example" -ForegroundColor Green
        Write-Host "      [!] Please edit .env with your PROJECT_ENDPOINT and API keys." -ForegroundColor Yellow
    }
} else {
    Write-Host "      [OK] Existing .env file found." -ForegroundColor Green
}

if (-not $SkipAzure) {
    Write-Host "      Checking Azure CLI for AI Foundry provisioning..." -ForegroundColor Gray
    $AzCmd = Get-Command az -ErrorAction SilentlyContinue
    if ($AzCmd) {
        $AccountJson = az account show --output json 2>$null
        if ($AccountJson) {
            $AccountObj = $AccountJson | ConvertFrom-Json
            Write-Host "      [OK] Azure account authenticated: $($AccountObj.user.name)" -ForegroundColor Green

            $RgExists = az group exists --name $ResourceGroupName
            if ($RgExists -ne "true") {
                az group create --name $ResourceGroupName --location $AzureLocation --output none
                Write-Host "      [OK] Created Resource Group: $ResourceGroupName ($AzureLocation)" -ForegroundColor Green
            }

            # Check for soft-deleted Cognitive Services accounts with btai- prefix and purge
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
                    $ProjectEndpoint = $Outputs.PROJECT_ENDPOINT.value
                    $LlmDeploymentName = $Outputs.LLM_DEPLOYMENT_NAME.value

                    Write-Host "      [OK] Azure AI Foundry deployment completed!" -ForegroundColor Green

                    # Update .env
                    $ExistingEnv = @{}
                    if (Test-Path $EnvFile) {
                        Get-Content $EnvFile | ForEach-Object {
                            $line = $_.Trim()
                            if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
                                $idx = $line.IndexOf("=")
                                $k = $line.Substring(0, $idx).Trim()
                                $v = $line.Substring($idx + 1).Trim()
                                $ExistingEnv[$k] = $v
                            }
                        }
                    }
                    $ExistingEnv["PROJECT_ENDPOINT"] = $ProjectEndpoint
                    $ExistingEnv["LLM_DEPLOYMENT_NAME"] = $LlmDeploymentName

                    $EnvLines = @(
                        "# ==============================================================================",
                        "# BlueTeamAI Environment Variables",
                        "# Automatically configured by setup/setup.ps1",
                        "# =============================================================================="
                    )
                    foreach ($key in $ExistingEnv.Keys) {
                        $EnvLines += "$key=$($ExistingEnv[$key])"
                    }
                    $EnvLines | Set-Content -Path $EnvFile -Encoding utf8
                    Write-Host "      [OK] Updated $EnvFile with Azure endpoints." -ForegroundColor Green
                }
            }
        }
    }
}

# ------------------------------------------------------------------------------
# SECTION 7: VALIDATION & SUMMARY
# ------------------------------------------------------------------------------
Write-Host "`n[7/7] Running pre-flight self-test..." -ForegroundColor Yellow

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

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Setup complete! Ready for listening & investigations." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Start Live Sysmon Watcher (Admin prompt recommended):" -ForegroundColor Yellow
Write-Host "   .\.venv\Scripts\python detection/watch.py" -ForegroundColor Cyan
Write-Host "   (Or tag a scenario: .\.venv\Scripts\python detection/watch.py --scenario A1)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "2. Start Investigation Web UI:" -ForegroundColor Yellow
Write-Host "   .\.venv\Scripts\python -m UI.main.server" -ForegroundColor Cyan
Write-Host "   Open: http://127.0.0.1:8766" -ForegroundColor DarkGray
Write-Host ""
Write-Host "3. View Evaluated Scenario Runs:" -ForegroundColor Yellow
Write-Host "   .\.venv\Scripts\python record_run.py --view" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan