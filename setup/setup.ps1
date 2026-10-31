# ==============================================================================
# setup.ps1 - BlueTeamingAI Setup & Downloader Script
# ==============================================================================
# This script sets up the local development environment by:
#
# 1. TOOLS (for live monitoring):
#    - Sysmon + SwiftOnSecurity Config -> saved in 'tools/sysmon/'
#
# 2. TEST DATA (Pre-recorded attack logs for safe offline testing):
#    - .evtx files from sbousseaden/EVTX-ATTACK-SAMPLES
#    - Saved in 'detection/test_data/'
#
# 3. SIGMA RULES (Open-source attack detection signatures in YAML):
#    - Detection rules from SigmaHQ/sigma
#    - Saved in 'detection/rules/'
#
# 4. AZURE AI FOUNDRY (Cloud LLM Infrastructure):
#    - Creates Resource Group in US East ('eastus')
#    - Deploys setup/azure.bicep (Claude 3.5 Sonnet + Foundry Project)
#    - Writes PROJECT_ENDPOINT and LLM_DEPLOYMENT_NAME to .env automatically
#
# 5. LIVE WATCHER:
#    - Starts detection/watch.py in the background via pythonw.exe
# ==============================================================================

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "rg-blueteamingai",
    [string]$AzureLocation     = "eastus",
    [switch]$SkipAzure         = $false
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RootDir = Split-Path -Parent $PSScriptRoot

# Define target directories
$ToolsDir    = Join-Path $RootDir "tools\sysmon"
$TestDataDir = Join-Path $RootDir "detection\test_data"
$RulesDir    = Join-Path $RootDir "detection\rules"

# Create directories if they do not exist
@($ToolsDir, $TestDataDir, $RulesDir) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " BlueTeamingAI: Environment Setup & Downloader" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# SECTION 1: SYSMON TOOLS (Microsoft System Monitor)
# ------------------------------------------------------------------------------
# Sysmon records system activity (like process launches) to Windows event logs.
# - Sysmon.zip contains the Sysmon64.exe binary.
# - sysmonconfig-export.xml is SwiftOnSecurity's community configuration.
# ------------------------------------------------------------------------------
$SysmonExePath = Join-Path $ToolsDir "Sysmon64.exe"
if (-not (Test-Path $SysmonExePath)) {
    Write-Host "`n[1/5] Downloading Sysmon from Microsoft Sysinternals..." -ForegroundColor Yellow
    $SysmonZip = Join-Path $ToolsDir "Sysmon.zip"
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $SysmonZip -UseBasicParsing
    Expand-Archive -Path $SysmonZip -DestinationPath $ToolsDir -Force
    Remove-Item -Path $SysmonZip -Force
    Write-Host "      [OK] Extracted Sysmon to: $ToolsDir" -ForegroundColor Green
} else {
    Write-Host "`n[1/5] Sysmon is already downloaded in: $ToolsDir" -ForegroundColor Green
}

$SysmonConfigPath = Join-Path $ToolsDir "sysmonconfig-export.xml"
if (-not (Test-Path $SysmonConfigPath)) {
    Write-Host "      Downloading SwiftOnSecurity Sysmon configuration..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $SysmonConfigPath -UseBasicParsing
    Write-Host "      [OK] Saved config to: $SysmonConfigPath" -ForegroundColor Green
} else {
    Write-Host "      [EXISTS] sysmonconfig-export.xml in: $ToolsDir" -ForegroundColor DarkGray
}

# Install and start Sysmon service
$SysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue
if ($SysmonService -and $SysmonService.Status -eq "Running") {
    Write-Host "      [OK] Sysmon service is already running on this machine." -ForegroundColor Green
} else {
    Write-Host "      Installing and starting Sysmon background service..." -ForegroundColor Yellow
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($IsAdmin) {
        & $SysmonExePath -accepteula -i $SysmonConfigPath
        Write-Host "      [OK] Sysmon service installed and started successfully." -ForegroundColor Green
    } else {
        Write-Host "      Requesting Administrator elevation (UAC prompt)..." -ForegroundColor Yellow
        Start-Process -FilePath $SysmonExePath -ArgumentList "-accepteula -i `"$SysmonConfigPath`"" -Verb RunAs -Wait
        $SysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue
        if ($SysmonService -and $SysmonService.Status -eq "Running") {
            Write-Host "      [OK] Sysmon service installed and running." -ForegroundColor Green
        } else {
            Write-Host "      [!] Administrator permission was not granted." -ForegroundColor Yellow
            Write-Host "          To start manually: Open Administrator PowerShell and run:" -ForegroundColor Yellow
            Write-Host "          & '$SysmonExePath' -accepteula -i '$SysmonConfigPath'" -ForegroundColor Cyan
        }
    }
}

# ------------------------------------------------------------------------------
# SECTION 2: TEST DATA (Pre-recorded Attack .evtx Logs)
# ------------------------------------------------------------------------------
# These are real Windows event logs captured by security researchers during attacks.
# We replay these offline to safely test our detection engine.
# ------------------------------------------------------------------------------
Write-Host "`n[2/5] Downloading Sample Attack Logs into: $TestDataDir" -ForegroundColor Yellow

$Samples = @(
    @{
        Name        = "exec_sysmon_1_lolbin_pcalua.evtx"
        Description = "Attack: Program Compatibility Assistant (pcalua.exe) executing malicious commands"
        Url         = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Execution/exec_sysmon_1_lolbin_pcalua.evtx"
    },
    @{
        Name        = "babyshark_mimikatz_powershell.evtx"
        Description = "Attack: Mimikatz credential dumping executed via PowerShell"
        Url         = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Credential%20Access/babyshark_mimikatz_powershell.evtx"
    },
    @{
        Name        = "sysmon_mshta_sharpshooter_stageless_meterpreter.evtx"
        Description = "Attack: MSHTA.exe executing an in-memory Meterpreter reverse shell"
        Url         = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx"
    }
)

foreach ($Sample in $Samples) {
    $DestFile = Join-Path $TestDataDir $Sample.Name
    if (-not (Test-Path $DestFile)) {
        Write-Host "      Downloading $($Sample.Name)..." -ForegroundColor Gray
        Write-Host "      Purpose: $($Sample.Description)" -ForegroundColor DarkGray
        Invoke-WebRequest -Uri $Sample.Url -OutFile $DestFile -UseBasicParsing
        Write-Host "      [OK] Saved: $($Sample.Name)" -ForegroundColor Green
    } else {
        Write-Host "      [EXISTS] $($Sample.Name)" -ForegroundColor DarkGray
    }
}

# ------------------------------------------------------------------------------
# SECTION 3: SIGMA DETECTION RULES (High & Critical Process Creation Rules)
# ------------------------------------------------------------------------------
# We populate our rule database with all Windows process-creation rules from
# the official SigmaHQ repository that are marked as 'high' or 'critical' severity.
#
# Source: https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip
# Destination: detection/rules/
# ------------------------------------------------------------------------------
Write-Host "`n[3/5] Populating Sigma Rules Database (High & Critical Process Creation)..." -ForegroundColor Yellow

$ExistingRulesCount = (Get-ChildItem -Path $RulesDir -Filter *.yml -ErrorAction SilentlyContinue).Count
if ($ExistingRulesCount -lt 50) {
    Write-Host "      Downloading Sigma repository archive (~12 MB)..." -ForegroundColor Gray
    $SigmaZipPath = Join-Path $RootDir "sigma_master.zip"
    curl.exe -L -s -o $SigmaZipPath "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
    
    Write-Host "      Extracting High & Critical process-creation rules into: $RulesDir..." -ForegroundColor Gray
    $ExtractorScript = Join-Path $RootDir "setup\extract_rules.py"
    python $ExtractorScript --zip $SigmaZipPath --output $RulesDir
    
    Remove-Item -Path $SigmaZipPath -Force
} else {
    Write-Host "      [EXISTS] Found $ExistingRulesCount rules already populated in: $RulesDir" -ForegroundColor Green
}

# Also ensure our specific test rules are present (such as mshta dropper)
$SpecificRules = @(
    @{
        Name        = "proc_creation_win_wscript_cscript_mshta_dropper.yml"
        Description = "Detects wscript/cscript/mshta executing scripts from Temporary Internet Files"
        Url         = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_wscript_cscript_mshta_dropper.yml"
    }
)

foreach ($Rule in $SpecificRules) {
    $DestFile = Join-Path $RulesDir $Rule.Name
    if (-not (Test-Path $DestFile)) {
        Write-Host "      Downloading $($Rule.Name)..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $Rule.Url -OutFile $DestFile -UseBasicParsing
        Write-Host "      [OK] Saved: $($Rule.Name)" -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# SECTION 4: AZURE INFRASTRUCTURE & MODEL DEPLOYMENT (Azure AI Foundry)
# ------------------------------------------------------------------------------
# 1. Creates an Azure Resource Group in US East ('eastus').
# 2. Deploys setup/azure.bicep (Foundry Hub, Project, and Claude 3.5 Sonnet).
# 3. Automatically writes PROJECT_ENDPOINT and LLM_DEPLOYMENT_NAME to .env.
# ------------------------------------------------------------------------------
Write-Host "`n[4/5] Setting up Azure AI Foundry & Claude 3.5 Sonnet..." -ForegroundColor Yellow

if ($SkipAzure) {
    Write-Host "      [SKIPPED] -SkipAzure flag passed. Skipping cloud deployment." -ForegroundColor DarkGray
} else {
    $AzCmd = Get-Command az -ErrorAction SilentlyContinue
    if (-not $AzCmd) {
        Write-Host "      [!] Azure CLI (az) was not found in PATH." -ForegroundColor Yellow
        Write-Host "          Install Azure CLI: https://aka.ms/installazurecliwindows" -ForegroundColor DarkGray
    } else {
        # Check login status
        $AccountJson = az account show --output json 2>$null
        if (-not $AccountJson) {
            Write-Host "      [!] Not logged in to Azure CLI. Initiating login..." -ForegroundColor Yellow
            az login --output none
            $AccountJson = az account show --output json 2>$null
        }

        if ($AccountJson) {
            $AccountObj = $AccountJson | ConvertFrom-Json
            Write-Host "      [OK] Azure account authenticated: $($AccountObj.user.name) ($($AccountObj.name))" -ForegroundColor Green

            # 1. Ensure Resource Group exists in East US
            Write-Host "      Checking/creating Resource Group '$ResourceGroupName' in '$AzureLocation'..." -ForegroundColor Gray
            $RgExists = az group exists --name $ResourceGroupName
            if ($RgExists -ne "true") {
                az group create --name $ResourceGroupName --location $AzureLocation --output none
                Write-Host "      [OK] Created Resource Group: $ResourceGroupName ($AzureLocation)" -ForegroundColor Green
            } else {
                Write-Host "      [EXISTS] Resource Group: $ResourceGroupName" -ForegroundColor DarkGray
            }

            # Check for soft-deleted Cognitive Services accounts with btai- prefix and purge to prevent collision
            $DeletedAccounts = az cognitiveservices account list-deleted --output json 2>$null | ConvertFrom-Json
            if ($DeletedAccounts) {
                foreach ($delAcc in $DeletedAccounts) {
                    if ($delAcc.name -like "btai-*-aiservices" -and $delAcc.location -eq $AzureLocation) {
                        Write-Host "      [!] Purging soft-deleted Cognitive Services account '$($delAcc.name)' for fresh deployment..." -ForegroundColor Yellow
                        az cognitiveservices account purge --location $AzureLocation --resource-group $ResourceGroupName --name $delAcc.name --output none 2>$null
                    }
                }
            }

            # 2. Deploy Bicep template
            $BicepPath = Join-Path $PSScriptRoot "azure.bicep"
            if (Test-Path $BicepPath) {
                Write-Host "      Deploying Bicep template: $BicepPath..." -ForegroundColor Yellow
                Write-Host "      (Provisions Foundry Hub, Project, and Claude 3.5 Sonnet deployment)..." -ForegroundColor Gray

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

                if ($LASTEXITCODE -ne 0) {
                    Write-Host "      [!] Azure Bicep deployment returned an error:" -ForegroundColor Red
                    Write-Host "          $DeployResultRaw" -ForegroundColor Red
                } else {
                    $Outputs = $DeployResultRaw | ConvertFrom-Json
                    $ProjectEndpoint = $Outputs.PROJECT_ENDPOINT.value
                    $LlmDeploymentName = $Outputs.LLM_DEPLOYMENT_NAME.value

                    Write-Host "      [OK] Azure AI Foundry & Model deployment completed!" -ForegroundColor Green
                    Write-Host "           PROJECT_ENDPOINT:    $ProjectEndpoint" -ForegroundColor Cyan
                    Write-Host "           LLM_DEPLOYMENT_NAME: $LlmDeploymentName" -ForegroundColor Cyan

                    # 3. Automatically write/update .env file
                    $EnvFile = Join-Path $RootDir ".env"
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
                        "# BlueTeamingAI Environment Variables",
                        "# Automatically configured by setup/setup.ps1",
                        "# =============================================================================="
                    )
                    foreach ($key in $ExistingEnv.Keys) {
                        $EnvLines += "$key=$($ExistingEnv[$key])"
                    }
                    $EnvLines | Set-Content -Path $EnvFile -Encoding utf8
                    Write-Host "      [OK] Updated $EnvFile automatically with Azure endpoints." -ForegroundColor Green
                }
            } else {
                Write-Host "      [!] Bicep file not found at: $BicepPath" -ForegroundColor Red
            }
        } else {
            Write-Host "      [!] Could not authenticate with Azure CLI. Skipping cloud deployment." -ForegroundColor Yellow
        }
    }
}

# ------------------------------------------------------------------------------
# SECTION 5: LAUNCH BACKGROUND WATCHER (Method 1: Headless pythonw.exe)
# ------------------------------------------------------------------------------
# Starts detection/watch.py in the background using pythonw.exe.
# It runs silently without a console window, consuming ~25 MB RAM and 0% CPU idle.
# ------------------------------------------------------------------------------
Write-Host "`n[5/5] Starting Live Background Watcher (Method 1)..." -ForegroundColor Yellow

$WatchScript = Join-Path $RootDir "detection\watch.py"
$VenvPythonw = Join-Path $RootDir ".venv\Scripts\pythonw.exe"
if (Test-Path $VenvPythonw) {
    $PythonwExe = $VenvPythonw
} else {
    $PythonwCmd = Get-Command pythonw.exe -ErrorAction SilentlyContinue
    $PythonwExe = if ($PythonwCmd) { $PythonwCmd.Source } else { (Get-Command python.exe).Source }
}

# Check if watcher is already running
$RunningWatcher = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*detection\watch.py*" }
if ($RunningWatcher) {
    Write-Host "      [OK] Background watcher is already running (PID: $($RunningWatcher.ProcessId))." -ForegroundColor Green
} else {
    Write-Host "      Starting headless background process ($PythonwExe)..." -ForegroundColor Gray
    Start-Process -FilePath $PythonwExe -ArgumentList "`"$WatchScript`"" -WorkingDirectory $RootDir
    Start-Sleep -Seconds 1
    $RunningWatcher = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*detection\watch.py*" }
    if ($RunningWatcher) {
        Write-Host "      [OK] Background watcher started successfully (PID: $($RunningWatcher.ProcessId))." -ForegroundColor Green
    } else {
        Write-Host "      [!] To start manually run:" -ForegroundColor Yellow
        Write-Host "          Start-Process pythonw -ArgumentList `"$WatchScript`"" -ForegroundColor Cyan
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Setup complete! Summary of configuration:" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Attack EVTX Samples in detection/test_data/:" -ForegroundColor Yellow
Get-ChildItem -Path $TestDataDir | Select-Object Name, Length | Format-Table -AutoSize

Write-Host "Sigma Detection Rules in detection/rules/:" -ForegroundColor Yellow
Get-ChildItem -Path $RulesDir | Select-Object Name, Length | Format-Table -AutoSize

$EnvFileSummary = Join-Path $RootDir ".env"
if (Test-Path $EnvFileSummary) {
    $EnvContent = Get-Content $EnvFileSummary | Where-Object { $_ -and -not $_.StartsWith("#") }
    if ($EnvContent) {
        Write-Host "Configured .env Settings:" -ForegroundColor Yellow
        $EnvContent | ForEach-Object {
            $line = $_
            if ($line -match "^([^=]+)=(.*)$") {
                $varName = $matches[1].Trim()
                $varVal = $matches[2].Trim()
                if ($varName -match "KEY|SECRET|PASSWORD|TOKEN" -and $varVal.Length -gt 6) {
                    $varVal = $varVal.Substring(0, 3) + "..." + $varVal.Substring($varVal.Length - 3)
                }
                Write-Host "  $varName=$varVal" -ForegroundColor Cyan
            } else {
                Write-Host "  $line" -ForegroundColor Cyan
            }
        }
    }
    $HasVT = Select-String -Path $EnvFileSummary -Pattern "^VT_API_KEY=.+"
    if (-not $HasVT) {
        Write-Host "`n[!] VirusTotal API key (VT_API_KEY) is not yet configured in .env." -ForegroundColor Yellow
        Write-Host "    To enable global hash reputation lookups (lookup_hash), get a free API key at virustotal.com and add:" -ForegroundColor Gray
        Write-Host "    VT_API_KEY=your_key_here" -ForegroundColor Gray
    }
}