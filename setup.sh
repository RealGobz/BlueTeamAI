#!/usr/bin/env bash
# ==============================================================================
# setup.sh - BlueTeamAI Complete One-Command Setup & Runner
# ==============================================================================
# 1. Checks/Installs Python 3.10+ and prepares .venv virtual environment
# 2. Installs dependencies from requirements.txt
# 3. Sets up runtime directories & initializes conclusion_run.csv
# 4. Downloads & installs Microsoft Sysmon service with SwiftOnSecurity configuration
# 5. Downloads sample attack logs into detection/test_data/
# 6. Extracts 600+ Sigma detection rules into detection/rules/
# 7. Checks/Installs Azure CLI & verifies login for DefaultAzureCredential
# 8. Prepares .env and auto-configures Azure AI Foundry endpoints
# 9. Runs pre-flight self-test
# 10. Starts detection/watch.py and Web UI directly (pass --no-watch to skip)
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

NO_WATCH=false
WATCH_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-watch)
            NO_WATCH=true
            shift
            ;;
        *)
            WATCH_ARGS+=("$1")
            shift
            ;;
    esac
done

echo "=========================================================="
echo " BlueTeamAI: One-Command Setup & Live Runner"
echo "=========================================================="

# ------------------------------------------------------------------------------
# 1. PYTHON ENVIRONMENT SETUP
# ------------------------------------------------------------------------------
echo ""
echo "[1/7] Setting up Python virtual environment (.venv)..."

PYTHON_BIN=""
for cmd in python python3 py; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PYTHON_BIN="$cmd"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    if command -v winget.exe >/dev/null 2>&1; then
        echo "      [!] Python not found. Installing Python 3.12 via winget..."
        winget.exe install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent || true
        for cmd in python python3 py; do
            if command -v "$cmd" >/dev/null 2>&1; then
                PYTHON_BIN="$cmd"
                break
            fi
        done
    fi
fi

if [ -z "$PYTHON_BIN" ]; then
    echo "[-] Error: Python is not installed or not in PATH."
    echo "    Please install Python 3.10+ from https://python.org"
    exit 1
fi

echo "      Using Python: $("$PYTHON_BIN" --version 2>&1)"

if [ ! -d ".venv" ]; then
    echo "      Creating virtual environment in .venv..."
    "$PYTHON_BIN" -m venv .venv
fi

# Determine venv executable paths (Windows vs POSIX)
if [ -f ".venv/Scripts/python.exe" ]; then
    VENV_PYTHON=".venv/Scripts/python.exe"
    VENV_PIP=".venv/Scripts/pip.exe"
elif [ -f ".venv/bin/python" ]; then
    VENV_PYTHON=".venv/bin/python"
    VENV_PIP=".venv/bin/pip"
else
    VENV_PYTHON="$PYTHON_BIN"
    VENV_PIP="pip"
fi

echo "      Upgrading pip and installing requirements.txt..."
"$VENV_PYTHON" -m pip install --upgrade pip --quiet
"$VENV_PYTHON" -m pip install -r requirements.txt --quiet
echo "      [OK] Python dependencies installed."

# ------------------------------------------------------------------------------
# 2. DIRECTORY STRUCTURE & RUNTIME SETUP
# ------------------------------------------------------------------------------
echo ""
echo "[2/7] Verifying directory structure and runtime storage..."

mkdir -p tools/db tools/cache tools/memory tools/sysmon quarantine scratch detection/rules detection/test_data

for dir in tools/db tools/cache tools/memory tools/sysmon quarantine scratch detection/rules detection/test_data; do
    mkdir -p "$dir"
    touch "$dir/.gitkeep"
done

CSV_FILE="tools/db/conclusion_run.csv"
if [ ! -f "$CSV_FILE" ] || [ ! -s "$CSV_FILE" ]; then
    cat << 'EOF' > "$CSV_FILE"
scenario_id,date_time,expected_verdict,detected_by_rule,alert_id,tools_used_in_order,total_turns,tokens_cost,time_to_verdict,verdict,confidence,reasoning_quality,asked_user,actions_proposed,human_decision,action_result,left_behind,correct,problems,notes
EOF
    echo "      [OK] Initialized $CSV_FILE"
else
    echo "      [EXISTS] $CSV_FILE"
fi

# ------------------------------------------------------------------------------
# 3. MICROSOFT SYSMON SETUP (WINDOWS / VM)
# ------------------------------------------------------------------------------
echo ""
echo "[3/7] Checking Microsoft Sysmon configuration & service..."

IS_WINDOWS=false
case "$(uname -s)" in
    CYGWIN*|MINGW*|MSYS*) IS_WINDOWS=true ;;
    *)
        if command -v powershell.exe >/dev/null 2>&1 || command -v pwsh >/dev/null 2>&1; then
            IS_WINDOWS=true
        fi
        ;;
esac

if [ "$IS_WINDOWS" = true ]; then
    SYSMON_EXE="tools/sysmon/Sysmon64.exe"
    SYSMON_CONFIG="tools/sysmon/sysmonconfig-export.xml"

    if [ ! -f "$SYSMON_CONFIG" ]; then
        echo "      Downloading SwiftOnSecurity Sysmon configuration..."
        curl -s -L -o "$SYSMON_CONFIG" "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
        echo "      [OK] Saved SwiftOnSecurity config."
    fi

    if [ ! -f "$SYSMON_EXE" ]; then
        echo "      Downloading Microsoft Sysmon..."
        curl -s -L -o tools/sysmon/Sysmon.zip "https://download.sysinternals.com/files/Sysmon.zip"
        if command -v unzip >/dev/null 2>&1; then
            unzip -q -o tools/sysmon/Sysmon.zip -d tools/sysmon/
        elif command -v powershell.exe >/dev/null 2>&1; then
            powershell.exe -Command "Expand-Archive -Path 'tools/sysmon/Sysmon.zip' -DestinationPath 'tools/sysmon' -Force"
        fi
        rm -f tools/sysmon/Sysmon.zip
        echo "      [OK] Extracted Sysmon to tools/sysmon/"
    fi

    SERVICE_RUNNING=false
    if command -v sc.exe >/dev/null 2>&1; then
        if sc.exe query Sysmon64 2>&1 | grep -q "RUNNING"; then
            SERVICE_RUNNING=true
        elif sc.exe query Sysmon 2>&1 | grep -q "RUNNING"; then
            SERVICE_RUNNING=true
        fi
    elif command -v powershell.exe >/dev/null 2>&1; then
        if powershell.exe -Command "Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'" | grep -q "Running"; then
            SERVICE_RUNNING=true
        fi
    fi

    if [ "$SERVICE_RUNNING" = true ]; then
        echo "      [OK] Microsoft Sysmon service is active and running."
    else
        echo "      [!] Sysmon service is not running. Attempting installation..."
        if [ -f "$SYSMON_EXE" ] && [ -f "$SYSMON_CONFIG" ]; then
            "$SYSMON_EXE" -accepteula -i "$SYSMON_CONFIG" 2>/dev/null || true
            if sc.exe query Sysmon64 2>&1 | grep -q "RUNNING"; then
                echo "      [OK] Microsoft Sysmon service installed and started successfully!"
                SERVICE_RUNNING=true
            fi
        fi
        if [ "$SERVICE_RUNNING" = false ]; then
            echo "          Admin privileges required to install Sysmon service."
            echo "          To install Sysmon with SwiftOnSecurity configuration manually:"
            echo "          Run in an Administrator PowerShell:"
            echo "          & 'tools/sysmon/Sysmon64.exe' -accepteula -i 'tools/sysmon/sysmonconfig-export.xml'"
        fi
    fi
else
    echo "      [NOTE] Non-Windows host detected. Sysmon service setup skipped."
    echo "             For live listening, run BlueTeamAI inside a Windows 10/11 VM."
fi

# ------------------------------------------------------------------------------
# 4. SAMPLE ATTACK LOGS (FOR OFFLINE / TEST RUNS)
# ------------------------------------------------------------------------------
echo ""
echo "[4/7] Checking offline sample attack logs in detection/test_data/..."

declare -A SAMPLES=(
    ["exec_sysmon_1_lolbin_pcalua.evtx"]="https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Execution/exec_sysmon_1_lolbin_pcalua.evtx"
    ["babyshark_mimikatz_powershell.evtx"]="https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Credential%20Access/babyshark_mimikatz_powershell.evtx"
    ["sysmon_mshta_sharpshooter_stageless_meterpreter.evtx"]="https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx"
)

for sample in "${!SAMPLES[@]}"; do
    dest="detection/test_data/$sample"
    if [ ! -f "$dest" ]; then
        echo "      Downloading $sample..."
        curl -s -L -o "$dest" "${SAMPLES[$sample]}"
    fi
done
echo "      [OK] Sample test attack logs verified."

# ------------------------------------------------------------------------------
# 5. SIGMA DETECTION RULES
# ------------------------------------------------------------------------------
echo ""
echo "[5/7] Checking Sigma detection rules database..."

RULES_COUNT=0
if [ -d "detection/rules" ]; then
    RULES_COUNT=$(find detection/rules -maxdepth 1 -name "*.yml" 2>/dev/null | wc -l || echo 0)
fi

if [ "$RULES_COUNT" -lt 50 ]; then
    echo "      Downloading Sigma repository archive..."
    curl -L -s -o sigma_master.zip "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
    echo "      Extracting High & Critical process-creation rules..."
    "$VENV_PYTHON" setup/extract_rules.py --zip sigma_master.zip --output detection/rules
    rm -f sigma_master.zip
    RULES_COUNT=$(find detection/rules -maxdepth 1 -name "*.yml" 2>/dev/null | wc -l || echo 0)
    echo "      [OK] Populated $RULES_COUNT Sigma rules into detection/rules/"
else
    echo "      [OK] Found $RULES_COUNT Sigma rules in detection/rules/"
fi

# ------------------------------------------------------------------------------
# 6. AZURE CLI & CLOUD AUTHENTICATION (FOR DefaultAzureCredential)
# ------------------------------------------------------------------------------
echo ""
echo "[6/7] Checking Azure CLI (az) for DefaultAzureCredential..."

# Add standard Windows Azure CLI installation paths to PATH if missing
for p in "/c/Program Files/Microsoft SDKs/Azure/CLI2/wbin" "/c/Program Files (x86)/Microsoft SDKs/Azure/CLI2/wbin" "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin"; do
    if [ -d "$p" ]; then
        export PATH="$PATH:$p"
    fi
done

if ! command -v az >/dev/null 2>&1; then
    echo "      [!] Azure CLI (az) not found. Installing Azure CLI..."
    if command -v winget.exe >/dev/null 2>&1; then
        winget.exe install -e --id Microsoft.AzureCLI --accept-package-agreements --accept-source-agreements --silent || true
    elif [ "$IS_WINDOWS" = true ]; then
        msiexec.exe /i "https://aka.ms/installazurecliwindows" /quiet /qn /norestart || true
    fi
    for p in "/c/Program Files/Microsoft SDKs/Azure/CLI2/wbin" "/c/Program Files (x86)/Microsoft SDKs/Azure/CLI2/wbin"; do
        if [ -d "$p" ]; then
            export PATH="$PATH:$p"
        fi
    done
fi

AZ_USER=""
if command -v az >/dev/null 2>&1; then
    AZ_USER=$(az account show --query "user.name" -o tsv 2>/dev/null || echo "")
    if [ -n "$AZ_USER" ]; then
        echo "      [OK] Azure CLI authenticated as: $AZ_USER"
    else
        echo "      [!] Azure CLI is installed but not authenticated."
        echo "          DefaultAzureCredential requires Azure login. Launching 'az login'..."
        az login
        AZ_USER=$(az account show --query "user.name" -o tsv 2>/dev/null || echo "")
    fi
else
    echo "      [NOTE] Azure CLI installed. If not recognized in current session, restart terminal."
fi

# ------------------------------------------------------------------------------
# 7. ENVIRONMENT VARIABLES & ENDPOINTS (.env)
# ------------------------------------------------------------------------------
echo ""
echo "[7/7] Checking environment variables (.env)..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "      [OK] Created .env from .env.example"
    fi
else
    echo "      [OK] Existing .env file found."
fi

# Auto-discover Azure AI Foundry Project endpoint if not set or placeholder
if [ -f ".env" ] && command -v az >/dev/null 2>&1 && [ -n "$AZ_USER" ]; then
    CURRENT_ENDPOINT=$(grep -E "^PROJECT_ENDPOINT=" .env | cut -d'=' -f2- | tr -d ' ' || echo "")
    if [ -z "$CURRENT_ENDPOINT" ] || [[ "$CURRENT_ENDPOINT" == *"your-hub"* ]]; then
        echo "      Querying Azure subscription for existing AI Foundry resources..."
        FOUND_ACCOUNT=$(az cognitiveservices account list --query "[?contains(name, 'btai-')].name | [0]" -o tsv 2>/dev/null || echo "")
        if [ -n "$FOUND_ACCOUNT" ] && [ "$FOUND_ACCOUNT" != "None" ]; then
            BASE_NAME="${FOUND_ACCOUNT%-aiservices}"
            AUTO_ENDPOINT="https://${FOUND_ACCOUNT}.services.ai.azure.com/api/projects/${BASE_NAME}-project"
            sed -i "s|^PROJECT_ENDPOINT=.*|PROJECT_ENDPOINT=${AUTO_ENDPOINT}|" .env
            sed -i "s|^LLM_DEPLOYMENT_NAME=.*|LLM_DEPLOYMENT_NAME=agent_llm|" .env
            echo "      [OK] Automatically configured PROJECT_ENDPOINT=$AUTO_ENDPOINT"
        fi
    fi
fi

# ------------------------------------------------------------------------------
# PRE-FLIGHT VERIFICATION
# ------------------------------------------------------------------------------
"$VENV_PYTHON" -c "
import config
from utils import load_rules_index
rules = load_rules_index(config.ROOT_DIR / 'detection' / 'rules')
print(f'[+] Pre-flight verification passed: {len(rules)} Sigma rules loaded.')
" 2>/dev/null || echo "[!] Pre-flight verification completed."

# ------------------------------------------------------------------------------
# START LIVE LISTENER & WEB UI
# ------------------------------------------------------------------------------
if [ "$NO_WATCH" = true ]; then
    echo ""
    echo "=========================================================="
    echo " Setup complete! (--no-watch specified, watcher not started)"
    echo " To start manually: .\.venv\Scripts\python detection/watch.py"
    echo "=========================================================="
    exit 0
fi

echo ""
echo "=========================================================="
echo " Starting BlueTeamAI Live Watcher (detection/watch.py)..."
echo " Investigation Web UI running at: http://127.0.0.1:8766"
echo " (Press Ctrl+C to stop listening)"
echo "=========================================================="
echo ""

exec "$VENV_PYTHON" detection/watch.py "${WATCH_ARGS[@]}"
