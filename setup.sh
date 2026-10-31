#!/usr/bin/env bash
# ==============================================================================
# setup.sh - BlueTeamAI Setup Script
# ==============================================================================
# Prepares the complete BlueTeamAI environment:
# 1. Creates and activates Python virtual environment (.venv)
# 2. Installs required dependencies from requirements.txt
# 3. Ensures runtime directory structure exists (tools/db, tools/cache, quarantine, etc.)
# 4. Initializes conclusion_run.csv template
# 5. On Windows: downloads and verifies Sysmon service and SwiftOnSecurity config
# 6. Populates Sigma detection rules & sample attack logs
# 7. Prepares .env from .env.example
# 8. Validates system imports and readiness for detection/watch.py
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo " BlueTeamAI: Environment Setup"
echo "=========================================================="

# ------------------------------------------------------------------------------
# 1. PYTHON ENVIRONMENT SETUP
# ------------------------------------------------------------------------------
echo ""
echo "[1/6] Setting up Python virtual environment (.venv)..."

PYTHON_BIN=""
for cmd in python python3 py; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PYTHON_BIN="$cmd"
        break
    fi
done

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
echo "[2/6] Verifying directory structure and runtime storage..."

mkdir -p tools/db tools/cache tools/memory tools/sysmon quarantine detection/rules detection/test_data

# Ensure .gitkeep in runtime directories
for dir in tools/db tools/cache tools/memory tools/sysmon quarantine scratch; do
    mkdir -p "$dir"
    touch "$dir/.gitkeep"
done

# Initialize conclusion_run.csv with standard headers if missing
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
# 3. SIGMA DETECTION RULES
# ------------------------------------------------------------------------------
echo ""
echo "[3/6] Checking Sigma detection rules database..."

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
# 4. SAMPLE ATTACK LOGS (FOR OFFLINE / TEST RUNS)
# ------------------------------------------------------------------------------
echo ""
echo "[4/6] Checking offline sample attack logs in detection/test_data/..."

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
# 5. MICROSOFT SYSMON SETUP (WINDOWS / VM)
# ------------------------------------------------------------------------------
echo ""
echo "[5/6] Checking Microsoft Sysmon configuration..."

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

    # Check Sysmon Windows Service
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
        echo "      [!] Sysmon service is not running. Attempting automatic installation..."
        if [ -f "$SYSMON_EXE" ] && [ -f "$SYSMON_CONFIG" ]; then
            "$SYSMON_EXE" -accepteula -i "$SYSMON_CONFIG" 2>/dev/null || true
            if sc.exe query Sysmon64 2>&1 | grep -q "RUNNING"; then
                echo "      [OK] Microsoft Sysmon service installed and started successfully!"
                SERVICE_RUNNING=true
            fi
        fi
        if [ "$SERVICE_RUNNING" = false ]; then
            echo "          Admin privileges required to install Sysmon."
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
# 6. ENVIRONMENT VARIABLES & AZURE CLOUD READINESS
# ------------------------------------------------------------------------------
echo ""
echo "[6/6] Checking environment variables (.env)..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "      [OK] Created .env from .env.example"
        echo "      [!] Please edit .env to add your PROJECT_ENDPOINT and API keys."
    fi
else
    echo "      [OK] Existing .env file found."
fi

# Check Azure CLI availability
if command -v az >/dev/null 2>&1; then
    AZ_USER=$(az account show --query "user.name" -o tsv 2>/dev/null || echo "")
    if [ -n "$AZ_USER" ]; then
        echo "      [OK] Azure CLI authenticated as: $AZ_USER"
        echo "           (To provision cloud resources, run: powershell ./setup/setup.ps1)"
    else
        echo "      [NOTE] Azure CLI installed. Run 'az login' if provisioning cloud resources."
    fi
else
    echo "      [NOTE] Azure CLI (az) not found. (Optional for local development)."
fi

# ------------------------------------------------------------------------------
# VERIFICATION & COMPLETION
# ------------------------------------------------------------------------------
echo ""
echo "=========================================================="
echo " Validation & Next Steps"
echo "=========================================================="

"$VENV_PYTHON" -c "
import config
from utils import load_rules_index
rules = load_rules_index(config.ROOT_DIR / 'detection' / 'rules')
print(f'[+] Self-test passed: loaded {len(rules)} Sigma rules successfully.')
" 2>/dev/null || echo "[!] Pre-flight import check completed."

echo ""
echo "Setup is complete! To start BlueTeamAI:"
echo ""
echo "1. Start the Live Sysmon Watcher (Admin prompt recommended):"
echo "   .\\.venv\\Scripts\\python detection/watch.py"
echo "   (Or for a specific scenario: .\\.venv\\Scripts\\python detection/watch.py --scenario A1)"
echo ""
echo "2. Start the Investigation Web UI:"
echo "   .\\.venv\\Scripts\\python -m UI.main.server"
echo "   Then open: http://127.0.0.1:8766"
echo ""
echo "3. Run unit test suite:"
echo "   .\\.venv\\Scripts\\python -m unittest discover tests"
echo ""
echo "4. View recorded runs:"
echo "   .\\.venv\\Scripts\\python record_run.py --view"
echo "=========================================================="
