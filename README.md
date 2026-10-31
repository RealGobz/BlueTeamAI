# BlueTeamAI 🛡️

**Autonomous Blue Team Security Investigator Agent for Windows Endpoint Defense**

BlueTeamAI is an autonomous, agentic cybersecurity analyst designed to investigate, triage, and mitigate Windows endpoint security alerts in real time. Built with **LangGraph**, **Microsoft Sysmon**, **Sigma Detection Rules**, and **Azure AI Foundry**, BlueTeamAI bridges the gap between raw detection and actionable, evidence-backed security decisions.

---

## 🚀 Key Capabilities

- **Real-Time Detection & Event Streaming**: Ingests and parses live Windows event logs via Microsoft Sysmon with 24-hour historical event correlation.
- **600+ Sigma Rules Built-In**: Pre-compiled and indexed open-source Sigma detection rules for high and critical process-creation behaviors.
- **Autonomous Forensic Investigation**: Guided by an investigative playbook with 12 distinct tools:
  - Process tree & ancestry reconstruction (`get_process_tree`, `get_children`)
  - Historical process event queries & prevalence checks (`get_events_for_process`, `get_events_by_hash`)
  - Incident window temporal correlation (`get_events_in_window`)
  - On-disk binary inspection & hash matching (`get_file_info`)
  - Authenticode digital signature verification (`get_file_signature`)
  - Live process liveness & network socket inspection (`is_process_running`, `get_live_connections`)
  - Global reputation lookups via VirusTotal (`lookup_hash`)
  - Threat intelligence & LOLBAS research via Exa AI (`exa_search`)
- **Strict Evidence Validation & Anti-Hallucination**: Verdicts must cite evidence directly derived from executed tools. Revisions are versioned in an append-only database.
- **Human-In-The-Loop (HITL) Containment Gate**: Critical containment actions (`kill_process`, `quarantine_file`) require operator approval, with built-in OS protection for core Windows binaries.
- **Interactive Chat Web UI**: Real-time investigation timeline, live event cards, HITL approvals, and interactive operator chat on `http://127.0.0.1:8766`.
- **Automated Research Telemetry**: Generates evaluation metrics (turns, token costs, duration, tools used, verdict accuracy) into `tools/db/conclusion_run.csv`.

---

## 🏛️ System Architecture

```text
[ Microsoft-Windows-Sysmon ]
           │ (Live Event Stream)
           ▼
[ detection/watch.py ] ──► [ detection/record.py ] ──► tools/db/events.db (24h Retention)
           │
           ├─► Custom Sigma Engine (619 Rules)
           │          │
           │          ▼ (Alert Matched)
           │   [ agent/agent.py (LangGraph) ]
           │          │
           │          ├─► Forensic Tools (Tree, Signatures, VT, Exa AI, Sockets)
           │          ├─► Human-In-The-Loop Gate (kill_process, quarantine_file)
           │          └─► Verdict Engine (Strict Evidence & Anti-Hallucination)
           ▼
[ UI/main/server.py ] ◄──► [ tools/db/results.db ] + [ tools/db/conclusion_run.csv ]
   (Web Dashboard & Chat)
```

---

## 📋 Prerequisites

1. **Operating System**: Windows 10, Windows 11, or Windows Server (or Windows inside a VM such as VMware/VirtualBox).
2. **Permissions**: Administrator privileges (required to listen to the live Sysmon event channel).
3. **Python**: Python 3.10 or higher.
4. **Azure AI Foundry Account**: An Azure subscription with access to Azure AI Foundry (Claude 3.5 Sonnet or GPT-4o).

---

## ⚡ Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/RealGobz/BlueTeamAI.git
cd BlueTeamAI
```

### 2. Run Setup
Run `setup.sh` in Git Bash (or `setup.ps1` in PowerShell):
```bash
# In Git Bash:
bash setup.sh

# Or in an Administrator PowerShell:
.\setup.ps1
```
The setup script automatically:
- Creates the `.venv` virtual environment and installs all dependencies.
- Sets up runtime directories (`tools/db`, `tools/cache`, `tools/memory`, `quarantine`).
- Downloads and starts Microsoft Sysmon with SwiftOnSecurity configuration.
- Verifies 600+ Sigma detection rules and sample attack logs.
- Prepares your `.env` configuration file.

### 3. Configure Credentials (`.env`)
Copy `.env.example` to `.env` if not already created, and configure your Azure AI Foundry endpoint:
```env
# Azure AI Foundry Configuration
PROJECT_ENDPOINT=https://<your-hub>-aiservices.services.ai.azure.com/api/projects/<your-project>
LLM_DEPLOYMENT_NAME=agent_llm

# External Threat Intelligence (Optional)
VT_API_KEY=your_virustotal_api_key
EXAAI_SEARCH_API_KEY=your_exa_api_key

# UI & Safety Settings
HITL_MODE=web
HITL_PORT=8765
UI_MAIN_PORT=8766
DRY_RUN=false
```

---

## 🔍 Running BlueTeamAI

### Start the Live Watcher
In an **Administrator** console:
```bash
.\.venv\Scripts\python detection/watch.py
```
To tag investigations for a specific test scenario (e.g. `A1`):
```bash
.\.venv\Scripts\python detection/watch.py --scenario A1
```

### Open the Investigation Web UI
The watcher automatically starts the UI server in the background, or you can launch it independently:
```bash
.\.venv\Scripts\python -m UI.main.server
```
Visit **http://127.0.0.1:8766** to view real-time investigation threads, inspect tool outputs, respond to operator inquiries, and chat with the agent.

---

## 🧪 Testing & Evaluation

### Offline Simulation (Replay Pre-Recorded Attack Logs)
Scan pre-recorded Sysmon `.evtx` logs without live execution:
```bash
.\.venv\Scripts\python detection/watch.py --file detection/test_data/exec_sysmon_1_lolbin_pcalua.evtx
```

### Run Full Test Suite
Run all unit tests across the detection pipeline, forensic tools, verdict validation, and web UI:
```bash
.\.venv\Scripts\python -m unittest discover tests
```

### View Evaluated Runs
Review all recorded investigations and metrics extracted for your report:
```bash
.\.venv\Scripts\python record_run.py --view
```

---

## 📂 Repository Structure

```text
├── agent/                  # LangGraph autonomous agent workflow
│   ├── agent.py            # Graph definition, nodes, routers
│   ├── memory.py           # SqliteSaver checkpointer & thread history
│   ├── results_db.py       # Append-only verdicts database (results.db)
│   ├── verdict.py          # Structured verdict validation & evidence checking
│   └── tools/              # Forensic tool implementations
│       └── tools.py        # 12 forensic investigation tools + containment
├── detection/              # Detection engine & Sysmon listener
│   ├── watch.py            # Event pipeline & live Sysmon listener
│   ├── dispatch.py         # Alert deduplication & dispatcher
│   ├── record.py           # 24h SQLite event retention (events.db)
│   ├── rules/              # 600+ Sigma detection YAML rules
│   └── test_data/          # Sample attack .evtx logs
├── UI/                     # User interface servers & static assets
│   ├── HITL/               # Human-In-The-Loop approval server (port 8765)
│   └── main/               # Investigation dashboard & chat UI (port 8766)
├── setup/                  # Cloud infrastructure & deployment automation
│   ├── azure.bicep         # Azure AI Foundry & Model deployment Bicep template
│   ├── extract_rules.py    # Sigma rule archive extraction utility
│   └── setup.ps1           # PowerShell environment setup script
├── hackathon/              # Research & scenario testing documentation
│   └── hackathon plan.md   # Lab attack matrix (A1..A10, B1..B12, S1)
├── record_run.py           # Automated telemetry extraction script
├── config.py               # Global settings, paths, and system prompts
├── utils.py                # Sysmon XML parser, Sigma evaluator, hash helpers
├── requirements.txt        # Python package dependencies
├── setup.sh                # Universal bash setup script
└── .env.example            # Environment configuration template
```

---

## 📄 License
This project is licensed under the Apache License 2.0.
