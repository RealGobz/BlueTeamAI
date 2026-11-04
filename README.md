# Triagent

> **"What if every alert came with an answer?"**  
> *An AI security analyst that investigates Windows alerts, and asks before it acts.*

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6.svg)](https://www.microsoft.com/windows)
[![Engine: LangGraph](https://img.shields.io/badge/Agent-LangGraph-FF6F00.svg)](https://github.com/langchain-ai/langgraph)
[![Research: Benchmark](https://img.shields.io/badge/Research-10%20Scenario%20Benchmark-brightgreen.svg)](https://realgobz.github.io/Triagent-Research/)

Triagent is an autonomous, agentic cybersecurity analyst designed to investigate, triage, and remediate Windows endpoint security alerts in real time. Operating locally on the endpoint, Triagent bridges the gap between raw detection and evidence-backed triage by executing deep forensic investigations, validating digital signatures, correlating process trees, and consulting a human operator before taking critical containment actions.

---

## ⚡ Quick Start (For Judges & Evaluators)

To start Triagent from a clean clone, open **PowerShell as Administrator** and run:

```powershell
# 1. Clone the repository
git clone https://github.com/RealGobz/Triagent.git
cd Triagent

# 2. Run the all-in-one setup launcher
.\setup.bat
```

> [!NOTE]
> `setup.bat` (or `powershell -ExecutionPolicy Bypass -File .\setup.ps1`) is **fully autonomous**:
> 1. Creates `.venv` and installs all dependencies (`requirements.txt`).
> 2. Downloads, configures, and starts **Microsoft Sysmon** with the SwiftOnSecurity detection configuration.
> 3. Indexes 600+ open-source **Sigma detection rules**.
> 4. Connects to Azure AI Foundry via Azure CLI (`az login` if needed) and **automatically fills `.env`**.
> 5. **Directly starts the live event watcher and Web UI** on [http://127.0.0.1:8766](http://127.0.0.1:8766)!

Once running, visit **[http://127.0.0.1:8766](http://127.0.0.1:8766)** in your browser to view the live investigation dashboard, review forensic tool executions, and interact directly with the agent.

---

## 🏛️ How It Works

Triagent operates in three streamlined phases:

```text
Detection (Sysmon + Sigma) ──► Agent Forensics (LangGraph + Tools) ──► Verdict & HITL in Web UI
```

1. **Detection**: Microsoft Sysmon streams endpoint events into a local 24-hour event retention database. A native Sigma engine continuously matches incoming process-creation telemetry against 600+ threat detection rules.
2. **Agent Forensics**: When a rule fires, Triagent formulates an investigation plan and autonomously executes specialized forensic tools:
   - Reconstructs full process ancestry and descendant process trees (`get_process_tree`, `get_children`).
   - Verifies Microsoft Authenticode digital signatures on disk binaries (`get_file_signature`).
   - Correlates incident time windows and local hash prevalence (`get_events_in_window`, `get_events_by_hash`).
   - Inspects active process liveness and open network sockets (`is_process_running`, `get_live_connections`).
   - Queries global threat intelligence (VirusTotal & Exa AI) and Sigma rule logic context.
3. **Verdict & HITL Containment**: Triagent constructs an evidence-grounded verdict (`true_positive` vs `false_positive`). If high-impact containment is required (e.g. `kill_process` or `quarantine_file`), the agent halts and requests operator approval via interactive desktop and Web UI Human-in-the-Loop (HITL) prompts.

---

## ⚙️ Configuration (`.env`)

The setup script automatically populates your `.env` configuration file with your Azure project endpoint and UI ports.

```env
# Automatically configured by setup script:
PROJECT_ENDPOINT=https://<your-hub>-aiservices.services.ai.azure.com/api/projects/<your-project>
LLM_DEPLOYMENT_NAME=agent_llm
HITL_MODE=web
HITL_PORT=8765
UI_MAIN_PORT=8766
DRY_RUN=false

# Optional external threat intelligence (add manually if available):
VT_API_KEY=your_virustotal_api_key
EXAAI_SEARCH_API_KEY=your_exa_api_key
```

*(External keys for VirusTotal and Exa AI are optional; if omitted, Triagent gracefully uses local file inspection, digital signatures, hash prevalence, and rule context).*

---

## 🔍 Running Triagent Manually

If you have already run the setup script and wish to start components independently:

### 1. Start the Live Event Watcher
In an **Administrator** console:
```powershell
.\.venv\Scripts\python detection/watch.py
```
*(The watcher listens to live Sysmon telemetry, triggers investigations upon rule detection, and automatically starts the Web UI server in the background).*

### 2. Open the Web Dashboard
Visit **[http://127.0.0.1:8766](http://127.0.0.1:8766)** to monitor active threads, review timeline evidence, answer agent clarification queries, and approve or reject remediation actions.

To run the Web UI independently:
```powershell
.\.venv\Scripts\python -m UI.main.server
```

---

## 📊 Research Benchmark & Evaluation

Triagent was rigorously evaluated across 10 controlled scenarios (5 real-world attack simulations and 5 benign administrative false alarms):

- **Attack Accuracy**: **70.0%** (3 Yes, 1 Partial weighted at 0.5, 1 No out of 5 attacks)
- **Benign Resolution**: **100.0%** (5 of 5 false alarms safely cleared, 0 wrongly escalated)
- **Median Time to Verdict**: **52.0 seconds**
- **Average Cost per Investigation**: **$0.1358**

For full technical details, video demonstrations, and downloadable simulation scripts:
- 🌐 **Live Research Webpage**: [https://realgobz.github.io/Triagent-Research/](https://realgobz.github.io/Triagent-Research/)
- 📄 **Research Paper (PDF)**: [Triagent-Research-Paper.pdf](https://realgobz.github.io/Triagent-Research/Triagent-Research-Paper.pdf)

---

## 🧪 Running Unit Tests

To run the test suite across the detection pipeline, forensic tools, verdict verification, and UI servers:

```powershell
.\.venv\Scripts\python -m unittest discover tests
```

---

## 📂 Repository Layout

```text
├── agent/                  # LangGraph autonomous agent workflow & nodes
│   ├── agent.py            # Graph definition, router logic, and execution steps
│   ├── memory.py           # SqliteSaver checkpointer & thread history
│   ├── results_db.py       # Append-only verdicts database
│   ├── verdict.py          # Structured verdict validation & evidence checking
│   └── tools/              # 12 forensic investigation & response tools
├── detection/              # Detection engine & live Sysmon pipeline
│   ├── watch.py            # Live Sysmon channel listener
│   ├── dispatch.py         # Alert deduplication & dispatcher
│   ├── record.py           # 24-hour SQLite event retention (events.db)
│   └── rules/              # 600+ compiled Sigma detection rules
├── UI/                     # User interface servers & static assets
│   ├── HITL/               # Human-in-the-loop approval server (port 8765)
│   ├── main/               # Investigation dashboard & chat UI (port 8766)
│   └── brand/              # Triagent brand design tokens & vector logos
├── setup.bat               # Windows all-in-one launcher
├── setup.ps1               # Automated setup & environment configuration
└── requirements.txt        # Python package dependencies
```

---

## 📄 License
This project is licensed under the Apache License 2.0.
