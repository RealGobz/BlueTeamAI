"""
UI/HITL/dev_trigger.py - Manual Developer Testing CLI for Human-In-The-Loop UI

Allows testing the local web UI, approval pages, decision recording, and notifications
in complete isolation without needing to run the full detection pipeline or agent.

Usage:
    python -m UI.HITL.dev_trigger --kind kill
    python -m UI.HITL.dev_trigger --kind quarantine --open
    python -m UI.HITL.dev_trigger --kind continue --open --notify
"""

import argparse
import sys
import uuid

from config import (
    HITL_PORT,
    HITL_DB_PATH,
    DRY_RUN,
)
from UI.HITL.server import (
    start_server_in_background,
    request_tool_approval,
    request_continue,
)


def run_trigger() -> None:
    parser = argparse.ArgumentParser(description="Trigger test HITL approval requests for manual UI verification.")
    parser.add_argument(
        "--kind",
        choices=["kill", "quarantine", "continue"],
        default="kill",
        help="Type of request to simulate (kill, quarantine, or continue).",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Automatically open the request URL in your default browser.",
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Send a Windows toast notification.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=HITL_PORT,
        help=f"Local server port (default: {HITL_PORT}).",
    )
    args = parser.parse_args()

    # Ensure background server is started
    start_server_in_background(port=args.port, db_path=HITL_DB_PATH)

    thread_id = f"dev_thread_{uuid.uuid4().hex[:8]}"

    if args.open:
        import config
        config.HITL_OPEN_BROWSER = True

    if args.kind == "kill":
        sample_guid = "{12345678-abcd-ef01-2345-6789abcdef01}"
        screen_text = (
            "================================================================================\n"
            "                 [HUMAN-IN-THE-LOOP] PROCESS TERMINATION PROPOSAL\n"
            "================================================================================\n"
            f">>> [!] {'DRY RUN MODE ACTIVE' if DRY_RUN else 'LIVE EXECUTION MODE'} [!] <<<\n"
            "--------------------------------------------------------------------------------\n"
            "ALERT CONTEXT:\n"
            "  Alert Title:  Suspicious PowerShell Encoded Command Execution\n"
            "  Severity:     HIGH\n\n"
            "TARGET PROCESS:\n"
            f"  Process GUID: {sample_guid}\n"
            "  PID:          9824\n"
            "  Image Path:   C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "  Command Line: powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==\n"
            "  User:         SYSTEM\n"
            "  Start Time:   2026-10-31 11:20:00.000\n"
            "  Live Status:  RUNNING (PID 9824)\n\n"
            "AGENT PROPOSAL & EVIDENCE:\n"
            "  Reason:       Base64 encoded payload executed from scheduled task, initiating C2 socket.\n\n"
            "CONSEQUENCES & SCOPE:\n"
            "  - Stops this single process only. Cannot be undone.\n"
            "  - Does NOT remove dropped files, startup keys, or scheduled tasks.\n"
            "================================================================================"
        )
        print(f"[*] Triggering dev kill_process request on thread {thread_id}...")
        res = request_tool_approval(
            thread_id=thread_id,
            tool_name="kill_process",
            tool_args={
                "guid": sample_guid,
                "reason": "Base64 encoded payload executed from scheduled task, initiating C2 socket.",
            },
            alert={"title": "Suspicious PowerShell Encoded Command", "level": "HIGH"},
            rule={"title": "Suspicious PowerShell Execution", "level": "HIGH"},
            approval_screen=screen_text,
            port=args.port,
            timeout=300,
        )
        print(f"[+] Result received: {res}")

    elif args.kind == "quarantine":
        sample_path = "C:\\Users\\Public\\malicious_dropper.exe"
        screen_text = (
            "================================================================================\n"
            "                 [HUMAN-IN-THE-LOOP] FILE QUARANTINE PROPOSAL\n"
            "================================================================================\n"
            f">>> [!] {'DRY RUN MODE ACTIVE' if DRY_RUN else 'LIVE EXECUTION MODE'} [!] <<<\n"
            "--------------------------------------------------------------------------------\n"
            "ALERT CONTEXT:\n"
            "  Alert Title:     Suspicious Executable Dropped in Public Directory\n"
            "  Severity:        CRITICAL\n\n"
            "TARGET FILE DETAILS:\n"
            f"  Path:            {sample_path}\n"
            "  Exists on Disk:  True\n"
            "  Size:            48,128 bytes\n"
            "  SHA256:          E7837FE45EA0B740D1F95C3D2E94D8769EB3B9D6299F3565820C976CC16AC9EC\n\n"
            "AGENT PROPOSAL & EVIDENCE:\n"
            "  Reason:          File dropped by PowerShell script, VirusTotal 52/70 detection.\n\n"
            "CONSEQUENCES & SCOPE:\n"
            "  - Moves file to locked quarantine folder and renames with .quarantine extension.\n"
            "  - Does NOT delete the file; can be restored by human analyst.\n"
            "================================================================================"
        )
        print(f"[*] Triggering dev quarantine_file request on thread {thread_id}...")
        res = request_tool_approval(
            thread_id=thread_id,
            tool_name="quarantine_file",
            tool_args={
                "path": sample_path,
                "reason": "File dropped by PowerShell script, VirusTotal 52/70 detection.",
            },
            alert={"title": "Executable Dropped in Public Directory", "level": "CRITICAL"},
            rule={"title": "Suspicious File Drop", "level": "CRITICAL"},
            approval_screen=screen_text,
            port=args.port,
            timeout=300,
        )
        print(f"[+] Result received: {res}")

    elif args.kind == "continue":
        print(f"[*] Triggering dev continue_turns request on thread {thread_id}...")
        res = request_continue(
            thread_id=thread_id,
            turns=5,
            turn_limit=5,
            continues=1,
            max_continues=3,
            plan=[
                "1. Investigate parent process lineage",
                "2. Check live socket connections",
                "3. Perform VirusTotal hash lookup",
                "4. Determine containment strategy",
            ],
            tools_used=["get_process_tree", "get_children", "get_events_for_process", "lookup_hash"],
            last_message="I have confirmed the parent process spawned multiple suspicious children, but I need additional turns to inspect the network connections.",
            port=args.port,
            timeout=300,
        )
        print(f"[+] Result received: {res}")


if __name__ == "__main__":
    run_trigger()
