"""
detection/watch.py - Event Processing Pipeline & Live Sysmon Listener

This module:
1. Listens continuously to live events from Microsoft-Windows-Sysmon/Operational.
2. Runs pipeline(event) on every event:
   - Stores the event in SQLite (tools/db/events.db) for 24h retention.
   - Evaluates the event against 600+ Sigma detection rules.
   - If an attack is detected, formats the alert and dispatches it with deduplication.
   - Returns 0 upon completion.
"""

from __future__ import annotations

import glob
from pathlib import Path
import sys
from typing import Any

# Ensure project root is accessible on sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agent.agent import workflow
from agent.memory import generate_thread_id
from agent.results_db import record_incomplete_verdict, check_and_mark_incomplete_threads
from detection.dispatch import dispatch_alert
from detection.record import record_event
from utils import evaluate_event, format_alert, load_rules_index, parse_event_xml

# Pre-load Sigma rules once at module import for high throughput
_RULES_DIR = _ROOT / "detection" / "rules"
RULES: list[dict[str, Any]] = list(load_rules_index(_RULES_DIR).values())


def pipeline(event: dict[str, Any]) -> int:
    """
    Process an incoming event through the complete BlueTeamingAI workflow.
    1. Stores the event in the SQLite database for historical context.
    2. Runs custom Sigma rule detection.
    3. Formats alerts and dispatches them with deduplication.
    4. Generates a new random thread ID for the investigation and stores in memory DB.
    5. Returns 0 when everything is done.
    """
    # 1. Record event in SQLite database
    record_event(event)

    # 2. Check event against populated Sigma rules
    is_detected, matches = evaluate_event(event, RULES)

    # 3. If matched, format and dispatch
    if is_detected:
        print("detected a suspicious event... calling the agent.")
        for match in matches:
            alert = format_alert(match)
            # Dispatch handles on-disk deduplication and saves to alerts.jsonl
            dispatched, _ = dispatch_alert(alert)
            if dispatched:
                # Generate a new random thread ID every time a detection occurs
                thread_id = generate_thread_id()
                alert["thread_id"] = thread_id

                initial_state = {
                    "alert": alert,
                    "sigma_rule": match.get("rule", match),
                    "plan": [],
                    "turns": 0,
                    "messages": [],
                }
                try:
                    print(f"[*] Starting agent investigation with thread_id: {thread_id}")
                    from UI.main.runner import run_alert_investigation
                    result = run_alert_investigation(thread_id, initial_state)
                    last_msg = result["messages"][-1] if result.get("messages") else None
                    if last_msg:
                        content = getattr(last_msg, "content", "")
                        tool_calls = getattr(last_msg, "tool_calls", [])
                        print(f"[+] Agent investigation completed for {thread_id}: {content or tool_calls}")
                except Exception as err:
                    print(f"[-] Agent execution error for {thread_id}: {err}")
                    try:
                        record_incomplete_verdict(
                            thread_id=thread_id,
                            alert=alert,
                            sigma_rule=match.get("rule", match),
                            end_reason=f"error: {err}",
                        )
                    except Exception:
                        pass
                finally:
                    # Automatically record run metrics to tools/db/conclusion_run.csv
                    try:
                        from record_run import auto_record_run
                        auto_record_run(thread_id)
                    except Exception as rec_err:
                        print(f"[-] Auto-record run failed for {thread_id}: {rec_err}")

    return 0


def start_listener() -> None:
    """
    Listen continuously to live events from Microsoft-Windows-Sysmon/Operational.
    Each incoming event is parsed and passed through pipeline(event).
    """
    import time
    import win32evtlog

    # Startup recovery check: find active/unfinished threads and mark incomplete
    try:
        from agent.memory import list_chat_threads
        known_threads = [t.get("thread_id") for t in list_chat_threads() if t.get("thread_id")]
        check_and_mark_incomplete_threads(known_threads)
    except Exception:
        pass

    # Ensure HITL approval and Main UI servers are listening in background
    try:
        from UI.HITL.server import start_server_in_background
        start_server_in_background()
    except Exception as e:
        print(f"[!] Warning: Could not start HITL server: {e}")

    try:
        from UI.main.server import start_server_in_background as start_main_ui
        start_main_ui()
    except Exception as e:
        print(f"[!] Warning: Could not start Main UI server: {e}")

    def _on_event(action: int, context: Any, event_handle: Any) -> None:
        if action == win32evtlog.EvtSubscribeActionDeliver:
            try:
                xml_str = win32evtlog.EvtRender(
                    event_handle, win32evtlog.EvtRenderEventXml
                )
                event_dict = parse_event_xml(xml_str)
                pipeline(event_dict)
            except Exception:
                pass

    channel = "Microsoft-Windows-Sysmon/Operational"
    try:
        query_handle = win32evtlog.EvtSubscribe(
            channel,
            win32evtlog.EvtSubscribeToFutureEvents,
            None,
            Callback=_on_event,
            Context=None,
            Query="*",
        )
    except Exception as err:
        print(f"[-] Failed to subscribe to {channel}: {err}")
        print("    Note: Subscribing to Sysmon requires Administrator privileges.")
        return

    print(f"[*] Live Sysmon listener active on channel: {channel}")
    print(f"[*] Loaded {len(RULES)} Sigma detection rules.")
    print("[*] Watching Windows activity in real time (Press Ctrl+C to stop)...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Listener stopped by user.")
    finally:
        try:
            win32evtlog.CloseEventLog(query_handle)
        except Exception:
            pass


if __name__ == "__main__":
    import argparse
    from utils import read_evtx

    parser = argparse.ArgumentParser(description="BlueTeamingAI Watcher")
    parser.add_argument(
        "--file",
        help="Path to a saved .evtx file to scan instead of live listening",
    )
    parser.add_argument(
        "--scenario",
        "-s",
        default="",
        help="Active scenario ID (e.g. A1..A10, B1..B12, S1) for automatic run logging",
    )
    args = parser.parse_args()

    if args.scenario:
        try:
            from record_run import set_current_scenario
            set_current_scenario(args.scenario)
            print(f"[*] Active scenario set for watcher: {args.scenario}")
        except Exception:
            pass

    if args.file:
        try:
            from UI.HITL.server import start_server_in_background
            start_server_in_background()
        except Exception:
            pass
        try:
            from UI.main.server import start_server_in_background as start_main_ui
            start_main_ui()
        except Exception:
            pass
        print(f"[*] Scanning file: {args.file}")
        for event in read_evtx(args.file):
            pipeline(event)
        print("[+] File processing complete.")
    else:
        start_listener()
