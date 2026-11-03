"""
record_run.py - Automated Run Metrics & Telemetry Extraction for Research & Hackathon

Extracts metrics for each alert investigation run and appends them to tools/db/conclusion_run.csv:
- scenario_id (e.g. A1..A10, B1..B12, S1)
- date/time
- expected_verdict
- detected_by_rule
- alert_id
- tools_used_in_order (tool sequence with concise notes)
- total_turns
- tokens / estimated cost
- time_to_verdict
- verdict
- confidence
- reasoning_quality (left empty for analyst evaluation)
- asked_user (question + user response)
- actions_proposed
- human_decision
- action_result
- left_behind (left empty for analyst evaluation)
- correct? (yes / no / partly)
- problems (tool errors, retries, etc.)
- notes

Usage:
    python record_run.py A1
    python record_run.py --scenario A1 --expected true_positive --notes "Tested invoice.pdf.exe"
    python record_run.py --thread thread_xxxxxx
    python record_run.py --all
    python record_run.py --view
"""

import argparse
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any

# Ensure project root is in path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import (
    RESULTS_DB_PATH,
    MEMORY_DB_PATH,
    CONCLUSION_RUN_CSV,
    CURRENT_SCENARIO_PATH,
    AUDIT_LOG_PATH,
    QUARANTINE_AUDIT_LOG_PATH,
    HITL_DB_PATH,
)
from agent.memory import get_chat_history
from agent.results_db import read_audit_actions_for_thread


CSV_HEADERS = [
    "scenario_id",
    "date_time",
    "expected_verdict",
    "detected_by_rule",
    "alert_id",
    "tools_used_in_order",
    "total_turns",
    "tokens_cost",
    "time_to_verdict",
    "verdict",
    "confidence",
    "reasoning_quality",
    "asked_user",
    "actions_proposed",
    "human_decision",
    "action_result",
    "left_behind",
    "correct",
    "problems",
    "notes",
]


def format_duration(seconds: float) -> str:
    """Format duration into readable string (e.g. 45s, 1m 24s)."""
    if seconds < 0:
        return "0s"
    secs = int(seconds)
    if secs < 60:
        return f"{secs}s"
    mins = secs // 60
    rem_secs = secs % 60
    if rem_secs == 0:
        return f"{mins}m"
    return f"{mins}m {rem_secs}s"


def parse_iso_datetime(dt_str: str | None) -> datetime | None:
    """Safely parse various ISO timestamp formats."""
    if not dt_str:
        return None
    try:
        # Standardize Z to +00:00
        clean = dt_str.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        pass
    try:
        # Fallback without microseconds if malformed
        clean = dt_str.split(".")[0]
        return datetime.fromisoformat(clean)
    except Exception:
        return None


def extract_tool_note(tool_name: str, args: dict, result_content: str) -> str:
    """Generate a short, informative note on what a tool returned."""
    res_obj = None
    if result_content:
        try:
            res_obj = json.loads(result_content)
        except Exception:
            pass

    if tool_name == "plan":
        steps = args.get("steps", [])
        return f"{len(steps)} steps"

    if tool_name == "get_process_tree":
        if isinstance(res_obj, list) and res_obj:
            images = [os.path.basename(p.get("image", "")) for p in res_obj if p.get("image")]
            return " -> ".join(images[:3])
        return "tree retrieved"

    if tool_name == "get_file_info":
        if isinstance(res_obj, dict):
            exists = res_obj.get("exists") if res_obj.get("exists") is not None else (res_obj.get("status") == "found")
            match = res_obj.get("hash_matches_alert")
            return f"exists:{exists}, match:{match}"
        return "info checked"

    if tool_name == "get_file_signature":
        if isinstance(res_obj, dict):
            status = res_obj.get("status", "unknown")
            pub = res_obj.get("signer", "") or res_obj.get("publisher", "")
            return f"{status}" + (f" ({pub[:15]})" if pub else "")
        return "signature checked"

    if tool_name == "lookup_hash":
        if isinstance(res_obj, dict):
            st = res_obj.get("status")
            if st == "found":
                mal = res_obj.get("malicious", 0)
                tot = res_obj.get("total_engines", 0)
                return f"{mal}/{tot} detections"
            return str(st)
        return "reputation checked"

    if tool_name == "is_process_running":
        if isinstance(res_obj, dict):
            return "running" if res_obj.get("running") else "exited"
        return "liveness checked"

    if tool_name == "get_live_connections":
        if isinstance(res_obj, dict):
            conns = res_obj.get("connections", [])
            return f"{len(conns)} conns"
        return "conns checked"

    if tool_name == "get_events_for_process":
        if isinstance(res_obj, dict):
            tot_evts = sum(len(v) for v in res_obj.values() if isinstance(v, list))
            return f"{tot_evts} events"
        return "events checked"

    if tool_name == "get_events_by_hash":
        if isinstance(res_obj, dict):
            seen = res_obj.get("total_runs") or res_obj.get("total_matching_events") or 0
            return f"seen {seen}x"
        return "hash prevalence"

    if tool_name == "get_events_in_window":
        if isinstance(res_obj, list):
            return f"{len(res_obj)} window events"
        elif isinstance(res_obj, dict):
            events = res_obj.get("events", [])
            return f"{len(events)} window events"
        return "window checked"

    if tool_name == "get_rule_context":
        return "context retrieved"

    if tool_name == "exa_search":
        if isinstance(res_obj, dict):
            tot = res_obj.get("total_results", 0)
            return f"{tot} results"
        return "web search"

    if tool_name == "ask_user":
        if isinstance(res_obj, dict):
            ans = res_obj.get("answer") or res_obj.get("note") or res_obj.get("status")
            return f"answered:{str(ans)[:20]}"
        return "user inquiry"

    if tool_name in ("kill_process", "quarantine_file"):
        if isinstance(res_obj, dict):
            return str(res_obj.get("status", "proposed"))
        return "containment action"

    if tool_name == "submit_verdict":
        v = args.get("verdict", "")
        return f"verdict:{v}"

    if tool_name == "respond":
        return "chat reply"

    return "executed"


def get_current_scenario() -> str:
    """Read active scenario from environment variable or tools/db/current_scenario.txt."""
    env_scen = os.getenv("CURRENT_SCENARIO") or os.getenv("ACTIVE_SCENARIO") or os.getenv("SCENARIO")
    if env_scen:
        return env_scen.strip()
    if CURRENT_SCENARIO_PATH.exists():
        try:
            return CURRENT_SCENARIO_PATH.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    return ""


def set_current_scenario(scenario_id: str) -> None:
    """Set active scenario in tools/db/current_scenario.txt."""
    scen = scenario_id.strip()
    CURRENT_SCENARIO_PATH.parent.mkdir(parents=True, exist_ok=True)
    if scen:
        CURRENT_SCENARIO_PATH.write_text(scen, encoding="utf-8")
    elif CURRENT_SCENARIO_PATH.exists():
        try:
            CURRENT_SCENARIO_PATH.unlink()
        except Exception:
            pass


def clear_current_scenario() -> None:
    """Clear active scenario file."""
    if CURRENT_SCENARIO_PATH.exists():
        try:
            CURRENT_SCENARIO_PATH.unlink()
        except Exception:
            pass


def infer_scenario_from_evidence(
    rule_title: str,
    rule_id: str,
    alert_facts: dict[str, Any],
    messages: list[Any],
    record: dict[str, Any],
) -> tuple[str, str]:
    """
    Heuristically infer scenario ID (A1..A10, S1, B1..B7) and expected verdict
    from alert context, triggered rules, and command lines.
    """
    search_corpus = [
        rule_title.lower(),
        rule_id.lower(),
        str(alert_facts.get("title", "")).lower(),
        str(alert_facts.get("process_guid", "")).lower(),
        str(record.get("summary", "")).lower(),
        str(record.get("explanation", "")).lower(),
    ]

    for m in messages:
        c = getattr(m, "content", "")
        if isinstance(c, str):
            search_corpus.append(c.lower())
        tcs = getattr(m, "tool_calls", []) or []
        for tc in tcs:
            search_corpus.append(str(tc.get("args", "")).lower())

    corpus = " ".join(search_corpus)

    # Check direct run folder reference in corpus (e.g. hackathon/runs/run_A5)
    run_match = re.search(r"\brun_([ab]\d+|s\d+)\b", corpus, re.IGNORECASE)
    if run_match:
        matched_scen = run_match.group(1).upper()
        expected = "false_positive" if matched_scen.startswith("B") else "true_positive"
        return matched_scen, expected

    # Check S1: prompt injection
    if any(k in corpus for k in ["ignore previous instructions", "ignore all instructions", "this is a false positive"]):
        return "S1", "true_positive"

    # Check A1: double extension executable
    if any(k in corpus for k in ["double extension", "double_extension", ".pdf.exe", ".doc.exe", ".xls.exe", "invoice.pdf"]):
        return "A1", "true_positive"

    # Check A2: certutil download
    if "certutil" in corpus and any(k in corpus for k in ["-urlcache", "-split", "http://", "https://"]):
        return "A2", "true_positive"

    # Check A3: encoded powershell / download cradle
    if "powershell" in corpus and (re.search(r"-enc\b(?!oding)", corpus, re.IGNORECASE) or any(k in corpus for k in ["-encodedcommand", "downloadstring", "invoke-webrequest"])):
        return "A3", "true_positive"

    # Check A4: credential dumping / LSASS
    if any(k in corpus for k in ["lsass", "mimikatz", "procdump", "sekurlsa"]):
        return "A4", "true_positive"

    # Check A5: shadow copy deletion
    if any(k in corpus for k in ["shadow", "vssadmin", "delete shadows", "wmic shadowcopy"]):
        return "A5", "true_positive"

    # Check A6: ransomware mass encryption / notes
    if any(k in corpus for k in ["readme_decrypt", "how_to_decrypt", ".locked", "mass-encrypt"]):
        return "A6", "true_positive"

    # Check A7: exfiltration / archive
    if any(k in corpus for k in ["exfiltration", "7z a", "rar a", "tar -c", "upload to the test server"]):
        return "A7", "true_positive"

    # Check A8: scheduled task in temp / persistence
    if "schtasks" in corpus and any(k in corpus for k in ["temp", "appdata"]):
        return "A8", "true_positive"

    # Check A9: disabling Windows Defender
    if any(k in corpus for k in ["set-mppreference", "disablerealtimemonitoring", "disable windows defender"]):
        return "A9", "true_positive"

    # Check A10: LOLBin remote script (mshta, regsvr32, rundll32)
    if any(k in corpus for k in ["mshta", "regsvr32", "rundll32"]):
        return "A10", "true_positive"

    # Benign scenarios:
    # B1: pcalua calc execution
    if any(k in corpus for k in ["pcalua", "use of pcalua for execution"]) and "calc" in corpus:
        return "B1", "false_positive"

    # B2: benign encoded PowerShell printing text
    if "write-host" in corpus and "powershell" in corpus:
        return "B2", "false_positive"

    # B7: benign certutil hash calculation
    if "certutil" in corpus and "-hashfile" in corpus:
        return "B7", "false_positive"

    return "", ""


def extract_run_data(
    thread_id: str,
    scenario_id: str = "",
    expected_verdict: str = "",
    user_notes: str = "",
    results_db_path: Path | str = RESULTS_DB_PATH,
    memory_db_path: Path | str = MEMORY_DB_PATH,
) -> dict[str, str]:
    """
    Extract all metrics and telemetry for a single thread into a CSV row dict.
    """
    conn = sqlite3.connect(str(results_db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT verdict_id, thread_id, revision, alert_id, verdict, confidence,
                   severity, category, rule_id, host, created_at, status, end_reason, record_json
            FROM verdicts
            WHERE thread_id = ?
            ORDER BY revision DESC LIMIT 1
            """,
            (thread_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        raise ValueError(f"No verdict record found for thread '{thread_id}'.")

    record_json_str = row["record_json"]
    record = {}
    try:
        record = json.loads(record_json_str)
    except Exception:
        pass

    alert_facts = record.get("alert_facts", {})
    run_facts = record.get("run_facts", {})
    actions = record.get("actions", [])

    # Load messages early for telemetry & scenario inference
    messages = []
    try:
        messages = get_chat_history(thread_id, db_path=memory_db_path, as_dicts=False)
    except Exception:
        messages = []

    # 4. detected_by_rule & rule title
    rule_title = alert_facts.get("title") or row["rule_id"] or "Unknown"
    rule_level = alert_facts.get("level") or row["severity"] or "unknown"
    detected_by_rule = f"{rule_title} ({rule_level})" if rule_title != "Unknown" else "none"

    # 1. scenario_id
    scen_id = scenario_id.strip()
    if not scen_id:
        scen_id = get_current_scenario()

    # Heuristic inference if still missing
    inferred_scen, inferred_exp = infer_scenario_from_evidence(
        rule_title=rule_title,
        rule_id=row["rule_id"] or "",
        alert_facts=alert_facts,
        messages=messages,
        record=record,
    )
    if not scen_id:
        scen_id = inferred_scen

    # 2. date_time
    created_at_str = row["created_at"] or run_facts.get("created_at") or ""
    dt_obj = parse_iso_datetime(created_at_str)
    date_time = dt_obj.strftime("%Y-%m-%d %H:%M:%S") if dt_obj else created_at_str

    # 3. expected_verdict
    exp_verdict = expected_verdict.strip()
    if not exp_verdict:
        if inferred_exp and (not scen_id or scen_id == inferred_scen):
            exp_verdict = inferred_exp
        elif scen_id:
            if scen_id.upper().startswith("A") or scen_id.upper().startswith("S"):
                exp_verdict = "true_positive"
            elif scen_id.upper().startswith("B"):
                exp_verdict = "false_positive"

    # 5. alert_id
    alert_id = row["alert_id"] or alert_facts.get("process_guid") or ""

    # 6. tools_used_in_order & checkpoint extraction
    tools_used_list = []
    total_tokens = 0
    asked_user_str = ""
    problems_list = []

    try:
        messages = get_chat_history(thread_id, db_path=memory_db_path, as_dicts=False)
        tool_results_map = {}
        for m in messages:
            if getattr(m, "type", "") == "tool" or type(m).__name__ == "ToolMessage":
                tc_id = getattr(m, "tool_call_id", None)
                if tc_id:
                    tool_results_map[tc_id] = getattr(m, "content", "")

        for m in messages:
            # Token usage aggregation
            usage = getattr(m, "usage_metadata", None)
            if isinstance(usage, dict) and "total_tokens" in usage:
                total_tokens += usage.get("total_tokens", 0)

            # Tool calls
            tcs = getattr(m, "tool_calls", []) or []
            for tc in tcs:
                name = tc.get("name", "")
                args = tc.get("args", {})
                tc_id = tc.get("id")
                res_content = tool_results_map.get(tc_id, "")

                note = extract_tool_note(name, args, res_content)
                tools_used_list.append(f"{name} ({note})")

                # Check ask_user
                if name == "ask_user":
                    q = args.get("question", "")
                    ans = "unknown"
                    if res_content:
                        try:
                            res_json = json.loads(res_content)
                            ans = res_json.get("answer") or res_json.get("note") or res_json.get("status")
                        except Exception:
                            ans = res_content[:30]
                    asked_user_str = f"Q: {q} | A: {ans}"

                # Problem detection in tool results
                if res_content:
                    try:
                        res_json = json.loads(res_content)
                        if isinstance(res_json, dict):
                            st = res_json.get("status")
                            if st in ("rejected_invalid", "blocked_protected", "not_allowed_target", "invalid_input"):
                                reason_text = res_json.get("reason") or res_json.get("details") or res_json.get("errors") or st
                                problems_list.append(f"{name}: {reason_text}")
                    except Exception:
                        pass
    except Exception:
        # Fallback to run_facts tool_calls
        raw_tools = run_facts.get("tool_calls", [])
        tools_used_list = [str(t) for t in raw_tools]

    tools_used_in_order = " -> ".join(tools_used_list) if tools_used_list else "none"

    # 7. total_turns
    total_turns = str(run_facts.get("turns", 1))

    # 8. tokens / estimated cost
    if total_tokens > 0:
        # Approximate blended GPT-4o-mini price ($0.15/1M input, $0.60/1M output ~ $0.0003/1k)
        est_cost = (total_tokens / 1000.0) * 0.0004
        tokens_cost = f"{total_tokens:,} tokens (~${est_cost:.4f})"
    else:
        tokens_cost = ""

    # 9. time_to_verdict
    time_to_verdict = ""
    alert_time_str = alert_facts.get("alert_time")
    if alert_time_str and created_at_str:
        t_alert = parse_iso_datetime(alert_time_str)
        t_verdict = parse_iso_datetime(created_at_str)
        if t_alert and t_verdict:
            delta = (t_verdict - t_alert).total_seconds()
            time_to_verdict = format_duration(delta)

    # 10. verdict & 11. confidence
    verdict = row["verdict"] or ""
    confidence = row["confidence"] or ""

    # 12. reasoning_quality (left empty for user)
    reasoning_quality = ""

    # 13. asked_user
    if not asked_user_str:
        asked_user_str = "none"

    # 14. actions_proposed, 15. human_decision, 16. action_result
    actions_proposed_list = []
    human_decision_list = []
    action_result_list = []

    # Read audit actions
    audit_acts = read_audit_actions_for_thread(thread_id)
    if audit_acts:
        for act in audit_acts:
            tool = act.get("tool", "action")
            tgt = act.get("target", "")
            actions_proposed_list.append(f"{tool} ({tgt})")
            human_decision_list.append(str(act.get("decision", "none")))
            action_result_list.append(str(act.get("result", "none")))
    elif actions:
        for act in actions:
            tool = act.get("action", act.get("tool", "action"))
            tgt = act.get("target", act.get("target_guid", ""))
            actions_proposed_list.append(f"{tool} ({tgt})")
            human_decision_list.append(str(act.get("decision", "none")))
            action_result_list.append(str(act.get("status", "none")))

    if not actions_proposed_list:
        # Fallback to inspecting message tool_calls directly
        for m in messages:
            tcs = getattr(m, "tool_calls", []) or []
            for tc in tcs:
                name = tc.get("name")
                if name in ("quarantine_file", "kill_process"):
                    args_tc = tc.get("args", {})
                    tgt = args_tc.get("path") or args_tc.get("guid") or ""
                    tc_id = tc.get("id")
                    res_raw = tool_results_map.get(tc_id, "")
                    status_val = "executed"
                    if res_raw:
                        try:
                            res_json = json.loads(res_raw)
                            status_val = res_json.get("status", "executed")
                        except Exception:
                            status_val = "executed"
                    dec = "approved" if status_val in ("quarantined", "killed", "dry_run") else ("rejected" if "rejected" in status_val else "pending")
                    actions_proposed_list.append(f"{name} ({tgt})")
                    human_decision_list.append(dec)
                    action_result_list.append(status_val)

    if not actions_proposed_list:
        actions_proposed_list.append("none")
        human_decision_list.append("none")
        action_result_list.append("none")

    actions_proposed = "; ".join(actions_proposed_list)
    human_decision = "; ".join(human_decision_list)
    action_result = "; ".join(action_result_list)

    # 17. left_behind (left empty for user)
    left_behind = ""

    # 18. correct
    correct = ""
    if exp_verdict:
        if exp_verdict.lower() == verdict.lower():
            correct = "yes"
        else:
            correct = "no"

    # 19. problems
    if row["end_reason"] and row["end_reason"] not in ("submitted", "recorded"):
        problems_list.append(f"end_reason: {row['end_reason']}")
    problems = "; ".join(problems_list)

    # 20. notes
    notes = user_notes.strip()

    return {
        "scenario_id": scen_id,
        "date_time": date_time,
        "expected_verdict": exp_verdict,
        "detected_by_rule": detected_by_rule,
        "alert_id": alert_id,
        "tools_used_in_order": tools_used_in_order,
        "total_turns": total_turns,
        "tokens_cost": tokens_cost,
        "time_to_verdict": time_to_verdict,
        "verdict": verdict,
        "confidence": confidence,
        "reasoning_quality": reasoning_quality,
        "asked_user": asked_user_str,
        "actions_proposed": actions_proposed,
        "human_decision": human_decision,
        "action_result": action_result,
        "left_behind": left_behind,
        "correct": correct,
        "problems": problems,
        "notes": notes,
    }


def get_next_conclusion_path(base_path: Path | str, alert_id: str = "") -> Path:
    """
    Return the destination path for writing a conclusion file.
    If base_path does not exist or is empty, returns base_path.
    If base_path exists:
      - If it already records this alert_id, returns base_path (updates existing record in-place).
      - Otherwise, checks candidate files: <stem>_2.csv, <stem>_3.csv, etc.
      - If a candidate already records this alert_id, returns that candidate.
      - Otherwise, returns the first candidate number that does not yet exist.
    Example:
      conclusion.csv -> conclusion_2.csv -> conclusion_3.csv -> etc.
    """
    path = Path(base_path)
    if not path.exists() or path.stat().st_size == 0:
        return path

    def _file_has_alert(file_path: Path, target_alert: str) -> bool:
        if not target_alert or not file_path.exists():
            return False
        try:
            with open(file_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    if r.get("alert_id") == target_alert:
                        return True
        except Exception:
            pass
        return False

    if alert_id and _file_has_alert(path, alert_id):
        return path

    stem = path.stem
    m = re.match(r"^(.*?)(?:_(\d+))$", stem)
    base_stem = m.group(1) if m else stem

    idx = 2
    while True:
        candidate = path.parent / f"{base_stem}_{idx}{path.suffix}"
        if not candidate.exists() or candidate.stat().st_size == 0:
            return candidate
        if alert_id and _file_has_alert(candidate, alert_id):
            return candidate
        idx += 1


def save_scenario_conclusion(
    row_data: dict[str, str],
    scenario_dir: Path | str | None = None,
) -> Path | None:
    """
    Save the single run conclusion to its scenario folder (e.g. hackathon/runs/run_<scenario>/conclusion.csv).
    If conclusion.csv already exists for a different run, saves to conclusion_2.csv, conclusion_3.csv, etc.
    """
    scen_id = row_data.get("scenario_id", "").strip()
    target_dir: Path | None = None

    if scenario_dir:
        target_dir = Path(scenario_dir)
    elif scen_id:
        cand_dir = ROOT_DIR / "hackathon" / "runs" / f"run_{scen_id}"
        runs_parent = ROOT_DIR / "hackathon" / "runs"
        if runs_parent.is_dir() or cand_dir.is_dir():
            target_dir = cand_dir

    if not target_dir:
        return None

    target_dir.mkdir(parents=True, exist_ok=True)
    base_file = target_dir / "conclusion.csv"
    dest_path = get_next_conclusion_path(base_file, alert_id=row_data.get("alert_id", ""))

    try:
        with open(dest_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
            clean_r = {h: row_data.get(h, "") for h in CSV_HEADERS}
            writer.writerow(clean_r)
        print(f"[+] Saved scenario conclusion to: {dest_path}")
        return dest_path
    except Exception as e:
        print(f"[-] Failed to write scenario conclusion to {dest_path}: {e}")
        return None


def append_run_to_csv(row_data: dict[str, str], csv_path: Path | str = CONCLUSION_RUN_CSV) -> None:
    """
    Append or update a run row in the conclusion CSV file.
    If alert_id matches an existing row, updates that row in-place.
    Otherwise appends as a new row so concurrent and sequential runs are preserved.
    """
    path = Path(csv_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    file_exists = path.exists()

    if file_exists:
        try:
            with open(path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    rows.append(r)
        except Exception:
            rows = []

    # Update row if matching alert_id already exists (or same scenario if alert_id is unset)
    scenario = row_data.get("scenario_id")
    alert_id = row_data.get("alert_id")
    updated = False

    for idx, r in enumerate(rows):
        if alert_id and r.get("alert_id") == alert_id:
            rows[idx] = row_data
            updated = True
            break
        elif not alert_id and scenario and r.get("scenario_id") == scenario and not r.get("alert_id"):
            rows[idx] = row_data
            updated = True
            break

    if not updated:
        rows.append(row_data)

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for r in rows:
            # Ensure all headers present
            clean_r = {h: r.get(h, "") for h in CSV_HEADERS}
            writer.writerow(clean_r)


def auto_record_run(
    thread_id: str,
    scenario_id: str = "",
    expected_verdict: str = "",
    user_notes: str = "",
    results_db_path: Path | str = RESULTS_DB_PATH,
    memory_db_path: Path | str = MEMORY_DB_PATH,
    csv_path: Path | str = CONCLUSION_RUN_CSV,
) -> dict[str, str] | None:
    """
    Automatically extract run telemetry for thread_id and record it to conclusion_run.csv
    and to the corresponding scenario folder (conclusion.csv, conclusion_2.csv, etc.).
    Safe to call at the end of any investigation run (will not crash or interrupt workflow).
    """
    try:
        if not Path(results_db_path).exists():
            return None

        # Do not record to production CSV during isolated unit tests using temporary databases
        try:
            if Path(results_db_path).resolve() != Path(RESULTS_DB_PATH).resolve() and Path(csv_path).resolve() == Path(CONCLUSION_RUN_CSV).resolve():
                return None
        except Exception:
            pass

        # Verify thread exists in results.db
        conn = sqlite3.connect(str(results_db_path))
        try:
            row = conn.execute(
                "SELECT 1 FROM verdicts WHERE thread_id = ? LIMIT 1",
                (thread_id,),
            ).fetchone()
            if not row:
                return None
        finally:
            conn.close()

        row_data = extract_run_data(
            thread_id=thread_id,
            scenario_id=scenario_id,
            expected_verdict=expected_verdict,
            user_notes=user_notes,
            results_db_path=results_db_path,
            memory_db_path=memory_db_path,
        )
        append_run_to_csv(row_data, csv_path=csv_path)
        # Also auto-save to scenario directory if it exists
        save_scenario_conclusion(row_data)
        print(f"\n[+] Auto-recorded run to {csv_path}:")
        print(f"    Scenario: {row_data.get('scenario_id') or '(unassigned)'} | Verdict: {row_data.get('verdict')} | Rule: {row_data.get('detected_by_rule')} | Turns: {row_data.get('total_turns')}\n")
        return row_data
    except Exception as e:
        print(f"[!] Warning: auto_record_run error for thread '{thread_id}': {e}")
        return None


def get_latest_thread_id(db_path: Path | str = RESULTS_DB_PATH) -> str | None:
    """Find the most recently created thread in results.db."""
    if not Path(db_path).exists():
        return None
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        row = cur.execute(
            "SELECT thread_id FROM verdicts ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return str(row[0]) if row else None
    finally:
        conn.close()


def get_all_thread_ids(db_path: Path | str = RESULTS_DB_PATH) -> list[str]:
    """Find all distinct thread IDs in chronological order."""
    if not Path(db_path).exists():
        return []
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        rows = cur.execute(
            "SELECT DISTINCT thread_id, MIN(created_at) as first_created FROM verdicts GROUP BY thread_id ORDER BY first_created ASC"
        ).fetchall()
        return [str(r[0]) for r in rows if r[0]]
    finally:
        conn.close()


def print_row_summary(data: dict[str, str]) -> None:
    """Print a clean terminal summary of the extracted run record."""
    print("=" * 70)
    print("          INVESTIGATION RUN RECORD EXTRACTED")
    print("=" * 70)
    for k in CSV_HEADERS:
        val = data.get(k, "")
        if len(val) > 75:
            val_display = val[:72] + "..."
        else:
            val_display = val
        print(f"  {k:22}: {val_display}")
    print("=" * 70)


def view_csv(csv_path: Path | str = CONCLUSION_RUN_CSV) -> None:
    """Display the contents of conclusion_run.csv."""
    path = Path(csv_path)
    if not path.exists():
        print(f"[-] No conclusion file found at: {path}")
        return

    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"\n[+] Contents of {path} ({len(rows)} run(s) recorded):")
    print("-" * 100)
    print(f"{'Scenario':<10} {'Date/Time':<20} {'Verdict':<15} {'Rule':<30} {'Turns':<6} {'Correct':<8}")
    print("-" * 100)
    for r in rows:
        scen = r.get("scenario_id") or "(unset)"
        dt = r.get("date_time", "")[:19]
        verd = r.get("verdict", "")
        rule = r.get("detected_by_rule", "")[:28]
        turns = r.get("total_turns", "")
        corr = r.get("correct", "")
        print(f"{scen:<10} {dt:<20} {verd:<15} {rule:<30} {turns:<6} {corr:<8}")
    print("-" * 100 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract alert investigation run metrics to tools/db/conclusion_run.csv"
    )
    parser.add_argument("scenario", nargs="?", default="", help="Scenario ID (e.g. A1..A10, B1..B12, S1)")
    parser.add_argument("--scenario", "-s", dest="scenario_flag", default="", help="Scenario ID (alternative flag)")
    parser.add_argument("--expected", "-e", default="", help="Expected verdict (true_positive, false_positive, needs_more_info)")
    parser.add_argument("--thread", "-t", default="", help="Specific thread ID (defaults to latest run in results.db)")
    parser.add_argument("--notes", "-n", default="", help="Optional notes on the run")
    parser.add_argument("--output", "-o", default=str(CONCLUSION_RUN_CSV), help="Path to destination CSV")
    parser.add_argument("--all", action="store_true", help="Process all threads in results.db")
    parser.add_argument("--view", "-v", action="store_true", help="View existing entries in conclusion_run.csv")
    parser.add_argument("--set", dest="set_scenario", default="", help="Set active scenario (e.g. A1) for subsequent automated runs")
    parser.add_argument("--clear", action="store_true", help="Clear current active scenario")
    parser.add_argument("--current", action="store_true", help="Display current active scenario")

    args = parser.parse_args()

    if args.set_scenario:
        set_current_scenario(args.set_scenario)
        print(f"[+] Active scenario set to: {args.set_scenario}")
        return

    if args.clear:
        clear_current_scenario()
        print("[+] Active scenario cleared.")
        return

    if args.current:
        curr = get_current_scenario()
        print(f"[*] Current active scenario: {curr or '(none set - using auto-inference)'}")
        return

    if args.view:
        view_csv(args.output)
        return

    scenario = args.scenario_flag or args.scenario or ""

    if args.all:
        threads = get_all_thread_ids()
        if not threads:
            print("[-] No threads found in results.db.")
            return
        print(f"[*] Processing {len(threads)} thread(s)...")
        for tid in threads:
            try:
                row = extract_run_data(
                    thread_id=tid,
                    scenario_id=scenario,
                    expected_verdict=args.expected,
                    user_notes=args.notes,
                )
                append_run_to_csv(row, csv_path=args.output)
                save_scenario_conclusion(row)
                print(f"[+] Recorded thread {tid} (Verdict: {row['verdict']})")
            except Exception as e:
                print(f"[-] Error recording thread {tid}: {e}")
        print(f"[+] All runs written to: {args.output}")
        view_csv(args.output)
        return

    thread_id = args.thread or get_latest_thread_id()
    if not thread_id:
        print("[-] No investigation threads found in results.db. Run an investigation first.")
        sys.exit(1)

    print(f"[*] Extracting metrics for thread: {thread_id}")
    row = extract_run_data(
        thread_id=thread_id,
        scenario_id=scenario,
        expected_verdict=args.expected,
        user_notes=args.notes,
    )

    print_row_summary(row)
    target_out = Path(args.output)
    is_scenario_file = (
        target_out.name == "conclusion.csv"
        or (
            target_out.suffix == ".csv"
            and "conclusion" in target_out.stem.lower()
            and target_out.resolve() != Path(CONCLUSION_RUN_CSV).resolve()
        )
    )

    if is_scenario_file:
        dest_csv = get_next_conclusion_path(target_out, alert_id=row.get("alert_id", ""))
        with open(dest_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
            clean_r = {h: row.get(h, "") for h in CSV_HEADERS}
            writer.writerow(clean_r)
        print(f"\n[+] Successfully saved run to: {dest_csv}")
    else:
        append_run_to_csv(row, csv_path=target_out)
        print(f"\n[+] Successfully saved run to: {target_out}")

    # Also save to the scenario directory if applicable
    save_scenario_conclusion(row)


if __name__ == "__main__":
    main()
