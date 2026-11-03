"""
UI/main/transcript.py - Pure transformation functions turning saved data into display items.

PURE functions: testable without a running web server.
Transforms:
- Checkpoint messages from LangGraph
- Results DB rows from results.db
- HITL DB records from hitl.db
- Audit log records from audit_kill.jsonl and audit_quarantine.jsonl

Rules:
1. Everything dynamic is treated as untrusted text.
2. System prompt message is NEVER shown.
3. AIMessage with content blocks shows ONLY text blocks, NEVER reasoning/thinking blocks.
4. AIMessage fallback with plain text shows bubble labeled "unstructured reply".
5. respond tool calls are chat bubbles on the agent side; HumanMessages are bubbles on the user side.
6. submit_verdict is NOT a tool card. When rejected, shows a small verdict_rejected chip.
   When recorded, shows the Verdict card built strictly from Results DB row.
7. kill_process / quarantine_file show target, reason, and human decision from HITL DB & audit log.
8. ask_user shows question, choices, answer, and status.
9. Tool calls paired with ToolMessage by tool_call_id.
10. Does not invent timestamps.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from config import RESULTS_DB_PATH, HITL_DB_PATH, HITL_PORT, AUDIT_LOG_PATH, QUARANTINE_AUDIT_LOG_PATH
from agent.results_db import get_verdicts_for_thread, read_audit_actions_for_thread


def extract_text_from_ai_content(content: Any) -> str:
    """
    Extract only plain text from AIMessage content.
    If content is a list of blocks (future Claude model support):
    - Extracts ONLY blocks with type 'text' or text key.
    - NEVER includes 'thinking' or 'reasoning' blocks.
    """
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        text_parts = []
        for block in content:
            if isinstance(block, str):
                text_parts.append(block)
            elif isinstance(block, dict):
                b_type = block.get("type", "")
                if b_type in ("thinking", "reasoning", "thought"):
                    continue
                if b_type == "text" and "text" in block:
                    text_parts.append(str(block["text"]))
                elif "text" in block and b_type != "thinking":
                    text_parts.append(str(block["text"]))
            elif hasattr(block, "type"):
                b_type = getattr(block, "type", "")
                if b_type in ("thinking", "reasoning"):
                    continue
                if hasattr(block, "text"):
                    text_parts.append(str(getattr(block, "text", "")))
        return "\n".join(text_parts).strip()

    return str(content or "").strip()


def parse_tool_args_display(args: Any, max_val_len: int = 300) -> dict[str, str]:
    """
    Format tool args as short key: value mappings with truncated values.
    """
    if not isinstance(args, dict):
        return {"input": str(args)[:max_val_len]}

    formatted = {}
    for k, v in args.items():
        if isinstance(v, (dict, list)):
            val_str = json.dumps(v, default=str)
        else:
            val_str = str(v)
        if len(val_str) > max_val_len:
            val_str = val_str[:max_val_len] + "..."
        formatted[k] = val_str
    return formatted


def get_hitl_requests_for_thread(thread_id: str, db_path: Path | str = HITL_DB_PATH) -> list[dict[str, Any]]:
    """
    Read all HITL requests for a thread from hitl.db.
    """
    path = Path(db_path)
    if not path.exists():
        return []

    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT request_id, thread_id, kind, status, payload_json, token,
                   decision, note, created_at, expires_at, decided_at
            FROM hitl_requests
            WHERE thread_id = ?
            ORDER BY created_at ASC
            """,
            (thread_id,),
        )
        rows = cur.fetchall()
        results = []
        for r in rows:
            req = dict(r)
            payload = {}
            if req.get("payload_json"):
                try:
                    payload = json.loads(req["payload_json"])
                except Exception:
                    payload = {}
            req["payload"] = payload
            req["tool_name"] = payload.get("tool_name")
            req["tool_args"] = payload.get("tool_args", {})
            req["target"] = payload.get("target")
            req["reason"] = payload.get("reason")
            req["question"] = payload.get("question")
            choices = payload.get("choices", [])
            req["choices"] = choices
            dec_val = req.get("decision")
            if req.get("kind") == "ask_user" and dec_val is not None and str(dec_val).isdigit() and choices:
                try:
                    c_idx = int(dec_val)
                    if 0 <= c_idx < len(choices):
                        req["answer"] = choices[c_idx]
                except Exception:
                    pass
            results.append(req)
        return results
    except Exception:
        return []
    finally:
        conn.close()


def build_timeline_items(
    thread_id: str,
    raw_messages: list[Any],
    alert_info: dict[str, Any] | None = None,
    verdicts: list[dict[str, Any]] | None = None,
    hitl_requests: list[dict[str, Any]] | None = None,
    audit_actions: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Pure transformation function turning thread data into an ordered list of UI display items.
    """
    items: list[dict[str, Any]] = []

    alert_info = alert_info or {}
    verdicts = verdicts or []
    hitl_requests = hitl_requests or []
    audit_actions = audit_actions or []

    # Map tool results by tool_call_id
    tool_results: dict[str, Any] = {}
    for m in raw_messages:
        m_type = getattr(m, "type", "")
        if m_type == "tool" or type(m).__name__ == "ToolMessage":
            tc_id = getattr(m, "tool_call_id", None)
            if tc_id:
                tool_results[tc_id] = m

    # 1. Alert Card (first in timeline)
    if alert_info:
        event = alert_info.get("event") or alert_info
        alert_item = {
            "id": f"alert_{thread_id}",
            "type": "alert",
            "timestamp": alert_info.get("timestamp") or event.get("UtcTime") or event.get("timestamp"),
            "title": alert_info.get("rule_name") or alert_info.get("title") or "Security Alert",
            "level": str(alert_info.get("severity") or alert_info.get("level") or "unknown").lower(),
            "host": event.get("computer_name") or event.get("Computer") or alert_info.get("host", ""),
            "user": event.get("user") or event.get("User") or alert_info.get("user", ""),
            "process_name": event.get("image") or event.get("Image") or "",
            "command_line": event.get("command_line") or event.get("CommandLine") or "",
            "raw_alert": json.dumps(alert_info, indent=2, default=str),
        }
        items.append(alert_item)

    # 2. Iterate through messages in chronological order
    for idx, msg in enumerate(raw_messages):
        msg_type = getattr(msg, "type", type(msg).__name__.lower().replace("message", ""))

        # System prompt is NEVER shown
        if msg_type == "system" or type(msg).__name__ == "SystemMessage":
            continue

        # Human message -> user chat bubble
        if msg_type in ("human", "user") or type(msg).__name__ == "HumanMessage":
            text = getattr(msg, "content", "")
            items.append({
                "id": getattr(msg, "id", None) or f"user_msg_{idx}",
                "type": "chat_bubble",
                "timestamp": getattr(msg, "response_metadata", {}).get("timestamp"),
                "sender": "user",
                "text": str(text),
                "unstructured": False,
            })
            continue

        # AI Message
        if msg_type in ("ai", "assistant") or type(msg).__name__ == "AIMessage":
            tool_calls = getattr(msg, "tool_calls", None) or []

            # If no tool calls: fallback plain-text AIMessage
            if not tool_calls:
                text = extract_text_from_ai_content(getattr(msg, "content", ""))
                if text:
                    items.append({
                        "id": getattr(msg, "id", None) or f"ai_msg_{idx}",
                        "type": "chat_bubble",
                        "timestamp": getattr(msg, "response_metadata", {}).get("timestamp"),
                        "sender": "agent",
                        "text": text,
                        "unstructured": True,
                    })
                continue

            # Process each tool call in the AIMessage
            for tc_idx, tc in enumerate(tool_calls):
                tc_id = tc.get("id") or f"call_{idx}_{tc_idx}"
                name = tc.get("name", "")
                args = tc.get("args") or {}

                # A. respond tool call -> agent chat bubble (NOT a tool card)
                if name == "respond":
                    text = str(args.get("text", ""))
                    items.append({
                        "id": tc_id,
                        "type": "chat_bubble",
                        "timestamp": None,
                        "sender": "agent",
                        "text": text,
                        "unstructured": False,
                    })
                    continue

                # B. plan tool call -> Plan card
                if name == "plan":
                    steps = args.get("steps", [])
                    if isinstance(steps, str):
                        steps = [s.strip() for s in steps.split("\n") if s.strip()]
                    elif not isinstance(steps, list):
                        steps = [str(steps)]
                    items.append({
                        "id": tc_id,
                        "type": "plan",
                        "timestamp": None,
                        "steps": steps,
                    })
                    continue

                # C. submit_verdict -> NOT a tool card
                if name == "submit_verdict":
                    # Check if result was rejected_invalid
                    t_msg = tool_results.get(tc_id)
                    if t_msg:
                        content_str = getattr(t_msg, "content", "")
                        try:
                            res_obj = json.loads(content_str)
                            if res_obj.get("status") == "rejected_invalid":
                                items.append({
                                    "id": f"rejected_{tc_id}",
                                    "type": "verdict_rejected",
                                    "timestamp": None,
                                    "errors": res_obj.get("errors", ["Verdict rejected, retrying"]),
                                })
                        except Exception:
                            pass
                    continue

                # Pair with ToolMessage result
                t_msg = tool_results.get(tc_id)
                res_content = getattr(t_msg, "content", "") if t_msg else ""
                res_obj = None
                try:
                    res_obj = json.loads(res_content) if res_content else None
                except Exception:
                    pass

                # D. kill_process / quarantine_file -> Action card
                if name in ("kill_process", "quarantine_file"):
                    target = str(args.get("guid") or args.get("path") or "")
                    reason = str(args.get("reason") or "")

                    # Find corresponding HITL decision & audit details
                    decision = "unknown"
                    result_status = "waiting"
                    details = ""
                    norm_target = target.strip().strip("{}").lower()

                    # Correlate from hitl_requests
                    matched_req = None
                    for hr in hitl_requests:
                        if hr.get("tool_name") == name:
                            hr_args = hr.get("tool_args", {})
                            hr_tgt = str(hr.get("target") or hr_args.get("guid") or hr_args.get("path") or "").strip().strip("{}").lower()
                            if hr_tgt == norm_target or norm_target in hr_tgt or hr_tgt in norm_target:
                                matched_req = hr
                                break

                    if matched_req:
                        decision = matched_req.get("decision") or matched_req.get("status") or "pending"
                        if matched_req.get("note"):
                            details = matched_req["note"]

                    # Inspect direct tool result (ground truth from conversation state)
                    if isinstance(res_obj, dict):
                        res_status = res_obj.get("status", "")
                        if res_status in ("killed", "quarantined", "dry_run"):
                            decision = "approved" if res_status != "dry_run" else "dry_run"
                            result_status = res_status
                            details = res_obj.get("reason") or details
                        elif res_status == "rejected_by_user":
                            if decision != "approved":
                                decision = "rejected"
                            result_status = "rejected_by_user"
                            details = res_obj.get("reason") or details
                        elif res_status in ("not_allowed_target", "blocked_protected", "invalid_input", "not_found"):
                            decision = "blocked"
                            result_status = res_status
                            details = res_obj.get("reason") or details
                        else:
                            result_status = res_status
                            if not details:
                                details = res_obj.get("reason", "")

                    # Correlate from audit log (latest first to capture final outcome)
                    for act in reversed(audit_actions):
                        act_target = str(act.get("target") or "").strip().strip("{}").lower()
                        if act.get("tool") == name and (act_target == norm_target or norm_target in act_target or act_target in norm_target):
                            act_dec = act.get("decision")
                            if act_dec == "approved" or decision in ("unknown", "pending"):
                                decision = act_dec or decision
                                result_status = act.get("result", result_status)
                                if act.get("details"):
                                    details = act["details"]
                            if act.get("dry_run"):
                                decision = "dry_run"
                                result_status = "dry_run"
                            break

                    if decision == "unknown" and result_status in ("not_allowed_target", "blocked_protected", "invalid_input", "not_found"):
                        decision = "blocked"

                    approval_url = None
                    if matched_req and decision == "pending" and matched_req.get("token"):
                        approval_url = f"http://127.0.0.1:{HITL_PORT}/r/{matched_req['request_id']}?t={matched_req['token']}"

                    items.append({
                        "id": tc_id,
                        "type": "action",
                        "timestamp": None,
                        "tool_name": name,
                        "target": target,
                        "reason": reason,
                        "decision": decision,
                        "result": result_status,
                        "details": details,
                        "approval_url": approval_url,
                    })
                    continue

                # E. ask_user -> question, choices, answer
                if name == "ask_user":
                    question = str(args.get("question", ""))
                    choices = args.get("choices") or []
                    answer = None
                    ask_status = "pending"

                    if isinstance(res_obj, dict):
                        ask_status = res_obj.get("status", "pending")
                        answer = res_obj.get("answer")

                    for hr in hitl_requests:
                        if hr.get("kind") == "ask_user":
                            hr_args = hr.get("tool_args", {})
                            if hr_args.get("question") == question:
                                if hr.get("status") == "decided":
                                    hr_res = hr.get("result", {})
                                    answer = hr_res.get("answer") or hr.get("decision")
                                    ask_status = "answered"
                                elif hr.get("status") == "expired":
                                    ask_status = "expired"

                    items.append({
                        "id": tc_id,
                        "type": "ask_user",
                        "timestamp": None,
                        "question": question,
                        "choices": choices,
                        "answer": answer,
                        "status": ask_status,
                    })
                    continue

                # F. Normal tool call card
                status_chip = "ok"
                if not t_msg:
                    status_chip = "waiting"
                elif isinstance(res_obj, dict):
                    st = res_obj.get("status")
                    if st == "not_executed":
                        status_chip = "not_executed"
                    elif st in ("invalid_input", "failed", "error"):
                        status_chip = "error"
                    elif st == "rejected_by_user":
                        status_chip = "rejected"
                    elif st in ("recorded", "found", "ok", "restored", "plan_recorded"):
                        status_chip = "ok"

                preview_len = 600
                full_len = 4000
                res_preview = res_content[:preview_len] + ("..." if len(res_content) > preview_len else "")
                res_full = res_content[:full_len] + ("..." if len(res_content) > full_len else "")

                items.append({
                    "id": tc_id,
                    "type": "tool",
                    "timestamp": None,
                    "tool_name": name,
                    "args": parse_tool_args_display(args),
                    "status": status_chip,
                    "result_preview": res_preview,
                    "result_full": res_full,
                })

    # 3. Verdict Cards from Results DB
    if verdicts:
        # User questions from HITL requests for footer/summary
        user_questions_list = []
        for hr in hitl_requests:
            if hr.get("kind") == "ask_user":
                hr_args = hr.get("tool_args", {})
                hr_res = hr.get("result", {})
                user_questions_list.append({
                    "question": hr_args.get("question", ""),
                    "answer": hr_res.get("answer") or hr.get("decision") or "No answer",
                })

        # Count distinct tools used in thread
        tool_names_set = set()
        for itm in items:
            if itm["type"] == "tool":
                tool_names_set.add(itm["tool_name"])
            elif itm["type"] == "action":
                tool_names_set.add(itm["tool_name"])

        total_verdicts = len(verdicts)
        for v_idx, v in enumerate(verdicts):
            is_superseded = v_idx < (total_verdicts - 1)
            raw_v = v.get("verdict")
            status = v.get("status", "closed")

            headline_badge = "Needs more info"
            if status == "incomplete":
                headline_badge = "Incomplete"
            elif raw_v == "true_positive":
                headline_badge = "Real attack"
            elif raw_v == "false_positive":
                headline_badge = "False alarm"
            elif raw_v == "needs_more_info":
                headline_badge = "Needs more info"

            # Compute duration from alert timestamp to verdict created_at if possible
            duration_sec = None
            alert_ts = alert_info.get("timestamp") or (alert_info.get("event") or {}).get("UtcTime")
            verdict_ts = v.get("created_at")
            if alert_ts and verdict_ts:
                try:
                    from datetime import datetime
                    dt_start = datetime.fromisoformat(str(alert_ts).replace("Z", "+00:00"))
                    dt_end = datetime.fromisoformat(str(verdict_ts).replace("Z", "+00:00"))
                    duration_sec = max(0, int((dt_end - dt_start).total_seconds()))
                except Exception:
                    duration_sec = None

            run_facts = v.get("run_facts") or {}
            turns_completed = run_facts.get("turns", 0)

            items.append({
                "id": v.get("verdict_id") or f"verdict_{v.get('revision', 1)}",
                "type": "verdict",
                "timestamp": v.get("created_at"),
                "revision": v.get("revision", 1),
                "supersedes": v.get("supersedes"),
                "superseded": is_superseded,
                "verdict": raw_v,
                "headline_badge": headline_badge,
                "confidence": v.get("confidence"),
                "severity": v.get("severity"),
                "category": v.get("category"),
                "summary": v.get("summary") or "Investigation completed",
                "explanation": v.get("explanation") or "",
                "evidence": v.get("evidence") or [],
                "assumptions": v.get("assumptions") or [],
                "not_checked": v.get("not_checked") or [],
                "recommended_next_steps": v.get("recommended_next_steps") or [],
                "benign_explanation": v.get("benign_explanation"),
                "missing_info": v.get("missing_info"),
                "remaining_risk": v.get("remaining_risk"),
                "threat_active": v.get("threat_active"),
                "actions": v.get("actions") or audit_actions,
                "user_questions": user_questions_list,
                "footer": {
                    "revision": v.get("revision", 1),
                    "duration_seconds": duration_sec,
                    "turns": turns_completed,
                    "tool_count": len(tool_names_set),
                },
            })

    return items


def summarize_thread(
    thread_id: str,
    checkpoint_values: dict[str, Any] | None = None,
    latest_verdict: dict[str, Any] | None = None,
    active_run: dict[str, Any] | None = None,
    pending_hitl_count: int = 0,
) -> dict[str, Any]:
    """
    Produce a concise summary object for the left sidebar thread listing.
    """
    checkpoint_values = checkpoint_values or {}
    alert = checkpoint_values.get("alert") or {}
    rule = checkpoint_values.get("sigma_rule") or {}
    event = alert.get("event") or alert

    title = alert.get("rule_name") or rule.get("title") or alert.get("title") or "Unknown Alert"
    level = str(alert.get("severity") or rule.get("level") or "unknown").lower()
    host = event.get("computer_name") or event.get("Computer") or alert.get("host") or ""
    user = event.get("user") or event.get("User") or alert.get("user") or ""

    # Status: working / waiting for you / done / incomplete
    if active_run:
        status = "working"
    elif pending_hitl_count > 0:
        status = "waiting_human"
    elif latest_verdict:
        status = "incomplete" if latest_verdict.get("status") == "incomplete" else "done"
    else:
        status = "incomplete"

    v_val = latest_verdict.get("verdict") if latest_verdict else None
    conf_val = latest_verdict.get("confidence") if latest_verdict else None
    sev_val = latest_verdict.get("severity") if latest_verdict else None

    updated_at = None
    if latest_verdict and latest_verdict.get("created_at"):
        updated_at = latest_verdict.get("created_at")
    elif alert.get("timestamp"):
        updated_at = alert.get("timestamp")

    return {
        "thread_id": thread_id,
        "title": title,
        "level": level,
        "host": host,
        "user": user,
        "status": status,
        "verdict": v_val,
        "confidence": conf_val,
        "severity": sev_val,
        "updated_at": updated_at,
    }
