"""
agent/verdict.py - Structured Verdict Validation & Processing

Validates agent verdict submissions according to strict Blue Team rules:
- Valid enums, character limits, list bounds, and plain text sanitization (no HTML)
- Conditional field requirements based on verdict choice and revision
- Consistency checks (severity, evidence direction, high-confidence dual evidence)
- Pre-verdict investigation verification (at least 2 distinct investigation tools)
- Evidence source verification (tool must have actually been called in thread)
- Hallucinated indicator detection (indicators must exist in alert or tool results)
- Retry limits: 2 retries allowed; on 3rd failure, records fallback 'invalid_output'
"""

import json
import os
import re
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from config import (
    RESULTS_DB_PATH,
    AUDIT_LOG_PATH,
    QUARANTINE_AUDIT_LOG_PATH,
    PROMPT_VERSION,
    CODE_VERSION,
    DRY_RUN,
)
from agent.results_db import (
    insert_verdict,
    get_verdicts_for_thread,
    read_audit_actions_for_thread,
)

# Allowed Enum Values
VERDICT_CHOICES = {"true_positive", "false_positive", "needs_more_info"}
CONFIDENCE_CHOICES = {"low", "medium", "high"}
SEVERITY_CHOICES = {"none", "low", "medium", "high", "critical"}
CATEGORY_CHOICES = {
    "malware_execution",
    "persistence",
    "credential_theft",
    "ransomware_activity",
    "data_exfiltration",
    "defense_evasion",
    "remote_access",
    "recon",
    "benign_admin",
    "benign_software",
    "benign_other",
    "unknown",
}
DIRECTION_CHOICES = {"suspicious", "benign", "neutral"}
THREAT_ACTIVE_CHOICES = {"active", "inactive", "unknown"}

# Known forensic investigation tools that count toward "investigate before concluding"
INVESTIGATION_TOOLS = {
    "get_process_tree",
    "get_children",
    "get_events_for_process",
    "get_events_in_window",
    "get_events_by_hash",
    "get_rule_context",
    "get_file_info",
    "get_file_signature",
    "is_process_running",
    "get_live_connections",
    "lookup_hash",
    "exa_search",
}


def sanitize_plain_text(text: Any) -> str:
    """
    Sanitize text to plain text:
    - Strips control characters (retaining newlines, tabs)
    - Strips HTML tags (<...>)
    - Converts markdown links [label](url) to label
    """
    if not isinstance(text, str):
        text = str(text or "")

    # Strip control characters except newline, carriage return, tab
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Strip HTML tags
    text = re.sub(r"<[^>]+>", "", text)

    # Strip markdown links: [text](http...) -> text
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)

    return text.strip()


def extract_called_tools_and_results(messages: list[Any]) -> tuple[list[str], set[str], list[str]]:
    """
    Extract ordered tool calls, distinct called tool names, and tool result message strings.
    """
    ordered_tool_names = []
    tool_results_text = []

    for msg in messages:
        # Check tool calls on assistant message
        tool_calls = getattr(msg, "tool_calls", None)
        if tool_calls:
            for tc in tool_calls:
                name = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", None)
                if name:
                    ordered_tool_names.append(name)

        # Check tool result message
        msg_type = getattr(msg, "type", "")
        if msg_type == "tool" or type(msg).__name__ == "ToolMessage":
            content = getattr(msg, "content", "")
            if content:
                tool_results_text.append(str(content))

    return ordered_tool_names, set(ordered_tool_names), tool_results_text


def validate_verdict(
    args: dict[str, Any],
    thread_id: str,
    alert: dict[str, Any] | None = None,
    sigma_rule: dict[str, Any] | None = None,
    messages: list[Any] | None = None,
    db_path: Path | str = RESULTS_DB_PATH,
) -> tuple[bool, list[str], dict[str, Any]]:
    """
    Validate all fields and rules for submit_verdict.
    Returns (is_valid, errors_list, sanitized_data).
    """
    errors: list[str] = []
    sanitized: dict[str, Any] = {}

    alert = alert or {}
    sigma_rule = sigma_rule or {}
    messages = messages or []

    # Determine revision context
    existing_revisions = get_verdicts_for_thread(thread_id, db_path=db_path)
    # Only count completed verdicts as prior revisions that require change_from_previous
    completed_revisions = [
        r for r in existing_revisions
        if r.get("status") == "closed" or (r.get("verdict") and r.get("status") != "incomplete")
    ]
    current_revision = len(completed_revisions) + 1

    # 1. Basic Enums
    verdict = str(args.get("verdict", "")).strip().lower()
    if verdict not in VERDICT_CHOICES:
        errors.append(f"Invalid verdict: '{verdict}'. Allowed values: {sorted(VERDICT_CHOICES)}.")
    sanitized["verdict"] = verdict

    confidence = str(args.get("confidence", "")).strip().lower()
    if confidence not in CONFIDENCE_CHOICES:
        errors.append(f"Invalid confidence: '{confidence}'. Allowed values: {sorted(CONFIDENCE_CHOICES)}.")
    sanitized["confidence"] = confidence

    severity = str(args.get("severity", "")).strip().lower()
    if severity not in SEVERITY_CHOICES:
        errors.append(f"Invalid severity: '{severity}'. Allowed values: {sorted(SEVERITY_CHOICES)}.")
    sanitized["severity"] = severity

    category = str(args.get("category", "")).strip().lower()
    if category not in CATEGORY_CHOICES:
        errors.append(f"Invalid category: '{category}'. Allowed values: {sorted(CATEGORY_CHOICES)}.")
    sanitized["category"] = category

    # 2. Text fields and caps
    summary_raw = args.get("summary", "")
    summary = sanitize_plain_text(summary_raw)
    if not summary:
        errors.append("summary is required and cannot be empty.")
    elif len(summary) > 280:
        errors.append(f"summary exceeds 280 characters (length: {len(summary)}).")
    sanitized["summary"] = summary

    explanation_raw = args.get("explanation", "")
    explanation = sanitize_plain_text(explanation_raw)
    if not explanation:
        errors.append("explanation is required and cannot be empty.")
    elif len(explanation) > 1200:
        errors.append(f"explanation exceeds 1200 characters (length: {len(explanation)}).")
    sanitized["explanation"] = explanation

    # 3. Evidence
    evidence_raw = args.get("evidence", [])
    if not isinstance(evidence_raw, list) or len(evidence_raw) < 1 or len(evidence_raw) > 8:
        errors.append("evidence must be a list of 1 to 8 items.")
        sanitized["evidence"] = []
    else:
        sanitized_evidence = []
        for i, item in enumerate(evidence_raw):
            if not isinstance(item, dict):
                errors.append(f"evidence[{i}] must be an object with finding, source_tool, and direction.")
                continue
            finding = sanitize_plain_text(item.get("finding", ""))
            source_tool = str(item.get("source_tool", "")).strip()
            direction = str(item.get("direction", "")).strip().lower()

            if not finding:
                errors.append(f"evidence[{i}].finding is required.")
            elif len(finding) > 200:
                errors.append(f"evidence[{i}].finding exceeds 200 characters (length: {len(finding)}).")

            if not source_tool:
                errors.append(f"evidence[{i}].source_tool is required.")

            if direction not in DIRECTION_CHOICES:
                errors.append(f"evidence[{i}].direction must be one of {sorted(DIRECTION_CHOICES)} (got '{direction}').")

            sanitized_evidence.append({
                "finding": finding,
                "source_tool": source_tool,
                "direction": direction,
            })
        sanitized["evidence"] = sanitized_evidence

    # 4. Optional lists
    assumptions_raw = args.get("assumptions", [])
    if isinstance(assumptions_raw, list):
        sanitized["assumptions"] = [sanitize_plain_text(a) for a in assumptions_raw if a]
    else:
        sanitized["assumptions"] = []

    not_checked_raw = args.get("not_checked", [])
    if isinstance(not_checked_raw, list):
        sanitized["not_checked"] = [sanitize_plain_text(n) for n in not_checked_raw if n]
    else:
        sanitized["not_checked"] = []

    rec_raw = args.get("recommended_next_steps", [])
    if isinstance(rec_raw, list):
        if len(rec_raw) > 5:
            errors.append(f"recommended_next_steps exceeds 5 items (found {len(rec_raw)}).")
        sanitized["recommended_next_steps"] = [sanitize_plain_text(r) for r in rec_raw if r]
    else:
        sanitized["recommended_next_steps"] = []

    # 5. Conditional fields
    benign_exp = sanitize_plain_text(args.get("benign_explanation", ""))
    if verdict == "false_positive":
        if not benign_exp:
            errors.append("benign_explanation is required when verdict is 'false_positive'.")
    sanitized["benign_explanation"] = benign_exp or None

    missing_info = sanitize_plain_text(args.get("missing_info", ""))
    if verdict == "needs_more_info":
        if not missing_info:
            errors.append("missing_info is required when verdict is 'needs_more_info'.")
    sanitized["missing_info"] = missing_info or None

    rem_risk = sanitize_plain_text(args.get("remaining_risk", ""))
    threat_active = str(args.get("threat_active", "")).strip().lower()
    if verdict == "true_positive":
        if not rem_risk:
            errors.append("remaining_risk is required when verdict is 'true_positive'.")
        if threat_active not in THREAT_ACTIVE_CHOICES:
            errors.append(f"threat_active must be one of {sorted(THREAT_ACTIVE_CHOICES)} when verdict is 'true_positive'.")
    sanitized["remaining_risk"] = rem_risk or None
    sanitized["threat_active"] = threat_active if threat_active in THREAT_ACTIVE_CHOICES else None

    # Change from previous (revision 2+)
    change_prev = sanitize_plain_text(args.get("change_from_previous", ""))
    if current_revision >= 2:
        if not change_prev:
            errors.append("change_from_previous is required for revision 2 or later.")
    sanitized["change_from_previous"] = change_prev or None

    # 6. Consistency rules
    if verdict == "false_positive":
        if severity != "none":
            errors.append(f"Severity must be 'none' for a false_positive verdict (got '{severity}').")
        has_benign_evidence = any(e.get("direction") == "benign" for e in sanitized.get("evidence", []))
        if not has_benign_evidence:
            errors.append("A false_positive verdict requires at least one evidence item with direction 'benign'.")

    if verdict == "true_positive":
        if severity == "none":
            errors.append("Severity must be above 'none' (low, medium, high, critical) for a true_positive verdict.")
        has_suspicious_evidence = any(e.get("direction") == "suspicious" for e in sanitized.get("evidence", []))
        if not has_suspicious_evidence:
            errors.append("A true_positive verdict requires at least one evidence item with direction 'suspicious'.")

    if confidence == "high":
        directions = [e.get("direction") for e in sanitized.get("evidence", [])]
        if verdict == "true_positive" and directions.count("suspicious") < 2:
            errors.append("High confidence requires at least 2 evidence items with direction 'suspicious'.")
        elif verdict == "false_positive" and directions.count("benign") < 2:
            errors.append("High confidence requires at least 2 evidence items with direction 'benign'.")
        elif verdict == "needs_more_info" and (directions.count("neutral") < 2 and max(directions.count("benign"), directions.count("suspicious")) < 2):
            errors.append("High confidence requires at least 2 evidence items pointing in the same direction.")

    # 7. Investigate First rule & Tool execution checks
    ordered_tools, distinct_tools, tool_results = extract_called_tools_and_results(messages)

    # Exclude submit_verdict itself and plan
    investigation_tools_called = distinct_tools & INVESTIGATION_TOOLS
    if len(investigation_tools_called) < 2:
        errors.append(
            f"investigate before concluding: at least 2 different investigation tools must be called before submitting a verdict (called: {sorted(investigation_tools_called)})."
        )

    # Every evidence.source_tool was actually called
    for ev in sanitized.get("evidence", []):
        st = ev.get("source_tool", "")
        if st:
            # Allow single tool name or delimiter-separated tools (e.g. 'tool1, tool2')
            cited_tools = [t.strip() for t in re.split(r"[,;]|\band\b", st) if t.strip()]
            uncalled = [t for t in cited_tools if t not in distinct_tools]
            if uncalled:
                errors.append(
                    f"Evidence cites source_tool '{', '.join(uncalled)}', which was never called in this thread."
                )

    # 8. Indicators hallucination check
    indicators_raw = args.get("indicators")
    sanitized["indicators"] = indicators_raw if isinstance(indicators_raw, (dict, list)) else None

    def _extract_ioc_values(raw: Any) -> list[str]:
        vals = []
        if isinstance(raw, dict):
            for k in ("value", "val", "indicator", "ioc", "path", "file", "hash", "sha256", "registry_key"):
                if k in raw and isinstance(raw[k], str) and raw[k].strip():
                    vals.append(raw[k].strip())
                    return vals
            for v in raw.values():
                vals.extend(_extract_ioc_values(v))
        elif isinstance(raw, list):
            for item in raw:
                vals.extend(_extract_ioc_values(item))
        elif isinstance(raw, str):
            s = raw.strip()
            if s:
                if s.startswith("{") and ("'value'" in s or '"value"' in s or "'val'" in s or '"val"' in s):
                    try:
                        import ast
                        parsed = ast.literal_eval(s)
                        if isinstance(parsed, (dict, list)):
                            return _extract_ioc_values(parsed)
                    except Exception:
                        pass
                    try:
                        parsed = json.loads(s)
                        if isinstance(parsed, (dict, list)):
                            return _extract_ioc_values(parsed)
                    except Exception:
                        pass
                vals.append(s)
        return vals

    indicators_to_check = _extract_ioc_values(indicators_raw)

    if indicators_to_check:
        def _norm_for_search(text: str) -> str:
            if not text:
                return ""
            # Strip outer quotes, lowercase, and collapse multiple slashes/backslashes to a single forward slash
            t = text.strip().strip("'\"").lower()
            return re.sub(r"[\\/]+", "/", t)

        corpus_items = [
            json.dumps(alert, default=str),
            json.dumps(sigma_rule, default=str),
        ]
        corpus_items.extend(tool_results)
        # Also include tool call arguments and assistant contents from conversation messages
        for m in messages:
            tcs = getattr(m, "tool_calls", []) or []
            for tc in tcs:
                corpus_items.append(json.dumps(tc.get("args", {}), default=str))
            content = getattr(m, "content", "")
            if isinstance(content, str):
                corpus_items.append(content)

        norm_corpus = _norm_for_search(" ".join(corpus_items))

        for ind in indicators_to_check:
            norm_ind = _norm_for_search(ind)
            if norm_ind and norm_ind not in norm_corpus:
                errors.append(
                    f"Hallucinated indicator detected: '{ind}' does not appear in the alert or in any tool results from this thread."
                )

    return len(errors) == 0, errors, sanitized


def process_verdict_submission(
    args: dict[str, Any],
    thread_id: str,
    alert: dict[str, Any] | None = None,
    sigma_rule: dict[str, Any] | None = None,
    messages: list[Any] | None = None,
    turns: int = 0,
    retries_so_far: int = 0,
    db_path: Path | str = RESULTS_DB_PATH,
    kill_audit_path: Path | str = AUDIT_LOG_PATH,
    quarantine_audit_path: Path | str = QUARANTINE_AUDIT_LOG_PATH,
) -> tuple[dict[str, Any], int]:
    """
    Process an incoming submit_verdict tool invocation:
    - Validates fields against strict rules
    - If valid: persists complete record with status='closed', returns 'recorded'
    - If invalid and retries_left > 0: returns 'rejected_invalid' with error list
    - If invalid and retries exhausted (3 attempts): persists fallback with status='invalid_output',
      returns 'recorded_with_problems'
    """
    alert = alert or {}
    sigma_rule = sigma_rule or {}
    messages = messages or []

    is_valid, errors, sanitized_data = validate_verdict(
        args=args,
        thread_id=thread_id,
        alert=alert,
        sigma_rule=sigma_rule,
        messages=messages,
        db_path=db_path,
    )

    if is_valid:
        # Build complete record with system-filled facts
        event = alert.get("event") or alert
        alert_id = alert.get("alert_id") or alert.get("id") or event.get("process_guid", "")
        rule_id = sigma_rule.get("id") or sigma_rule.get("rule_id") or alert.get("rule_id", "")
        rule_title = sigma_rule.get("title") or alert.get("title", "")
        rule_level = sigma_rule.get("level") or alert.get("level", "medium")
        attack_tags = sigma_rule.get("tags") or []
        host = event.get("computer_name") or event.get("Computer") or alert.get("host", "")
        user = event.get("user") or event.get("User") or alert.get("user", "")
        process_guid = event.get("process_guid") or alert.get("process_guid", "")
        alert_time = event.get("timestamp") or event.get("UtcTime") or alert.get("timestamp", "")

        actions = read_audit_actions_for_thread(
            thread_id,
            alert_id=alert_id,
            kill_audit_path=kill_audit_path,
            quarantine_audit_path=quarantine_audit_path,
        )

        ordered_tools, _, _ = extract_called_tools_and_results(messages)

        record = {
            "thread_id": thread_id,
            "alert_id": alert_id,
            "rule_id": rule_id,
            "host": host,
            "user": user,
            "process_guid": process_guid,
            "verdict": sanitized_data["verdict"],
            "confidence": sanitized_data["confidence"],
            "severity": sanitized_data["severity"],
            "category": sanitized_data["category"],
            "status": "closed",
            "end_reason": "submitted",
            "summary": sanitized_data["summary"],
            "explanation": sanitized_data["explanation"],
            "evidence": sanitized_data["evidence"],
            "assumptions": sanitized_data["assumptions"],
            "not_checked": sanitized_data["not_checked"],
            "recommended_next_steps": sanitized_data["recommended_next_steps"],
            "benign_explanation": sanitized_data.get("benign_explanation"),
            "missing_info": sanitized_data.get("missing_info"),
            "remaining_risk": sanitized_data.get("remaining_risk"),
            "threat_active": sanitized_data.get("threat_active"),
            "change_from_previous": sanitized_data.get("change_from_previous"),
            "indicators": sanitized_data.get("indicators"),
            "alert_facts": {
                "rule_id": rule_id,
                "title": rule_title,
                "level": rule_level,
                "attack_tags": attack_tags,
                "host": host,
                "user": user,
                "process_guid": process_guid,
                "alert_time": alert_time,
            },
            "run_facts": {
                "turns": turns,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "tool_calls": ordered_tools,
                "model": os.getenv("GEMINI_MODEL", "gemini-2.5-pro"),
                "prompt_version": PROMPT_VERSION,
                "code_version": CODE_VERSION,
                "dry_run": DRY_RUN,
            },
            "actions": actions,
        }

        saved_record = insert_verdict(record, db_path=db_path)
        try:
            from record_run import auto_record_run
            auto_record_run(thread_id, results_db_path=db_path)
        except Exception:
            pass

        return {
            "status": "recorded",
            "verdict_id": saved_record["verdict_id"],
            "revision": saved_record["revision"],
            "message": f"Verdict recorded successfully (ID: {saved_record['verdict_id']}, Revision: {saved_record['revision']}). The investigation is closed.",
        }, retries_so_far

    # Validation failed: Check retry limits (2 retries allowed -> 3 attempts total)
    new_retries = retries_so_far + 1
    retries_left = 3 - new_retries

    if retries_left > 0:
        return {
            "status": "rejected_invalid",
            "errors": errors,
            "retries_left": retries_left,
            "message": f"Verdict submission rejected. {len(errors)} error(s) found. Please fix the listed errors and call submit_verdict again ({retries_left} retries left).",
        }, new_retries

    # 3 invalid attempts reached: Save fallback record marked 'invalid_output'
    event = alert.get("event") or alert
    alert_id = alert.get("alert_id") or alert.get("id") or event.get("process_guid", "")
    rule_id = sigma_rule.get("id") or sigma_rule.get("rule_id") or alert.get("rule_id", "")
    host = event.get("computer_name") or event.get("Computer") or alert.get("host", "")
    actions = read_audit_actions_for_thread(
        thread_id,
        alert_id=alert_id,
        kill_audit_path=kill_audit_path,
        quarantine_audit_path=quarantine_audit_path,
    )

    fallback_record = {
        "thread_id": thread_id,
        "alert_id": alert_id,
        "rule_id": rule_id,
        "host": host,
        "verdict": args.get("verdict"),
        "confidence": args.get("confidence"),
        "severity": args.get("severity") or "none",
        "category": args.get("category") or "unknown",
        "status": "invalid_output",
        "end_reason": "fallback_invalid_output",
        "summary": sanitize_plain_text(args.get("summary", "Fallback verdict: submission failed validation limit.")),
        "explanation": sanitize_plain_text(args.get("explanation", "The agent failed validation after 3 attempts.")),
        "validation_errors": errors,
        "raw_args": args,
        "evidence": args.get("evidence", []),
        "assumptions": args.get("assumptions", []),
        "not_checked": args.get("not_checked", []),
        "recommended_next_steps": ["Review raw model output and conduct human review"],
        "actions": actions,
        "run_facts": {
            "turns": turns,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "model": os.getenv("GEMINI_MODEL", "gemini-2.5-pro"),
            "prompt_version": PROMPT_VERSION,
            "code_version": CODE_VERSION,
            "dry_run": DRY_RUN,
        },
    }

    saved_fallback = insert_verdict(fallback_record, db_path=db_path)
    try:
        from record_run import auto_record_run
        auto_record_run(thread_id, results_db_path=db_path)
    except Exception:
        pass

    return {
        "status": "recorded_with_problems",
        "verdict_id": saved_fallback["verdict_id"],
        "revision": saved_fallback["revision"],
        "errors": errors,
        "message": f"Verdict recorded with problems after reaching retry limit (ID: {saved_fallback['verdict_id']}). The investigation is closed.",
    }, new_retries
