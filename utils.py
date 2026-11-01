"""
utils.py - BlueTeamingAI Event Parsing & Detection Engine

This module provides:
1. read_evtx: Reads a Windows .evtx log file and parses records into Python dicts.
2. load_sigma_rule: Loads a Sigma YAML detection rule.
3. match_event: Checks whether a single event matches a specific Sigma rule.
4. evaluate_event: Takes an event and runs it against a list of Sigma rules.
   Returns (True, list_of_matches) if any rule triggers, otherwise (False, []).
5. scan_evtx_file: Reads an .evtx file and evaluates every event through the pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
import glob
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
from typing import Any
import uuid
import xml.etree.ElementTree as ET

import psutil
import requests

import Evtx.Evtx as evtx
import yaml

from config import (
    DB_PATH,
    VT_API_KEY,
    EXAAI_SEARCH_API_KEY,
    DRY_RUN,
    AUDIT_LOG_PATH,
    QUARANTINE_DIR,
    QUARANTINE_AUDIT_LOG_PATH,
    ROOT_DIR,
    DB_DIR,
    MEMORY_DIR,
    HITL_DB_PATH,
    ASK_USER_TIMEOUT_SECONDS,
)

# Standard Windows Event Log XML namespace
XML_NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}


# ==============================================================================
# 1. EVTX LOG PARSER
# ==============================================================================


def parse_event_xml(xml_str: str) -> dict[str, Any]:
    """Parse raw Windows Event XML into a clean, flat Python dictionary."""
    root = ET.fromstring(xml_str)
    event: dict[str, Any] = {}

    # Extract System header elements (EventID, TimeCreated, Computer, Provider, etc.)
    system = root.find("ns:System", XML_NS)
    if system is not None:
        eid_elem = system.find("ns:EventID", XML_NS)
        if eid_elem is not None and eid_elem.text:
            try:
                event["EventID"] = int(eid_elem.text)
            except ValueError:
                event["EventID"] = eid_elem.text

        provider_elem = system.find("ns:Provider", XML_NS)
        if provider_elem is not None:
            event["Provider"] = provider_elem.get("Name", "")

        time_elem = system.find("ns:TimeCreated", XML_NS)
        if time_elem is not None:
            event["TimeCreated"] = time_elem.get("SystemTime", "")

        computer_elem = system.find("ns:Computer", XML_NS)
        if computer_elem is not None:
            event["Computer"] = computer_elem.text or ""

        record_elem = system.find("ns:EventRecordID", XML_NS)
        if record_elem is not None and record_elem.text:
            try:
                event["RecordID"] = int(record_elem.text)
            except ValueError:
                event["RecordID"] = record_elem.text

    # Extract EventData elements (Sysmon fields: Image, CommandLine, ParentImage, etc.)
    event_data = root.find("ns:EventData", XML_NS)
    if event_data is not None:
        for data_elem in event_data.findall("ns:Data", XML_NS):
            name = data_elem.get("Name")
            if name:
                text = data_elem.text or ""
                # Convert ProcessId to integer when possible
                if name in (
                    "ProcessId",
                    "ParentProcessId",
                    "SourceProcessId",
                    "TargetProcessId",
                ):
                    try:
                        event[name] = int(text)
                        continue
                    except ValueError:
                        pass
                event[name] = text

    return event


def read_evtx(file_path: str) -> list[dict[str, Any]]:
    """Read a Windows .evtx file and return a list of parsed event dictionaries."""
    events: list[dict[str, Any]] = []
    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                event_dict = parse_event_xml(record.xml())
                events.append(event_dict)
            except Exception:
                # Skip malformed individual records without failing the entire file
                continue
    return events


# ==============================================================================
# 2. SIGMA RULE LOADER
# ==============================================================================


def load_sigma_rule(rule_path: str) -> dict[str, Any]:
    """Load a Sigma YAML rule file."""
    with open(rule_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(
            f"Invalid Sigma rule format in {rule_path}: expected dictionary."
        )
    return data


_RULES_INDEX: dict[str, dict[str, Any]] = {}


def load_rules_index(
    rules_dir: Path | str | None = None,
) -> dict[str, dict[str, Any]]:
    """Build and return a dictionary mapping rule ID to rule definition."""
    global _RULES_INDEX
    if _RULES_INDEX:
        return _RULES_INDEX

    target_dir = (
        Path(rules_dir)
        if rules_dir
        else Path(__file__).resolve().parent / "detection" / "rules"
    )
    if not target_dir.exists():
        return {}

    for yml_path in glob.glob(str(target_dir / "*.yml")):
        try:
            rule = load_sigma_rule(yml_path)
            r_id = rule.get("id")
            if r_id:
                _RULES_INDEX[str(r_id).strip().lower()] = rule
        except Exception:
            continue

    return _RULES_INDEX


def fetch_rule_context(
    rule_id: str, rules_dir: Path | str | None = None
) -> dict[str, Any]:
    """
    Retrieve metadata and context for a Sigma rule by its ID.
    Returns title, description, falsepositives, level, tags, and references.
    Returns error dictionary if rule is missing or not found.
    """
    if not rule_id or not isinstance(rule_id, str):
        return {"error": "Invalid or missing rule_id"}

    index = load_rules_index(rules_dir)
    rule = index.get(rule_id.strip().lower())
    if not rule:
        return {"error": f"Rule not found for ID: {rule_id}"}

    return {
        "rule_id": rule.get("id", rule_id),
        "title": rule.get("title", ""),
        "description": rule.get("description", ""),
        "falsepositives": rule.get("falsepositives", []),
        "level": rule.get("level", "medium"),
        "tags": rule.get("tags", []),
        "references": rule.get("references", []),
    }


# ==============================================================================
# 3. RULE MATCHING LOGIC (NO EXTERNAL SIGMA LIBRARIES)
# ==============================================================================


def _check_field_match(
    event_value: Any, pattern: Any, modifier: str | None
) -> bool:
    """Check if a single event field value matches a pattern under a given modifier."""
    if event_value is None:
        return False

    str_event = str(event_value).lower()
    str_pattern = str(pattern).lower()

    if modifier == "endswith":
        return str_event.endswith(str_pattern)
    elif modifier == "startswith":
        return str_event.startswith(str_pattern)
    elif modifier == "contains":
        return str_pattern in str_event
    else:
        # Exact match
        return str_event == str_pattern


def _evaluate_field(
    event: dict[str, Any], field_spec: str, pattern_or_list: Any
) -> tuple[bool, str, Any]:
    """
    Evaluate a field condition like 'Image|endswith' or 'CommandLine|contains'.
    If pattern_or_list is a list, matches if ANY pattern matches (OR logic).
    """
    if "|" in field_spec:
        field_name, modifier = field_spec.split("|", 1)
    else:
        field_name, modifier = field_spec, None

    # Retrieve the event field value (case-insensitive key lookup)
    event_val = None
    for k, v in event.items():
        if k.lower() == field_name.lower():
            event_val = v
            break

    if event_val is None:
        return False, field_name, None

    if isinstance(pattern_or_list, list):
        # List of values is treated as OR in Sigma
        for pat in pattern_or_list:
            if _check_field_match(event_val, pat, modifier):
                return True, field_name, event_val
        return False, field_name, event_val
    else:
        matched = _check_field_match(event_val, pattern_or_list, modifier)
        return matched, field_name, event_val


def _evaluate_selection_map(
    event: dict[str, Any], selection_map: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    """All keys in a selection dictionary must match (AND logic)."""
    matched_fields: dict[str, Any] = {}
    for field_spec, pattern in selection_map.items():
        matched, field_name, val = _evaluate_field(event, field_spec, pattern)
        if not matched:
            return False, {}
        matched_fields[field_name] = val
    return True, matched_fields


def _evaluate_block(
    event: dict[str, Any], block_data: Any
) -> tuple[bool, dict[str, Any]]:
    """
    Evaluate a detection block (e.g. 'selection' or 'filter').
    - If dict: all keys must match (AND).
    - If list: any item matching satisfies the block (OR).
    """
    if isinstance(block_data, dict):
        return _evaluate_selection_map(event, block_data)
    elif isinstance(block_data, list):
        for item in block_data:
            if isinstance(item, dict):
                matched, fields = _evaluate_selection_map(event, item)
                if matched:
                    return True, fields
        return False, {}
    return False, {}


def _evaluate_condition(
    condition_expr: str, block_results: dict[str, bool]
) -> bool:
    """Evaluate a Sigma condition string (e.g. 'selection', '1 of selection_*', 'all of them')."""
    cond = condition_expr.strip()

    # Direct block lookup (e.g. 'selection')
    if cond in block_results:
        return block_results[cond]

    # Pattern: '1 of selection_*' or 'any of selection_*'
    m_one_of = re.match(r"^(?:1|any)\s+of\s+([a-zA-Z0-9_*]+)$", cond, re.IGNORECASE)
    if m_one_of:
        pattern = m_one_of.group(1).replace("*", ".*")
        matched_blocks = [
            k for k in block_results if re.match(f"^{pattern}$", k)
        ]
        return any(block_results[b] for b in matched_blocks)

    # Pattern: 'all of selection_*'
    m_all_of = re.match(r"^all\s+of\s+([a-zA-Z0-9_*]+)$", cond, re.IGNORECASE)
    if m_all_of:
        pattern = m_all_of.group(1).replace("*", ".*")
        matched_blocks = [
            k for k in block_results if re.match(f"^{pattern}$", k)
        ]
        if not matched_blocks:
            return False
        return all(block_results[b] for b in matched_blocks)

    # Pattern: '1 of them'
    if re.match(r"^(?:1|any)\s+of\s+them$", cond, re.IGNORECASE):
        return any(block_results.values())

    # Pattern: 'all of them'
    if re.match(r"^all\s+of\s+them$", cond, re.IGNORECASE):
        return bool(block_results and all(block_results.values()))

    # Basic boolean evaluation: replace block names with True/False
    # Sort keys by length descending to avoid prefix substitution issues
    eval_str = cond
    for key in sorted(block_results.keys(), key=len, reverse=True):
        val = str(block_results[key])
        eval_str = re.sub(rf"\b{re.escape(key)}\b", val, eval_str)

    # Convert Sigma boolean syntax to Python syntax
    eval_str = re.sub(r"\band\b", "and", eval_str, flags=re.IGNORECASE)
    eval_str = re.sub(r"\bor\b", "or", eval_str, flags=re.IGNORECASE)
    eval_str = re.sub(r"\bnot\b", "not", eval_str, flags=re.IGNORECASE)

    try:
        # Safe evaluation restricted to booleans and logical operators
        return bool(
            eval(eval_str, {"__builtins__": None}, {"True": True, "False": False})
        )
    except Exception:
        return False


def match_event(
    event: dict[str, Any], rule: dict[str, Any]
) -> tuple[bool, dict[str, Any] | None]:
    """
    Check whether a single event matches a Sigma rule.
    Returns (True, match_info) if matched, otherwise (False, None).
    """
    detection = rule.get("detection")
    if not detection or "condition" not in detection:
        return False, None

    condition_expr = str(detection["condition"])
    block_results: dict[str, bool] = {}
    matched_fields_all: dict[str, Any] = {}

    # Evaluate each detection block (selection, selection_cli, filter, etc.)
    for block_name, block_data in detection.items():
        if block_name == "condition":
            continue
        matched, fields = _evaluate_block(event, block_data)
        block_results[block_name] = matched
        if matched:
            matched_fields_all.update(fields)

    # Evaluate the overall condition
    is_match = _evaluate_condition(condition_expr, block_results)
    if not is_match:
        return False, None

    match_info = {
        "rule_id": rule.get("id"),
        "rule_title": rule.get("title"),
        "level": rule.get("level", "medium"),
        "tags": rule.get("tags", []),
        "condition": condition_expr,
        "matched_fields": matched_fields_all,
        "event": event,
        "rule": rule,
    }
    return True, match_info


# ==============================================================================
# 4. PIPELINE INTERFACE (Requested by User)
# ==============================================================================


def evaluate_event(
    event: dict[str, Any], rules: list[dict[str, Any]]
) -> tuple[bool, list[dict[str, Any]]]:
    """
    Takes an event dictionary, runs it through the matching pipeline against
    all provided Sigma rules, and returns (True, [matches]) if detected,
    or (False, []) if no rules matched.
    """
    matches: list[dict[str, Any]] = []
    for rule in rules:
        is_matched, match_info = match_event(event, rule)
        if is_matched and match_info:
            matches.append(match_info)

    if matches:
        return True, matches
    return False, []


def format_alert(match_info: dict[str, Any]) -> dict[str, Any]:
    """
    Format a rule detection match into a structured alert dictionary for the AI agent.
    Includes: rule name, severity, attack tags, matching event, process GUIDs, and parent program info.
    """
    event = match_info.get("event", {})
    tags = match_info.get("tags", [])
    attack_tags = [t for t in tags if str(t).startswith("attack.")] or tags

    process_guid = event.get("ProcessGuid") or event.get("process_guid")
    parent_process_guid = event.get("ParentProcessGuid") or event.get("parent_process_guid")

    return {
        "alert_id": f"alert-{uuid.uuid4().hex[:8]}",
        "timestamp": event.get("TimeCreated") or datetime.now(timezone.utc).isoformat(),
        "rule_id": match_info.get("rule_id", ""),
        "rule_name": match_info.get("rule_title", "Unknown Rule"),
        "severity": match_info.get("level", "medium"),
        "attack_tags": attack_tags,
        "process_guid": process_guid,
        "parent_process_guid": parent_process_guid,
        "matched_fields": match_info.get("matched_fields", {}),
        "event": {
            "event_id": event.get("EventID"),
            "process_id": event.get("ProcessId") if event.get("ProcessId") is not None else event.get("process_id"),
            "process_guid": process_guid,
            "image": event.get("Image"),
            "command_line": event.get("CommandLine"),
            "user": event.get("User"),
            "computer": event.get("Computer"),
        },
        "parent_process": {
            "parent_process_id": event.get("ParentProcessId") if event.get("ParentProcessId") is not None else event.get("parent_process_id"),
            "parent_process_guid": parent_process_guid,
            "parent_image": event.get("ParentImage"),
            "parent_command_line": event.get("ParentCommandLine"),
        },
        "raw_event": event,
    }


def scan_evtx_file(
    file_path: str, rules: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Read an .evtx file, evaluate all events through the pipeline,
    and return all detected matches.
    """
    all_matches: list[dict[str, Any]] = []
    events = read_evtx(file_path)
    for event in events:
        detected, matches = evaluate_event(event, rules)
        if detected:
            all_matches.extend(matches)
    return all_matches


def fetch_process_tree(
    guid: str | dict[str, Any],
    db_path: Path | str = DB_PATH,
    max_depth: int = 10,
) -> list[dict[str, Any]]:
    if isinstance(guid, dict):
        guid = guid.get("guid") or guid.get("process_guid") or ""

    if not guid:
        return []

    tree: list[dict[str, Any]] = []
    visited: set[str] = set()
    current_guid = str(guid).strip()

    conn = sqlite3.connect(str(db_path))
    try:
        for _ in range(max_depth):
            if not current_guid or current_guid in visited:
                break
            visited.add(current_guid)

            g_with_braces = current_guid if current_guid.startswith("{") else f"{{{current_guid}}}"
            g_without_braces = current_guid.strip("{}")

            cursor = conn.execute(
                """
                SELECT raw_data FROM events
                WHERE event_id = 1
                  AND (json_extract(raw_data, '$.ProcessGuid') = ? COLLATE NOCASE OR json_extract(raw_data, '$.ProcessGuid') = ? COLLATE NOCASE)
                ORDER BY id DESC LIMIT 1
                """,
                (g_with_braces, g_without_braces),
            )
            row = cursor.fetchone()
            if not row:
                break

            data = json.loads(row[0])
            tree.append({
                "process_guid": data.get("ProcessGuid"),
                "process_id": data.get("ProcessId"),
                "image": data.get("Image"),
                "command_line": data.get("CommandLine"),
                "parent_process_guid": data.get("ParentProcessGuid"),
                "parent_process_id": data.get("ParentProcessId"),
                "parent_image": data.get("ParentImage"),
                "user": data.get("User"),
                "timestamp": data.get("TimeCreated") or data.get("UtcTime"),
            })

            parent_guid = data.get("ParentProcessGuid")
            if not parent_guid or parent_guid == "{00000000-0000-0000-0000-000000000000}":
                break
            current_guid = str(parent_guid).strip()
    finally:
        conn.close()

    return tree


def fetch_process_children(
    guid: str | dict[str, Any],
    db_path: Path | str = DB_PATH,
    depth: int = 2,
    max_children: int = 50,
) -> list[dict[str, Any]]:
    if isinstance(guid, dict):
        guid = guid.get("guid") or guid.get("process_guid") or ""

    if not guid or depth < 1:
        return []

    conn = sqlite3.connect(str(db_path))
    children: list[dict[str, Any]] = []
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(str(guid).strip(), 1)]

    try:
        while queue and len(children) < max_children:
            parent_guid, current_level = queue.pop(0)
            if parent_guid in visited or current_level > depth:
                continue
            visited.add(parent_guid)

            g_with_braces = parent_guid if parent_guid.startswith("{") else f"{{{parent_guid}}}"
            g_without_braces = parent_guid.strip("{}")

            cursor = conn.execute(
                """
                SELECT raw_data FROM events
                WHERE event_id = 1
                  AND (json_extract(raw_data, '$.ParentProcessGuid') = ? COLLATE NOCASE OR json_extract(raw_data, '$.ParentProcessGuid') = ? COLLATE NOCASE)
                ORDER BY id ASC
                """,
                (g_with_braces, g_without_braces),
            )

            for (raw_str,) in cursor.fetchall():
                if len(children) >= max_children:
                    break
                data = json.loads(raw_str)
                child_guid = data.get("ProcessGuid")
                children.append({
                    "process_guid": child_guid,
                    "process_id": data.get("ProcessId"),
                    "image": data.get("Image"),
                    "command_line": data.get("CommandLine"),
                    "parent_process_guid": data.get("ParentProcessGuid"),
                    "parent_process_id": data.get("ParentProcessId"),
                    "parent_image": data.get("ParentImage"),
                    "user": data.get("User"),
                    "timestamp": data.get("TimeCreated") or data.get("UtcTime"),
                    "depth": current_level,
                })

                if child_guid and current_level < depth:
                    queue.append((str(child_guid).strip(), current_level + 1))
    finally:
        conn.close()

    return children


def fetch_events_for_process(
    guid: str | dict[str, Any],
    db_path: Path | str = DB_PATH,
) -> dict[str, list[dict[str, Any]]]:
    if isinstance(guid, dict):
        guid = guid.get("guid") or guid.get("process_guid") or ""

    categories: dict[str, list[dict[str, Any]]] = {
        "network": [],
        "file": [],
        "registry": [],
        "dns": [],
        "image_loads": [],
        "process": [],
        "other": [],
    }

    if not guid:
        return categories

    clean = str(guid).strip()
    g_with_braces = clean if clean.startswith("{") else f"{{{clean}}}"
    g_without_braces = clean.strip("{}")

    event_map = {
        1: "process",
        5: "process",
        3: "network",
        2: "file",
        11: "file",
        15: "file",
        23: "file",
        26: "file",
        12: "registry",
        13: "registry",
        14: "registry",
        22: "dns",
        7: "image_loads",
    }

    conn = sqlite3.connect(str(db_path))
    try:
        # Also discover direct child process GUIDs (e.g. reg.exe adding Run key)
        child_cursor = conn.execute(
            """
            SELECT json_extract(raw_data, '$.ProcessGuid') FROM events
            WHERE event_id = 1
              AND (json_extract(raw_data, '$.ParentProcessGuid') = ? COLLATE NOCASE
                   OR json_extract(raw_data, '$.ParentProcessGuid') = ? COLLATE NOCASE)
            """,
            (g_with_braces, g_without_braces),
        )
        all_guids = {g_with_braces, g_without_braces}
        for (cg,) in child_cursor.fetchall():
            if cg:
                c_clean = str(cg).strip()
                all_guids.add(c_clean if c_clean.startswith("{") else f"{{{c_clean}}}")
                all_guids.add(c_clean.strip("{}"))

        placeholders = ", ".join(["?"] * len(all_guids))
        guid_list = list(all_guids)

        cursor = conn.execute(
            f"""
            SELECT event_id, raw_data FROM events
            WHERE (json_extract(raw_data, '$.ProcessGuid') IN ({placeholders}) COLLATE NOCASE
               OR json_extract(raw_data, '$.SourceProcessGuid') IN ({placeholders}) COLLATE NOCASE
               OR json_extract(raw_data, '$.process_guid') IN ({placeholders}) COLLATE NOCASE)
            ORDER BY id ASC
            """,
            guid_list + guid_list + guid_list,
        )

        for eid, raw_str in cursor.fetchall():
            cat = event_map.get(eid, "other")
            try:
                data = json.loads(raw_str)
            except Exception:
                data = {"raw": raw_str}
            categories[cat].append(data)
    finally:
        conn.close()

    return categories


def fetch_events_in_window(
    start: str,
    end: str,
    event_id: int | None = None,
    row_limit: int = 50,
    db_path: Path | str = DB_PATH,
) -> list[dict[str, Any]]:
    if not start or not end:
        return []

    s_norm = str(start).strip().replace("T", " ")
    e_norm = str(end).strip().replace("T", " ")

    query = """
        SELECT event_id, timestamp, process_id, image, command_line, parent_image, user, raw_data
        FROM events
        WHERE replace(timestamp, 'T', ' ') >= ? AND replace(timestamp, 'T', ' ') <= ?
    """
    params: list[Any] = [s_norm, e_norm]

    if event_id is not None:
        query += " AND event_id = ?"
        params.append(event_id)

    query += " ORDER BY timestamp ASC LIMIT ?"
    params.append(max(1, min(row_limit, 200)))

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    results: list[dict[str, Any]] = []

    try:
        cursor = conn.execute(query, params)
        for row in cursor.fetchall():
            item = dict(row)
            if item.get("raw_data"):
                try:
                    item["raw_data"] = json.loads(item["raw_data"])
                except Exception:
                    pass
            results.append(item)
    finally:
        conn.close()

    return results


def parse_hashes(s: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (s or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().upper()
    return out


def fetch_events_by_hash(
    sha256: str, limit: int = 20, db_path: Path | str = DB_PATH
) -> dict[str, Any]:
    sha256 = str(sha256).strip().upper()
    if not re.fullmatch(r"[0-9A-F]{64}", sha256):
        return {"error": "invalid sha256", "sha256": sha256}

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        win_row = conn.execute(
            "SELECT MIN(timestamp) AS oldest, MAX(timestamp) AS newest FROM events"
        ).fetchone()
        store_window = {
            "oldest_event": win_row["oldest"] if win_row else None,
            "newest_event": win_row["newest"] if win_row else None,
        }

        rows = conn.execute(
            """
            SELECT image,
                   COUNT(*)                            AS runs,
                   MIN(timestamp)                      AS first_seen,
                   MAX(timestamp)                      AS last_seen,
                   COUNT(DISTINCT user)                AS users,
                   COUNT(DISTINCT parent_image)        AS distinct_parents,
                   GROUP_CONCAT(DISTINCT parent_image) AS parents
            FROM events
            WHERE (sha256 = ? COLLATE NOCASE
                   OR json_extract(raw_data, '$.Hashes') LIKE ?
                   OR json_extract(raw_data, '$.sha256') = ? COLLATE NOCASE)
              AND event_id = 1
            GROUP BY image
            ORDER BY runs DESC
            LIMIT ?
            """,
            (sha256, f"%SHA256={sha256}%", sha256, limit),
        ).fetchall()

        if not rows:
            return {
                "sha256": sha256,
                "total_runs": 0,
                "distinct_paths": 0,
                "first_seen": None,
                "last_seen": None,
                "paths": [],
                "store_window": store_window,
            }

        total_runs = sum(r["runs"] for r in rows)
        distinct_paths = len(rows)
        first_seen = min(r["first_seen"] for r in rows if r["first_seen"])
        last_seen = max(r["last_seen"] for r in rows if r["last_seen"])

        paths = []
        for r in rows:
            parents_raw = r["parents"] or ""
            parents_list = [p.strip() for p in parents_raw.split(",") if p.strip()]
            paths.append({
                "image": r["image"],
                "runs": r["runs"],
                "users": r["users"],
                "distinct_parents": r["distinct_parents"],
                "parents": parents_list,
            })

        return {
            "sha256": sha256,
            "total_runs": total_runs,
            "distinct_paths": distinct_paths,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "paths": paths,
            "store_window": store_window,
        }
    finally:
        conn.close()


# ==============================================================================
# 9. FILE SYSTEM INSPECTION TOOLS (GROUP 2)
# ==============================================================================

MAX_HASH_BYTES = 200 * 1024 * 1024  # skip hashing files bigger than 200 MB

# Folders where normal programs rarely live
RISKY_FOLDERS = [
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\$recycle.bin\\",
]


def validate_local_path(path: str) -> str:
    """Accept only local drive paths like C:\\... Reject network paths (\\\\server\\share)."""
    if not isinstance(path, str):
        raise ValueError("path rejected: path must be a string")
    clean_p = path.strip().strip("'\"")
    # Convert forward slashes to backslashes and collapse multiple consecutive backslashes
    norm_path = clean_p.replace("/", "\\")
    norm_path = re.sub(r"\\+", r"\\", norm_path)
    if not re.match(r"^[A-Za-z]:\\", norm_path):
        raise ValueError("path rejected: only local drive paths are allowed")
    real = os.path.realpath(norm_path)  # resolves shortcuts/links
    if not re.match(r"^[A-Za-z]:\\", real):  # re-check after resolving
        raise ValueError("path rejected: resolves outside local drives")
    return real


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def sha256_of_file(path: str) -> str:
    """Calculate the SHA256 hex digest of a file in 1MB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def file_info(path: str, expected_sha256: str | None = None) -> dict[str, Any]:
    """
    Inspect a local file on disk without executing or modifying it.
    Reports existence, size, timestamps, risky folder location, current SHA256 hash,
    and whether the current hash matches the alert's expected SHA256 hash.
    """
    try:
        real = validate_local_path(path)
    except ValueError as e:
        return {"error": str(e)}

    if not os.path.isfile(real):
        return {
            "path": path,
            "exists": False,
            "note": "File not found. It may have been deleted after running.",
        }

    try:
        st = os.stat(real)
        info: dict[str, Any] = {
            "path": real,
            "exists": True,
            "folder": os.path.dirname(real),
            "size_bytes": st.st_size,
            "created_utc": _iso(st.st_ctime),
            "modified_utc": _iso(st.st_mtime),
            "in_risky_folder": any(f in real.lower() for f in RISKY_FOLDERS),
        }
        if st.st_size > MAX_HASH_BYTES:
            info["sha256_now"] = None
            info["note"] = "File too large to hash."
            return info

        now = sha256_of_file(real)
        info["sha256_now"] = now
        if expected_sha256:
            info["hash_matches_alert"] = now == expected_sha256.strip().upper()
        return info
    except PermissionError:
        return {"path": real, "exists": True, "error": "Permission denied reading file."}
    except OSError as e:
        return {"path": real, "error": f"Could not read file: {e.strerror}"}


def check_file_signature(path: str, timeout_seconds: int = 15) -> dict[str, Any]:
    """
    Check the digital Authenticode signature of a local file via PowerShell.
    Returns status (Valid, NotSigned, HashMismatch, NotTrusted, etc.) and signer name.
    Returns errors as data dictionaries rather than raising exceptions.
    """
    try:
        real = validate_local_path(path)
    except ValueError as e:
        return {"path": path, "error": str(e)}

    if not os.path.isfile(real):
        return {
            "path": path,
            "status": "FileNotFound",
            "signer": None,
            "error": "File not found. It may have been deleted after running.",
        }

    env = os.environ.copy()
    env["TARGET_FILE_PATH"] = real

    ps_command = (
        "$p = $env:TARGET_FILE_PATH; "
        "$s = Get-AuthenticodeSignature -LiteralPath $p; "
        "$cert = $s.SignerCertificate; "
        "$name = if ($cert) { $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { $null }; "
        "if (-not $name -and $cert) { $name = $cert.Subject }; "
        "[PSCustomObject]@{ Status = $s.Status.ToString(); StatusMessage = $s.StatusMessage; Signer = $name } | ConvertTo-Json -Compress"
    )

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_seconds,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip() or "PowerShell execution failed"
            return {"path": real, "status": "UnknownError", "signer": None, "error": err}

        output = json.loads(proc.stdout.strip())
        status = output.get("Status", "UnknownError")
        signer = output.get("Signer")
        if signer and isinstance(signer, str):
            signer = signer[:200]

        return {
            "path": real,
            "status": status,
            "status_message": output.get("StatusMessage"),
            "signer": signer,
        }
    except subprocess.TimeoutExpired:
        return {
            "path": real,
            "status": "UnknownError",
            "signer": None,
            "error": f"Signature check timed out after {timeout_seconds} seconds.",
        }
    except PermissionError:
        return {"path": real, "status": "UnknownError", "signer": None, "error": "Permission denied reading file."}
    except Exception as e:
        return {"path": real, "status": "UnknownError", "signer": None, "error": f"Signature verification error: {str(e)}"}


def parse_utc_timestamp(ts: str | None) -> float | None:
    """Parse UTC datetime string into Unix epoch timestamp (seconds)."""
    if not ts:
        return None
    s = str(ts).strip().replace("T", " ")
    if s.endswith("Z"):
        s = s[:-1].strip()
    if "+" in s:
        s = s.split("+")[0].strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(str(ts))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def classify_ip(ip_str: str | None) -> str | None:
    """Classify an IP address as 'loopback', 'private', or 'public'."""
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return "loopback"
        if ip.is_private or ip.is_unspecified:
            return "private"
        return "public"
    except ValueError:
        return "unknown"


def extract_ip_port(addr: Any) -> tuple[str | None, int | None]:
    """Safely extract IP and port from a psutil connection endpoint."""
    if not addr:
        return None, None
    ip = getattr(addr, "ip", None)
    port = getattr(addr, "port", None)
    if ip is None and isinstance(addr, (list, tuple)):
        if len(addr) > 0:
            ip = addr[0]
        if len(addr) > 1:
            port = addr[1]
    return (str(ip) if ip else None, int(port) if port is not None else None)


def resolve_live_process(
    guid: str,
    db_path: Path | str = DB_PATH,
    time_tolerance_seconds: float = 3.0,
) -> dict[str, Any]:
    """
    Resolve a ProcessGuid to a live Windows process and verify its identity.
    Checks Event 1 in the SQLite store, verifies PID existence, image path match,
    and start time within tolerance to protect against PID reuse.
    Also queries Event 5 for process termination time if recorded.
    """
    if not guid or not isinstance(guid, str):
        return {
            "status": "invalid_guid",
            "guid": str(guid) if guid is not None else "",
            "reason": "Process GUID is required.",
        }

    guid_str = guid.strip()
    guid_pattern = r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
    if not re.match(guid_pattern, guid_str):
        return {
            "status": "invalid_guid",
            "guid": guid_str,
            "reason": f"Invalid GUID format: '{guid_str}'. Expected format like {{7e67f797-b9de-6ae0-6b12-000000002600}}.",
        }

    if not os.path.exists(str(db_path)):
        return {
            "status": "error",
            "guid": guid_str,
            "reason": f"Event database store not found at {db_path}.",
        }

    g_with_braces = guid_str if guid_str.startswith("{") else f"{{{guid_str}}}"
    g_without_braces = guid_str.strip("{}")

    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute(
            """
            SELECT raw_data FROM events
            WHERE event_id = 1
              AND (json_extract(raw_data, '$.ProcessGuid') = ? OR json_extract(raw_data, '$.ProcessGuid') = ?)
            ORDER BY id DESC LIMIT 1
            """,
            (g_with_braces, g_without_braces),
        )
        row = cursor.fetchone()
        if not row:
            return {
                "status": "not_found",
                "guid": guid_str,
                "reason": f"Process GUID '{guid_str}' was not found in event history.",
            }

        try:
            event_data = json.loads(row[0])
        except Exception:
            return {
                "status": "error",
                "guid": guid_str,
                "reason": "Failed to parse raw event data from store.",
            }

        term_cursor = conn.execute(
            """
            SELECT raw_data FROM events
            WHERE event_id = 5
              AND (json_extract(raw_data, '$.ProcessGuid') = ? OR json_extract(raw_data, '$.ProcessGuid') = ?)
            ORDER BY id DESC LIMIT 1
            """,
            (g_with_braces, g_without_braces),
        )
        term_row = term_cursor.fetchone()
        exit_time = None
        if term_row:
            try:
                term_data = json.loads(term_row[0])
                exit_time = term_data.get("UtcTime") or term_data.get("TimeCreated")
            except Exception:
                pass
    except Exception as e:
        return {
            "status": "error",
            "guid": guid_str,
            "reason": f"Database query failed: {str(e)}",
        }
    finally:
        conn.close()

    raw_pid = event_data.get("ProcessId")
    try:
        pid = int(raw_pid)
    except (TypeError, ValueError):
        return {
            "status": "error",
            "guid": guid_str,
            "reason": f"Event 1 for GUID '{guid_str}' does not contain a valid ProcessId: {raw_pid}",
        }

    event_image = event_data.get("Image") or ""
    event_cmd_line = event_data.get("CommandLine") or ""
    event_user = event_data.get("User") or ""
    event_parent_image = event_data.get("ParentImage") or ""
    event_parent_guid = event_data.get("ParentProcessGuid") or ""
    event_time_str = event_data.get("UtcTime") or event_data.get("TimeCreated")
    event_ts = parse_utc_timestamp(event_time_str)

    base_metadata = {
        "command_line": event_cmd_line,
        "user": event_user,
        "parent_image": event_parent_image,
        "parent_guid": event_parent_guid,
        "event_data": event_data,
    }

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {
            "status": "exited",
            "guid": guid_str,
            "pid": pid,
            "image": event_image,
            "reason": f"Process with PID {pid} no longer exists (has exited).",
            "exit_time": exit_time,
            **base_metadata,
        }
    except psutil.AccessDenied:
        return {
            "status": "access_denied",
            "guid": guid_str,
            "pid": pid,
            "image": event_image,
            "reason": f"Windows denied access when reading details for PID {pid} (protected or elevated process).",
            "exit_time": exit_time,
            **base_metadata,
        }
    except Exception as e:
        return {
            "status": "error",
            "guid": guid_str,
            "pid": pid,
            "image": event_image,
            "reason": f"Error inspecting live process PID {pid}: {str(e)}",
            "exit_time": exit_time,
            **base_metadata,
        }

    try:
        live_exe = proc.exe()
        live_create_time = proc.create_time()
    except psutil.NoSuchProcess:
        return {
            "status": "exited",
            "guid": guid_str,
            "pid": pid,
            "image": event_image,
            "reason": f"Process with PID {pid} exited while inspecting.",
            "exit_time": exit_time,
            **base_metadata,
        }
    except psutil.AccessDenied:
        return {
            "status": "access_denied",
            "guid": guid_str,
            "pid": pid,
            "image": event_image,
            "reason": f"Windows denied access when reading details for PID {pid} (protected or elevated process).",
            "exit_time": exit_time,
            **base_metadata,
        }
    except Exception as e:
        return {
            "status": "error",
            "guid": guid_str,
            "pid": pid,
            "image": event_image,
            "reason": f"Failed to retrieve process details for PID {pid}: {str(e)}",
            "exit_time": exit_time,
            **base_metadata,
        }

    norm_live_exe = os.path.normcase(os.path.normpath(live_exe)) if live_exe else ""
    norm_event_image = os.path.normcase(os.path.normpath(event_image)) if event_image else ""

    if norm_live_exe and norm_event_image and norm_live_exe != norm_event_image:
        return {
            "status": "exited",
            "guid": guid_str,
            "pid": pid,
            "image": event_image,
            "reason": f"PID {pid} exists but belongs to a different process ('{live_exe}' vs expected '{event_image}'). The original process has exited.",
            "exit_time": exit_time,
            **base_metadata,
        }

    if event_ts is not None:
        time_diff = abs(live_create_time - event_ts)
        if time_diff > time_tolerance_seconds:
            return {
                "status": "exited",
                "guid": guid_str,
                "pid": pid,
                "image": event_image,
                "reason": f"PID {pid} is running '{live_exe}', but start time differs by {time_diff:.1f}s (reused PID). The original process has exited.",
                "exit_time": exit_time,
                **base_metadata,
            }

    live_start_dt = datetime.fromtimestamp(live_create_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return {
        "status": "running",
        "guid": guid_str,
        "pid": pid,
        "image": event_image,
        "start_time": event_time_str,
        "matched_live_start_time": live_start_dt,
        "proc": proc,
        "exit_time": exit_time,
        **base_metadata,
    }


def check_process_running(
    guid: str,
    db_path: Path | str = DB_PATH,
    time_tolerance_seconds: float = 3.0,
) -> dict[str, Any]:
    """
    Check whether a process identified by its Sysmon ProcessGuid is still alive right now.
    Reads process info from Event 1 in the SQLite store and verifies PID, image path,
    and start time against live system processes.
    """
    resolved = resolve_live_process(guid, db_path=db_path, time_tolerance_seconds=time_tolerance_seconds)
    status = resolved.get("status")

    if status == "running":
        res: dict[str, Any] = {
            "guid": resolved["guid"],
            "pid": resolved["pid"],
            "running": True,
            "image": resolved["image"],
            "start_time": resolved["start_time"],
            "matched_live_start_time": resolved["matched_live_start_time"],
        }
        if resolved.get("exit_time"):
            res["exit_time"] = resolved["exit_time"]
        return res

    elif status == "exited":
        res = {
            "guid": resolved["guid"],
            "pid": resolved.get("pid"),
            "running": False,
            "reason": resolved.get("reason"),
        }
        if resolved.get("exit_time"):
            res["exit_time"] = resolved["exit_time"]
        return res

    else:
        res = {
            "guid": resolved.get("guid", str(guid)),
            "running": "unknown",
            "reason": resolved.get("reason", "Unknown error inspecting process."),
        }
        if resolved.get("pid"):
            res["pid"] = resolved["pid"]
        return res


def fetch_live_connections(
    guid: str,
    db_path: Path | str = DB_PATH,
    max_connections: int = 50,
) -> dict[str, Any]:
    """
    List open network connections for a process identified by its Sysmon ProcessGuid.
    Verifies the process is alive using resolve_live_process, then reads local/remote
    sockets via psutil and classifies remote IP scopes (public, private, loopback).
    Never performs DNS resolution or outbound network connections.
    """
    resolved = resolve_live_process(guid, db_path=db_path)
    status = resolved.get("status")

    if status != "running":
        if status == "exited":
            return {
                "guid": resolved["guid"],
                "pid": resolved.get("pid"),
                "process_running": False,
                "reason": f"{resolved.get('reason')} The process has exited, so there are no live connections to report. (Note: an empty list does not mean the process was clean, nor that it made no connections earlier).",
                "total_connections": 0,
                "returned_connections": 0,
                "connections": [],
            }
        else:
            res: dict[str, Any] = {
                "guid": resolved.get("guid", str(guid)),
                "process_running": "unknown",
                "reason": resolved.get("reason", "Could not verify process."),
                "total_connections": 0,
                "returned_connections": 0,
                "connections": [],
            }
            if resolved.get("pid"):
                res["pid"] = resolved["pid"]
            return res

    proc: psutil.Process = resolved["proc"]
    pid = resolved["pid"]
    image = resolved["image"]

    try:
        get_conns = getattr(proc, "net_connections", getattr(proc, "connections", None))
        if not get_conns:
            return {
                "guid": resolved["guid"],
                "pid": pid,
                "process_running": "unknown",
                "reason": "psutil net_connections method is unavailable.",
                "total_connections": 0,
                "returned_connections": 0,
                "connections": [],
            }
        raw_conns = get_conns()
    except psutil.AccessDenied:
        return {
            "guid": resolved["guid"],
            "pid": pid,
            "process_running": "unknown",
            "reason": f"Windows denied access when reading network connections for PID {pid} (protected or elevated process).",
            "total_connections": 0,
            "returned_connections": 0,
            "connections": [],
        }
    except psutil.NoSuchProcess:
        return {
            "guid": resolved["guid"],
            "pid": pid,
            "process_running": False,
            "reason": f"Process with PID {pid} exited while reading network connections. (Note: an empty list does not mean the process was clean).",
            "total_connections": 0,
            "returned_connections": 0,
            "connections": [],
        }
    except Exception as e:
        return {
            "guid": resolved["guid"],
            "pid": pid,
            "process_running": "unknown",
            "reason": f"Failed reading network connections for PID {pid}: {str(e)}",
            "total_connections": 0,
            "returned_connections": 0,
            "connections": [],
        }

    total_conns = len(raw_conns)
    parsed_conns = []
    for c in raw_conns[:max_connections]:
        proto = "tcp" if c.type == socket.SOCK_STREAM else ("udp" if c.type == socket.SOCK_DGRAM else str(c.type))
        local_ip, local_port = extract_ip_port(c.laddr)
        remote_ip, remote_port = extract_ip_port(c.raddr)
        remote_scope = classify_ip(remote_ip) if remote_ip else None

        state = c.status if hasattr(c, "status") and c.status and c.status != "NONE" else None

        parsed_conns.append({
            "protocol": proto,
            "local_address": local_ip,
            "local_port": local_port,
            "remote_address": remote_ip,
            "remote_port": remote_port,
            "remote_scope": remote_scope,
            "state": state,
        })

    result: dict[str, Any] = {
        "guid": resolved["guid"],
        "pid": pid,
        "image": image,
        "process_running": True,
        "total_connections": total_conns,
        "returned_connections": len(parsed_conns),
        "connections": parsed_conns,
    }
    if total_conns > max_connections:
        omitted = total_conns - max_connections
        result["omitted_connections"] = f"{omitted} more connection(s) omitted"

    return result


class VirusTotalRateLimiter:
    """
    Process-wide thread-safe rate limiter for the VirusTotal free API tier.
    Enforces a minimum spacing between calls (default: 15s) and a daily limit (default: 450).
    """

    def __init__(self, min_interval_seconds: float = 15.0, daily_limit: int = 450):
        self.lock = threading.Lock()
        self.min_interval = min_interval_seconds
        self.daily_limit = daily_limit
        self.last_call_time: float = 0.0
        self.day_start_timestamp: float = time.time()
        self.daily_count: int = 0

    def acquire(self) -> tuple[bool, str | None]:
        with self.lock:
            now = time.time()
            if now - self.day_start_timestamp >= 86400:
                self.day_start_timestamp = now
                self.daily_count = 0

            if self.daily_count >= self.daily_limit:
                reset_in = int(86400 - (now - self.day_start_timestamp))
                return (
                    False,
                    f"Daily VirusTotal query quota ({self.daily_limit}) reached. Quota resets in ~{reset_in}s.",
                )

            elapsed = now - self.last_call_time
            if self.last_call_time > 0 and elapsed < self.min_interval:
                sleep_needed = self.min_interval - elapsed
                time.sleep(sleep_needed)

            self.last_call_time = time.time()
            self.daily_count += 1
            return True, None


VT_RATE_LIMITER = VirusTotalRateLimiter()


def get_vt_cache(
    sha256: str,
    db_path: Path | str = DB_PATH,
) -> dict[str, Any] | None:
    """Retrieve cached VirusTotal result if within TTL (24h for found, 1h for not_found)."""
    if not os.path.exists(str(db_path)):
        return None

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                status TEXT,
                data TEXT,
                fetched_at REAL
            )
            """
        )
        row = conn.execute(
            "SELECT status, data, fetched_at FROM vt_cache WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if not row:
            return None

        status, data_str, fetched_at = row
        age = time.time() - float(fetched_at)

        # TTL: 24h (86400s) for found, 1h (3600s) for not_found
        max_age = (
            86400.0 if status == "found" else (3600.0 if status == "not_found" else 0.0)
        )
        if age > max_age:
            return None

        result = json.loads(data_str)
        result["from_cache"] = True
        result["fetched_at"] = datetime.fromtimestamp(
            fetched_at, tz=timezone.utc
        ).isoformat()
        return result
    except Exception:
        return None
    finally:
        conn.close()


def save_vt_cache(
    sha256: str,
    status: str,
    data: dict[str, Any],
    db_path: Path | str = DB_PATH,
) -> None:
    """Save a successful or not_found VirusTotal result to SQLite cache."""
    if status not in ("found", "not_found"):
        return

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                status TEXT,
                data TEXT,
                fetched_at REAL
            )
            """
        )
        clean_copy = dict(data)
        clean_copy["from_cache"] = False
        conn.execute(
            """
            INSERT OR REPLACE INTO vt_cache (sha256, status, data, fetched_at)
            VALUES (?, ?, ?, ?)
            """,
            (sha256, status, json.dumps(clean_copy), time.time()),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def fetch_hash_reputation(
    sha256: str,
    api_key: str | None = None,
    db_path: Path | str = DB_PATH,
    timeout_seconds: float = 10.0,
    rate_limiter: VirusTotalRateLimiter | None = None,
) -> dict[str, Any]:
    """
    Look up a file's SHA256 hash on VirusTotal to check global antivirus detection rates.
    Checks local SQLite cache first (24h TTL for found, 1h for not_found), obeys 15s
    rate limiting and daily quotas, and returns only clean numbers and dates.
    Never uploads files or passes raw untrusted text from VirusTotal.
    """
    if not sha256 or not isinstance(sha256, str):
        return {
            "sha256": str(sha256) if sha256 is not None else "",
            "status": "invalid_input",
            "reason": "SHA256 hash string is required.",
        }

    clean_hash = sha256.strip().upper()
    if not re.fullmatch(r"[0-9A-F]{64}", clean_hash):
        return {
            "sha256": clean_hash,
            "status": "invalid_input",
            "reason": f"Invalid SHA256 format: '{clean_hash}'. Expected exactly 64 hexadecimal characters.",
        }

    # Step 2: Check local cache first
    cached = get_vt_cache(clean_hash, db_path=db_path)
    if cached is not None:
        return cached

    # Resolve API Key
    key = api_key if api_key is not None else VT_API_KEY
    if not key:
        return {
            "sha256": clean_hash,
            "status": "unavailable",
            "reason": "No VirusTotal API key configured in environment (VT_API_KEY).",
        }

    # Step 3: Rate Limiter
    limiter = rate_limiter or VT_RATE_LIMITER
    allowed, limit_reason = limiter.acquire()
    if not allowed:
        return {
            "sha256": clean_hash,
            "status": "rate_limited",
            "reason": limit_reason
            or "VirusTotal rate limit exceeded. Do not retry; continue investigation without reputation data.",
        }

    # Step 4: Perform HTTP request
    url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"
    headers = {
        "x-apikey": key,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout_seconds)
        now_iso = datetime.now(timezone.utc).isoformat()

        if resp.status_code == 200:
            try:
                body = resp.json()
            except Exception:
                return {
                    "sha256": clean_hash,
                    "status": "unavailable",
                    "reason": "Invalid JSON response from VirusTotal.",
                }

            attrs = body.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            first_sub = attrs.get("first_submission_date")
            last_anal = attrs.get("last_analysis_date")

            first_seen_iso = (
                datetime.fromtimestamp(first_sub, tz=timezone.utc).isoformat()
                if isinstance(first_sub, (int, float))
                else None
            )
            last_analyzed_iso = (
                datetime.fromtimestamp(last_anal, tz=timezone.utc).isoformat()
                if isinstance(last_anal, (int, float))
                else None
            )

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total_engines = sum(
                int(v) for v in stats.values() if isinstance(v, (int, float))
            )

            result = {
                "sha256": clean_hash,
                "status": "found",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines,
                "first_seen": first_seen_iso,
                "last_analyzed": last_analyzed_iso,
                "from_cache": False,
                "fetched_at": now_iso,
            }
            save_vt_cache(clean_hash, "found", result, db_path=db_path)
            return result

        elif resp.status_code == 404:
            result = {
                "sha256": clean_hash,
                "status": "not_found",
                "reason": "VirusTotal has never seen this file.",
                "from_cache": False,
                "fetched_at": now_iso,
            }
            save_vt_cache(clean_hash, "not_found", result, db_path=db_path)
            return result

        elif resp.status_code == 429:
            return {
                "sha256": clean_hash,
                "status": "rate_limited",
                "reason": "VirusTotal quota exceeded (HTTP 429). Do not retry; continue investigation without reputation data.",
            }

        elif resp.status_code == 401:
            return {
                "sha256": clean_hash,
                "status": "unavailable",
                "reason": "VirusTotal API key is invalid or unauthorized (HTTP 401).",
            }

        else:
            return {
                "sha256": clean_hash,
                "status": "unavailable",
                "reason": f"VirusTotal returned HTTP {resp.status_code}.",
            }

    except requests.exceptions.Timeout:
        return {
            "sha256": clean_hash,
            "status": "unavailable",
            "reason": f"VirusTotal request timed out after {timeout_seconds} seconds.",
        }
    except Exception as e:
        return {
            "sha256": clean_hash,
            "status": "unavailable",
            "reason": f"VirusTotal network error: {str(e)}",
        }


# ==============================================================================
# 12b. EXA AI WEB & THREAT INTELLIGENCE SEARCH
# ==============================================================================


def get_exa_cache(
    query: str,
    db_path: Path | str = DB_PATH,
) -> dict[str, Any] | None:
    """Retrieve cached Exa search result if within TTL (24h for success, 1h for not_found)."""
    path = Path(db_path)
    if not path.exists():
        return None

    norm_query = query.strip().lower()
    query_hash = hashlib.sha256(norm_query.encode("utf-8")).hexdigest()

    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS exa_cache (
                query_hash TEXT PRIMARY KEY,
                query TEXT,
                status TEXT,
                data TEXT,
                fetched_at REAL
            )
            """
        )
        row = conn.execute(
            "SELECT status, data, fetched_at FROM exa_cache WHERE query_hash = ?",
            (query_hash,),
        ).fetchone()
        if not row:
            return None

        status, data_str, fetched_at = row
        age = time.time() - float(fetched_at)

        # TTL: 24h (86400s) for success, 1h (3600s) for not_found
        max_age = 86400.0 if status == "success" else (3600.0 if status == "not_found" else 0.0)
        if age > max_age:
            return None

        result = json.loads(data_str)
        result["from_cache"] = True
        return result
    except Exception:
        return None
    finally:
        conn.close()


def save_exa_cache(
    query: str,
    status: str,
    data: dict[str, Any],
    db_path: Path | str = DB_PATH,
) -> None:
    """Save Exa search result to SQLite cache."""
    if status not in ("success", "not_found"):
        return

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    norm_query = query.strip().lower()
    query_hash = hashlib.sha256(norm_query.encode("utf-8")).hexdigest()

    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS exa_cache (
                query_hash TEXT PRIMARY KEY,
                query TEXT,
                status TEXT,
                data TEXT,
                fetched_at REAL
            )
            """
        )
        data_to_store = dict(data)
        data_to_store["from_cache"] = False
        conn.execute(
            """
            INSERT OR REPLACE INTO exa_cache (query_hash, query, status, data, fetched_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (query_hash, query.strip(), status, json.dumps(data_to_store), time.time()),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def fetch_exa_search(
    query: str,
    num_results: int = 3,
    api_key: str | None = None,
    db_path: Path | str = DB_PATH,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """
    Search the web using Exa AI for threat intelligence, LOLBAS, CVEs, or security research.
    Checks local SQLite cache first (24h TTL for success, 1h for not_found),
    sanitizes text snippets from web pages, and returns structured results.
    """
    if not query or not isinstance(query, str) or not query.strip():
        return {
            "query": str(query) if query is not None else "",
            "status": "invalid_input",
            "reason": "Search query string is required.",
        }

    clean_query = query.strip()
    if len(clean_query) > 500:
        return {
            "query": clean_query[:500],
            "status": "invalid_input",
            "reason": f"Search query exceeds 500 characters (length: {len(clean_query)}).",
        }

    # Clamp num_results between 1 and 5
    try:
        num_results = max(1, min(int(num_results or 3), 5))
    except (ValueError, TypeError):
        num_results = 3

    # Check local cache
    cached = get_exa_cache(clean_query, db_path=db_path)
    if cached is not None:
        return cached

    # Resolve API Key
    key = api_key if api_key is not None else EXAAI_SEARCH_API_KEY
    if not key:
        return {
            "query": clean_query,
            "status": "unavailable",
            "reason": "No Exa AI API key configured in environment (EXAAI_SEARCH_API_KEY).",
        }

    url = "https://api.exa.ai/search"
    headers = {
        "x-api-key": key,
        "Content-Type": "application/json",
    }
    payload = {
        "query": clean_query,
        "numResults": num_results,
        "contents": {
            "text": {
                "maxCharacters": 800,
            }
        },
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout_seconds)
        now_iso = datetime.now(timezone.utc).isoformat()

        if resp.status_code == 200:
            try:
                body = resp.json()
            except Exception:
                return {
                    "query": clean_query,
                    "status": "unavailable",
                    "reason": "Invalid JSON response from Exa AI.",
                }

            raw_results = body.get("results", [])
            if not raw_results:
                result = {
                    "query": clean_query,
                    "status": "not_found",
                    "results": [],
                    "message": "No relevant search results found on Exa AI.",
                    "from_cache": False,
                    "fetched_at": now_iso,
                }
                save_exa_cache(clean_query, "not_found", result, db_path=db_path)
                return result

            parsed_results = []
            for r in raw_results[:num_results]:
                # Sanitize text
                raw_text = r.get("text", "") or ""
                clean_text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw_text)
                clean_text = re.sub(r"<[^>]+>", "", clean_text)
                clean_text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", clean_text).strip()

                title = re.sub(r"<[^>]+>", "", r.get("title", "") or "").strip()
                url_str = str(r.get("url", "") or "").strip()
                pub_date = str(r.get("publishedDate", "") or "").strip()

                parsed_results.append({
                    "title": title,
                    "url": url_str,
                    "published_date": pub_date,
                    "snippet": clean_text[:800],
                })

            result = {
                "query": clean_query,
                "status": "success",
                "results": parsed_results,
                "total_results": len(parsed_results),
                "from_cache": False,
                "fetched_at": now_iso,
            }
            save_exa_cache(clean_query, "success", result, db_path=db_path)
            return result

        elif resp.status_code in (401, 403):
            return {
                "query": clean_query,
                "status": "unavailable",
                "reason": f"Exa AI authentication failed (HTTP {resp.status_code}). Invalid API key.",
            }

        elif resp.status_code == 429:
            return {
                "query": clean_query,
                "status": "rate_limited",
                "reason": "Exa AI rate limit or quota exceeded (HTTP 429). Continue investigation without web search.",
            }

        else:
            return {
                "query": clean_query,
                "status": "unavailable",
                "reason": f"Exa AI returned HTTP {resp.status_code}.",
            }

    except requests.exceptions.Timeout:
        return {
            "query": clean_query,
            "status": "unavailable",
            "reason": f"Exa AI request timed out after {timeout_seconds} seconds.",
        }
    except Exception as e:
        return {
            "query": clean_query,
            "status": "unavailable",
            "reason": f"Exa AI network error: {str(e)}",
        }


# ==============================================================================
# 13. PROCESS TERMINATION & HUMAN-IN-THE-LOOP CONTAINMENT
# ==============================================================================


def check_protected_process(
    pid: int | None,
    image_path: str = "",
) -> tuple[bool, bool, str]:
    """
    Check whether a process is protected and cannot be terminated.
    Returns (is_protected, is_masquerading, reason).

    Rules:
    - Never kill your own tool: Block agent's PID, watcher's PID, and their parents.
    - System / Kernel: PID 0, PID 4, System, Registry.
    - Genuine Windows system processes: smss.exe, csrss.exe, wininit.exe, winlogon.exe,
      services.exe, lsass.exe, svchost.exe, explorer.exe, dwm.exe, fontdrvhost.exe,
      Sysmon, and Defender when running from their genuine Windows locations.
    - If a protected binary name runs from an unexpected / untrusted directory (e.g. Temp),
      it is NOT protected (can be killed), but is_masquerading is set to True.
    """
    # 1. Self & Kernel PID protection
    if pid is not None:
        try:
            current_pid = os.getpid()
            parent_pid = os.getppid() if hasattr(os, "getppid") else None
        except Exception:
            current_pid = -1
            parent_pid = -1

        protected_pids = {0, 4}
        if current_pid > 0:
            protected_pids.add(current_pid)
        if parent_pid and parent_pid > 0:
            protected_pids.add(parent_pid)

        if pid in protected_pids:
            return True, False, f"Protected process: PID {pid} is a core system or agent/tool process."

    # 2. Check Image Name & Path
    norm_image = os.path.normpath(image_path).strip() if image_path else ""
    base_name = os.path.basename(norm_image).lower()

    if base_name in ("system", "registry"):
        return True, False, f"Protected OS component: '{base_name}'."

    # Protected binary names
    protected_system_names = {
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "dwm.exe",
        "fontdrvhost.exe",
    }
    protected_windows_names = {
        "explorer.exe",
        "sysmon.exe",
        "sysmon64.exe",
    }
    defender_names = {
        "msmpeng.exe",
        "nissrv.exe",
        "mpcmdrun.exe",
        "sensediscovery.exe",
        "senseir.exe",
        "sensendr.exe",
        "sensecncproxy.exe",
    }

    all_protected_names = protected_system_names | protected_windows_names | defender_names
    if base_name not in all_protected_names:
        return False, False, "Process is not on the protected list."

    # Determine genuine system directories
    system_root = os.path.normcase(os.path.normpath(os.environ.get("SystemRoot", r"C:\Windows")))
    system32 = os.path.normcase(os.path.normpath(os.path.join(system_root, "System32")))
    syswow64 = os.path.normcase(os.path.normpath(os.path.join(system_root, "SysWOW64")))

    image_dir = os.path.normcase(os.path.dirname(norm_image)) if norm_image else ""

    # Check if image is in genuine locations
    is_genuine = False
    if base_name in protected_system_names:
        is_genuine = (image_dir == system32 or image_dir == syswow64)
    elif base_name in protected_windows_names:
        is_genuine = (image_dir == system_root or image_dir == system32 or image_dir == syswow64)
    elif base_name in defender_names:
        is_genuine = any(
            frag in image_dir
            for frag in ("windows defender", "microsoft defender", "defender advanced threat protection")
        )

    if is_genuine:
        return True, False, f"Protected system binary '{base_name}' running from genuine path '{norm_image}'."
    else:
        # Masquerading!
        return False, True, (
            f"WARNING: Process name matches protected system binary '{base_name}' "
            f"but is running from untrusted path '{norm_image}' (masquerading detected)."
        )


def is_in_alert_tree(
    target_guid: str,
    alert_guid: str,
    db_path: Path | str = DB_PATH,
    max_depth: int = 50,
) -> bool:
    """
    Verify whether target_guid is within the alert's process tree lineage:
    - The alert process itself
    - A descendant of the alert process (spawned by alert or downstream)
    - An ancestor of the alert process (parent/launcher that executed the alert)
    """
    if not target_guid or not alert_guid:
        return False

    def norm_g(g: str) -> str:
        return g.strip().strip("{}").lower()

    target_norm = norm_g(target_guid)
    alert_norm = norm_g(alert_guid)

    if target_norm == alert_norm:
        return True

    if not os.path.exists(str(db_path)):
        return False

    conn = sqlite3.connect(str(db_path))
    try:
        def get_parent(guid_norm: str) -> str | None:
            g_with_braces = f"{{{guid_norm}}}"
            cursor = conn.execute(
                """
                SELECT json_extract(raw_data, '$.ParentProcessGuid')
                FROM events
                WHERE event_id = 1
                  AND (json_extract(raw_data, '$.ProcessGuid') = ? OR json_extract(raw_data, '$.ProcessGuid') = ?
                       OR LOWER(json_extract(raw_data, '$.ProcessGuid')) = ? OR LOWER(json_extract(raw_data, '$.ProcessGuid')) = ?)
                ORDER BY id DESC LIMIT 1
                """,
                (g_with_braces, guid_norm, g_with_braces.lower(), guid_norm.lower()),
            )
            row = cursor.fetchone()
            if row and row[0]:
                return norm_g(str(row[0]))
            return None

        # 1. Check if target_guid is a descendant of alert_guid (climb up from target to alert)
        curr = target_norm
        visited = {curr}
        for _ in range(max_depth):
            p = get_parent(curr)
            if not p:
                break
            if p == alert_norm:
                return True
            if p in visited:
                break
            visited.add(p)
            curr = p

        # 2. Check if target_guid is an ancestor of alert_guid (climb up from alert to target)
        curr = alert_norm
        visited = {curr}
        for _ in range(max_depth):
            p = get_parent(curr)
            if not p:
                break
            if p == target_norm:
                return True
            if p in visited:
                break
            visited.add(p)
            curr = p

        return False
    finally:
        conn.close()


def log_audit_kill(entry: dict, audit_path: Path | str = AUDIT_LOG_PATH) -> None:
    """
    Append an entry to the kill_process audit log in JSON Lines format.
    Ensures parent directory exists.
    """
    try:
        path = Path(audit_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        print(f"[!] Warning: Failed to write to audit log at {audit_path}: {e}")


def format_approval_screen(
    guid: str,
    reason: str,
    alert: dict | None = None,
    rule: dict | None = None,
    db_path: Path | str = DB_PATH,
    dry_run: bool | None = None,
) -> str:
    """
    Format a clear, readable Human-In-The-Loop approval screen showing:
    - Alert title and severity
    - Target details from event store and live system (image, PID, command line, user, start time, parent)
    - Live process running status
    - Prominent warning if a protected binary name appears at an untrusted path (masquerading)
    - Agent's proposal reasoning
    - Scope and consequence warnings
    - Clear DRY RUN banner when enabled
    """
    effective_dry_run = DRY_RUN if dry_run is None else dry_run

    alert = alert or {}
    rule = rule or {}

    alert_title = alert.get("rule_name") or rule.get("title") or "Security Alert"
    severity = str(alert.get("severity") or rule.get("level") or "unknown").upper()

    resolved = resolve_live_process(guid, db_path=db_path)
    pid = resolved.get("pid", "Unknown")
    image = resolved.get("image", "Unknown")
    command_line = resolved.get("command_line", "Unknown")
    user = resolved.get("user", "Unknown")
    start_time = resolved.get("start_time", "Unknown")
    parent_image = resolved.get("parent_image", "Unknown")
    parent_guid = resolved.get("parent_guid", "Unknown")

    res_status = resolved.get("status")
    if res_status == "running":
        live_status = f"RUNNING (PID {pid}, verified start time: {resolved.get('matched_live_start_time')})"
    elif res_status == "exited":
        live_status = f"EXITED ({resolved.get('reason')})"
    else:
        live_status = f"UNKNOWN / {res_status} ({resolved.get('reason', '')})"

    # Check protected & masquerading
    int_pid = int(pid) if isinstance(pid, int) or (isinstance(pid, str) and pid.isdigit()) else None
    _, is_masq, masq_warning = check_protected_process(int_pid, image)

    banner_mode = (
        ">>> [!] DRY RUN MODE ACTIVE - SIMULATION ONLY (NO PROCESS WILL BE TERMINATED) [!] <<<"
        if effective_dry_run
        else ">>> [!] LIVE EXECUTION MODE - TARGET WILL BE PERMANENTLY TERMINATED [!] <<<"
    )

    lines = [
        "=" * 80,
        "                 [HUMAN-IN-THE-LOOP] PROCESS TERMINATION PROPOSAL",
        "=" * 80,
        banner_mode,
        "-" * 80,
        "ALERT CONTEXT:",
        f"  Alert Title:  {alert_title}",
        f"  Severity:     {severity}",
        "",
        "TARGET PROCESS (from Event Store & Live System):",
        f"  Process GUID: {guid}",
        f"  PID:          {pid}",
        f"  Image Path:   {image}",
        f"  Command Line: {command_line}",
        f"  User:         {user}",
        f"  Start Time:   {start_time}",
        f"  Parent Image: {parent_image}",
        f"  Parent GUID:  {parent_guid}",
        f"  Live Status:  {live_status}",
    ]

    if is_masq:
        lines.extend([
            "",
            "********************************************************************************",
            "  [!] MASQUERADING WARNING:",
            f"  {masq_warning}",
            "********************************************************************************",
        ])

    lines.extend([
        "",
        "AGENT PROPOSAL & EVIDENCE:",
        f"  Reason:       {reason}",
        "",
        "CONSEQUENCES & SCOPE:",
        "  - Stops this single process only. Cannot be undone.",
        "  - Does NOT remove dropped files, startup keys, or scheduled tasks.",
        "  - Child processes may remain active. Attacker may attempt to relaunch.",
        "  - The agent must inspect for relaunches and document cleanup requirements.",
        "=" * 80,
    ])

    return "\n".join(lines)


def terminate_process(
    guid: str,
    reason: str = "",
    alert_guid: str | None = None,
    alert_id: str | None = None,
    approved: bool = False,
    dry_run: bool | None = None,
    db_path: Path | str = DB_PATH,
    audit_path: Path | str = AUDIT_LOG_PATH,
    thread_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Terminate one process that the agent has decided is malicious, following
    the Human-In-The-Loop containment protocol and strict safety checks:
    1. Validate GUID format (rejects malformed strings).
    2. Resolve stored process record from Event 1.
    3. Verify target process is within the alert's process tree (alert itself or descendant).
    4. Verify process is not on the protected list (OS kernel, core system binaries, agent/watcher itself).
    5. Check live status: ensure process is alive and PID has not been reused.
    6. Verify human approval (refuses if not approved).
    7. Post-approval re-check: re-verify liveness and PID identity before killing.
    8. Dry-run simulation mode support.
    9. Terminate process with psutil, wait, and confirm gone.
    10. Write append-only audit log for EVERY attempt and outcome.
    """
    effective_dry_run = DRY_RUN if dry_run is None else dry_run

    _orig_kill_log = globals()["log_audit_kill"]
    def log_audit_kill(entry: dict, audit_path: Path | str = audit_path) -> None:
        if thread_id and "thread_id" not in entry:
            entry["thread_id"] = thread_id
        if alert_id and ("alert_id" not in entry or entry["alert_id"] == "unknown"):
            entry["alert_id"] = alert_id
        elif alert_guid and ("alert_id" not in entry or entry["alert_id"] == "unknown"):
            entry["alert_id"] = alert_guid
        if alert_guid and "alert_guid" not in entry:
            entry["alert_guid"] = alert_guid
        if "target" not in entry:
            entry["target"] = entry.get("target_guid") or entry.get("image")
        _orig_kill_log(entry, audit_path=audit_path)

    # 1. Validate GUID format
    guid_str = str(guid).strip() if guid else ""
    guid_pattern = r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
    if not guid_str or not re.match(guid_pattern, guid_str):
        result = {
            "guid": guid_str,
            "status": "invalid_input",
            "pid": None,
            "image": "",
            "reason": f"Invalid GUID format: '{guid}'. Expected standard UUID format.",
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": None,
            "image": "",
            "command_line": "",
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "invalid_input",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 2. Resolve stored process info
    resolved = resolve_live_process(guid_str, db_path=db_path)
    target_pid = resolved.get("pid")
    target_image = resolved.get("image", "")
    cmd_line = resolved.get("command_line", "")

    if resolved.get("status") in ("invalid_guid", "not_found"):
        result = {
            "guid": guid_str,
            "status": "invalid_input",
            "pid": None,
            "image": "",
            "reason": resolved.get("reason", f"GUID '{guid_str}' not found in event history."),
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": None,
            "image": "",
            "command_line": "",
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "invalid_input",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 3. Tree containment check (must be alert process itself or something it launched)
    if not alert_guid or not is_in_alert_tree(guid_str, alert_guid, db_path=db_path):
        result = {
            "guid": guid_str,
            "status": "not_allowed_target",
            "pid": target_pid,
            "image": target_image,
            "reason": f"Target process '{guid_str}' is not in the alert's process tree (alert GUID: '{alert_guid}').",
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "not_allowed_target",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 4. Protected process check
    is_protected, is_masq, prot_reason = check_protected_process(target_pid, target_image)
    if is_protected:
        result = {
            "guid": guid_str,
            "status": "blocked_protected",
            "pid": target_pid,
            "image": target_image,
            "reason": prot_reason,
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "blocked_protected",
            "dry_run": effective_dry_run,
            "details": prot_reason,
        }, audit_path=audit_path)
        return result

    # 5. Pre-check live status: running, exited, reused PID, or access denied
    res_status = resolved.get("status")
    if res_status == "exited":
        resolved_reason = resolved.get("reason", "")
        if "different process" in resolved_reason or "reused PID" in resolved_reason:
            final_status = "not_same_process"
        else:
            final_status = "already_exited"
        result = {
            "guid": guid_str,
            "status": final_status,
            "pid": target_pid,
            "image": target_image,
            "reason": resolved_reason,
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": final_status,
            "dry_run": effective_dry_run,
            "details": resolved_reason,
        }, audit_path=audit_path)
        return result
    elif res_status == "access_denied":
        result = {
            "guid": guid_str,
            "status": "access_denied",
            "pid": target_pid,
            "image": target_image,
            "reason": resolved.get("reason", "Windows denied access when reading process details."),
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "access_denied",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result
    elif res_status != "running":
        result = {
            "guid": guid_str,
            "status": "failed",
            "pid": target_pid,
            "image": target_image,
            "reason": resolved.get("reason", "Could not resolve live process state."),
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "failed",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 6. Verify human approval
    if not approved:
        result = {
            "guid": guid_str,
            "status": "rejected_by_user",
            "pid": target_pid,
            "image": target_image,
            "reason": "Termination proposal was rejected by user (or approval was not granted).",
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": False,
            "approver": "none",
            "status": "rejected_by_user",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 7. Post-approval re-check: re-verify live state right before termination
    re_resolved = resolve_live_process(guid_str, db_path=db_path)
    re_status = re_resolved.get("status")
    if re_status == "exited":
        re_reason = re_resolved.get("reason", "")
        if "different process" in re_reason or "reused PID" in re_reason:
            final_status = "not_same_process"
        else:
            final_status = "already_exited"
        result = {
            "guid": guid_str,
            "status": final_status,
            "pid": target_pid,
            "image": target_image,
            "reason": f"Post-approval re-check: {re_reason}",
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": final_status,
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result
    elif re_status == "access_denied":
        result = {
            "guid": guid_str,
            "status": "access_denied",
            "pid": target_pid,
            "image": target_image,
            "reason": re_resolved.get("reason", "Access denied during post-approval re-check."),
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "access_denied",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result
    elif re_status != "running":
        result = {
            "guid": guid_str,
            "status": "failed",
            "pid": target_pid,
            "image": target_image,
            "reason": f"Post-approval re-check failed: {re_resolved.get('reason')}",
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "failed",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 8. Dry-run mode check
    if effective_dry_run:
        result = {
            "guid": guid_str,
            "status": "dry_run",
            "pid": target_pid,
            "image": target_image,
            "reason": "DRY RUN active: all safety checks passed and kill was simulated, but process was not terminated.",
        }
        log_audit_kill({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "target_guid": guid_str,
            "target_pid": target_pid,
            "image": target_image,
            "command_line": cmd_line,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "dry_run",
            "dry_run": True,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 9. Live termination execution
    proc: psutil.Process = re_resolved["proc"]
    try:
        proc.terminate()
        gone, alive = psutil.wait_procs([proc], timeout=3.0)
        if alive:
            for p in alive:
                try:
                    p.kill()
                except Exception:
                    pass
            gone, alive = psutil.wait_procs(alive, timeout=2.0)

        if alive:
            outcome_status = "failed"
            msg = f"Process PID {target_pid} did not terminate within timeout."
        else:
            outcome_status = "executed"
            msg = f"Process PID {target_pid} ('{target_image}') was successfully terminated and confirmed gone."
    except psutil.AccessDenied:
        outcome_status = "access_denied"
        msg = f"Windows denied access when terminating PID {target_pid} (higher privilege or protected process)."
    except psutil.NoSuchProcess:
        outcome_status = "already_exited"
        msg = f"Process PID {target_pid} exited before termination could complete."
    except Exception as e:
        outcome_status = "failed"
        msg = f"Error terminating PID {target_pid}: {str(e)}"

    result = {
        "guid": guid_str,
        "status": outcome_status,
        "pid": target_pid,
        "image": target_image,
        "reason": msg,
    }
    log_audit_kill({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert_id or "unknown",
        "target_guid": guid_str,
        "target_pid": target_pid,
        "image": target_image,
        "command_line": cmd_line,
        "reason": reason,
        "approved": approved,
        "approver": "human",
        "status": outcome_status,
        "dry_run": False,
        "details": msg,
    }, audit_path=audit_path)

    return result


# ==============================================================================
# 14. FILE QUARANTINE & HUMAN-IN-THE-LOOP CONTAINMENT
# ==============================================================================


def init_quarantine_dir(quarantine_dir: Path | str = QUARANTINE_DIR) -> Path:
    """
    Ensure the quarantine folder exists and lock it down.
    The .quarantine extension and hash-based naming provide the primary protection;
    folder-level permission lockdowns provide a defense-in-depth second layer.
    """
    path = Path(quarantine_dir)
    path.mkdir(parents=True, exist_ok=True)

    # Attempt to deny execution permissions on Windows if possible
    try:
        if os.name == "nt":
            # Deny execute permissions to Everyone on the quarantine folder
            subprocess.run(
                ["icacls", str(path), "/deny", "*S-1-1-0:(OI)(CI)(X)"],
                capture_output=True,
                check=False,
            )
    except Exception:
        pass

    return path


def check_protected_file(
    path: str,
    quarantine_dir: Path | str = QUARANTINE_DIR,
    audit_path: Path | str | None = None,
) -> tuple[bool, str]:
    """
    Check whether a file is in a protected system or project location and cannot be quarantined.
    Returns (is_protected, reason).

    Rules:
    - Block files in core Windows folders: C:\\Windows\\System32, SysWOW64, WinSxS.
    - Block security tooling: Windows Defender directories, Sysmon binaries in Windows directories.
    - Block own project files: project root, code files, .env, event database, audit logs,
      and the quarantine folder itself.
    - Note: Matching is by path, so a copy of a system binary in a Temp folder is NOT blocked.
    """
    try:
        norm = os.path.normcase(os.path.realpath(path))
    except Exception:
        norm = os.path.normcase(os.path.normpath(path))

    # 1. Windows core system directories
    system_root = os.path.normcase(os.path.realpath(os.environ.get("SystemRoot", r"C:\Windows")))
    system32 = os.path.normcase(os.path.join(system_root, "system32"))
    syswow64 = os.path.normcase(os.path.join(system_root, "syswow64"))
    winsxs = os.path.normcase(os.path.join(system_root, "winsxs"))

    for protected_dir in (system32, syswow64, winsxs):
        if norm == protected_dir or norm.startswith(protected_dir + os.sep):
            return True, f"Protected system binary located in Windows core directory: '{norm}'."

    # 2. Security software directories
    lower_norm = norm.lower()
    security_dir_frags = (
        "\\windows defender",
        "\\microsoft defender",
        "\\defender advanced threat protection",
    )
    if any(frag in lower_norm for frag in security_dir_frags):
        return True, f"Protected security software component: '{norm}'."

    base_name = os.path.basename(norm).lower()
    if base_name in ("sysmon.exe", "sysmon64.exe", "sysmondrv.sys") and norm.startswith(system_root + os.sep):
        return True, f"Protected security tool binary: '{norm}'."

    # 3. Environment configuration (.env)
    if base_name == ".env" or norm.endswith(os.sep + ".env"):
        return True, f"Protected environment configuration file: '{norm}'."

    # 4. Own project files & quarantine folder & audit log
    proj_root = os.path.normcase(os.path.realpath(str(ROOT_DIR)))
    q_dir = os.path.normcase(os.path.realpath(str(quarantine_dir)))
    db_directory = os.path.normcase(os.path.realpath(str(DB_DIR)))

    if norm == q_dir or norm.startswith(q_dir + os.sep):
        return True, f"Protected quarantine directory component: '{norm}'."

    if norm == db_directory or norm.startswith(db_directory + os.sep):
        return True, f"Protected database / audit component: '{norm}'."

    mem_directory = os.path.normcase(os.path.realpath(str(MEMORY_DIR)))
    if norm == mem_directory or norm.startswith(mem_directory + os.sep):
        return True, f"Protected agent memory directory component: '{norm}'."

    if audit_path:
        try:
            a_norm = os.path.normcase(os.path.realpath(str(audit_path)))
        except Exception:
            a_norm = os.path.normcase(os.path.normpath(str(audit_path)))
        if norm == a_norm:
            return True, f"Protected audit log file: '{norm}'."

    if norm == proj_root or norm.startswith(proj_root + os.sep):
        # Inside project root
        return True, f"Protected project workspace file: '{norm}'."

    return False, ""


def get_alert_tree_guids(
    alert_guid: str,
    db_path: Path | str = DB_PATH,
    max_depth: int = 50,
) -> set[str]:
    """
    Find all Sysmon process GUIDs in the alert's process tree (the alert process itself
    plus all descendants launched by it, up to max_depth).
    """
    if not alert_guid:
        return set()

    def norm_g(g: str) -> str:
        return g.strip().strip("{}").lower()

    root_norm = norm_g(alert_guid)
    tree: set[str] = {root_norm}

    if not os.path.exists(str(db_path)):
        return tree

    conn = sqlite3.connect(str(db_path))
    try:
        queue = [root_norm]
        visited = {root_norm}
        depth = 0

        while queue and depth < max_depth:
            depth += 1
            curr = queue.pop(0)
            g_with_braces = f"{{{curr}}}"

            cursor = conn.execute(
                """
                SELECT json_extract(raw_data, '$.ProcessGuid')
                FROM events
                WHERE event_id = 1
                  AND (json_extract(raw_data, '$.ParentProcessGuid') = ?
                       OR json_extract(raw_data, '$.ParentProcessGuid') = ?
                       OR LOWER(json_extract(raw_data, '$.ParentProcessGuid')) = ?
                       OR LOWER(json_extract(raw_data, '$.ParentProcessGuid')) = ?)
                """,
                (g_with_braces, curr, g_with_braces.lower(), curr.lower()),
            )

            for row in cursor.fetchall():
                if row and row[0]:
                    child_norm = norm_g(str(row[0]))
                    if child_norm not in visited:
                        visited.add(child_norm)
                        tree.add(child_norm)
                        queue.append(child_norm)
    finally:
        conn.close()

    return tree


def is_file_linked_to_alert(
    file_path: str,
    alert_guid: str,
    db_path: Path | str = DB_PATH,
) -> tuple[bool, str | None, dict[str, Any] | None]:
    """
    Verify whether file_path is linked to the alert:
    1. It is the executable image of the alert's process or a descendant process in the alert tree.
    2. Or it is a file created/written by those processes (Sysmon Event 11, Event 15, Event 2, etc.).

    Returns (is_linked, expected_sha256, match_details).
    """
    if not file_path or not alert_guid:
        return False, None, None

    try:
        norm_target = os.path.normcase(os.path.realpath(file_path))
    except Exception:
        norm_target = os.path.normcase(os.path.normpath(file_path))

    tree_guids = get_alert_tree_guids(alert_guid, db_path=db_path)
    if not tree_guids:
        return False, None, None

    if not os.path.exists(str(db_path)):
        return False, None, None

    conn = sqlite3.connect(str(db_path))
    try:
        # Check 1: Process images in alert tree (Event 1)
        cursor = conn.execute(
            """
            SELECT image, raw_data, sha256
            FROM events
            WHERE event_id = 1
            ORDER BY id ASC
            """
        )
        for row in cursor.fetchall():
            row_image = row[0] or ""
            try:
                norm_img = os.path.normcase(os.path.realpath(row_image))
            except Exception:
                norm_img = os.path.normcase(os.path.normpath(row_image))

            raw_str = row[1] or "{}"
            try:
                data = json.loads(raw_str)
            except Exception:
                data = {}

            p_guid = str(data.get("ProcessGuid") or "").strip().strip("{}").lower()
            if p_guid in tree_guids and norm_img == norm_target:
                # Extract hash
                h = row[2]
                if not h:
                    h = parse_hashes(data.get("Hashes", "")).get("sha256")
                return True, (h.upper() if h else None), {
                    "event_type": "process_image",
                    "process_guid": p_guid,
                    "image": row_image,
                }

        # Check 2: Files written/created by alert tree processes (Event 11, Event 2, Event 15, Event 23, Event 26)
        file_event_ids = (11, 2, 15, 23, 26)
        cursor = conn.execute(
            """
            SELECT event_id, raw_data, sha256
            FROM events
            WHERE event_id IN (11, 2, 15, 23, 26)
            ORDER BY id ASC
            """
        )
        for row in cursor.fetchall():
            raw_str = row[1] or "{}"
            try:
                data = json.loads(raw_str)
            except Exception:
                data = {}

            p_guid = str(data.get("ProcessGuid") or data.get("SourceProcessGuid") or "").strip().strip("{}").lower()
            if p_guid in tree_guids:
                target_fn = data.get("TargetFilename") or data.get("TargetFileName") or ""
                try:
                    norm_fn = os.path.normcase(os.path.realpath(target_fn))
                except Exception:
                    norm_fn = os.path.normcase(os.path.normpath(target_fn))

                if norm_fn and norm_fn == norm_target:
                    h = row[2]
                    if not h:
                        h = parse_hashes(data.get("Hashes", "")).get("sha256")
                    return True, (h.upper() if h else None), {
                        "event_type": f"file_event_{row[0]}",
                        "process_guid": p_guid,
                        "target_filename": target_fn,
                    }

        return False, None, None
    finally:
        conn.close()


def log_audit_quarantine(entry: dict, audit_path: Path | str = QUARANTINE_AUDIT_LOG_PATH) -> None:
    """
    Append an entry to the quarantine audit log in JSON Lines format.
    Ensures parent directory exists.
    """
    try:
        path = Path(audit_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        print(f"[!] Warning: Failed to write to quarantine audit log at {audit_path}: {e}")


def format_quarantine_approval_screen(
    path: str,
    reason: str,
    alert: dict | None = None,
    rule: dict | None = None,
    db_path: Path | str = DB_PATH,
    dry_run: bool | None = None,
) -> str:
    """
    Format a clear, readable Human-In-The-Loop approval screen for file quarantine:
    - Alert title and severity
    - Target file details (original path, size, timestamps, hash, existence)
    - Linked process info
    - Agent's proposal reasoning
    - Scope and consequence warnings (file moved & neutralized, can be restored)
    - Clear DRY RUN banner when enabled
    """
    effective_dry_run = DRY_RUN if dry_run is None else dry_run

    alert = alert or {}
    rule = rule or {}

    alert_title = alert.get("rule_name") or rule.get("title") or "Security Alert"
    severity = str(alert.get("severity") or rule.get("level") or "unknown").upper()

    try:
        real = validate_local_path(path)
        exists = os.path.isfile(real)
    except Exception:
        real = path
        exists = False

    size_str = "Unknown"
    created_str = "Unknown"
    modified_str = "Unknown"
    sha_str = "Unknown"

    if exists:
        try:
            st = os.stat(real)
            size_str = f"{st.st_size:,} bytes"
            created_str = _iso(st.st_ctime)
            modified_str = _iso(st.st_mtime)
            sha_str = sha256_of_file(real)
        except Exception:
            pass

    banner_mode = (
        ">>> [!] DRY RUN MODE ACTIVE - SIMULATION ONLY (NO FILE WILL BE MOVED) [!] <<<"
        if effective_dry_run
        else ">>> [!] LIVE EXECUTION MODE - FILE WILL BE MOVED TO QUARANTINE [!] <<<"
    )

    lines = [
        "=" * 80,
        "                 [HUMAN-IN-THE-LOOP] FILE QUARANTINE PROPOSAL",
        "=" * 80,
        banner_mode,
        "-" * 80,
        "ALERT CONTEXT:",
        f"  Alert Title:     {alert_title}",
        f"  Severity:        {severity}",
        "",
        "TARGET FILE DETAILS:",
        f"  Original Path:   {path}",
        f"  Resolved Path:   {real}",
        f"  Exists on Disk:  {exists}",
        f"  Size:            {size_str}",
        f"  Created (UTC):   {created_str}",
        f"  Modified (UTC):  {modified_str}",
        f"  SHA256 Hash:     {sha_str}",
        "",
        "AGENT PROPOSAL & EVIDENCE:",
        f"  Reason:          {reason}",
        "",
        "CONSEQUENCES & SCOPE:",
        "  - Neutralizes this file by moving it into the locked quarantine folder.",
        "  - Renames the file with a .quarantine extension so Windows cannot run it.",
        "  - Does NOT delete the file; a human can restore it to its original path.",
        "  - Does NOT terminate running processes; kill running process first if active.",
        "  - Does NOT remove registry or scheduled task persistence entries.",
        "=" * 80,
    ]

    return "\n".join(lines)


def format_ask_user_system_context(
    alert: dict[str, Any] | None = None,
    rule: dict[str, Any] | None = None,
    db_path: Path | str = DB_PATH,
) -> str:
    """
    Format system-recorded context for the ask_user tool question page:
    - Rule title and level
    - Alert time
    - Host
    - User
    - Process image
    - Command line (full)
    - Parent image
    """
    alert = alert or {}
    rule = rule or {}
    event = alert.get("event") or alert.get("event_data") or alert

    rule_title = rule.get("title") or alert.get("rule_name") or alert.get("title") or "Unknown Rule"
    rule_level = str(rule.get("level") or alert.get("severity") or alert.get("level") or "UNKNOWN").upper()
    alert_time = alert.get("timestamp") or alert.get("TimeCreated") or alert.get("created_at") or event.get("UtcTime") or "Unknown"
    host = alert.get("host") or alert.get("Computer") or event.get("Computer") or "Unknown"
    user = alert.get("user") or alert.get("User") or event.get("User") or "Unknown"

    guid = event.get("process_guid") or event.get("ProcessGuid") or alert.get("process_guid")
    resolved = resolve_live_process(guid, db_path=db_path) if guid else {}

    image = resolved.get("image") or event.get("Image") or event.get("image") or "Unknown"
    command_line = resolved.get("command_line") or event.get("CommandLine") or event.get("command_line") or "Unknown"
    parent_image = resolved.get("parent_image") or event.get("ParentImage") or event.get("parent_image") or "Unknown"

    lines = [
        f"Rule Title:    {rule_title}",
        f"Severity:      {rule_level}",
        f"Alert Time:    {alert_time}",
        f"Host:          {host}",
        f"User:          {user}",
        f"Process Image: {image}",
        f"Command Line:  {command_line}",
        f"Parent Image:  {parent_image}",
    ]
    return "\n".join(lines)


UNSURE_VARIANTS = {
    "i'm not sure",
    "im not sure",
    "not sure",
    "don't know",
    "dont know",
    "unsure",
    "unknown",
    "no idea",
}


def validate_ask_user_input(
    question: Any,
    choices: Any,
) -> tuple[bool, dict[str, Any], list[str]]:
    """
    Validate and sanitize question and choices according to HITL rules:
    - question: string, 10-300 characters, control characters stripped, newlines collapsed
    - choices: list of 2-5 strings, each 1-80 characters after trimming, unique ignoring case
    - removes any choice that is a variant of "I'm not sure" / "don't know"
    Returns (is_valid, sanitized_dict, errors)
    """
    errors: list[str] = []

    # 1. Question validation
    if not isinstance(question, str):
        errors.append("question must be a string")
        cleaned_question = ""
    else:
        # Strip control characters (ASCII 0-31, 127)
        cleaned_question = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", question)
        # Collapse newlines and whitespace
        cleaned_question = re.sub(r"\s+", " ", cleaned_question).strip()
        if len(cleaned_question) < 10:
            errors.append(f"question must be at least 10 characters (got {len(cleaned_question)})")
        elif len(cleaned_question) > 300:
            errors.append(f"question must be at most 300 characters (got {len(cleaned_question)})")

    # 2. Choices validation
    cleaned_choices: list[str] = []
    if not isinstance(choices, list):
        errors.append("choices must be a list of strings")
    else:
        seen_lower: set[str] = set()
        for idx, item in enumerate(choices):
            if not isinstance(item, str):
                errors.append(f"choice at index {idx} must be a string")
                continue
            # Strip control characters and whitespace
            c_clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", item)
            c_clean = re.sub(r"\s+", " ", c_clean).strip()

            # Remove variants of "I'm not sure" / "don't know"
            c_lower = c_clean.lower()
            if c_lower in UNSURE_VARIANTS:
                continue

            if len(c_clean) == 0:
                errors.append(f"choice at index {idx} cannot be empty")
                continue

            if len(c_clean) > 80:
                errors.append(f"choice '{c_clean[:20]}...' exceeds maximum length of 80 characters (got {len(c_clean)})")
                continue

            if c_lower in seen_lower:
                errors.append(f"duplicate choice '{c_clean}' (choices must be unique ignoring case)")
                continue

            seen_lower.add(c_lower)
            cleaned_choices.append(c_clean)

        if len(cleaned_choices) < 2:
            errors.append(f"at least 2 valid, distinct choices are required (got {len(cleaned_choices)})")
        elif len(cleaned_choices) > 5:
            errors.append(f"at most 5 choices are allowed (got {len(cleaned_choices)})")

    if errors:
        return False, {}, errors

    return True, {"question": cleaned_question, "choices": cleaned_choices}, []


def validate_and_ask_user(
    question: Any,
    choices: Any,
    thread_id: str | None = None,
    alert: dict[str, Any] | None = None,
    rule: dict[str, Any] | None = None,
    db_path: Path | str = DB_PATH,
    hitl_db_path: Path | str = HITL_DB_PATH,
    timeout: int = ASK_USER_TIMEOUT_SECONDS,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Validate inputs and request human answer via UI/HITL.
    If input validation fails, returns {"status": "invalid_input", "errors": errors}.
    """
    is_valid, sanitized, errors = validate_ask_user_input(question, choices)
    if not is_valid:
        return {
            "status": "invalid_input",
            "errors": errors,
        }

    from UI.HITL.server import request_ask_user
    system_context = format_ask_user_system_context(alert=alert, rule=rule, db_path=db_path)

    return request_ask_user(
        thread_id=thread_id or "direct_tool_thread",
        question=sanitized["question"],
        choices=sanitized["choices"],
        alert=alert,
        rule=rule,
        system_context=system_context,
        db_path=hitl_db_path,
        timeout=timeout,
    )


def validate_respond_input(text: Any) -> tuple[bool, str, list[str]]:
    """
    Validate and sanitize text for respond tool:
    - 1-1500 characters
    - plain text, control characters stripped (ASCII 0-31, 127 except newlines/tabs)
    Returns (is_valid, sanitized_text, errors).
    """
    errors: list[str] = []
    if not isinstance(text, str):
        errors.append("text must be a string")
        return False, "", errors

    # Strip control characters (retaining newline, carriage return, tab)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", text).strip()

    if len(sanitized) < 1:
        errors.append("text cannot be empty and must contain at least 1 character")
    elif len(sanitized) > 1500:
        errors.append(f"text exceeds maximum length of 1500 characters (got {len(sanitized)})")

    return len(errors) == 0, sanitized, errors


def respond_action(text: Any, awaiting_reply: bool = True) -> dict[str, Any]:
    """
    Business logic for respond tool:
    - If awaiting_reply is False: returns not_executed
    - Validates text (1-1500 chars plain text)
    - Returns sent | invalid_input | not_executed
    """
    if not awaiting_reply:
        return {
            "status": "not_executed",
            "reason": "No user message is waiting. Continue investigating and finish with submit_verdict.",
        }

    is_valid, sanitized, errors = validate_respond_input(text)
    if not is_valid:
        return {
            "status": "invalid_input",
            "errors": errors,
        }

    return {"status": "sent"}


def quarantine_file_action(
    path: str,
    reason: str = "",
    alert_guid: str | None = None,
    alert_id: str | None = None,
    approved: bool = False,
    dry_run: bool | None = None,
    db_path: Path | str = DB_PATH,
    quarantine_dir: Path | str = QUARANTINE_DIR,
    audit_path: Path | str = QUARANTINE_AUDIT_LOG_PATH,
    thread_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Quarantine one file that the agent has decided is malicious, following
    the Human-In-The-Loop containment protocol and strict safety checks:
    1. Validate path: local drive path only, no network paths, no wildcards, single file.
    2. Existence check: file must exist on disk.
    3. Protected location check: cannot quarantine core Windows system files, security software, or own project.
    4. Link to alert: must be the process image or a file written by the alert tree.
    5. Hash verification: disk SHA256 must match recorded event hash.
    6. Verify human approval.
    7. Post-approval re-check: verify file still exists and hash matches right before move.
    8. Dry-run simulation mode support.
    9. Move and neutralize: move to quarantine_dir/<sha256>.quarantine and write metadata JSON.
       Handles file-in-use and cross-drive copy-verify-delete safely.
    10. Write append-only audit log for EVERY attempt and outcome.
    """
    effective_dry_run = DRY_RUN if dry_run is None else dry_run

    _orig_quarantine_log = globals()["log_audit_quarantine"]
    def log_audit_quarantine(entry: dict, audit_path: Path | str = audit_path) -> None:
        if thread_id and "thread_id" not in entry:
            entry["thread_id"] = thread_id
        if alert_id and ("alert_id" not in entry or entry["alert_id"] == "unknown"):
            entry["alert_id"] = alert_id
        elif alert_guid and ("alert_id" not in entry or entry["alert_id"] == "unknown"):
            entry["alert_id"] = alert_guid
        if alert_guid and "alert_guid" not in entry:
            entry["alert_guid"] = alert_guid
        if "target" not in entry:
            entry["target"] = entry.get("target_path") or entry.get("original_path") or entry.get("path")
        if "target_path" not in entry:
            entry["target_path"] = entry.get("target") or entry.get("original_path")
        _orig_quarantine_log(entry, audit_path=audit_path)

    # 1. Path format validation
    if not path or not isinstance(path, str):
        result = {
            "path": str(path) if path is not None else "",
            "status": "invalid_input",
            "sha256": None,
            "quarantine_path": None,
            "reason": "File path is required and must be a string.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "invalid_input",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    raw_path = path.strip()
    if any(ch in raw_path for ch in ("*", "?", "<", ">", '"', "|")):
        result = {
            "path": raw_path,
            "status": "invalid_input",
            "sha256": None,
            "quarantine_path": None,
            "reason": f"Path '{raw_path}' contains invalid wildcard or special characters.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": raw_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "invalid_input",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    try:
        real_path = validate_local_path(raw_path)
    except ValueError as e:
        result = {
            "path": raw_path,
            "status": "invalid_input",
            "sha256": None,
            "quarantine_path": None,
            "reason": str(e),
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": raw_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "invalid_input",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 2. Protected location check (Windows core folders, security tools, project files, .env, audit log, quarantine dir)
    is_protected, prot_reason = check_protected_file(real_path, quarantine_dir=quarantine_dir, audit_path=audit_path)
    if is_protected:
        result = {
            "path": real_path,
            "status": "blocked_protected",
            "sha256": None,
            "quarantine_path": None,
            "reason": prot_reason,
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "path": real_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "blocked_protected",
            "outcome": "blocked_protected",
            "dry_run": effective_dry_run,
            "details": prot_reason,
        }, audit_path=audit_path)
        return result

    # 3. Existence check & Directory check
    if not os.path.exists(real_path):
        result = {
            "path": real_path,
            "status": "not_found",
            "sha256": None,
            "quarantine_path": None,
            "reason": f"File '{real_path}' does not exist (may have been deleted or moved).",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "path": real_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "not_found",
            "outcome": "not_found",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    if os.path.isdir(real_path) or not os.path.isfile(real_path):
        result = {
            "path": real_path,
            "status": "invalid_input",
            "sha256": None,
            "quarantine_path": None,
            "reason": f"Target path '{real_path}' is a directory, not a single file.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "path": real_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "invalid_input",
            "outcome": "invalid_input",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 4. Link to alert check
    if not alert_guid:
        result = {
            "path": real_path,
            "status": "not_allowed_target",
            "sha256": None,
            "quarantine_path": None,
            "reason": "File is not linked to alert (no alert GUID provided).",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "not_allowed_target",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    is_linked, expected_hash, link_details = is_file_linked_to_alert(real_path, alert_guid, db_path=db_path)
    if not is_linked:
        result = {
            "path": real_path,
            "status": "not_allowed_target",
            "sha256": None,
            "quarantine_path": None,
            "reason": f"File '{real_path}' is not linked to alert '{alert_guid}' or its process tree.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "not_allowed_target",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 5. Hash calculation and comparison
    try:
        now_sha = sha256_of_file(real_path)
    except PermissionError:
        result = {
            "path": real_path,
            "status": "file_in_use",
            "sha256": None,
            "quarantine_path": None,
            "reason": "Permission denied reading file (it may be locked by another process).",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "file_in_use",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result
    except Exception as e:
        result = {
            "path": real_path,
            "status": "failed",
            "sha256": None,
            "quarantine_path": None,
            "reason": f"Error computing file hash: {str(e)}",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": None,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "failed",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    if expected_hash and now_sha != expected_hash.strip().upper():
        result = {
            "path": real_path,
            "status": "hash_mismatch",
            "sha256": now_sha,
            "quarantine_path": None,
            "reason": f"File hash on disk ('{now_sha}') does not match recorded event hash ('{expected_hash}'). The file has changed.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "path": real_path,
            "sha256": now_sha,
            "reason": reason,
            "approved": approved,
            "approver": "human" if approved else "none",
            "status": "hash_mismatch",
            "outcome": "hash_mismatch",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 6. Check if file is actively running by any live process (Windows will not release running executables)
    try:
        norm_real = os.path.normcase(os.path.realpath(real_path))
        for proc in psutil.process_iter(['exe']):
            try:
                p_exe = proc.info.get('exe')
                if p_exe and os.path.normcase(os.path.realpath(p_exe)) == norm_real:
                    result = {
                        "path": real_path,
                        "status": "file_in_use",
                        "sha256": now_sha,
                        "quarantine_path": None,
                        "reason": f"Windows will not release the file: Process PID {proc.pid} is currently running this executable. Propose killing it first (kill_process), then retry.",
                    }
                    log_audit_quarantine({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "alert_id": alert_id or "unknown",
                        "original_path": real_path,
                        "path": real_path,
                        "sha256": now_sha,
                        "reason": reason,
                        "approved": approved,
                        "approver": "human" if approved else "none",
                        "status": "file_in_use",
                        "outcome": "file_in_use",
                        "dry_run": effective_dry_run,
                        "details": result["reason"],
                    }, audit_path=audit_path)
                    return result
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    # 6. Verify human approval
    if not approved:
        result = {
            "path": real_path,
            "status": "rejected_by_user",
            "sha256": now_sha,
            "quarantine_path": None,
            "reason": "Quarantine proposal was rejected by user (or approval was not granted).",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": now_sha,
            "reason": reason,
            "approved": False,
            "approver": "none",
            "status": "rejected_by_user",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 7. Post-approval re-check
    if not os.path.isfile(real_path):
        result = {
            "path": real_path,
            "status": "not_found",
            "sha256": now_sha,
            "quarantine_path": None,
            "reason": f"Post-approval re-check: File '{real_path}' was removed before it could be quarantined.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": now_sha,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "not_found",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    try:
        re_sha = sha256_of_file(real_path)
    except PermissionError:
        result = {
            "path": real_path,
            "status": "file_in_use",
            "sha256": now_sha,
            "quarantine_path": None,
            "reason": "Post-approval re-check: File is in use or locked.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": now_sha,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "file_in_use",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    if re_sha != now_sha:
        result = {
            "path": real_path,
            "status": "hash_mismatch",
            "sha256": re_sha,
            "quarantine_path": None,
            "reason": f"Post-approval re-check: File modified during approval window (expected {now_sha}, got {re_sha}).",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": re_sha,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "hash_mismatch",
            "dry_run": effective_dry_run,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 8. Dry-run mode check
    init_quarantine_dir(quarantine_dir)
    target_q_file = Path(quarantine_dir) / f"{now_sha}.quarantine"

    if effective_dry_run:
        result = {
            "path": real_path,
            "status": "dry_run",
            "sha256": now_sha,
            "quarantine_path": str(target_q_file),
            "reason": "DRY RUN active: all safety checks passed and quarantine was simulated, but file was not moved.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": now_sha,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "dry_run",
            "dry_run": True,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # 9. Live Move & Neutralize
    st = os.stat(real_path)
    metadata = {
        "sha256": now_sha,
        "original_path": real_path,
        "size_bytes": st.st_size,
        "created_utc": _iso(st.st_ctime),
        "modified_utc": _iso(st.st_mtime),
        "accessed_utc": _iso(st.st_atime),
        "quarantined_utc": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert_id or "unknown",
        "alert_guid": alert_guid,
        "reason": reason,
        "approver": "human",
        "dry_run": False,
    }
    meta_path = Path(quarantine_dir) / f"{now_sha}.json"

    # Cross-drive vs same-drive move logic
    is_same_drive = os.path.splitdrive(real_path)[0].lower() == os.path.splitdrive(str(target_q_file))[0].lower()

    if is_same_drive:
        try:
            os.replace(real_path, target_q_file)
        except PermissionError as e:
            # WinError 32: The process cannot access the file because it is being used by another process
            if getattr(e, "winerror", None) == 32 or "used by another process" in str(e).lower():
                status_code = "file_in_use"
                msg = f"File is currently open or locked by a running process: {str(e)}"
            else:
                status_code = "access_denied"
                msg = f"Windows denied permission to move file: {str(e)}"

            result = {
                "path": real_path,
                "status": status_code,
                "sha256": now_sha,
                "quarantine_path": None,
                "reason": msg,
            }
            log_audit_quarantine({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_id": alert_id or "unknown",
                "original_path": real_path,
                "sha256": now_sha,
                "reason": reason,
                "approved": approved,
                "approver": "human",
                "status": status_code,
                "dry_run": False,
                "details": msg,
            }, audit_path=audit_path)
            return result
        except Exception as e:
            result = {
                "path": real_path,
                "status": "failed",
                "sha256": now_sha,
                "quarantine_path": None,
                "reason": f"Move failed: {str(e)}",
            }
            log_audit_quarantine({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_id": alert_id or "unknown",
                "original_path": real_path,
                "sha256": now_sha,
                "reason": reason,
                "approved": approved,
                "approver": "human",
                "status": "failed",
                "dry_run": False,
                "details": result["reason"],
            }, audit_path=audit_path)
            return result
    else:
        # Cross-drive move: copy, verify, then delete original
        try:
            shutil.copy2(real_path, target_q_file)
            if sha256_of_file(str(target_q_file)) != now_sha:
                if os.path.exists(target_q_file):
                    os.remove(target_q_file)
                return {
                    "path": real_path,
                    "status": "failed",
                    "sha256": now_sha,
                    "quarantine_path": None,
                    "reason": "Hash mismatch after copying to quarantine location.",
                }
            os.remove(real_path)
        except PermissionError as e:
            if os.path.exists(target_q_file):
                try:
                    os.remove(target_q_file)
                except Exception:
                    pass
            if getattr(e, "winerror", None) == 32 or "used by another process" in str(e).lower():
                status_code = "file_in_use"
                msg = f"File is currently in use by a running process: {str(e)}"
            else:
                status_code = "access_denied"
                msg = f"Permission denied deleting original file during move: {str(e)}"

            result = {
                "path": real_path,
                "status": status_code,
                "sha256": now_sha,
                "quarantine_path": None,
                "reason": msg,
            }
            log_audit_quarantine({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_id": alert_id or "unknown",
                "original_path": real_path,
                "sha256": now_sha,
                "reason": reason,
                "approved": approved,
                "approver": "human",
                "status": status_code,
                "dry_run": False,
                "details": msg,
            }, audit_path=audit_path)
            return result
        except Exception as e:
            if os.path.exists(target_q_file):
                try:
                    os.remove(target_q_file)
                except Exception:
                    pass
            result = {
                "path": real_path,
                "status": "failed",
                "sha256": now_sha,
                "quarantine_path": None,
                "reason": f"Cross-drive move failed: {str(e)}",
            }
            log_audit_quarantine({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_id": alert_id or "unknown",
                "original_path": real_path,
                "sha256": now_sha,
                "reason": reason,
                "approved": approved,
                "approver": "human",
                "status": "failed",
                "dry_run": False,
                "details": result["reason"],
            }, audit_path=audit_path)
            return result

    # Confirm original is gone and quarantine copy exists with identical hash
    if os.path.exists(real_path) or not os.path.exists(target_q_file):
        result = {
            "path": real_path,
            "status": "failed",
            "sha256": now_sha,
            "quarantine_path": None,
            "reason": "Verification failed: original file still exists or quarantine file is missing.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": now_sha,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "failed",
            "dry_run": False,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    if sha256_of_file(str(target_q_file)) != now_sha:
        result = {
            "path": real_path,
            "status": "failed",
            "sha256": now_sha,
            "quarantine_path": None,
            "reason": "Verification failed: quarantined file SHA256 does not match original file SHA256.",
        }
        log_audit_quarantine({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id or "unknown",
            "original_path": real_path,
            "sha256": now_sha,
            "reason": reason,
            "approved": approved,
            "approver": "human",
            "status": "failed",
            "dry_run": False,
            "details": result["reason"],
        }, audit_path=audit_path)
        return result

    # Save quarantine metadata record
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        print(f"[!] Warning: Failed to write quarantine metadata JSON to {meta_path}: {e}")

    result = {
        "path": real_path,
        "status": "quarantined",
        "sha256": now_sha,
        "quarantine_path": str(target_q_file),
        "reason": f"File '{real_path}' was successfully moved to quarantine and neutralized as '{target_q_file.name}'.",
    }
    log_audit_quarantine({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert_id or "unknown",
        "original_path": real_path,
        "sha256": now_sha,
        "reason": reason,
        "approved": approved,
        "approver": "human",
        "status": "quarantined",
        "dry_run": False,
        "details": result["reason"],
    }, audit_path=audit_path)
    return result


def restore_quarantined_file(
    sha256: str,
    target_path: str | None = None,
    quarantine_dir: Path | str = QUARANTINE_DIR,
    audit_path: Path | str = QUARANTINE_AUDIT_LOG_PATH,
) -> dict[str, Any]:
    """
    Human/administrator utility function to restore a quarantined file to its original
    location (or an explicitly provided target path), restoring original timestamps.
    Note: This is NOT an agent tool; it is designed for human remediation only.
    """
    clean_sha = str(sha256).strip().upper()
    if not re.fullmatch(r"[0-9A-F]{64}", clean_sha):
        return {
            "status": "invalid_input",
            "sha256": clean_sha,
            "reason": f"Invalid SHA256 format: '{clean_sha}'.",
        }

    q_file = Path(quarantine_dir) / f"{clean_sha}.quarantine"
    meta_file = Path(quarantine_dir) / f"{clean_sha}.json"

    if not os.path.exists(q_file):
        return {
            "status": "not_found",
            "sha256": clean_sha,
            "reason": f"No quarantined file found for hash {clean_sha} in {quarantine_dir}.",
        }

    # Verify quarantine file hash
    if sha256_of_file(str(q_file)) != clean_sha:
        return {
            "status": "failed",
            "sha256": clean_sha,
            "reason": "Quarantine file integrity failure: current hash does not match expected hash.",
        }

    # Read metadata if present
    metadata: dict[str, Any] = {}
    if os.path.exists(meta_file):
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception:
            pass

    destination = target_path or metadata.get("original_path")
    if not destination:
        return {
            "status": "invalid_input",
            "sha256": clean_sha,
            "reason": "No destination path specified and metadata does not contain original_path.",
        }

    try:
        dest_parent = os.path.dirname(destination)
        if dest_parent:
            os.makedirs(dest_parent, exist_ok=True)
    except Exception as e:
        return {
            "status": "failed",
            "sha256": clean_sha,
            "reason": f"Failed to create destination parent folder: {str(e)}",
        }

    # Move file to destination
    is_same_drive = os.path.splitdrive(str(q_file))[0].lower() == os.path.splitdrive(destination)[0].lower()
    try:
        if is_same_drive:
            os.replace(q_file, destination)
        else:
            shutil.copy2(q_file, destination)
            if sha256_of_file(destination) != clean_sha:
                if os.path.exists(destination):
                    os.remove(destination)
                return {
                    "status": "failed",
                    "sha256": clean_sha,
                    "reason": "Hash mismatch after copying file back to destination.",
                }
            os.remove(q_file)
    except Exception as e:
        return {
            "status": "failed",
            "sha256": clean_sha,
            "reason": f"Failed to restore file to {destination}: {str(e)}",
        }

    # Restore original timestamps if present in metadata
    mod_utc = metadata.get("modified_utc")
    acc_utc = metadata.get("accessed_utc")
    if mod_utc:
        try:
            mod_epoch = parse_utc_timestamp(mod_utc)
            acc_epoch = parse_utc_timestamp(acc_utc) if acc_utc else mod_epoch
            if mod_epoch:
                os.utime(destination, (acc_epoch or mod_epoch, mod_epoch))
        except Exception:
            pass

    # Remove metadata record
    if os.path.exists(meta_file):
        try:
            os.remove(meta_file)
        except Exception:
            pass

    msg = f"Quarantined file {clean_sha} successfully restored to '{destination}'."
    log_audit_quarantine({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": metadata.get("alert_id", "unknown"),
        "original_path": destination,
        "sha256": clean_sha,
        "reason": "Human administrator restore",
        "approved": True,
        "approver": "human",
        "status": "restored",
        "dry_run": False,
        "details": msg,
    }, audit_path=audit_path)

    return {
        "status": "restored",
        "path": destination,
        "sha256": clean_sha,
        "reason": msg,
    }


if __name__ == "__main__":
    import glob
    import os

    print("==================================================")
    print(" BlueTeamingAI: Detection Engine Demo")
    print("==================================================")

    rule_files = glob.glob(os.path.join("detection", "rules", "*.yml"))
    rules = [load_sigma_rule(r) for r in rule_files]
    print(f"[+] Loaded {len(rules)} Sigma detection rules.")

    sample_files = glob.glob(os.path.join("detection", "test_data", "*.evtx"))
    print(f"[+] Found {len(sample_files)} sample EVTX log files.\n")

    for sample in sample_files:
        sample_name = os.path.basename(sample)
        print(f"[*] Scanning: {sample_name}...")
        matches = scan_evtx_file(sample, rules)
        if matches:
            print(f"    [!] DETECTED {len(matches)} suspicious activity alert(s):")
            for idx, m in enumerate(matches, 1):
                alert_dict = format_alert(m)
                print(f"        {idx}. Rule: {alert_dict['rule_name']} [{alert_dict['severity'].upper()}]")
                print(f"           Tags: {alert_dict['attack_tags']}")
                print(f"           Parent: {alert_dict['parent_process']['parent_image']}")
                print(f"           Program: {alert_dict['event']['image']}")
                print(f"           Command: {alert_dict['event']['command_line']}")

                # Demonstrate Step 7: Dispatch with deduplication
                from detection.dispatch import dispatch_alert
                dispatched, status_msg = dispatch_alert(alert_dict)
                print(f"           Dispatcher Status: {status_msg}")
        else:
            print("    [-] Clean: No rules matched.")
        print()

