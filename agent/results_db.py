"""
agent/results_db.py - Results Database & Append-Only Verdict Persistence

Manages the results database (tools/db/results.db) storing:
- Append-only verdicts for all investigation runs and revisions
- Incomplete terminal run records (e.g. max_turns, timeout, crash_recovery)
- Human reviews linked to verdicts
- Audit log action correlation
"""

import json
import os
from pathlib import Path
import sqlite3
from typing import Any
import uuid
from datetime import datetime, timezone

from config import (
    RESULTS_DB_PATH,
    AUDIT_LOG_PATH,
    QUARANTINE_AUDIT_LOG_PATH,
    PROMPT_VERSION,
    CODE_VERSION,
    DRY_RUN,
)


def init_results_db(db_path: Path | str = RESULTS_DB_PATH) -> None:
    """
    Initialize SQLite tables, indexes, and append-only triggers for the results database.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")

        # 1. Verdicts table: stores final & fallback conclusions and terminal records
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS verdicts (
                verdict_id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                alert_id TEXT,
                verdict TEXT,
                confidence TEXT,
                severity TEXT,
                category TEXT,
                rule_id TEXT,
                host TEXT,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                end_reason TEXT NOT NULL,
                record_json TEXT NOT NULL,
                UNIQUE(thread_id, revision)
            );
            """
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_thread_id ON verdicts(thread_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_revision ON verdicts(revision);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_alert_id ON verdicts(alert_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_verdict ON verdicts(verdict);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_confidence ON verdicts(confidence);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_severity ON verdicts(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_category ON verdicts(category);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_rule_id ON verdicts(rule_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_host ON verdicts(host);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_created_at ON verdicts(created_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_status ON verdicts(status);")

        # Append-only triggers: forbid UPDATE and DELETE on verdicts table
        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_verdict_update
            BEFORE UPDATE ON verdicts
            BEGIN
                SELECT RAISE(ABORT, 'Updates are not allowed on verdicts table (append-only)');
            END;
            """
        )

        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_verdict_delete
            BEFORE DELETE ON verdicts
            BEGIN
                SELECT RAISE(ABORT, 'Deletions are not allowed on verdicts table (append-only)');
            END;
            """
        )

        # 2. Human reviews table: stores human analyst reviews submitted via UI
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS human_reviews (
                review_id TEXT PRIMARY KEY,
                verdict_id TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                agrees INTEGER NOT NULL,
                final_label TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL,
                record_json TEXT NOT NULL
            );
            """
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_reviews_verdict_id ON human_reviews(verdict_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_reviews_thread_id ON human_reviews(thread_id);")

        conn.commit()
    finally:
        conn.close()


def get_results_db_conn(db_path: Path | str = RESULTS_DB_PATH) -> sqlite3.Connection:
    """Return a configured connection with row_factory set to Row."""
    init_results_db(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def insert_verdict(record: dict[str, Any], db_path: Path | str = RESULTS_DB_PATH) -> dict[str, Any]:
    """
    Insert a new verdict row into the append-only verdicts table.
    Computes the next revision number atomically within the insert transaction.
    """
    thread_id = str(record.get("thread_id", "")).strip()
    if not thread_id:
        raise ValueError("thread_id is required to insert a verdict.")

    conn = get_results_db_conn(db_path)
    try:
        with conn:
            cursor = conn.cursor()

            # Atomically compute the next revision and fetch previous verdict ID for this thread
            cursor.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM verdicts WHERE thread_id = ?",
                (thread_id,),
            )
            next_revision = int(cursor.fetchone()[0])

            cursor.execute(
                "SELECT verdict_id FROM verdicts WHERE thread_id = ? ORDER BY revision DESC LIMIT 1",
                (thread_id,),
            )
            prev_row = cursor.fetchone()
            supersedes = prev_row["verdict_id"] if prev_row else None

            verdict_id = record.get("verdict_id") or f"v_{uuid.uuid4().hex}"
            created_at = record.get("created_at") or datetime.now(timezone.utc).isoformat()

            record["verdict_id"] = verdict_id
            record["thread_id"] = thread_id
            record["revision"] = next_revision
            record["supersedes"] = supersedes
            record["created_at"] = created_at

            alert_id = record.get("alert_id") or ""
            verdict_val = record.get("verdict")
            confidence_val = record.get("confidence")
            severity_val = record.get("severity")
            category_val = record.get("category")
            rule_id = record.get("rule_id") or ""
            host = record.get("host") or ""
            status = record.get("status", "closed")
            end_reason = record.get("end_reason", "submitted")

            record_json = json.dumps(record, default=str)

            cursor.execute(
                """
                INSERT INTO verdicts (
                    verdict_id, thread_id, revision, alert_id, verdict,
                    confidence, severity, category, rule_id, host,
                    created_at, status, end_reason, record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    verdict_id,
                    thread_id,
                    next_revision,
                    alert_id,
                    verdict_val,
                    confidence_val,
                    severity_val,
                    category_val,
                    rule_id,
                    host,
                    created_at,
                    status,
                    end_reason,
                    record_json,
                ),
            )

        return record
    finally:
        conn.close()


def get_verdict(verdict_id: str, db_path: Path | str = RESULTS_DB_PATH) -> dict[str, Any] | None:
    """Retrieve a verdict record by its unique verdict_id."""
    conn = get_results_db_conn(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT record_json FROM verdicts WHERE verdict_id = ?", (verdict_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return json.loads(row["record_json"])
    finally:
        conn.close()


def get_verdicts_for_thread(thread_id: str, db_path: Path | str = RESULTS_DB_PATH) -> list[dict[str, Any]]:
    """Retrieve all revisions of verdicts for a given thread, ordered by revision ASC."""
    conn = get_results_db_conn(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT record_json FROM verdicts WHERE thread_id = ? ORDER BY revision ASC",
            (thread_id,),
        )
        rows = cursor.fetchall()
        return [json.loads(row["record_json"]) for row in rows]
    finally:
        conn.close()


def get_latest_verdict_for_thread(thread_id: str, db_path: Path | str = RESULTS_DB_PATH) -> dict[str, Any] | None:
    """Retrieve the latest revision verdict for a given thread."""
    conn = get_results_db_conn(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT record_json FROM verdicts WHERE thread_id = ? ORDER BY revision DESC LIMIT 1",
            (thread_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return json.loads(row["record_json"])
    finally:
        conn.close()


def record_incomplete_verdict(
    thread_id: str,
    alert: dict[str, Any] | None = None,
    sigma_rule: dict[str, Any] | None = None,
    end_reason: str = "incomplete",
    turns: int = 0,
    messages: list[Any] | None = None,
    db_path: Path | str = RESULTS_DB_PATH,
) -> dict[str, Any]:
    """
    Record an incomplete terminal record for a thread (e.g. hit max_turns, timeout, crash, error).
    Ensures every thread has a terminal record even without a normal submitted verdict.
    """
    alert = alert or {}
    sigma_rule = sigma_rule or {}
    event = alert.get("event") or alert

    rule_id = sigma_rule.get("id") or sigma_rule.get("rule_id") or alert.get("rule_id", "")
    alert_id = alert.get("alert_id") or alert.get("id") or event.get("process_guid", "")
    host = event.get("computer_name") or event.get("Computer") or alert.get("host", "")
    user = event.get("user") or event.get("User") or alert.get("user", "")
    process_guid = event.get("process_guid") or alert.get("process_guid", "")

    actions = read_audit_actions_for_thread(thread_id, alert_id=alert_id)

    record = {
        "thread_id": thread_id,
        "alert_id": alert_id,
        "rule_id": rule_id,
        "host": host,
        "user": user,
        "process_guid": process_guid,
        "verdict": None,
        "confidence": None,
        "severity": "none",
        "category": "unknown",
        "status": "incomplete",
        "end_reason": end_reason,
        "summary": f"Investigation incomplete: terminated due to {end_reason}.",
        "explanation": f"The session ended without a recorded verdict. End reason: {end_reason}. Turns completed: {turns}.",
        "evidence": [],
        "assumptions": [],
        "not_checked": ["Entire investigation not finalized"],
        "recommended_next_steps": ["Resume thread or perform manual forensic analysis on alert"],
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

    res = insert_verdict(record, db_path=db_path)
    try:
        from record_run import auto_record_run
        auto_record_run(thread_id, results_db_path=db_path)
    except Exception:
        pass
    return res


def check_and_mark_incomplete_threads(
    known_thread_ids: list[str] | None = None,
    db_path: Path | str = RESULTS_DB_PATH,
) -> list[str]:
    """
    Startup check to find threads that were started/active but never received a terminal
    verdict record (e.g. following a system crash or power outage), and writes an incomplete
    record for each so reports and metrics have no missing holes.
    """
    if not known_thread_ids:
        return []

    marked = []
    conn = get_results_db_conn(db_path)
    try:
        cursor = conn.cursor()
        for tid in known_thread_ids:
            cursor.execute("SELECT 1 FROM verdicts WHERE thread_id = ? LIMIT 1", (tid,))
            if not cursor.fetchone():
                record_incomplete_verdict(
                    thread_id=tid,
                    end_reason="crash_recovery",
                    db_path=db_path,
                )
                marked.append(tid)
        return marked
    finally:
        conn.close()


def insert_human_review(
    verdict_id: str,
    reviewer: str,
    agrees: bool,
    final_label: str,
    note: str = "",
    thread_id: str | None = None,
    db_path: Path | str = RESULTS_DB_PATH,
) -> dict[str, Any]:
    """
    Insert a human review record for a given verdict into the separate human_reviews table.
    The verdict row itself remains untouched (append-only).
    """
    conn = get_results_db_conn(db_path)
    try:
        cursor = conn.cursor()
        if not thread_id:
            cursor.execute("SELECT thread_id FROM verdicts WHERE verdict_id = ?", (verdict_id,))
            row = cursor.fetchone()
            thread_id = row["thread_id"] if row else ""

        review_id = f"rev_{uuid.uuid4().hex}"
        created_at = datetime.now(timezone.utc).isoformat()

        record = {
            "review_id": review_id,
            "verdict_id": verdict_id,
            "thread_id": thread_id,
            "reviewer": reviewer,
            "agrees": bool(agrees),
            "final_label": final_label,
            "note": note,
            "created_at": created_at,
        }

        with conn:
            cursor.execute(
                """
                INSERT INTO human_reviews (
                    review_id, verdict_id, thread_id, reviewer, agrees,
                    final_label, note, created_at, record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    review_id,
                    verdict_id,
                    thread_id,
                    reviewer,
                    1 if agrees else 0,
                    final_label,
                    note,
                    created_at,
                    json.dumps(record),
                ),
            )

        return record
    finally:
        conn.close()


def get_human_reviews_for_thread(thread_id: str, db_path: Path | str = RESULTS_DB_PATH) -> list[dict[str, Any]]:
    """Retrieve all human review entries for a thread."""
    conn = get_results_db_conn(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT record_json FROM human_reviews WHERE thread_id = ? ORDER BY created_at ASC",
            (thread_id,),
        )
        return [json.loads(row["record_json"]) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_human_reviews_for_verdict(verdict_id: str, db_path: Path | str = RESULTS_DB_PATH) -> list[dict[str, Any]]:
    """Retrieve all human review entries for a specific verdict."""
    conn = get_results_db_conn(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT record_json FROM human_reviews WHERE verdict_id = ? ORDER BY created_at ASC",
            (verdict_id,),
        )
        return [json.loads(row["record_json"]) for row in cursor.fetchall()]
    finally:
        conn.close()


def read_audit_actions_for_thread(
    thread_id: str,
    alert_id: str | None = None,
    kill_audit_path: Path | str = AUDIT_LOG_PATH,
    quarantine_audit_path: Path | str = QUARANTINE_AUDIT_LOG_PATH,
) -> list[dict[str, Any]]:
    """
    Read actions proposal and execution timeline from the kill and quarantine audit logs.
    Correlates entries by thread_id or alert_id so verdicts record ground truth actions.
    """
    actions: list[dict[str, Any]] = []

    def _match(entry: dict) -> bool:
        if thread_id and (entry.get("thread_id") == thread_id):
            return True
        if alert_id and (entry.get("alert_id") == alert_id or entry.get("alert_guid") == alert_id):
            return True
        return False

    # 1. Process termination audit log
    k_path = Path(kill_audit_path)
    if k_path.exists():
        try:
            with open(k_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if _match(entry):
                            actions.append({
                                "tool": "kill_process",
                                "timestamp": entry.get("timestamp"),
                                "target": entry.get("target_guid") or entry.get("image"),
                                "reason": entry.get("reason"),
                                "decision": "approved" if entry.get("approved") else "rejected",
                                "result": entry.get("status"),
                                "dry_run": entry.get("dry_run"),
                                "details": entry.get("details", ""),
                            })
                    except Exception:
                        continue
        except Exception:
            pass

    # 2. File quarantine audit log
    q_path = Path(quarantine_audit_path)
    if q_path.exists():
        try:
            with open(q_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if _match(entry):
                            actions.append({
                                "tool": "quarantine_file",
                                "timestamp": entry.get("timestamp"),
                                "target": entry.get("target") or entry.get("target_path") or entry.get("resolved_path") or entry.get("original_path") or entry.get("path"),
                                "reason": entry.get("reason"),
                                "decision": "approved" if entry.get("approved") else "rejected",
                                "result": entry.get("status"),
                                "dry_run": entry.get("dry_run"),
                                "details": entry.get("details", ""),
                            })
                    except Exception:
                        continue
        except Exception:
            pass

    # Sort chronologically
    actions.sort(key=lambda a: a.get("timestamp") or "")
    return actions
