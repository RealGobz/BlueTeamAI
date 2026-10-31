"""
UI/HITL/store.py - SQLite Storage & Concurrency Engine for HITL Requests

Manages the hitl_requests table in tools/db/hitl.db:
- Atomic, single-use decisions with WAL mode
- Hash-based deduplication for repeated actions in the same thread
- Secure token verification with hmac.compare_digest
- Automatic expiration management
"""

from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Any, Literal
import uuid

from config import (
    HITL_DB_PATH,
    HITL_TIMEOUT_SECONDS,
    HITL_CONTINUE_TIMEOUT_SECONDS,
    ASK_USER_TIMEOUT_SECONDS,
)

# Allowed decision sets per request kind
ALLOWED_DECISIONS: dict[str, set[str]] = {
    "tool_approval": {"approved", "rejected"},
    "continue_turns": {"continue", "stop"},
}


def compute_action_hash(thread_id: str, tool_name: str, tool_args: dict[str, Any]) -> str:
    """
    Compute a deterministic SHA-256 action hash from thread_id, tool_name, and canonical tool arguments.
    Used to detect and short-circuit identical proposals that were already rejected in the same thread.
    """
    # Exclude internal/volatile parameters from the action hash
    filtered_args = {
        k: v for k, v in tool_args.items()
        if k not in ("thread_id", "approved", "alert_guid", "dry_run", "db_path", "audit_path", "quarantine_dir")
    }
    canonical_json = json.dumps(filtered_args, sort_keys=True, separators=(",", ":"), default=str)
    raw = f"{thread_id}:{tool_name}:{canonical_json}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def init_hitl_db(db_path: Path | str = HITL_DB_PATH) -> None:
    """Initialize SQLite tables and indexes for HITL requests in WAL mode."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hitl_requests (
                request_id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                action_hash TEXT,
                token TEXT NOT NULL,
                decision TEXT,
                note TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_at TEXT
            );
            """
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hitl_status ON hitl_requests(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hitl_thread_id ON hitl_requests(thread_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hitl_action_hash ON hitl_requests(thread_id, action_hash);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hitl_expires_at ON hitl_requests(expires_at);")

        conn.commit()
    finally:
        conn.close()


def get_hitl_db_conn(db_path: Path | str = HITL_DB_PATH) -> sqlite3.Connection:
    """Return a configured connection with row_factory set to Row."""
    init_hitl_db(db_path)
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    if "payload_json" in d and d["payload_json"]:
        try:
            d["payload"] = json.loads(d["payload_json"])
        except Exception:
            d["payload"] = {}
    return d


def create_request(
    thread_id: str,
    kind: Literal["tool_approval", "continue_turns"] | str,
    payload: dict[str, Any],
    action_hash: str | None = None,
    expires_in_seconds: int | None = None,
    db_path: Path | str = HITL_DB_PATH,
) -> dict[str, Any]:
    """
    Create a new pending HITL approval request.
    Generates a unique request_id and secure random access token.
    """
    request_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(16)

    now = datetime.now(timezone.utc)
    if expires_in_seconds is None:
        if kind == "continue_turns":
            expires_in_seconds = HITL_CONTINUE_TIMEOUT_SECONDS
        elif kind == "ask_user":
            expires_in_seconds = ASK_USER_TIMEOUT_SECONDS
        else:
            expires_in_seconds = HITL_TIMEOUT_SECONDS

    expires_at = (now + timedelta(seconds=expires_in_seconds)).isoformat()
    created_at = now.isoformat()
    payload_json = json.dumps(payload, default=str)

    conn = get_hitl_db_conn(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO hitl_requests (
                    request_id, thread_id, kind, status, payload_json,
                    action_hash, token, decision, note, created_at,
                    expires_at, decided_at
                ) VALUES (?, ?, ?, 'pending', ?, ?, ?, NULL, NULL, ?, ?, NULL)
                """,
                (
                    request_id,
                    thread_id,
                    kind,
                    payload_json,
                    action_hash,
                    token,
                    created_at,
                    expires_at,
                ),
            )

        return {
            "request_id": request_id,
            "thread_id": thread_id,
            "kind": kind,
            "status": "pending",
            "payload": payload,
            "action_hash": action_hash,
            "token": token,
            "decision": None,
            "note": None,
            "created_at": created_at,
            "expires_at": expires_at,
            "decided_at": None,
        }
    finally:
        conn.close()


def get_request(request_id: str, db_path: Path | str = HITL_DB_PATH) -> dict[str, Any] | None:
    """
    Retrieve a HITL request by ID.
    If the request is still pending but past its expires_at time, updates status to 'expired'.
    """
    conn = get_hitl_db_conn(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hitl_requests WHERE request_id = ?", (request_id,))
        row = cursor.fetchone()
        if not row:
            return None

        record = _row_to_dict(row)
        if record and record["status"] == "pending":
            now_iso = datetime.now(timezone.utc).isoformat()
            if record["expires_at"] < now_iso:
                with conn:
                    cursor.execute(
                        "UPDATE hitl_requests SET status = 'expired' WHERE request_id = ? AND status = 'pending'",
                        (request_id,),
                    )
                record["status"] = "expired"

        return record
    finally:
        conn.close()


def list_pending(db_path: Path | str = HITL_DB_PATH) -> list[dict[str, Any]]:
    """
    List all currently active pending requests.
    Automatically marks expired pending requests.
    """
    conn = get_hitl_db_conn(db_path)
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            cursor = conn.cursor()
            # Mark expired
            cursor.execute(
                "UPDATE hitl_requests SET status = 'expired' WHERE status = 'pending' AND expires_at < ?",
                (now_iso,),
            )
            # Fetch active pending
            cursor.execute(
                "SELECT * FROM hitl_requests WHERE status = 'pending' ORDER BY created_at ASC"
            )
            rows = cursor.fetchall()
            return [_row_to_dict(r) for r in rows if r is not None]  # type: ignore
    finally:
        conn.close()


def decide(
    request_id: str,
    decision: str,
    note: str = "",
    token: str | None = None,
    db_path: Path | str = HITL_DB_PATH,
) -> tuple[bool, str]:
    """
    Record a human decision atomically (single-use).
    Validates token via hmac.compare_digest and ensures decision is in the allowed set.
    First decision wins; concurrent or second attempts fail.
    """
    decision = str(decision).strip().lower()
    note = str(note or "").strip()[:500]

    conn = get_hitl_db_conn(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hitl_requests WHERE request_id = ?", (request_id,))
        row = cursor.fetchone()
        if not row:
            return False, "Request not found"

        record = _row_to_dict(row)
        assert record is not None

        # Verify token
        if token is not None:
            expected_token = record.get("token", "")
            if not hmac.compare_digest(str(token), str(expected_token)):
                return False, "Invalid authorization token"

        # Check allowed decision for this kind
        if record["kind"] == "ask_user":
            if note and len(str(note)) > 300:
                return False, "Note exceeds maximum length of 300 characters"
            payload = record.get("payload", {})
            choices = payload.get("choices", [])
            try:
                choice_idx = int(decision)
                if not (0 <= choice_idx <= len(choices)):
                    return False, f"Invalid decision index '{decision}' for ask_user. Must be between 0 and {len(choices)}"
            except (ValueError, TypeError):
                return False, f"Invalid decision '{decision}' for ask_user. Must be an integer index"
        else:
            allowed = ALLOWED_DECISIONS.get(record["kind"], set())
            if decision not in allowed:
                return False, f"Invalid decision '{decision}' for kind '{record['kind']}'. Allowed: {sorted(allowed)}"

        # Check status and expiration
        now_iso = datetime.now(timezone.utc).isoformat()
        if record["status"] != "pending":
            return False, f"Request is already {record['status']}"

        if record["expires_at"] < now_iso:
            with conn:
                cursor.execute(
                    "UPDATE hitl_requests SET status = 'expired' WHERE request_id = ? AND status = 'pending'",
                    (request_id,),
                )
            return False, "Request has expired"

        # Atomic update: only succeeds if status is still pending and not expired
        with conn:
            cursor.execute(
                """
                UPDATE hitl_requests
                SET status = 'decided',
                    decision = ?,
                    note = ?,
                    decided_at = ?
                WHERE request_id = ?
                  AND status = 'pending'
                  AND expires_at >= ?
                """,
                (decision, note, now_iso, request_id, now_iso),
            )
            if cursor.rowcount == 1:
                return True, "Decision recorded"
            else:
                return False, "Decision collision or request expired (single-use)"
    finally:
        conn.close()


def find_prior_rejection(
    thread_id: str,
    action_hash: str,
    db_path: Path | str = HITL_DB_PATH,
) -> dict[str, Any] | None:
    """
    Find if an identical action in this thread was already rejected by the user.
    Used by agent nodes to immediately short-circuit duplicate proposals.
    """
    if not action_hash:
        return None

    conn = get_hitl_db_conn(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM hitl_requests
            WHERE thread_id = ?
              AND action_hash = ?
              AND status = 'decided'
              AND decision = 'rejected'
            ORDER BY decided_at DESC
            LIMIT 1
            """,
            (thread_id, action_hash),
        )
        row = cursor.fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def wait_for_decision(
    request_id: str,
    poll_interval: float = 0.5,
    timeout: float | None = None,
    db_path: Path | str = HITL_DB_PATH,
) -> dict[str, Any]:
    """
    Poll the database for a human decision until decided or expired.
    If timeout or expiration is reached without a decision, marks status as 'expired'.
    """
    start_time = time.monotonic()

    while True:
        req = get_request(request_id, db_path=db_path)
        if not req:
            raise ValueError(f"HITL request '{request_id}' not found.")

        if req["status"] in ("decided", "expired"):
            return req

        # Check local timeout override if given
        if timeout is not None:
            elapsed = time.monotonic() - start_time
            if elapsed >= timeout:
                conn = get_hitl_db_conn(db_path)
                try:
                    with conn:
                        conn.execute(
                            "UPDATE hitl_requests SET status = 'expired' WHERE request_id = ? AND status = 'pending'",
                            (request_id,),
                        )
                finally:
                    conn.close()
                req["status"] = "expired"
                return req

        time.sleep(poll_interval)
