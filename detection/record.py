"""
detection/record.py - Event Storage & 24h Retention Manager

This module handles:
1. Creating the SQLite database in tools/db/events.db.
2. Recording events into the database.
3. Pruning events older than HOURS_SAVED (default: 24 hours).
4. Providing query helpers for the AI agent (e.g. process history lookup).
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any, Generator

# Ensure project root is accessible for config import
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import DB_PATH, HOURS_SAVED
from utils import parse_hashes


def get_db_connection(db_path: Path | str = DB_PATH) -> sqlite3.Connection:
    """Connect to SQLite database, ensuring parent directory exists and WAL mode is enabled."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db_session(
    db_path: Path | str = DB_PATH,
) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that commits changes and cleanly closes the connection upon exit."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db(db_path: Path | str = DB_PATH) -> None:
    """Initialize database tables and indices if they do not already exist."""
    with db_session(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_id INTEGER,
                process_id INTEGER,
                image TEXT,
                command_line TEXT,
                parent_process_id INTEGER,
                parent_image TEXT,
                user TEXT,
                computer TEXT,
                raw_data TEXT,
                recorded_at REAL,
                sha256 TEXT
            )
            """
        )
        # Ensure sha256 column exists if table was created previously
        cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
        if "sha256" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN sha256 TEXT")

        # Create indices for fast lookup by process_id, image, recorded_at, and sha256
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_proc_id ON events (process_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_image ON events (image)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_recorded_at ON events (recorded_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_sha256 ON events (sha256)"
        )

        # Backfill existing events with missing sha256
        missing_rows = conn.execute(
            "SELECT id, raw_data FROM events WHERE sha256 IS NULL AND raw_data LIKE '%SHA256=%'"
        ).fetchall()
        if missing_rows:
            updates = []
            for rid, raw_str in missing_rows:
                try:
                    d = json.loads(raw_str)
                    h = parse_hashes(d.get("Hashes", "")).get("sha256")
                    if h:
                        updates.append((h, rid))
                except Exception:
                    pass
            if updates:
                conn.executemany("UPDATE events SET sha256 = ? WHERE id = ?", updates)


def record_event(
    event: dict[str, Any], db_path: Path | str = DB_PATH
) -> int:
    """
    Save a single event dictionary into the database.
    Returns the newly created row ID.
    """
    init_db(db_path)

    timestamp = (
        event.get("TimeCreated") or datetime.now(timezone.utc).isoformat()
    )
    event_id = event.get("EventID")
    process_id = event.get("ProcessId")
    image = event.get("Image")
    command_line = event.get("CommandLine")
    parent_process_id = event.get("ParentProcessId")
    parent_image = event.get("ParentImage")
    user = event.get("User")
    computer = event.get("Computer")
    raw_data = json.dumps(event)
    recorded_at = time.time()
    sha256 = parse_hashes(event.get("Hashes", "")).get("sha256")

    with db_session(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO events (
                timestamp, event_id, process_id, image, command_line,
                parent_process_id, parent_image, user, computer, raw_data, recorded_at, sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event_id,
                process_id,
                image,
                command_line,
                parent_process_id,
                parent_image,
                user,
                computer,
                raw_data,
                recorded_at,
                sha256,
            ),
        )
        return int(cursor.lastrowid or 0)


def record_events_batch(
    events: list[dict[str, Any]], db_path: Path | str = DB_PATH
) -> int:
    """
    Efficiently insert multiple events into the database in a single transaction.
    Returns the count of events inserted.
    """
    if not events:
        return 0

    init_db(db_path)
    now_ts = time.time()
    rows = []

    for event in events:
        timestamp = (
            event.get("TimeCreated") or datetime.now(timezone.utc).isoformat()
        )
        sha256 = parse_hashes(event.get("Hashes", "")).get("sha256")
        rows.append(
            (
                timestamp,
                event.get("EventID"),
                event.get("ProcessId"),
                event.get("Image"),
                event.get("CommandLine"),
                event.get("ParentProcessId"),
                event.get("ParentImage"),
                event.get("User"),
                event.get("Computer"),
                json.dumps(event),
                now_ts,
                sha256,
            )
        )

    with db_session(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO events (
                timestamp, event_id, process_id, image, command_line,
                parent_process_id, parent_image, user, computer, raw_data, recorded_at, sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    return len(rows)


def prune_expired_events(
    hours: int = HOURS_SAVED, db_path: Path | str = DB_PATH
) -> int:
    """
    Delete events older than `hours` hours from the database.
    Returns the number of deleted records.
    """
    init_db(db_path)
    cutoff_ts = time.time() - (hours * 3600)

    with db_session(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM events WHERE recorded_at < ?", (cutoff_ts,)
        )
        return cursor.rowcount


def query_process_events(
    process_id: int, db_path: Path | str = DB_PATH
) -> list[dict[str, Any]]:
    """
    Look up all historical events associated with a specific process ID.
    Used by the AI agent to answer: 'What else did this program do?'
    """
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT id, timestamp, event_id, process_id, image, command_line,
                   parent_process_id, parent_image, user, computer, raw_data
            FROM events
            WHERE process_id = ?
            ORDER BY id ASC
            """,
            (process_id,),
        )
        results = []
        for row in cursor.fetchall():
            item = dict(row)
            if item.get("raw_data"):
                try:
                    item["raw_data"] = json.loads(item["raw_data"])
                except Exception:
                    pass
            results.append(item)
        return results


def count_events(db_path: Path | str = DB_PATH) -> int:
    """Return the total number of events currently stored in the database."""
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM events")
        return int(cursor.fetchone()[0])
