"""
tools/db/clear_events.py - 24-Hour Event Database Reset Utility

Safely clears all captured historical events from tools/db/events.db and
shrinks the database back to clean baseline.

Usage:
    python tools/db/clear_events.py
    python tools/db/clear_events.py --delete-file   (completely deletes and recreates events.db)
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sqlite3
import sys

# Locate repository root
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import DB_PATH, CACHE_PATH
from detection.record import init_db


def clear_events_database(delete_file: bool = False) -> None:
    db_path = Path(DB_PATH)
    wal_path = Path(str(DB_PATH) + "-wal")
    shm_path = Path(str(DB_PATH) + "-shm")

    if not db_path.exists():
        print(f"[*] No events database found at: {db_path}")
        init_db(db_path)
        print("[+] Initialized new empty events database.")
        return

    initial_size = db_path.stat().st_size

    # 1. Read current count
    count = 0
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            count = row[0] if row else 0
        except sqlite3.OperationalError:
            count = 0
        finally:
            conn.close()
    except Exception as e:
        print(f"[-] Warning: Failed to query event count: {e}")

    print(f"[*] Current events in 24h database: {count:,} ({initial_size / 1024:.1f} KB)")

    # 2. Complete file deletion if requested or possible
    deleted_files = False
    if delete_file:
        try:
            for p in (db_path, wal_path, shm_path):
                if p.exists():
                    p.unlink()
            deleted_files = True
            print("[+] Deleted events.db, -wal, and -shm files from disk.")
        except PermissionError:
            print("[!] Note: File is currently locked by a live process. Falling back to SQL wipe & vacuum.")

    if not deleted_files:
        # 3. SQL Wipe & Vacuum (safe even while background detection processes are running)
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("DELETE FROM events")
            try:
                conn.execute("DELETE FROM sqlite_sequence WHERE name = 'events'")
            except sqlite3.OperationalError:
                pass
            conn.commit()
            conn.execute("VACUUM")
        finally:
            conn.close()

    # 4. Guarantee table schema and indexes are freshly initialized
    init_db(db_path)

    final_size = db_path.stat().st_size if db_path.exists() else 0

    # 5. Flush alert deduplication cache so subsequent tests fire immediately
    if CACHE_PATH.exists():
        try:
            CACHE_PATH.write_text("{}", encoding="utf-8")
            print("[+] Flushed alert deduplication cache (alert_cache.json).")
        except Exception:
            pass

    print(f"[+] Successfully cleared 24h event database.")
    print(f"    Events remaining: 0")
    print(f"    Database size:    {final_size / 1024:.1f} KB (reclaimed {(initial_size - final_size) / 1024:.1f} KB)")
    print(f"    Path:             {db_path.resolve()}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wipe and reset the 24-hour event retention database.")
    parser.add_argument(
        "--delete-file",
        "-d",
        action="store_true",
        help="Attempt to completely delete the .db files before recreating schema.",
    )
    args = parser.parse_args()

    clear_events_database(delete_file=args.delete_file)

