"""
tests/test_record.py - Unit tests for SQLite event recording and retention
"""

import os
import tempfile
import time
import unittest

from config import HOURS_SAVED
from detection.record import (
    count_events,
    db_session,
    init_db,
    prune_expired_events,
    query_process_events,
    record_event,
    record_events_batch,
)


class TestEventRecord(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = os.path.join(self.temp_dir.name, "test_events.db")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_init_db(self):
        init_db(self.test_db_path)
        self.assertTrue(os.path.exists(self.test_db_path))
        self.assertEqual(count_events(self.test_db_path), 0)

    def test_record_single_event(self):
        event = {
            "EventID": 1,
            "ProcessId": 1234,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentProcessId": 4321,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "User": "TEST\\User",
            "Computer": "TESTPC",
        }
        row_id = record_event(event, self.test_db_path)
        self.assertGreater(row_id, 0)
        self.assertEqual(count_events(self.test_db_path), 1)

    def test_query_process_events(self):
        events = [
            {"EventID": 1, "ProcessId": 5000, "Image": "proc1.exe", "CommandLine": "proc1"},
            {"EventID": 1, "ProcessId": 5000, "Image": "proc1.exe", "CommandLine": "proc1 subtask"},
            {"EventID": 1, "ProcessId": 6000, "Image": "proc2.exe", "CommandLine": "proc2"},
        ]
        record_events_batch(events, self.test_db_path)

        # Lookup events for PID 5000
        p5000_history = query_process_events(5000, self.test_db_path)
        self.assertEqual(len(p5000_history), 2)
        self.assertEqual(p5000_history[0]["command_line"], "proc1")
        self.assertEqual(p5000_history[1]["command_line"], "proc1 subtask")

    def test_prune_expired_events(self):
        init_db(self.test_db_path)

        # Insert an old event (simulated recorded 25 hours ago)
        old_ts = time.time() - (25 * 3600)
        with db_session(self.test_db_path) as conn:
            conn.execute(
                """
                INSERT INTO events (
                    timestamp, event_id, process_id, image, command_line,
                    parent_process_id, parent_image, user, computer, raw_data, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("2026-10-25T12:00:00Z", 1, 9999, "old.exe", "old", 0, "", "user", "pc", "{}", old_ts),
            )

        # Insert a fresh event recorded right now
        fresh_event = {"EventID": 1, "ProcessId": 1111, "Image": "fresh.exe", "CommandLine": "fresh"}
        record_event(fresh_event, self.test_db_path)

        self.assertEqual(count_events(self.test_db_path), 2)

        # Prune events older than HOURS_SAVED (24h)
        deleted = prune_expired_events(hours=HOURS_SAVED, db_path=self.test_db_path)
        self.assertEqual(deleted, 1)

        # Verify only the fresh event remains
        self.assertEqual(count_events(self.test_db_path), 1)
        remaining = query_process_events(1111, self.test_db_path)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["image"], "fresh.exe")


if __name__ == "__main__":
    unittest.main()
