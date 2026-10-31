"""
tests/test_hitl_store.py - Unit Tests for HITL SQLite Storage & Concurrency Engine

Tests:
1. create_request and get_request (fields, token, json payload)
2. list_pending (active vs expired)
3. decide tool_approval (approved, rejected, note capping)
4. decide continue_turns (continue, stop)
5. Single-use enforcement (second decision rejected)
6. Token verification (wrong token rejected via hmac.compare_digest)
7. Invalid decision enum rejection per kind
8. Expiry enforcement (cannot decide expired request)
9. Action hash computation and find_prior_rejection lookup
10. Concurrent decision race condition (atomic single winner)
11. wait_for_decision polling and timeout expiration
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path
import tempfile
import time
import unittest

from UI.HITL.store import (
    init_hitl_db,
    compute_action_hash,
    create_request,
    get_request,
    list_pending,
    decide,
    find_prior_rejection,
    wait_for_decision,
)


class TestHitlStore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_hitl.db"
        init_hitl_db(self.db_path)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_create_and_get_request(self):
        payload = {"alert_title": "Test Alert", "severity": "HIGH", "target": "notepad.exe"}
        req = create_request(
            thread_id="t_test_01",
            kind="tool_approval",
            payload=payload,
            expires_in_seconds=300,
            db_path=self.db_path,
        )
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["kind"], "tool_approval")
        self.assertIsNotNone(req["token"])
        self.assertEqual(req["payload"]["alert_title"], "Test Alert")

        fetched = get_request(req["request_id"], db_path=self.db_path)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["request_id"], req["request_id"])
        self.assertEqual(fetched["status"], "pending")
        self.assertEqual(fetched["payload"]["target"], "notepad.exe")

    def test_list_pending(self):
        req1 = create_request(
            thread_id="t1",
            kind="tool_approval",
            payload={"id": 1},
            expires_in_seconds=300,
            db_path=self.db_path,
        )
        req2 = create_request(
            thread_id="t2",
            kind="continue_turns",
            payload={"id": 2},
            expires_in_seconds=300,
            db_path=self.db_path,
        )
        pending = list_pending(db_path=self.db_path)
        self.assertEqual(len(pending), 2)
        ids = [p["request_id"] for p in pending]
        self.assertIn(req1["request_id"], ids)
        self.assertIn(req2["request_id"], ids)

        # Decide req1 -> only req2 remains pending
        decide(req1["request_id"], "approved", token=req1["token"], db_path=self.db_path)
        pending_after = list_pending(db_path=self.db_path)
        self.assertEqual(len(pending_after), 1)
        self.assertEqual(pending_after[0]["request_id"], req2["request_id"])

    def test_decide_tool_approval(self):
        req = create_request(
            thread_id="t_approve",
            kind="tool_approval",
            payload={"cmd": "kill"},
            db_path=self.db_path,
        )
        ok, msg = decide(
            request_id=req["request_id"],
            decision="approved",
            note="Verified malware by analyst",
            token=req["token"],
            db_path=self.db_path,
        )
        self.assertTrue(ok)
        self.assertIn("recorded", msg.lower())

        saved = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(saved["status"], "decided")
        self.assertEqual(saved["decision"], "approved")
        self.assertEqual(saved["note"], "Verified malware by analyst")
        self.assertIsNotNone(saved["decided_at"])

    def test_decide_continue_turns(self):
        req = create_request(
            thread_id="t_continue",
            kind="continue_turns",
            payload={"turns": 5},
            db_path=self.db_path,
        )
        ok, msg = decide(
            request_id=req["request_id"],
            decision="continue",
            note="More investigation needed",
            token=req["token"],
            db_path=self.db_path,
        )
        self.assertTrue(ok)
        saved = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(saved["decision"], "continue")

    def test_single_use_enforcement(self):
        req = create_request(
            thread_id="t_single_use",
            kind="tool_approval",
            payload={},
            db_path=self.db_path,
        )
        # First decision succeeds
        ok1, msg1 = decide(req["request_id"], "approved", token=req["token"], db_path=self.db_path)
        self.assertTrue(ok1)

        # Second decision fails
        ok2, msg2 = decide(req["request_id"], "rejected", token=req["token"], db_path=self.db_path)
        self.assertFalse(ok2)
        self.assertIn("already decided", msg2.lower())

        # Decision remains the first one
        saved = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(saved["decision"], "approved")

    def test_token_verification(self):
        req = create_request(
            thread_id="t_token",
            kind="tool_approval",
            payload={},
            db_path=self.db_path,
        )
        # Wrong token rejected
        ok, msg = decide(req["request_id"], "approved", token="wrong_token_123", db_path=self.db_path)
        self.assertFalse(ok)
        self.assertIn("invalid authorization token", msg.lower())

        # Correct token accepted
        ok_valid, msg_valid = decide(req["request_id"], "approved", token=req["token"], db_path=self.db_path)
        self.assertTrue(ok_valid)

    def test_invalid_decision_for_kind(self):
        req = create_request(
            thread_id="t_bad_dec",
            kind="tool_approval",
            payload={},
            db_path=self.db_path,
        )
        # "continue" is not valid for tool_approval
        ok, msg = decide(req["request_id"], "continue", token=req["token"], db_path=self.db_path)
        self.assertFalse(ok)
        self.assertIn("invalid decision", msg.lower())

    def test_expiry_handling(self):
        # Create request with 0 seconds expiration
        req = create_request(
            thread_id="t_expired",
            kind="tool_approval",
            payload={},
            expires_in_seconds=-5,
            db_path=self.db_path,
        )
        # Attempting decision on expired request must fail
        ok, msg = decide(req["request_id"], "approved", token=req["token"], db_path=self.db_path)
        self.assertFalse(ok)
        self.assertIn("expired", msg.lower())

        saved = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(saved["status"], "expired")

    def test_action_hash_and_find_prior_rejection(self):
        thread_id = "t_dedup_01"
        tool_name = "kill_process"
        args = {"guid": "{12345678-1234-1234-1234-123456789abc}", "reason": "malicious"}

        h1 = compute_action_hash(thread_id, tool_name, args)
        # Internal args must not change the hash
        args_with_internals = dict(args)
        args_with_internals["approved"] = True
        args_with_internals["dry_run"] = True
        h2 = compute_action_hash(thread_id, tool_name, args_with_internals)
        self.assertEqual(h1, h2)

        # Before any rejection, find_prior_rejection returns None
        self.assertIsNone(find_prior_rejection(thread_id, h1, db_path=self.db_path))

        # Create request and reject it
        req = create_request(
            thread_id=thread_id,
            kind="tool_approval",
            payload=args,
            action_hash=h1,
            db_path=self.db_path,
        )
        decide(req["request_id"], "rejected", note="User declined kill", token=req["token"], db_path=self.db_path)

        # Now find_prior_rejection must find it
        prior = find_prior_rejection(thread_id, h1, db_path=self.db_path)
        self.assertIsNotNone(prior)
        self.assertEqual(prior["decision"], "rejected")
        self.assertEqual(prior["action_hash"], h1)

    def test_concurrent_decide(self):
        req = create_request(
            thread_id="t_race",
            kind="tool_approval",
            payload={},
            db_path=self.db_path,
        )
        token = req["token"]
        rid = req["request_id"]

        results = []

        def _try_decide(choice: str):
            return decide(rid, choice, token=token, db_path=self.db_path)

        with ThreadPoolExecutor(max_workers=5) as executor:
            f1 = executor.submit(_try_decide, "approved")
            f2 = executor.submit(_try_decide, "rejected")
            results = [f1.result(), f2.result()]

        success_count = sum(1 for ok, _ in results if ok)
        fail_count = sum(1 for ok, _ in results if not ok)

        self.assertEqual(success_count, 1)
        self.assertEqual(fail_count, 1)

    def test_wait_for_decision_timeout(self):
        req = create_request(
            thread_id="t_wait_timeout",
            kind="tool_approval",
            payload={},
            expires_in_seconds=1,
            db_path=self.db_path,
        )
        # Polling with 0.1s interval and 0.3s timeout
        res = wait_for_decision(
            request_id=req["request_id"],
            poll_interval=0.1,
            timeout=0.3,
            db_path=self.db_path,
        )
    def test_ask_user_create_and_decide(self):
        payload = {
            "question": "Did you run this command?",
            "choices": ["Yes", "No"],
        }
        req = create_request(
            thread_id="t_ask_user_01",
            kind="ask_user",
            payload=payload,
            db_path=self.db_path,
        )
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["kind"], "ask_user")

        # Decide with valid index 0 (agent choice "Yes")
        ok, msg = decide(req["request_id"], "0", token=req["token"], note="Confirmed by admin", db_path=self.db_path)
        self.assertTrue(ok)
        self.assertEqual(msg, "Decision recorded")

        fetched = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(fetched["status"], "decided")
        self.assertEqual(fetched["decision"], "0")
        self.assertEqual(fetched["note"], "Confirmed by admin")

    def test_ask_user_unsure_index(self):
        payload = {
            "question": "Did you run this command?",
            "choices": ["Yes", "No"],
        }
        req = create_request(
            thread_id="t_ask_user_02",
            kind="ask_user",
            payload=payload,
            db_path=self.db_path,
        )
        # len(choices) is 2, so index 2 represents "I'm not sure"
        ok, msg = decide(req["request_id"], "2", token=req["token"], db_path=self.db_path)
        self.assertTrue(ok)
        fetched = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(fetched["decision"], "2")

    def test_ask_user_invalid_index_rejected(self):
        payload = {
            "question": "Did you run this command?",
            "choices": ["Yes", "No"],
        }
        req = create_request(
            thread_id="t_ask_user_03",
            kind="ask_user",
            payload=payload,
            db_path=self.db_path,
        )
        # Index 3 is out of range (allowed: 0, 1, 2)
        ok, msg = decide(req["request_id"], "3", token=req["token"], db_path=self.db_path)
        self.assertFalse(ok)
        self.assertIn("Invalid decision index", msg)

        # Negative index
        ok, msg = decide(req["request_id"], "-1", token=req["token"], db_path=self.db_path)
        self.assertFalse(ok)

        # Non-integer
        ok, msg = decide(req["request_id"], "approved", token=req["token"], db_path=self.db_path)
        self.assertFalse(ok)
        self.assertIn("integer index", msg)

    def test_ask_user_oversized_note_rejected(self):
        payload = {
            "question": "Did you run this command?",
            "choices": ["Yes", "No"],
        }
        req = create_request(
            thread_id="t_ask_user_04",
            kind="ask_user",
            payload=payload,
            db_path=self.db_path,
        )
        long_note = "A" * 301
        ok, msg = decide(req["request_id"], "0", note=long_note, token=req["token"], db_path=self.db_path)
        self.assertFalse(ok)
        self.assertIn("exceeds maximum length", msg)

    def test_ask_user_wrong_token_rejected(self):
        payload = {
            "question": "Did you run this command?",
            "choices": ["Yes", "No"],
        }
        req = create_request(
            thread_id="t_ask_user_05",
            kind="ask_user",
            payload=payload,
            db_path=self.db_path,
        )
        ok, msg = decide(req["request_id"], "0", token="wrong_token_val", db_path=self.db_path)
        self.assertFalse(ok)
        self.assertIn("Invalid authorization token", msg)


if __name__ == "__main__":
    unittest.main()
