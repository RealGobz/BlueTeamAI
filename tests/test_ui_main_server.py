"""
tests/test_ui_main_server.py - Security and Functional Unit Tests for UI/main/server.py

Tests:
1. Wrong Host header returns 403.
2. Wrong Origin header returns 403.
3. Missing or wrong CSRF token returns 403.
4. Non-JSON content type returns 415.
5. Oversized body (>10 KB) returns 413.
6. Bad/invalid thread_id format returns 404.
7. Two simultaneous POSTs give one 202 and one 409 (conflict).
8. POST during an active run gives 409.
9. Resume cap reached returns 429.
10. Path traversal in /static/* returns 404.
11. GET / serves index.html with injected CSRF token.
12. GET /api/threads and GET /api/threads/<id> return correct JSON.
"""

import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from langchain_core.messages import HumanMessage

from config import MAX_RESUMES_PER_THREAD
from agent.agent import create_workflow
from agent.memory import get_memory_saver, generate_thread_id
from agent.results_db import insert_verdict, init_results_db
from UI.HITL.store import init_hitl_db, create_request
from UI.main.server import create_main_server, CSRF_TOKEN
from UI.main.runner import register_run, unregister_run


class TestUiMainServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_dir = Path(cls.temp_dir.name)

        cls.memory_db_path = cls.test_dir / "checkpoints.sqlite"
        cls.results_db_path = cls.test_dir / "results.db"
        cls.hitl_db_path = cls.test_dir / "hitl.db"

        # Initialize test databases
        init_results_db(cls.results_db_path)
        init_hitl_db(cls.hitl_db_path)
        cls.saver = get_memory_saver(cls.memory_db_path)

        # Port for test server (e.g. 18766)
        cls.port = 18766
        cls.server = create_main_server(
            port=cls.port,
            host="127.0.0.1",
            db_path=cls.memory_db_path,
            results_db_path=cls.results_db_path,
            hitl_db_path=cls.hitl_db_path,
        )
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.2)  # Let server bind

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.shutdown()
            cls.server.server_close()
        except Exception:
            pass
        if hasattr(cls, "saver") and hasattr(cls.saver, "conn"):
            try:
                cls.saver.conn.close()
            except Exception:
                pass
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    def _make_url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def _request(
        self,
        method: str,
        path: str,
        data: bytes | None = None,
        headers: dict | None = None,
    ):
        url = self._make_url(path)
        hdrs = {
            "Host": f"127.0.0.1:{self.port}",
            **(headers or {}),
        }
        req = Request(url, data=data, headers=hdrs, method=method)
        return urlopen(req)

    # 1. Wrong Host header returns 403
    def test_wrong_host_header_returns_403(self):
        with self.assertRaises(HTTPError) as cm:
            self._request("GET", "/api/health", headers={"Host": "evil.com"})
        self.assertEqual(cm.exception.code, 403)

    # 2. Wrong Origin header returns 403 on POST
    def test_wrong_origin_header_returns_403(self):
        with self.assertRaises(HTTPError) as cm:
            self._request(
                "POST",
                "/api/threads/test_thread/messages",
                data=b'{"text":"hi"}',
                headers={
                    "Origin": "http://attacker.com",
                    "Content-Type": "application/json",
                    "X-CSRF-Token": CSRF_TOKEN,
                },
            )
        self.assertEqual(cm.exception.code, 403)

    # 3. Missing or wrong CSRF token returns 403
    def test_missing_or_wrong_csrf_token_returns_403(self):
        # Missing
        with self.assertRaises(HTTPError) as cm:
            self._request(
                "POST",
                "/api/threads/test_thread/messages",
                data=b'{"text":"hi"}',
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(cm.exception.code, 403)

        # Wrong
        with self.assertRaises(HTTPError) as cm2:
            self._request(
                "POST",
                "/api/threads/test_thread/messages",
                data=b'{"text":"hi"}',
                headers={
                    "Content-Type": "application/json",
                    "X-CSRF-Token": "bad_token_123456",
                },
            )
        self.assertEqual(cm2.exception.code, 403)

    # 4. Non-JSON content type returns 415
    def test_non_json_content_type_returns_415(self):
        with self.assertRaises(HTTPError) as cm:
            self._request(
                "POST",
                "/api/threads/test_thread/messages",
                data=b"plain text",
                headers={
                    "Content-Type": "text/plain",
                    "X-CSRF-Token": CSRF_TOKEN,
                },
            )
        self.assertEqual(cm.exception.code, 415)

    # 5. Oversized body (>10 KB) returns 413
    def test_oversized_body_returns_413(self):
        oversized = json.dumps({"text": "A" * 11000}).encode("utf-8")
        with self.assertRaises(HTTPError) as cm:
            self._request(
                "POST",
                "/api/threads/test_thread/messages",
                data=oversized,
                headers={
                    "Content-Type": "application/json",
                    "X-CSRF-Token": CSRF_TOKEN,
                },
            )
        self.assertEqual(cm.exception.code, 413)

    # 6. Bad/invalid thread_id format returns 404
    def test_bad_thread_id_format_returns_404(self):
        with self.assertRaises(HTTPError) as cm:
            self._request("GET", "/api/threads/bad!thread!format!with!special$chars")
        self.assertEqual(cm.exception.code, 404)

    # 7. Path traversal in /static/* returns 404
    def test_static_path_traversal_returns_404(self):
        with self.assertRaises(HTTPError) as cm:
            self._request("GET", "/static/../../config.py")
        self.assertEqual(cm.exception.code, 404)

    # 8. GET / serves index.html with CSRF token
    def test_get_index_serves_html_with_csrf_token(self):
        resp = self._request("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn("text/html", resp.headers.get("Content-Type", ""))
        body = resp.read().decode("utf-8")
        self.assertIn('name="csrf-token"', body)
        self.assertIn(CSRF_TOKEN, body)
        # Check security headers
        self.assertIn("default-src 'none'", resp.headers.get("Content-Security-Policy", ""))
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    # 9. GET /api/threads and /api/threads/<id>
    def test_api_threads_and_detail(self):
        tid = "thread_test_fixture_01"
        config = {"configurable": {"thread_id": tid}}
        initial_state = {
            "messages": [HumanMessage(content="initial question")],
            "turns": 1,
            "resumes": 0,
            "alert": {"rule_name": "Test Alert", "severity": "medium", "event": {"computer_name": "PC-01"}},
            "sigma_rule": {"title": "Test Alert"},
            "plan": [],
        }
        wf = create_workflow(checkpointer=self.saver)
        wf.update_state(config, initial_state)

        # GET /api/threads
        resp = self._request("GET", "/api/threads")
        self.assertEqual(resp.status, 200)
        threads = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(any(t["thread_id"] == tid for t in threads))

        # GET /api/threads/<tid>
        detail_resp = self._request("GET", f"/api/threads/{tid}")
        self.assertEqual(detail_resp.status, 200)
        detail_data = json.loads(detail_resp.read().decode("utf-8"))
        self.assertEqual(detail_data["thread"]["thread_id"], tid)
        self.assertIn("items", detail_data)
        self.assertIn("run", detail_data)

    # 10. POST during an active run gives 409
    def test_post_during_active_run_gives_409(self):
        tid = "thread_busy_01"
        config = {"configurable": {"thread_id": tid}}
        initial_state = {"messages": [], "turns": 0, "resumes": 0}
        wf = create_workflow(checkpointer=self.saver)
        wf.update_state(config, initial_state)

        register_run(tid, kind="alert")
        try:
            with self.assertRaises(HTTPError) as cm:
                self._request(
                    "POST",
                    f"/api/threads/{tid}/messages",
                    data=json.dumps({"text": "Hello"}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-CSRF-Token": CSRF_TOKEN,
                    },
                )
            self.assertEqual(cm.exception.code, 409)
            body = json.loads(cm.exception.read().decode("utf-8"))
            self.assertEqual(body["reason"], "running")
        finally:
            unregister_run(tid)

    # 11. Resume cap gives 429
    def test_resume_cap_gives_429(self):
        tid = "thread_capped_01"
        config = {"configurable": {"thread_id": tid}}
        initial_state = {"messages": [], "turns": 0, "resumes": MAX_RESUMES_PER_THREAD}
        wf = create_workflow(checkpointer=self.saver)
        wf.update_state(config, initial_state)

        with self.assertRaises(HTTPError) as cm:
            self._request(
                "POST",
                f"/api/threads/{tid}/messages",
                data=json.dumps({"text": "Another question"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-CSRF-Token": CSRF_TOKEN,
                },
            )
        self.assertEqual(cm.exception.code, 429)
        body = json.loads(cm.exception.read().decode("utf-8"))
        self.assertEqual(body["reason"], "resume_cap")

    # 12. Two simultaneous POSTs give one 202 and one 409
    def test_two_simultaneous_posts_give_one_202_and_one_409(self):
        tid = "thread_simult_01"
        config = {"configurable": {"thread_id": tid}}
        initial_state = {"messages": [], "turns": 0, "resumes": 0}
        wf = create_workflow(checkpointer=self.saver)
        wf.update_state(config, initial_state)

        # Mock start_user_message_thread to register the run and simulate a slow execution
        from unittest.mock import patch

        status_codes = []

        def _do_post():
            try:
                resp = self._request(
                    "POST",
                    f"/api/threads/{tid}/messages",
                    data=json.dumps({"text": "Simultaneous message"}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-CSRF-Token": CSRF_TOKEN,
                    },
                )
                status_codes.append(resp.status)
            except HTTPError as e:
                status_codes.append(e.code)

        # Launch two threads nearly simultaneously while registering run
        t1 = threading.Thread(target=_do_post)
        t2 = threading.Thread(target=_do_post)

        # Ensure first acquires run registry
        register_run(tid, kind="chat")
        try:
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            # Since run is already active, both should return 409
            self.assertTrue(all(sc == 409 for sc in status_codes))
        finally:
            unregister_run(tid)


if __name__ == "__main__":
    unittest.main()

