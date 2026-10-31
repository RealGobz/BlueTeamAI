"""
tests/test_hitl_server.py - Unit Tests for HITL HTTP Web Server & HTML Pages

Tests:
1. GET /health returns 200 OK and JSON metrics
2. GET / renders pending requests list
3. GET /r/<id>?t=<token> renders approval form
4. GET /r/<id>?t=wrong returns 403 Forbidden
5. GET never changes request state (remains pending)
6. POST /r/<id>/decide records decision and returns 200 with confirmation
7. POST /r/<id>/decide with wrong token returns 403 Forbidden
8. POST /r/<id>/decide with untrusted Host header returns 403 Forbidden
9. POST /r/<id>/decide with untrusted Origin header returns 403 Forbidden
10. Double POST returns 409 Conflict (single-use enforcement)
11. Oversize POST body (> 10 KB) returns 413 Payload Too Large
12. HTML escaping: dynamic <script> payloads are safely rendered as &lt;script&gt;
13. Security response headers (CSP, Cache-Control: no-store, X-Frame-Options: DENY)
"""

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import urllib.parse

from config import DRY_RUN
from UI.HITL.server import HitlRequestHandler
from UI.HITL.store import init_hitl_db, create_request, get_request


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestHitlServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_server_hitl.db"
        init_hitl_db(cls.db_path)

        cls.port = _get_free_port()

        class TestHandler(HitlRequestHandler):
            pass
        TestHandler.db_path = cls.db_path

        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), TestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    def _get_conn(self) -> HTTPConnection:
        return HTTPConnection("127.0.0.1", self.port, timeout=5)

    def test_health_endpoint(self):
        conn = self._get_conn()
        conn.request("GET", "/health")
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        body = res.read().decode("utf-8")
        self.assertIn('"status": "ok"', body)
        conn.close()

    def test_get_pending_list(self):
        conn = self._get_conn()
        conn.request("GET", "/")
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        # Check security headers
        self.assertIn("default-src 'none'", res.getheader("Content-Security-Policy", ""))
        self.assertIn("no-store", res.getheader("Cache-Control", ""))
        self.assertEqual(res.getheader("X-Frame-Options"), "DENY")
        body = res.read().decode("utf-8")
        self.assertIn("BlueTeamingAI - Pending Approval Requests", body)
        conn.close()

    def test_get_request_page_valid_token(self):
        req = create_request(
            thread_id="t_srv_01",
            kind="tool_approval",
            payload={"tool_name": "kill_process", "target": "notepad.exe", "reason": "Suspicious"},
            db_path=self.db_path,
        )
        conn = self._get_conn()
        conn.request("GET", f"/r/{req['request_id']}?t={req['token']}")
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        body = res.read().decode("utf-8")
        self.assertIn("Human-In-The-Loop: Action Approval Required", body)
        self.assertIn("notepad.exe", body)
        self.assertIn('name="decision" value="approved"', body)
        conn.close()

    def test_get_request_page_wrong_token(self):
        req = create_request(
            thread_id="t_srv_02",
            kind="tool_approval",
            payload={"tool_name": "kill_process"},
            db_path=self.db_path,
        )
        conn = self._get_conn()
        conn.request("GET", f"/r/{req['request_id']}?t=fake_token_bad")
        res = conn.getresponse()
        self.assertEqual(res.status, 403)
        conn.close()

    def test_get_never_changes_state(self):
        req = create_request(
            thread_id="t_srv_get_idempotent",
            kind="tool_approval",
            payload={"tool_name": "kill_process"},
            db_path=self.db_path,
        )
        conn = self._get_conn()
        conn.request("GET", f"/r/{req['request_id']}?t={req['token']}")
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        res.read()
        conn.close()

        saved = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(saved["status"], "pending")
        self.assertIsNone(saved["decision"])

    def test_post_decide_success(self):
        req = create_request(
            thread_id="t_srv_post_ok",
            kind="tool_approval",
            payload={"tool_name": "kill_process"},
            db_path=self.db_path,
        )
        form_data = urllib.parse.urlencode({
            "t": req["token"],
            "decision": "approved",
            "note": "Analyst verified malicious hash",
        })
        conn = self._get_conn()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": f"127.0.0.1:{self.port}",
        }
        conn.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        body = res.read().decode("utf-8")
        self.assertIn("Decision Recorded", body)
        self.assertIn("APPROVED", body)
        conn.close()

        saved = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(saved["status"], "decided")
        self.assertEqual(saved["decision"], "approved")

    def test_post_decide_wrong_token(self):
        req = create_request(
            thread_id="t_srv_post_bad_token",
            kind="tool_approval",
            payload={"tool_name": "kill_process"},
            db_path=self.db_path,
        )
        form_data = urllib.parse.urlencode({
            "t": "bad_token_xyz",
            "decision": "approved",
        })
        conn = self._get_conn()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": f"127.0.0.1:{self.port}",
        }
        conn.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 403)
        conn.close()

    def test_post_decide_wrong_host(self):
        req = create_request(
            thread_id="t_srv_post_bad_host",
            kind="tool_approval",
            payload={"tool_name": "kill_process"},
            db_path=self.db_path,
        )
        form_data = urllib.parse.urlencode({"t": req["token"], "decision": "approved"})
        conn = self._get_conn()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "attacker.evil.com:8765",  # Untrusted host!
        }
        conn.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 403)
        conn.close()

    def test_post_decide_wrong_origin(self):
        req = create_request(
            thread_id="t_srv_post_bad_origin",
            kind="tool_approval",
            payload={"tool_name": "kill_process"},
            db_path=self.db_path,
        )
        form_data = urllib.parse.urlencode({"t": req["token"], "decision": "approved"})
        conn = self._get_conn()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": f"127.0.0.1:{self.port}",
            "Origin": "http://evil-cross-origin.com",  # Malicious origin!
        }
        conn.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 403)
        conn.close()

    def test_post_decide_double_submit_rejected(self):
        req = create_request(
            thread_id="t_srv_post_double",
            kind="tool_approval",
            payload={"tool_name": "kill_process"},
            db_path=self.db_path,
        )
        form_data = urllib.parse.urlencode({"t": req["token"], "decision": "approved"})
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": f"127.0.0.1:{self.port}",
        }

        # 1st POST
        conn1 = self._get_conn()
        conn1.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res1 = conn1.getresponse()
        self.assertEqual(res1.status, 200)
        res1.read()
        conn1.close()

        # 2nd POST -> must fail (409 Conflict)
        conn2 = self._get_conn()
        conn2.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res2 = conn2.getresponse()
        self.assertEqual(res2.status, 409)
        body2 = res2.read().decode("utf-8")
        self.assertIn("Already Decided", body2)
        conn2.close()

    def test_post_decide_oversize_payload(self):
        req = create_request(
            thread_id="t_srv_post_oversize",
            kind="tool_approval",
            payload={"tool_name": "kill_process"},
            db_path=self.db_path,
        )
        huge_note = "A" * 15000  # 15 KB (exceeds 10 KB limit)
        form_data = urllib.parse.urlencode({"t": req["token"], "decision": "approved", "note": huge_note})
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": f"127.0.0.1:{self.port}",
        }
        conn = self._get_conn()
        conn.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 413)
        conn.close()

    def test_html_escaping_in_pages(self):
        xss_reason = "<script>alert('pwned')</script>Malicious activity"
        xss_target = "C:\\Windows\\<script>\\malware.exe"
        req = create_request(
            thread_id="t_xss",
            kind="tool_approval",
            payload={"tool_name": "quarantine_file", "target": xss_target, "reason": xss_reason},
            db_path=self.db_path,
        )
        conn = self._get_conn()
        conn.request("GET", f"/r/{req['request_id']}?t={req['token']}")
        res = conn.getresponse()
        body = res.read().decode("utf-8")
        self.assertEqual(res.status, 200)
        # Verify script tag was escaped
        self.assertNotIn("<script>alert('pwned')</script>", body)
        self.assertIn("&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;", body)
    def test_get_ask_user_page_escapes_xss_and_preserves_urls(self):
        xss_q = "<script>alert('xss_q')</script> Did you download http://example.com/malware.exe?"
        xss_c1 = "<script>alert('xss_c1')</script> Yes, from http://corp.internal/file"
        xss_c2 = "No, never seen http://malicious.org"
        req = create_request(
            thread_id="t_ask_user_server_xss",
            kind="ask_user",
            payload={
                "question": xss_q,
                "choices": [xss_c1, xss_c2],
                "system_context": "Host: WS-01\nURL: http://internal.net",
            },
            db_path=self.db_path,
        )
        conn = self._get_conn()
        conn.request("GET", f"/r/{req['request_id']}?t={req['token']}")
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        body = res.read().decode("utf-8")
        conn.close()

        # HTML Escaping verified
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;alert(&#x27;xss_q&#x27;)&lt;/script&gt;", body)
        self.assertIn("&lt;script&gt;alert(&#x27;xss_c1&#x27;)&lt;/script&gt;", body)
        # Verify URLs are NOT converted to hyperlinks
        self.assertNotIn("<a href=\"http://example.com/malware.exe", body)
        self.assertNotIn("<a href=\"http://corp.internal/file", body)
        # Radio values
        self.assertIn('value="0"', body)
        self.assertIn('value="1"', body)
        self.assertIn('value="2"', body)
        self.assertIn("I&#x27;m not sure", body)

        # GET changes nothing in DB
        fetched = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(fetched["status"], "pending")

    def test_post_ask_user_valid_answer_and_unsure(self):
        req = create_request(
            thread_id="t_ask_user_post_valid",
            kind="ask_user",
            payload={
                "question": "Is this authorized?",
                "choices": ["Yes, authorized", "No, malicious"],
            },
            db_path=self.db_path,
        )
        form_data = urllib.parse.urlencode({"t": req["token"], "decision": "0", "note": "Checked with owner"})
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": f"127.0.0.1:{self.port}",
        }
        conn = self._get_conn()
        conn.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        body = res.read().decode("utf-8")
        self.assertIn("Decision Recorded", body)
        self.assertIn("Yes, authorized", body)
        conn.close()

        fetched = get_request(req["request_id"], db_path=self.db_path)
        self.assertEqual(fetched["status"], "decided")
        self.assertEqual(fetched["decision"], "0")

    def test_post_ask_user_invalid_index_and_oversized_note(self):
        req = create_request(
            thread_id="t_ask_user_post_invalid",
            kind="ask_user",
            payload={
                "question": "Is this authorized?",
                "choices": ["Yes", "No"],
            },
            db_path=self.db_path,
        )
        # Out-of-range index (allowed: 0, 1, 2)
        form_data = urllib.parse.urlencode({"t": req["token"], "decision": "99"})
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": f"127.0.0.1:{self.port}",
        }
        conn = self._get_conn()
        conn.request("POST", f"/r/{req['request_id']}/decide", body=form_data, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 400)
        conn.close()

        # Non-integer index
        conn2 = self._get_conn()
        form_data2 = urllib.parse.urlencode({"t": req["token"], "decision": "approved"})
        conn2.request("POST", f"/r/{req['request_id']}/decide", body=form_data2, headers=headers)
        res2 = conn2.getresponse()
        self.assertEqual(res2.status, 400)
        conn2.close()

        # Oversized note > 300 chars
        conn3 = self._get_conn()
        form_data3 = urllib.parse.urlencode({"t": req["token"], "decision": "0", "note": "B" * 305})
        conn3.request("POST", f"/r/{req['request_id']}/decide", body=form_data3, headers=headers)
        res3 = conn3.getresponse()
        self.assertEqual(res3.status, 400)
        conn3.close()


if __name__ == "__main__":
    unittest.main()
