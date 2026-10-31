"""
UI/main/server.py - Lightweight local web server for chat-style investigation UI.

Conventions:
- stdlib ThreadingHTTPServer strictly bound to 127.0.0.1
- Port from config (UI_MAIN_PORT, default 8766)
- Host and Origin header checks (guarding against DNS rebinding & cross-origin attacks)
- Strict security headers (CSP, no-store, nosniff, frame-ancestors none)
- Per-start random CSRF token injected into index.html and validated with hmac.compare_digest
- Parameterized SQL only, read-only DB access for queries
- thread_id format validation before any lookup
- Runnable alone (python -m UI.main.server) or in background thread (start_server_in_background)
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Any
import urllib.parse

# Ensure repository root is on sys.path
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import (
    UI_MAIN_PORT,
    HITL_PORT,
    MEMORY_DB_PATH,
    RESULTS_DB_PATH,
    HITL_DB_PATH,
    AUDIT_LOG_PATH,
    QUARANTINE_AUDIT_LOG_PATH,
    MAX_TURNS_PER_ALERT,
    MAX_RESUMES_PER_THREAD,
)
from agent.memory import get_chat_history, get_thread_state, list_chat_threads
from agent.results_db import (
    get_verdicts_for_thread,
    get_latest_verdict_for_thread,
    read_audit_actions_for_thread,
)
from UI.main.transcript import (
    build_timeline_items,
    summarize_thread,
    get_hitl_requests_for_thread,
)
from UI.main.runner import (
    get_active_run,
    has_pending_hitl,
    start_user_message_thread,
    list_active_runs,
)

logger = logging.getLogger("UI.main.server")

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Per-start CSRF token
CSRF_TOKEN = secrets.token_hex(32)

_ACTIVE_SERVER: ThreadingHTTPServer | None = None
_SERVER_LOCK = threading.Lock()

# Thread ID validation regex
THREAD_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is already bound on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


class MainUiRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for BlueTeamingAI Main Investigation UI."""

    # Configurable paths for test isolation
    memory_db_path: Path | str = MEMORY_DB_PATH
    results_db_path: Path | str = RESULTS_DB_PATH
    hitl_db_path: Path | str = HITL_DB_PATH
    audit_log_path: Path | str = AUDIT_LOG_PATH
    quarantine_audit_path: Path | str = QUARANTINE_AUDIT_LOG_PATH
    static_dir: Path = STATIC_DIR
    csrf_token: str = CSRF_TOKEN
    server_port: int = UI_MAIN_PORT

    def _send_security_headers(self, content_type: str, content_length: int) -> None:
        """Send strict standard security headers."""
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none';",
        )
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def _send_json(self, status_code: int, data: Any) -> None:
        """Send JSON response with security headers."""
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status_code)
        self._send_security_headers("application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _send_html(self, status_code: int, html_str: str) -> None:
        """Send HTML response with security headers."""
        body = html_str.encode("utf-8")
        self.send_response(status_code)
        self._send_security_headers("text/html; charset=utf-8", len(body))
        self.wfile.write(body)

    def _validate_host_and_origin(self) -> bool:
        """Validate Host and Origin headers to guard against DNS rebinding and cross-site attacks."""
        host_header = self.headers.get("Host", "").strip().lower()
        allowed_hosts = [
            f"127.0.0.1:{self.server_port}",
            f"localhost:{self.server_port}",
            "127.0.0.1",
            "localhost",
        ]
        if not any(host_header == h or host_header.startswith(h) for h in allowed_hosts):
            return False

        origin_header = self.headers.get("Origin", "").strip().lower()
        if origin_header:
            allowed_origins = [
                f"http://127.0.0.1:{self.server_port}",
                f"http://localhost:{self.server_port}",
            ]
            if not any(origin_header == o or origin_header.startswith(o) for o in allowed_origins):
                return False

        return True

    def _drain_body(self) -> None:
        """Drain request body up to 64KB to avoid socket aborts."""
        try:
            cl = int(self.headers.get("Content-Length", 0))
            if 0 < cl <= 65536:
                self.rfile.read(cl)
        except Exception:
            pass

    def do_GET(self) -> None:
        """Handle GET requests (read-only endpoints)."""
        if not self._validate_host_and_origin():
            self._send_html(403, "<h1>403 Forbidden</h1><p>Untrusted Host header.</p>")
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. Health check
        if path == "/api/health":
            self._send_json(200, {
                "status": "ok",
                "port": self.server_port,
                "active_runs": len(list_active_runs()),
            })
            return

        # 2. Index page
        if path == "/" or path == "":
            index_path = self.static_dir / "index.html"
            if not index_path.exists():
                self._send_html(404, "<h1>404 Not Found</h1><p>index.html not found.</p>")
                return
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    content = f.read()
                # Inject CSRF token and hitl port into index.html
                injected = content.replace(
                    "</head>",
                    f'<meta name="csrf-token" content="{self.csrf_token}">\n<meta name="hitl-port" content="{HITL_PORT}">\n</head>',
                )
                self._send_html(200, injected)
            except Exception as e:
                self._send_html(500, f"<h1>500 Internal Error</h1><p>{e}</p>")
            return

        # 3. Static files: /static/*
        if path.startswith("/static/"):
            rel_name = path[len("/static/"):]
            # Prevent directory traversal
            try:
                target_file = (self.static_dir / rel_name).resolve()
                if not target_file.is_relative_to(self.static_dir.resolve()) or not target_file.is_file():
                    self._send_html(404, "<h1>404 Not Found</h1>")
                    return
            except Exception:
                self._send_html(404, "<h1>404 Not Found</h1>")
                return

            ext = target_file.suffix.lower()
            mime_map = {
                ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".html": "text/html; charset=utf-8",
                ".json": "application/json; charset=utf-8",
            }
            content_type = mime_map.get(ext, "application/octet-stream")

            try:
                body_bytes = target_file.read_bytes()
                self.send_response(200)
                self._send_security_headers(content_type, len(body_bytes))
                self.wfile.write(body_bytes)
            except Exception as e:
                self._send_html(500, f"<h1>500 Internal Error</h1><p>{e}</p>")
            return

        # 4. List threads: GET /api/threads
        if path == "/api/threads":
            try:
                # Query thread list from checkpointer
                threads = list_chat_threads(db_path=self.memory_db_path)
                active_runs = list_active_runs()

                summaries = []
                for t in threads:
                    t_id = t.get("thread_id")
                    if not t_id:
                        continue
                    state_vals = get_thread_state(t_id, db_path=self.memory_db_path) or {}
                    latest_v = get_latest_verdict_for_thread(t_id, db_path=self.results_db_path)
                    act = active_runs.get(t_id)
                    pending_cnt = 1 if has_pending_hitl(t_id, db_path=self.hitl_db_path) else 0

                    summary = summarize_thread(
                        thread_id=t_id,
                        checkpoint_values=state_vals,
                        latest_verdict=latest_v,
                        active_run=act,
                        pending_hitl_count=pending_cnt,
                    )
                    summaries.append(summary)

                # Sort newest activity first
                summaries.sort(key=lambda s: s.get("updated_at") or "", reverse=True)
                self._send_json(200, summaries)
            except Exception as e:
                logger.error(f"Error listing threads: {e}", exc_info=True)
                self._send_json(500, {"error": str(e)})
            return

        # 4b. Active scenario: GET /api/scenario
        if path == "/api/scenario":
            try:
                from record_run import get_current_scenario
                scen = get_current_scenario()
                self._send_json(200, {"active_scenario": scen})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        # 5. Thread details: GET /api/threads/<id>
        thread_match = re.match(r"^/api/threads/([^/]+)$", path)
        if thread_match:
            t_id = thread_match.group(1)
            if not THREAD_ID_RE.match(t_id):
                self._send_json(404, {"error": "Invalid thread_id format"})
                return

            try:
                state_vals = get_thread_state(t_id, db_path=self.memory_db_path)
                verdicts = get_verdicts_for_thread(t_id, db_path=self.results_db_path)
                latest_v = verdicts[-1] if verdicts else None
                act_run = get_active_run(t_id)
                is_hitl_pending = has_pending_hitl(t_id, db_path=self.hitl_db_path)

                if not state_vals and not verdicts:
                    self._send_json(404, {"error": "Thread not found"})
                    return

                # Read conversation messages
                raw_messages = get_chat_history(t_id, db_path=self.memory_db_path, as_dicts=False)
                hitl_requests = get_hitl_requests_for_thread(t_id, db_path=self.hitl_db_path)
                audit_actions = read_audit_actions_for_thread(
                    thread_id=t_id,
                    kill_audit_path=self.audit_log_path,
                    quarantine_audit_path=self.quarantine_audit_path,
                )

                alert_info = (state_vals or {}).get("alert") or {}
                if not alert_info and latest_v:
                    alert_info = {
                        "rule_name": latest_v.get("rule_id"),
                        "severity": latest_v.get("severity"),
                        "host": latest_v.get("host"),
                        "user": latest_v.get("user"),
                        "timestamp": latest_v.get("created_at"),
                    }

                items = build_timeline_items(
                    thread_id=t_id,
                    raw_messages=raw_messages,
                    alert_info=alert_info,
                    verdicts=verdicts,
                    hitl_requests=hitl_requests,
                    audit_actions=audit_actions,
                )

                # Thread summary
                thread_summary = summarize_thread(
                    thread_id=t_id,
                    checkpoint_values=state_vals,
                    latest_verdict=latest_v,
                    active_run=act_run,
                    pending_hitl_count=1 if is_hitl_pending else 0,
                )

                # Run state
                run_state = "idle"
                if act_run:
                    run_state = "running"
                elif is_hitl_pending:
                    run_state = "waiting_human"

                turns = (state_vals or {}).get("turns", 0)
                resumes = (state_vals or {}).get("resumes", 0)

                response_payload = {
                    "thread": thread_summary,
                    "items": items,
                    "run": {
                        "state": run_state,
                        "turn": turns,
                        "max_turns": MAX_TURNS_PER_ALERT,
                        "resumes": resumes,
                        "max_resumes": MAX_RESUMES_PER_THREAD,
                        "waiting_for": "human_decision" if is_hitl_pending else None,
                    },
                }
                self._send_json(200, response_payload)
            except Exception as e:
                logger.error(f"Error fetching thread {t_id}: {e}", exc_info=True)
                self._send_json(500, {"error": str(e)})
            return

        # 404 for any other GET path
        self._send_html(404, "<h1>404 Not Found</h1>")

    def do_POST(self) -> None:
        """Handle POST requests (submitting messages to threads)."""
        # 1. Host and Origin validation
        if not self._validate_host_and_origin():
            self._drain_body()
            self._send_json(403, {"error": "Untrusted Host or Origin"})
            return

        # 2. CSRF Token verification
        token_header = self.headers.get("X-CSRF-Token", "").strip()
        if not token_header or not hmac.compare_digest(token_header, self.csrf_token):
            self._drain_body()
            self._send_json(403, {"error": "Invalid or missing CSRF token"})
            return

        # 3. Content-Type verification
        ct = self.headers.get("Content-Type", "")
        if "application/json" not in ct.lower():
            self._drain_body()
            self._send_json(415, {"error": "Content-Type must be application/json"})
            return

        # 4. Content-Length verification (max 10 KB)
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._drain_body()
            self._send_json(400, {"error": "Invalid Content-Length"})
            return

        if content_length <= 0:
            self._send_json(400, {"error": "Empty request body"})
            return
        if content_length > 10240:
            self._drain_body()
            self._send_json(413, {"error": "Payload exceeds 10 KB limit"})
            return

        # Read JSON body safely
        try:
            body_bytes = self.rfile.read(content_length)
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Malformed JSON payload"})
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Scenario endpoint: POST /api/scenario
        if path == "/api/scenario":
            scen = payload.get("scenario", "")
            try:
                from record_run import set_current_scenario
                set_current_scenario(scen)
                self._send_json(200, {"active_scenario": scen.strip()})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        # Match /api/threads/<id>/messages
        msg_match = re.match(r"^/api/threads/([^/]+)/messages$", path)
        if not msg_match:
            self._send_json(404, {"error": "Not Found"})
            return

        t_id = msg_match.group(1)
        if not THREAD_ID_RE.match(t_id):
            self._send_json(404, {"error": "Invalid thread_id format"})
            return

        text = payload.get("text", "")
        if not isinstance(text, str) or not text.strip():
            self._send_json(400, {"error": "text is required and must not be empty"})
            return
        if len(text) > 2000:
            self._send_json(400, {"error": "text exceeds 2000 characters limit"})
            return

        # Check if thread exists in checkpointer
        state_vals = get_thread_state(t_id, db_path=self.memory_db_path)
        if not state_vals:
            self._send_json(404, {"error": f"Thread '{t_id}' not found"})
            return

        # Check resume cap
        resumes = state_vals.get("resumes", 0)
        if resumes >= MAX_RESUMES_PER_THREAD:
            self._send_json(429, {
                "error": "too_many_requests",
                "reason": "resume_cap",
                "message": f"Thread '{t_id}' has reached the maximum allowed resumes ({MAX_RESUMES_PER_THREAD}).",
            })
            return

        # Check conflict: is thread already running or waiting for HITL approval?
        if get_active_run(t_id):
            self._send_json(409, {"error": "conflict", "reason": "running"})
            return
        if has_pending_hitl(t_id, db_path=self.hitl_db_path):
            self._send_json(409, {"error": "conflict", "reason": "waiting_human"})
            return

        # Launch background execution
        launched = start_user_message_thread(
            thread_id=t_id,
            text=text.strip(),
            db_path=self.results_db_path,
        )
        if not launched:
            self._send_json(409, {"error": "conflict", "reason": "running"})
            return

        self._send_json(202, {"status": "accepted", "thread_id": t_id})

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stdout access logging to keep console clean."""
        pass


def create_main_server(
    port: int = UI_MAIN_PORT,
    host: str = "127.0.0.1",
    db_path: Path | str = MEMORY_DB_PATH,
    results_db_path: Path | str = RESULTS_DB_PATH,
    hitl_db_path: Path | str = HITL_DB_PATH,
    static_dir: Path = STATIC_DIR,
) -> ThreadingHTTPServer:
    """Factory creating and configuring the ThreadingHTTPServer."""
    class ConfiguredHandler(MainUiRequestHandler):
        pass

    ConfiguredHandler.server_port = port
    ConfiguredHandler.memory_db_path = db_path
    ConfiguredHandler.results_db_path = results_db_path
    ConfiguredHandler.hitl_db_path = hitl_db_path
    ConfiguredHandler.static_dir = static_dir

    server = ThreadingHTTPServer((host, port), ConfiguredHandler)
    return server


def start_server_in_background(
    port: int = UI_MAIN_PORT,
    host: str = "127.0.0.1",
) -> ThreadingHTTPServer | None:
    """
    Start the Main UI server in a daemon background thread.
    Safe to call multiple times (idempotent).
    """
    global _ACTIVE_SERVER
    with _SERVER_LOCK:
        if _ACTIVE_SERVER is not None:
            return _ACTIVE_SERVER

        if is_port_in_use(port, host):
            logger.info(f"Main UI port {port} is already in use; reusing existing service.")
            return None

        server = create_main_server(port=port, host=host)
        t = threading.Thread(target=server.serve_forever, daemon=True, name="UI_Main_Server")
        t.start()
        _ACTIVE_SERVER = server
        logger.info(f"Main UI server started at http://{host}:{port}/")
        print(f"[+] Main Investigation UI active at: http://{host}:{port}/")
        return server


def stop_server() -> None:
    """Shutdown active background server instance."""
    global _ACTIVE_SERVER
    with _SERVER_LOCK:
        if _ACTIVE_SERVER is not None:
            _ACTIVE_SERVER.shutdown()
            _ACTIVE_SERVER.server_close()
            _ACTIVE_SERVER = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    port = UI_MAIN_PORT
    print(f"[*] Starting BlueTeamingAI Main UI server on http://127.0.0.1:{port}/")
    srv = create_main_server(port=port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Main UI server stopped by user.")
        srv.server_close()
