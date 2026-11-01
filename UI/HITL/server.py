"""
UI/HITL/server.py - Local Web Server for Human-In-The-Loop Security Approvals

Runs a lightweight ThreadingHTTPServer bound strictly to 127.0.0.1:
- GET / : List of active pending requests
- GET /r/<request_id>?t=<token> : Request approval form
- POST /r/<request_id>/decide : Process human decision (single-use)
- GET /health : Health check
Strict security headers (CSP, no-store, X-Frame-Options) and Host/Origin validation.
"""

from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import hmac
import json
import os
from pathlib import Path
import re
import socket
import threading
from typing import Any
import urllib.parse
import webbrowser

from config import (
    HITL_DB_PATH,
    HITL_PORT,
    HITL_TIMEOUT_SECONDS,
    HITL_CONTINUE_TIMEOUT_SECONDS,
    ASK_USER_TIMEOUT_SECONDS,
    HITL_OPEN_BROWSER,
    HITL_MODE,
    DRY_RUN,
)
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
from UI.HITL.pages import (
    render_pending_list,
    render_tool_approval_page,
    render_continue_page,
    render_ask_user_page,
    render_decided_page,
    render_already_decided_page,
    render_expired_page,
    render_not_found_page,
)

# Global server instance tracking
_ACTIVE_SERVER: ThreadingHTTPServer | None = None
_SERVER_LOCK = threading.Lock()

BRAND_DIR = Path(__file__).resolve().parent.parent / "brand"
HITL_STATIC_DIR = Path(__file__).resolve().parent / "static"

BRAND_ALLOWLIST = {
    "theme.css": "text/css; charset=utf-8",
    "triagent-icon.svg": "image/svg+xml; charset=utf-8",
    "triagent-lockup-dark.svg": "image/svg+xml; charset=utf-8",
    "triagent-lockup-light.svg": "image/svg+xml; charset=utf-8",
    "triagent-wordmark-dark.svg": "image/svg+xml; charset=utf-8",
    "triagent-wordmark-light.svg": "image/svg+xml; charset=utf-8",
}


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is already bound on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


class HitlRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for local HITL approval actions."""

    # Set by the server factory
    db_path: Path | str = HITL_DB_PATH
    brand_dir: Path = BRAND_DIR
    static_dir: Path = HITL_STATIC_DIR

    def _send_response_html(self, status_code: int, html_body: str) -> None:
        """Send standard security headers and UTF-8 HTML response body."""
        body_bytes = html_body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        # Security headers
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none';",
        )
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body_bytes)

    def _validate_host_and_origin(self) -> bool:
        """Validate Host and Origin headers to guard against DNS rebinding and cross-origin attacks."""
        host_header = self.headers.get("Host", "").strip().lower()
        allowed_hosts = [
            f"127.0.0.1:{HITL_PORT}",
            f"localhost:{HITL_PORT}",
            "127.0.0.1",
            "localhost",
        ]
        if not any(host_header == h or host_header.startswith(h) for h in allowed_hosts):
            return False

        origin_header = self.headers.get("Origin", "").strip().lower()
        if origin_header:
            allowed_origins = [
                f"http://127.0.0.1:{HITL_PORT}",
                f"http://localhost:{HITL_PORT}",
            ]
            if not any(origin_header == o or origin_header.startswith(o) for o in allowed_origins):
                return False

        return True

    def do_GET(self) -> None:
        """Handle GET requests (never modifies state)."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Health endpoint
        if path == "/health":
            pending = list_pending(db_path=self.db_path)
            data = json.dumps({"status": "ok", "pending_count": len(pending)}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # Brand assets: GET /brand/<name>
        if path.startswith("/brand/"):
            name = path[len("/brand/"):]
            if name not in BRAND_ALLOWLIST:
                self._send_response_html(404, render_not_found_page("Brand asset not found"))
                return

            brand_file = (self.brand_dir / name).resolve()
            if not brand_file.is_file() or not brand_file.is_relative_to(self.brand_dir.resolve()):
                self._send_response_html(404, render_not_found_page("Brand asset not found"))
                return

            try:
                body_bytes = brand_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", BRAND_ALLOWLIST[name])
                self.send_header("Content-Length", str(len(body_bytes)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none';",
                )
                self.end_headers()
                self.wfile.write(body_bytes)
            except Exception:
                self._send_response_html(500, "<h1>500 Internal Server Error</h1>")
            return

        # HITL stylesheet: exact-match GET /static/hitl.css
        if path.startswith("/static/"):
            if path != "/static/hitl.css":
                self._send_response_html(404, render_not_found_page("Static file not found"))
                return

            css_file = (self.static_dir / "hitl.css").resolve()
            if not css_file.is_file() or not css_file.is_relative_to(self.static_dir.resolve()):
                self._send_response_html(404, render_not_found_page("Stylesheet not found"))
                return

            try:
                body_bytes = css_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/css; charset=utf-8")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none';",
                )
                self.end_headers()
                self.wfile.write(body_bytes)
            except Exception:
                self._send_response_html(500, "<h1>500 Internal Server Error</h1>")
            return

        # Pending requests index
        if path == "/" or path == "":
            pending = list_pending(db_path=self.db_path)
            html_body = render_pending_list(pending)
            self._send_response_html(200, html_body)
            return

        # Specific request page: /r/<request_id>?t=<token>
        match = re.match(r"^/r/([a-zA-Z0-9_\-]+)$", path)
        if match:
            request_id = match.group(1)
            token = query.get("t", [""])[0]

            req = get_request(request_id, db_path=self.db_path)
            if not req:
                self._send_response_html(404, render_not_found_page(request_id))
                return

            # Verify token
            if not token or not hmac.compare_digest(str(token), str(req.get("token", ""))):
                self._send_response_html(403, "<h1>403 Forbidden</h1><p>Invalid or missing access token.</p>")
                return

            status = req.get("status")
            # Check for expiration either via status or timestamp
            expires_at = req.get("expires_at", "")
            is_time_expired = False
            if expires_at:
                try:
                    exp_dt = datetime.fromisoformat(str(expires_at))
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) >= exp_dt:
                        is_time_expired = True
                except Exception:
                    pass

            if status == "decided":
                self._send_response_html(200, render_already_decided_page(req))
            elif status == "expired" or is_time_expired:
                self._send_response_html(200, render_expired_page(req))
            else:
                kind = req.get("kind")
                if kind == "continue_turns":
                    self._send_response_html(200, render_continue_page(req))
                elif kind == "ask_user":
                    self._send_response_html(200, render_ask_user_page(req))
                else:
                    self._send_response_html(200, render_tool_approval_page(req, dry_run=DRY_RUN))
            return

        # Not found
        self._send_response_html(404, render_not_found_page(path))

    def _drain_body(self) -> None:
        """Safely drain request body up to 64KB to avoid Windows socket aborts."""
        try:
            cl = int(self.headers.get("Content-Length", 0))
            if 0 < cl <= 65536:
                self.rfile.read(cl)
        except Exception:
            pass

    def do_POST(self) -> None:
        """Handle POST decision submissions."""
        # 1. Host and Origin validation
        if not self._validate_host_and_origin():
            self._drain_body()
            self._send_response_html(403, "<h1>403 Forbidden</h1><p>Untrusted Host or Origin header.</p>")
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Match /r/<request_id>/decide
        match = re.match(r"^/r/([a-zA-Z0-9_\-]+)/decide$", path)
        if not match:
            self._drain_body()
            self._send_response_html(404, render_not_found_page(path))
            return

        request_id = match.group(1)

        # 2. Content-Length check (max 10 KB)
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_length = 0

        if content_length <= 0 or content_length > 10240:
            self._drain_body()
            self._send_response_html(413, "<h1>413 Payload Too Large</h1><p>Request payload exceeds 10 KB limit.</p>")
            return

        # 3. Read and parse body
        body_bytes = self.rfile.read(content_length)
        try:
            body_str = body_bytes.decode("utf-8")
            params = urllib.parse.parse_qs(body_str, keep_blank_values=True)
        except Exception:
            self._send_response_html(400, "<h1>400 Bad Request</h1><p>Failed to parse form body.</p>")
            return

        token = params.get("t", [""])[0]
        decision = params.get("decision", [""])[0]
        note = params.get("note", [""])[0][:500]

        # 4. Fetch request
        req = get_request(request_id, db_path=self.db_path)
        if not req:
            self._send_response_html(404, render_not_found_page(request_id))
            return

        # 5. Token verification
        if not token or not hmac.compare_digest(str(token), str(req.get("token", ""))):
            self._send_response_html(403, "<h1>403 Forbidden</h1><p>Invalid authorization token.</p>")
            return

        # 6. Apply atomic decision
        ok, msg = decide(
            request_id=request_id,
            decision=decision,
            note=note,
            token=token,
            db_path=self.db_path,
        )

        updated_req = get_request(request_id, db_path=self.db_path) or req
        if ok:
            self._send_response_html(200, render_decided_page(updated_req, msg))
        else:
            if updated_req.get("status") == "decided":
                self._send_response_html(409, render_already_decided_page(updated_req))
            elif updated_req.get("status") == "expired":
                self._send_response_html(409, render_expired_page(updated_req))
            else:
                self._send_response_html(400, f"<h1>400 Bad Request</h1><p>{msg}</p>")

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress noisy request logging to console, but keep server errors visible."""
        if args and str(args[1]).startswith(("4", "5")):
            print(f"[-] HITL WebServer: {args[0]} -> {args[1]}")


def start_server_in_background(
    host: str = "127.0.0.1",
    port: int = HITL_PORT,
    db_path: Path | str = HITL_DB_PATH,
) -> ThreadingHTTPServer:
    """
    Start the HITL web server on a background daemon thread.
    Binds strictly to 127.0.0.1. Reuses existing server instance if already active.
    """
    global _ACTIVE_SERVER
    with _SERVER_LOCK:
        if _ACTIVE_SERVER is not None:
            return _ACTIVE_SERVER

        init_hitl_db(db_path)

        # Create handler class with bound db_path
        class ConfiguredHandler(HitlRequestHandler):
            pass
        ConfiguredHandler.db_path = db_path

        try:
            server = ThreadingHTTPServer((host, port), ConfiguredHandler)
        except OSError as e:
            if "already in use" in str(e).lower() or getattr(e, "winerror", None) == 10048:
                raise RuntimeError(
                    f"HITL server port {port} is already in use on {host}. "
                    "Please free the port or change HITL_PORT in config.py."
                ) from e
            raise

        thread = threading.Thread(target=server.serve_forever, daemon=True, name="HITL-Server-Thread")
        thread.start()

        _ACTIVE_SERVER = server
        print(f"[*] HITL Approval Server active on http://{host}:{port}/ (Background Thread)")
        return server


def request_tool_approval(
    thread_id: str,
    tool_name: str,
    tool_args: dict[str, Any],
    alert: dict[str, Any] | None = None,
    rule: dict[str, Any] | None = None,
    approval_screen: str = "",
    db_path: Path | str = HITL_DB_PATH,
    port: int = HITL_PORT,
    timeout: int = HITL_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """
    Request human approval for a sensitive tool (kill_process, quarantine_file).
    1. Computes action hash and checks for prior rejection in this thread.
    2. Creates pending request in SQLite store.
    3. Starts local web server in background if not already running.
    4. Triggers desktop notification and prints direct decision link to console.
    5. Polls until human decides or timeout is reached.
    """
    alert = alert or {}
    rule = rule or {}

    action_hash = compute_action_hash(thread_id, tool_name, tool_args)

    # 1. Short-circuit: check if identical action was already rejected by user in this thread
    prior_rejection = find_prior_rejection(thread_id, action_hash, db_path=db_path)
    if prior_rejection:
        print(f"[*] Action {tool_name} was previously rejected by user in this session. Re-prompt skipped.")
        return {
            "status": "rejected_by_user",
            "decision": "rejected",
            "reason": f"Action was previously rejected by user in this session (Note: {prior_rejection.get('note') or 'None'}).",
            "action_hash": action_hash,
            "repeated": True,
        }

    # 2. Extract target and reason
    target = tool_args.get("guid") or tool_args.get("path") or "Unknown"
    reason = tool_args.get("reason", "Malicious activity confirmed by investigation tools.")

    payload = {
        "alert_title": alert.get("title") or rule.get("title") or "Security Alert",
        "severity": str(alert.get("level") or rule.get("level") or "MEDIUM").upper(),
        "tool_name": tool_name,
        "target": target,
        "reason": reason,
        "approval_screen": approval_screen,
        "tool_args": tool_args,
    }

    # 3. Create request in store
    req = create_request(
        thread_id=thread_id,
        kind="tool_approval",
        payload=payload,
        action_hash=action_hash,
        expires_in_seconds=timeout,
        db_path=db_path,
    )

    url = f"http://127.0.0.1:{port}/r/{req['request_id']}?t={req['token']}"

    # 4. Ensure server is running
    try:
        start_server_in_background(port=port, db_path=db_path)
    except Exception as e:
        print(f"[!] Warning: Could not start HITL server: {e}")

    # 5. Notify human
    print("\n" + "=" * 80)
    print(f"  [!] HUMAN APPROVAL REQUIRED FOR {tool_name.upper()}")
    print(f"  Target: {target}")
    print(f"  Approval URL: {url}")
    print(f"  Pending Timeout: {timeout} seconds")
    print("=" * 80 + "\n")

    try:
        from UI.HITL.notify import send_toast
        rule_title = str(payload["alert_title"])[:100]
        send_toast(
            title="Triagent: approval needed",
            message=f"{rule_title} - Click to approve or reject",
            url=url,
        )
    except Exception as e:
        print(f"[!] Notification dispatch error: {e}")

    if HITL_OPEN_BROWSER:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    # 6. Wait for decision
    result = wait_for_decision(req["request_id"], timeout=float(timeout), db_path=db_path)

    if result.get("status") == "decided" and result.get("decision") == "approved":
        return {
            "status": "approved",
            "decision": "approved",
            "note": result.get("note", ""),
            "action_hash": action_hash,
        }
    elif result.get("status") == "decided" and result.get("decision") == "rejected":
        return {
            "status": "rejected_by_user",
            "decision": "rejected",
            "reason": result.get("note") or "Action rejected by human operator.",
            "action_hash": action_hash,
        }
    else:
        return {
            "status": "expired",
            "decision": "rejected",
            "reason": f"Approval request timed out after {timeout} seconds with no response.",
            "action_hash": action_hash,
        }


def request_continue(
    thread_id: str,
    turns: int,
    turn_limit: int,
    continues: int,
    max_continues: int,
    plan: list[str] | None = None,
    tools_used: list[str] | None = None,
    last_message: str = "",
    db_path: Path | str = HITL_DB_PATH,
    port: int = HITL_PORT,
    timeout: int = HITL_CONTINUE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """
    Request human approval to grant more turns to an ongoing investigation.
    """
    payload = {
        "turns": turns,
        "turn_limit": turn_limit,
        "continues": continues,
        "max_continues": max_continues,
        "plan": plan or [],
        "tools_used": tools_used or [],
        "last_message": last_message[:2000],
    }

    req = create_request(
        thread_id=thread_id,
        kind="continue_turns",
        payload=payload,
        expires_in_seconds=timeout,
        db_path=db_path,
    )

    url = f"http://127.0.0.1:{port}/r/{req['request_id']}?t={req['token']}"

    try:
        start_server_in_background(port=port, db_path=db_path)
    except Exception as e:
        print(f"[!] Warning: Could not start HITL server: {e}")

    print("\n" + "=" * 80)
    print("  [!] TURN LIMIT REACHED - HUMAN DECISION REQUIRED")
    print(f"  Turns used: {turns}/{turn_limit} | Continues: {continues}/{max_continues}")
    print(f"  Decision URL: {url}")
    print(f"  Timeout: {timeout} seconds")
    print("=" * 80 + "\n")

    try:
        from UI.HITL.notify import send_toast
        send_toast(
            title="Triagent: continue?",
            message="The AI investigator needs approval to continue.",
            url=url,
        )
    except Exception:
        pass

    if HITL_OPEN_BROWSER:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    result = wait_for_decision(req["request_id"], timeout=float(timeout), db_path=db_path)

    if result.get("status") == "decided":
        return {
            "status": "decided",
            "decision": result.get("decision", "stop"),
            "note": result.get("note", ""),
        }
    else:
        return {
            "status": "expired",
            "decision": "stop",
            "reason": f"Continue request timed out after {timeout} seconds with no response.",
        }


def request_ask_user(
    thread_id: str,
    question: str,
    choices: list[str],
    alert: dict[str, Any] | None = None,
    rule: dict[str, Any] | None = None,
    system_context: str = "",
    db_path: Path | str = HITL_DB_PATH,
    port: int = HITL_PORT,
    timeout: int = ASK_USER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """
    Request human answer for an ask_user question.
    1. If HITL_MODE is 'auto', returns no_response immediately with loud warning.
    2. Builds payload with question, choices, system_context, alert_title, severity.
    3. Creates pending request in store with kind='ask_user'.
    4. Dispatches desktop notification (fixed title + truncated rule title) and prints URL.
    5. Waits for human response or timeout.
    6. Returns:
       - {"status": "answered", "answer": choices[idx], "choice_index": idx, "is_unsure": False, "note": note}
       - {"status": "answered", "answer": None, "choice_index": len(choices), "is_unsure": True, "note": note}
       - {"status": "no_response", "reason": "timeout"}
    """
    alert = alert or {}
    rule = rule or {}

    if HITL_MODE == "auto":
        print("[!] WARNING: HITL_MODE is 'auto' (dry-run/test mode). ask_user cannot be answered by automation. Returning no_response immediately.")
        return {"status": "no_response", "reason": "timeout"}

    payload = {
        "question": question,
        "choices": choices,
        "system_context": system_context,
        "alert_title": alert.get("title") or rule.get("title") or "Security Alert",
        "severity": str(alert.get("level") or rule.get("level") or "UNKNOWN").upper(),
    }

    req = create_request(
        thread_id=thread_id,
        kind="ask_user",
        payload=payload,
        expires_in_seconds=timeout,
        db_path=db_path,
    )

    url = f"http://127.0.0.1:{port}/r/{req['request_id']}?t={req['token']}"

    try:
        start_server_in_background(port=port, db_path=db_path)
    except Exception as e:
        print(f"[!] Warning: Could not start HITL server: {e}")

    print("\n" + "=" * 80)
    print("  [!] THE AI ANALYST HAS A QUESTION")
    print(f"  Question: {question}")
    print(f"  Decision URL: {url}")
    print(f"  Timeout: {timeout} seconds")
    print("=" * 80 + "\n")

    try:
        from UI.HITL.notify import send_toast
        rule_title = str(payload["alert_title"])[:100]
        send_toast(
            title="Triagent: question for you",
            message=rule_title,
            url=url,
        )
    except Exception as e:
        print(f"[!] Notification dispatch error: {e}")

    if HITL_OPEN_BROWSER:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    result = wait_for_decision(req["request_id"], timeout=float(timeout), db_path=db_path)

    if result.get("status") == "decided":
        raw_decision = result.get("decision", "")
        note = result.get("note", "")
        try:
            idx = int(raw_decision)
            if 0 <= idx < len(choices):
                return {
                    "status": "answered",
                    "answer": choices[idx],
                    "choice_index": idx,
                    "is_unsure": False,
                    "note": note,
                }
            elif idx == len(choices):
                return {
                    "status": "answered",
                    "answer": None,
                    "choice_index": idx,
                    "is_unsure": True,
                    "note": note,
                }
        except (ValueError, TypeError):
            pass

    return {
        "status": "no_response",
        "reason": "timeout",
    }
