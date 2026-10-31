"""
UI/HITL/pages.py - Pure HTML Generation for Human-In-The-Loop Approval Pages

Design constraints:
- Plain HTML only: No CSS frameworks, no JavaScript.
- Everything dynamic is escaped with html.escape to neutralize HTML/injection attacks.
- Accessible headings, <pre> blocks with word wrapping, one form, and clean buttons.
"""

import html
from typing import Any


def _base_html(title: str, body_content: str) -> str:
    """Render the standard HTML skeleton with secure doctype and title."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)} - BlueTeamingAI HITL</title>
</head>
<body>
{body_content}
</body>
</html>"""


def render_pending_list(requests: list[dict[str, Any]]) -> str:
    """Render the dashboard listing all active pending approval requests."""
    items_html = []
    if not requests:
        items_html.append("<p>No pending approval requests at this time.</p>")
    else:
        items_html.append("<ul>")
        for req in requests:
            rid = html.escape(str(req.get("request_id", "")))
            tok = html.escape(str(req.get("token", "")))
            kind = html.escape(str(req.get("kind", "")))
            thread_id = html.escape(str(req.get("thread_id", "")))
            created = html.escape(str(req.get("created_at", "")))
            expires = html.escape(str(req.get("expires_at", "")))
            payload = req.get("payload", {})
            title = html.escape(str(payload.get("alert_title") or payload.get("tool_name") or kind))

            items_html.append(
                f'<li><strong><a href="/r/{rid}?t={tok}">[{kind}] {title}</a></strong> '
                f'(Thread: {thread_id}, Created: {created}, Expires: {expires})</li>'
            )
        items_html.append("</ul>")

    content = f"""<h1>BlueTeamingAI - Pending Approval Requests</h1>
<hr>
{''.join(items_html)}
<hr>
<p><small>BlueTeamingAI Human-In-The-Loop Security Approval Server (127.0.0.1)</small></p>"""
    return _base_html("Pending Requests", content)


def render_tool_approval_page(req: dict[str, Any], dry_run: bool = False) -> str:
    """Render the tool approval page (kill_process, quarantine_file)."""
    rid = html.escape(str(req.get("request_id", "")))
    token = html.escape(str(req.get("token", "")))
    thread_id = html.escape(str(req.get("thread_id", "")))
    expires_at = html.escape(str(req.get("expires_at", "")))

    payload = req.get("payload", {})
    alert_title = html.escape(str(payload.get("alert_title", "Security Alert")))
    severity = html.escape(str(payload.get("severity", "UNKNOWN")).upper())
    tool_name = html.escape(str(payload.get("tool_name", "HITL Tool")))
    target = html.escape(str(payload.get("target", "Unknown")))
    reason = html.escape(str(payload.get("reason", "No reason provided")))
    screen_text = html.escape(str(payload.get("approval_screen", "")))

    # Banner mode
    if dry_run:
        banner = "<h3>[!] DRY RUN MODE ACTIVE - SIMULATION ONLY (NO SYSTEM CHANGES WILL BE MADE) [!]</h3>"
    else:
        banner = "<h3>[!] LIVE EXECUTION MODE - ACTION WILL PERMANENTLY MODIFY THE SYSTEM UPON APPROVAL [!]</h3>"

    # Action scope description
    if "kill" in tool_name.lower():
        scope_text = (
            "<strong>Action Scope:</strong> Terminates this single running process. "
            "Cannot be undone. Does NOT remove dropped files, startup registry entries, or scheduled tasks."
        )
    else:
        scope_text = (
            "<strong>Action Scope:</strong> Moves the file into a locked quarantine directory and neutralizes it. "
            "Can be restored by an analyst if false positive. Does NOT terminate already running processes."
        )

    content = f"""<h1>Human-In-The-Loop: Action Approval Required</h1>
{banner}
<hr>
<p><strong>Alert Title:</strong> {alert_title} &nbsp;|&nbsp; <strong>Severity:</strong> {severity}</p>
<p><strong>Tool Requested:</strong> <code>{tool_name}</code></p>
<p><strong>Target:</strong> <code>{target}</code></p>
<p><strong>Thread ID:</strong> {thread_id} &nbsp;|&nbsp; <strong>Request ID:</strong> {rid}</p>
<p><strong>Expires At (UTC):</strong> {expires_at}</p>
<hr>
<h3>Agent's Stated Reason:</h3>
<p>{reason}</p>
<hr>
<h3>Full Approval & Target Details:</h3>
<pre style="white-space: pre-wrap; word-wrap: break-word; background: #f0f0f0; padding: 12px; border: 1px solid #ccc;">{screen_text}</pre>
<hr>
<p>{scope_text}</p>
<hr>
<h3>Submit Your Decision:</h3>
<form method="POST" action="/r/{rid}/decide">
    <input type="hidden" name="t" value="{token}">
    <p>
        <label for="note"><strong>Optional Analyst Note (Audit Trail, max 500 chars):</strong></label><br>
        <textarea id="note" name="note" rows="3" cols="70" maxlength="500" placeholder="Reason for decision, ticket reference, or analyst comments..."></textarea>
    </p>
    <p>
        <button type="submit" name="decision" value="approved" style="padding: 10px 24px; font-weight: bold; background: #e0f2e9; border: 2px solid #2e7d32; cursor: pointer;">Approve Action</button>
        &nbsp;&nbsp;&nbsp;&nbsp;
        <button type="submit" name="decision" value="rejected" style="padding: 10px 24px; font-weight: bold; background: #ffebee; border: 2px solid #c62828; cursor: pointer;">Reject Action</button>
    </p>
</form>
<hr>
<p><small><a href="/">Back to Pending Requests List</a></small></p>"""

    return _base_html(f"Approve {tool_name}", content)


def render_continue_page(req: dict[str, Any]) -> str:
    """Render the continue investigation prompt page."""
    rid = html.escape(str(req.get("request_id", "")))
    token = html.escape(str(req.get("token", "")))
    thread_id = html.escape(str(req.get("thread_id", "")))
    expires_at = html.escape(str(req.get("expires_at", "")))

    payload = req.get("payload", {})
    turns = html.escape(str(payload.get("turns", 5)))
    limit = html.escape(str(payload.get("turn_limit", 5)))
    continues = html.escape(str(payload.get("continues", 0)))
    max_continues = html.escape(str(payload.get("max_continues", 3)))

    plan = payload.get("plan", [])
    if isinstance(plan, list):
        plan_items = "".join(f"<li>{html.escape(str(p))}</li>" for p in plan)
        plan_html = f"<ol>{plan_items}</ol>" if plan_items else "<p>No formal plan recorded.</p>"
    else:
        plan_html = f"<p>{html.escape(str(plan))}</p>"

    tools_used = payload.get("tools_used", [])
    if isinstance(tools_used, list):
        tools_html = ", ".join(f"<code>{html.escape(str(t))}</code>" for t in tools_used) or "None"
    else:
        tools_html = html.escape(str(tools_used))

    last_message = html.escape(str(payload.get("last_message", "")[:2000]))

    content = f"""<h1>Human-In-The-Loop: Turn Limit Reached</h1>
<hr>
<p>The AI security investigator has completed its turn quota for this alert.</p>
<p><strong>Turns Used:</strong> {turns} / {limit} &nbsp;|&nbsp; <strong>Continues Granted:</strong> {continues} / {max_continues}</p>
<p><strong>Thread ID:</strong> {thread_id} &nbsp;|&nbsp; <strong>Request ID:</strong> {rid}</p>
<p><strong>Expires At (UTC):</strong> {expires_at}</p>
<hr>
<h3>Investigation Plan:</h3>
{plan_html}
<h3>Tools Executed So Far:</h3>
<p>{tools_html}</p>
<h3>Agent's Last Message:</h3>
<pre style="white-space: pre-wrap; word-wrap: break-word; background: #f0f0f0; padding: 12px; border: 1px solid #ccc;">{last_message}</pre>
<hr>
<h3>Submit Your Decision:</h3>
<form method="POST" action="/r/{rid}/decide">
    <input type="hidden" name="t" value="{token}">
    <p>
        <label for="note"><strong>Optional Analyst Note (Audit Trail, max 500 chars):</strong></label><br>
        <textarea id="note" name="note" rows="3" cols="70" maxlength="500" placeholder="Instructions or reason for continuing/stopping..."></textarea>
    </p>
    <p>
        <button type="submit" name="decision" value="continue" style="padding: 10px 24px; font-weight: bold; background: #e3f2fd; border: 2px solid #1565c0; cursor: pointer;">Continue Investigation</button>
        &nbsp;&nbsp;&nbsp;&nbsp;
        <button type="submit" name="decision" value="stop" style="padding: 10px 24px; font-weight: bold; background: #ffebee; border: 2px solid #c62828; cursor: pointer;">Stop Investigation</button>
    </p>
</form>
<hr>
<p><small><a href="/">Back to Pending Requests List</a></small></p>"""

    return _base_html("Continue Investigation?", content)


def render_ask_user_page(req: dict[str, Any]) -> str:
    """Render the human question page for the ask_user tool."""
    rid = html.escape(str(req.get("request_id", "")))
    token = html.escape(str(req.get("token", "")))
    expires_at = html.escape(str(req.get("expires_at", "")))

    payload = req.get("payload", {})
    question = html.escape(str(payload.get("question", "")))
    choices = payload.get("choices", [])
    system_context = html.escape(str(payload.get("system_context", "")))

    choice_items = []
    if isinstance(choices, list):
        for i, choice in enumerate(choices):
            escaped_choice = html.escape(str(choice))
            choice_items.append(
                f'<p><label><input type="radio" name="decision" value="{i}" required> {escaped_choice}</label></p>'
            )
        # System-added unsure option at index len(choices)
        unsure_idx = len(choices)
        unsure_text = html.escape("I'm not sure")
        choice_items.append(
            f'<p><label><input type="radio" name="decision" value="{unsure_idx}"> {unsure_text}</label></p>'
        )

    choices_html = "\n".join(choice_items)

    content = f"""<h1>The AI analyst has a question</h1>
<p><em>The question below was written by the AI. Never enter passwords or secrets here. Answering does not approve any action.</em></p>
<hr>

<h3>What the system recorded:</h3>
<pre style="white-space: pre-wrap; word-wrap: break-word; background: #f0f0f0; padding: 12px; border: 1px solid #ccc;">{system_context}</pre>
<hr>

<h3>Question:</h3>
<p style="font-size: 1.1em; font-weight: bold;">{question}</p>

<form method="POST" action="/r/{rid}/decide">
    <input type="hidden" name="t" value="{token}">
    <p><strong>Select one answer:</strong></p>
    {choices_html}
    <hr>

    <p>
        <label for="note"><strong>Optional Note (max 300 chars):</strong></label><br>
        <textarea id="note" name="note" rows="3" cols="70" maxlength="300" placeholder="Optional context or explanation..."></textarea>
    </p>

    <p>
        <button type="submit" style="padding: 10px 24px; font-weight: bold; background: #e3f2fd; border: 2px solid #1565c0; cursor: pointer;">Send answer</button>
    </p>
    <p><small>Time remaining: Request expires at {expires_at} UTC</small></p>
</form>
<hr>
<p><small><a href="/">Back to Pending Requests List</a></small></p>"""

    return _base_html("Analyst Question", content)


def _format_decision_display(req: dict[str, Any]) -> str:
    """Format stored decision into human-readable text."""
    kind = req.get("kind", "")
    raw = str(req.get("decision", ""))
    if kind == "ask_user":
        payload = req.get("payload", {})
        choices = payload.get("choices", [])
        try:
            idx = int(raw)
            if 0 <= idx < len(choices):
                return html.escape(f"Answer: {choices[idx]}")
            elif idx == len(choices):
                return "Answer: I'm not sure"
        except (ValueError, TypeError):
            pass
    return html.escape(raw.upper())


def render_decided_page(req: dict[str, Any], message: str = "") -> str:
    """Render confirmation page when a decision has been successfully recorded."""
    rid = html.escape(str(req.get("request_id", "")))
    decision = _format_decision_display(req)
    note = html.escape(str(req.get("note", "")))
    decided_at = html.escape(str(req.get("decided_at", "")))
    msg_html = f"<p><em>{html.escape(message)}</em></p>" if message else ""

    content = f"""<h1>Decision Recorded</h1>
<hr>
<p><strong>Decision:</strong> <span style="font-size: 1.2em; font-weight: bold;">{decision}</span></p>
<p><strong>Recorded At:</strong> {decided_at}</p>
<p><strong>Request ID:</strong> {rid}</p>
{f"<p><strong>Analyst Note:</strong> {note}</p>" if note else ""}
{msg_html}
<p>The AI security investigator is resuming with your decision. You may close this window.</p>
<hr>
<p><a href="/">View Other Pending Requests</a></p>"""
    return _base_html("Decision Recorded", content)


def render_already_decided_page(req: dict[str, Any]) -> str:
    """Render page when a request was already decided (single-use enforcement)."""
    rid = html.escape(str(req.get("request_id", "")))
    decision = _format_decision_display(req)
    decided_at = html.escape(str(req.get("decided_at", "")))
    note = html.escape(str(req.get("note", "")))

    content = f"""<h1>Request Already Decided</h1>
<hr>
<p>This approval request has already received a decision and cannot be modified (single-use).</p>
<p><strong>Decision:</strong> {decision}</p>
<p><strong>Decided At:</strong> {decided_at}</p>
<p><strong>Request ID:</strong> {rid}</p>
{f"<p><strong>Note:</strong> {note}</p>" if note else ""}
<hr>
<p><a href="/">Back to Pending Requests</a></p>"""
    return _base_html("Already Decided", content)


def render_expired_page(req: dict[str, Any]) -> str:
    """Render page when a request has timed out."""
    rid = html.escape(str(req.get("request_id", "")))
    expires_at = html.escape(str(req.get("expires_at", "")))

    content = f"""<h1>Request Expired</h1>
<hr>
<p>This approval request timed out with no response before the expiration window.</p>
<p><strong>Expiration Time:</strong> {expires_at}</p>
<p><strong>Request ID:</strong> {rid}</p>
<p>Per security policy, timed-out actions are treated as <strong>Rejected / Stopped</strong>.</p>
<hr>
<p><a href="/">Back to Pending Requests</a></p>"""
    return _base_html("Request Expired", content)


def render_not_found_page(request_id: str = "") -> str:
    """Render page when a request ID is not found."""
    rid = html.escape(str(request_id))
    content = f"""<h1>404 - Request Not Found</h1>
<hr>
<p>No approval request was found matching ID: <code>{rid}</code>.</p>
<p><a href="/">Back to Pending Requests</a></p>"""
    return _base_html("Not Found", content)
