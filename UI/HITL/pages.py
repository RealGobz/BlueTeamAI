"""
UI/HITL/pages.py - Pure HTML Generation for Triagent Human-In-The-Loop Approval Pages

Design constraints:
- Plain HTML only: No CSS frameworks, no JavaScript.
- Strict CSP compatibility: No inline styles (no style=""), no <style> blocks, no <script> blocks.
- Everything dynamic is escaped with html.escape.
- Calmed Triagent aesthetic ("calm, not alarm"):
  - Topbar with Triagent lockup (<picture> element).
  - Amber element ONLY for .needs-you eyebrow/label.
  - Neutral LIVE and DRY RUN notices (1px border, --surface-2, bold text, no color).
  - Neutral action buttons (Approve/Reject, Continue/Stop).
  - Monospace pre-wrapped evidence blocks.
  - Server-side formatted local expiration time with reload hint.
"""

from datetime import datetime, timezone
import html
from typing import Any


def format_time_left(expires_at_str: str) -> tuple[str, bool]:
    """
    Format expires_at into local PC time string:
    'Expires at HH:MM (about X minutes left)'
    Returns (formatted_string, is_expired).
    """
    if not expires_at_str:
        return "", False
    try:
        exp_dt = datetime.fromisoformat(str(expires_at_str))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        now_dt = datetime.now(timezone.utc)
        diff_seconds = (exp_dt - now_dt).total_seconds()
        if diff_seconds <= 0:
            return "Expired", True
        minutes_left = max(1, int(round(diff_seconds / 60.0)))
        local_exp = exp_dt.astimezone()
        time_str = local_exp.strftime("%H:%M")
        unit = "minute" if minutes_left == 1 else "minutes"
        return f"Expires at {time_str} (about {minutes_left} {unit} left)", False
    except Exception:
        return f"Expires at {html.escape(str(expires_at_str))}", False


def _base_html(title: str, body_content: str) -> str:
    """Render the standard HTML skeleton with secure doctype, brand lockup, and stylesheets."""
    escaped_title = html.escape(title)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escaped_title} - Triagent</title>
    <link rel="icon" type="image/svg+xml" href="/brand/triagent-icon.svg">
    <link rel="stylesheet" href="/brand/theme.css">
    <link rel="stylesheet" href="/static/hitl.css">
</head>
<body>
    <div class="container">
        <header class="topbar">
            <picture class="brand-lockup">
                <source media="(prefers-color-scheme: light)" srcset="/brand/triagent-lockup-light.svg">
                <img src="/brand/triagent-lockup-dark.svg" alt="Triagent" width="140" height="32">
            </picture>
        </header>
        <main>
{body_content}
        </main>
    </div>
</body>
</html>"""


def render_pending_list(requests: list[dict[str, Any]]) -> str:
    """Render the dashboard listing all active pending approval requests."""
    if not requests:
        content = """<h1>Pending requests</h1>
<p class="pending-empty">Nothing needs you right now.</p>"""
        return _base_html("Pending Requests", content)

    items_html = []
    for req in requests:
        rid = html.escape(str(req.get("request_id", "")))
        tok = html.escape(str(req.get("token", "")))
        raw_kind = str(req.get("kind", ""))

        if raw_kind == "tool_approval":
            kind_label = "Approve an action"
        elif raw_kind == "ask_user":
            kind_label = "Question"
        elif raw_kind == "continue_turns":
            kind_label = "Continue?"
        else:
            kind_label = "Pending decision"

        payload = req.get("payload", {})
        title_raw = str(payload.get("alert_title") or payload.get("tool_name") or kind_label)
        title = html.escape(title_raw)

        expires_str, _ = format_time_left(str(req.get("expires_at", "")))
        time_part = f'<span class="pending-time">{html.escape(expires_str)}</span>' if expires_str else ""

        items_html.append(
            f'<li><a href="/r/{rid}?t={tok}" class="pending-item">'
            f'<span class="pending-kind">{html.escape(kind_label)}</span>'
            f'<span class="pending-title">{title}</span>'
            f'{time_part}'
            f'</a></li>'
        )

    content = f"""<div class="eyebrow needs-you">Needs your decision</div>
<h1>Pending requests</h1>
<ul class="pending-list">
{''.join(items_html)}
</ul>"""
    return _base_html("Pending Requests", content)


def render_tool_approval_page(req: dict[str, Any], dry_run: bool = False) -> str:
    """Render the tool approval page (kill_process, quarantine_file)."""
    rid = html.escape(str(req.get("request_id", "")))
    token = html.escape(str(req.get("token", "")))
    thread_id = html.escape(str(req.get("thread_id", "")))

    payload = req.get("payload", {})
    alert_title = html.escape(str(payload.get("alert_title", "Security Alert")))
    severity = html.escape(str(payload.get("severity", "UNKNOWN")).upper())
    tool_name = html.escape(str(payload.get("tool_name", "HITL Tool")))
    target = html.escape(str(payload.get("target", "Unknown")))
    reason = html.escape(str(payload.get("reason", "No reason provided")))
    screen_text = html.escape(str(payload.get("approval_screen", "")))

    if dry_run:
        notice_box = '<div class="notice-dryrun"><strong>DRY RUN.</strong> Nothing will be changed.</div>'
    else:
        notice_box = '<div class="notice-live"><strong>LIVE.</strong> Approving this will run the action on this PC.</div>'

    # Plain summary lead
    if "kill" in tool_name.lower():
        action_summary = f"Triagent is asking to terminate process <code>{target}</code>."
        scope_text = (
            "Terminates this single running process. Cannot be undone. "
            "Does NOT remove dropped files, startup registry entries, or scheduled tasks."
        )
    else:
        action_summary = f"Triagent is asking to quarantine file <code>{target}</code>."
        scope_text = (
            "Moves the file into a locked quarantine directory and neutralizes it. "
            "Can be restored by an analyst if false positive. Does NOT terminate already running processes."
        )

    time_left_str, _ = format_time_left(str(req.get("expires_at", "")))

    content = f"""<div class="eyebrow needs-you">Needs your decision</div>
<h1>Action approval required</h1>
{notice_box}
<p class="lead">{action_summary}</p>

<div class="meta-grid">
    <span class="meta-label">Alert:</span>
    <span class="meta-value">{alert_title}</span>
    <span class="meta-label">Severity:</span>
    <span class="meta-value">{severity}</span>
    <span class="meta-label">Tool:</span>
    <span class="meta-value"><code>{tool_name}</code></span>
    <span class="meta-label">Target:</span>
    <span class="meta-value"><code>{target}</code></span>
    <span class="meta-label">Thread ID:</span>
    <span class="meta-value"><code>{thread_id}</code></span>
</div>

<h2>Agent's reason</h2>
<p class="lead">{reason}</p>

<h2>Evidence & target details</h2>
<pre class="evidence">{screen_text}</pre>

<h2>What this will and will not do</h2>
<p class="scope-text">{scope_text}</p>

<div class="time-left">{html.escape(time_left_str)}</div>
<div class="time-refresh">Reload the page to refresh.</div>

<form method="POST" action="/r/{rid}/decide">
    <input type="hidden" name="t" value="{token}">
    <label for="note" class="note-label">Optional analyst note (audit trail, max 500 chars):</label>
    <textarea id="note" name="note" class="note-box" rows="3" maxlength="500" placeholder="Reason for decision, ticket reference, or analyst comments..."></textarea>
    <div class="btn-group">
        <button type="submit" name="decision" value="approved" class="btn btn-primary">Approve action</button>
        <button type="submit" name="decision" value="rejected" class="btn btn-secondary">Reject action</button>
    </div>
</form>

<div class="footer-nav">
    <a href="/">Back to pending requests</a>
</div>"""

    return _base_html(f"Approve {tool_name}", content)


def render_continue_page(req: dict[str, Any]) -> str:
    """Render the continue investigation prompt page."""
    rid = html.escape(str(req.get("request_id", "")))
    token = html.escape(str(req.get("token", "")))
    thread_id = html.escape(str(req.get("thread_id", "")))

    payload = req.get("payload", {})
    turns = html.escape(str(payload.get("turns", 5)))
    limit = html.escape(str(payload.get("turn_limit", 5)))
    continues = html.escape(str(payload.get("continues", 0)))
    max_continues = html.escape(str(payload.get("max_continues", 3)))

    plan = payload.get("plan", [])
    if isinstance(plan, list):
        plan_items = "".join(f"<li>{html.escape(str(p))}</li>" for p in plan)
        plan_html = f"<ol>{plan_items}</ol>" if plan_items else "<p class=\"lead\">No formal plan recorded.</p>"
    else:
        plan_html = f"<p class=\"lead\">{html.escape(str(plan))}</p>"

    tools_used = payload.get("tools_used", [])
    if isinstance(tools_used, list):
        tools_html = ", ".join(f"<code>{html.escape(str(t))}</code>" for t in tools_used) or "None"
    else:
        tools_html = html.escape(str(tools_used))

    last_message = html.escape(str(payload.get("last_message", "")[:2000]))
    time_left_str, _ = format_time_left(str(req.get("expires_at", "")))

    content = f"""<div class="eyebrow needs-you">Continue?</div>
<h1>Investigation turn limit reached</h1>
<p class="lead">Triagent has completed its turn quota for this alert and needs approval to continue investigating.</p>

<div class="meta-grid">
    <span class="meta-label">Turns used:</span>
    <span class="meta-value">{turns} / {limit}</span>
    <span class="meta-label">Continues granted:</span>
    <span class="meta-value">{continues} / {max_continues}</span>
    <span class="meta-label">Thread ID:</span>
    <span class="meta-value"><code>{thread_id}</code></span>
</div>

<h2>Investigation plan</h2>
{plan_html}

<h2>Tools executed so far</h2>
<p class="lead">{tools_html}</p>

<h2>Agent's last message</h2>
<pre class="evidence">{last_message}</pre>

<div class="time-left">{html.escape(time_left_str)}</div>
<div class="time-refresh">Reload the page to refresh.</div>

<form method="POST" action="/r/{rid}/decide">
    <input type="hidden" name="t" value="{token}">
    <label for="note" class="note-label">Optional analyst note (audit trail, max 500 chars):</label>
    <textarea id="note" name="note" class="note-box" rows="3" maxlength="500" placeholder="Instructions or reason for continuing/stopping..."></textarea>
    <div class="btn-group">
        <button type="submit" name="decision" value="continue" class="btn btn-primary">Continue</button>
        <button type="submit" name="decision" value="stop" class="btn btn-secondary">Stop</button>
    </div>
</form>

<div class="footer-nav">
    <a href="/">Back to pending requests</a>
</div>"""

    return _base_html("Continue Investigation?", content)


def render_ask_user_page(req: dict[str, Any]) -> str:
    """Render the human question page for the ask_user tool."""
    rid = html.escape(str(req.get("request_id", "")))
    token = html.escape(str(req.get("token", "")))

    payload = req.get("payload", {})
    question = html.escape(str(payload.get("question", "")))
    choices = payload.get("choices", [])
    system_context = html.escape(str(payload.get("system_context", "")))

    choice_items = []
    if isinstance(choices, list):
        for i, choice in enumerate(choices):
            escaped_choice = html.escape(str(choice))
            choice_items.append(
                f'<label class="choice-row"><input type="radio" name="decision" value="{i}" required> <span>{escaped_choice}</span></label>'
            )
        # System-added unsure option at index len(choices)
        unsure_idx = len(choices)
        unsure_text = html.escape("I'm not sure")
        choice_items.append(
            f'<label class="choice-row"><input type="radio" name="decision" value="{unsure_idx}"> <span>{unsure_text}</span></label>'
        )

    choices_html = "\n".join(choice_items)
    time_left_str, _ = format_time_left(str(req.get("expires_at", "")))

    content = f"""<div class="eyebrow needs-you">Triagent has a question</div>
<h1>Question from the AI investigator</h1>
<div class="notice">The question below was written by the AI. Never enter passwords or secrets here. Answering does not approve any action.</div>

<h2>What the system recorded</h2>
<pre class="evidence">{system_context}</pre>

<h2>Question</h2>
<p class="question-text">{question}</p>

<form method="POST" action="/r/{rid}/decide">
    <input type="hidden" name="t" value="{token}">
    <div class="choices">
{choices_html}
    </div>

    <label for="note" class="note-label">Optional note (max 300 chars):</label>
    <textarea id="note" name="note" class="note-box" rows="3" maxlength="300" placeholder="Optional context or explanation..."></textarea>

    <div class="btn-group">
        <button type="submit" class="btn btn-primary">Send answer</button>
    </div>

    <div class="time-left">{html.escape(time_left_str)}</div>
    <div class="time-refresh">Reload the page to refresh.</div>
</form>

<div class="footer-nav">
    <a href="/">Back to pending requests</a>
</div>"""

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

    content = f"""<div class="page-short">
    <h1>Decision recorded</h1>
    <p>Decision: <strong>{decision}</strong></p>
    <p>Recorded at: {decided_at} (Request ID: <code>{rid}</code>)</p>
    {f"<p>Analyst note: {note}</p>" if note else ""}
    {msg_html}
    <p>Triagent is resuming with your decision. You may close this window.</p>
    <div class="footer-nav"><a href="/">View pending requests</a></div>
</div>"""
    return _base_html("Decision Recorded", content)


def render_already_decided_page(req: dict[str, Any]) -> str:
    """Render page when a request was already decided (single-use enforcement)."""
    rid = html.escape(str(req.get("request_id", "")))
    decision = _format_decision_display(req)
    decided_at = html.escape(str(req.get("decided_at", "")))

    content = f"""<div class="page-short">
    <h1>Request already decided</h1>
    <p>This approval request has already received a decision ({decision}) and cannot be modified.</p>
    <p>Recorded at: {decided_at} (Request ID: <code>{rid}</code>)</p>
    <div class="footer-nav"><a href="/">Back to pending requests</a></div>
</div>"""
    return _base_html("Already Decided", content)


def render_expired_page(req: dict[str, Any]) -> str:
    """Render page when a request has timed out."""
    rid = html.escape(str(req.get("request_id", "")))

    content = f"""<div class="page-short">
    <h1>Request expired</h1>
    <p>This approval request timed out before a decision was submitted.</p>
    <p>Per security policy, timed-out actions are treated as <strong>Rejected / Stopped</strong>.</p>
    <p>Request ID: <code>{rid}</code></p>
    <div class="footer-nav"><a href="/">Back to pending requests</a></div>
</div>"""
    return _base_html("Request Expired", content)


def render_not_found_page(request_id: str = "") -> str:
    """Render page when a request ID is not found."""
    rid = html.escape(str(request_id))
    content = f"""<div class="page-short">
    <h1>404 &mdash; Request not found</h1>
    <p>No approval request was found matching ID: <code>{rid}</code>.</p>
    <div class="footer-nav"><a href="/">Back to pending requests</a></div>
</div>"""
    return _base_html("Not Found", content)
