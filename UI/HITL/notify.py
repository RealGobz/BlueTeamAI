"""
UI/HITL/notify.py
================
Windows toast notification dispatcher for Human-In-The-Loop requests.

Dispatches local Windows notifications via winotify when user approval is needed.
Sanitizes inputs to prevent control character injection, limits message length,
and provides a safe fallback if notification services are unavailable.
"""

from __future__ import annotations

import re
import sys


def _sanitize_toast_text(text: str, max_len: int = 100) -> str:
    """
    Sanitize text for toast display:
    - Removes all control characters and newlines.
    - Truncates to max_len.
    """
    if not text:
        return ""
    # Strip any control characters (ASCII 0-31, 127)
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(text))
    # Collapse multiple whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


import uuid


def _ensure_winotify_priority(winotify_mod: Any) -> None:
    """Ensure winotify template uses High Priority so Windows does not suppress toasts."""
    try:
        if hasattr(winotify_mod, "TEMPLATE") and "$Toast.Priority" not in winotify_mod.TEMPLATE:
            winotify_mod.TEMPLATE = winotify_mod.TEMPLATE.replace(
                '$Toast.Group = "{group}"',
                '$Toast.Group = "{group}"\n$Toast.Priority = [Windows.UI.Notifications.ToastNotificationPriority]::High',
            )
    except Exception:
        pass


def send_toast(title: str, message: str, url: str, tag: str | None = None) -> bool:
    """
    Send a Windows toast notification pointing to the HITL approval page.

    Parameters
    ----------
    title: str
        Short title (e.g. "Approval Needed: kill_process")
    message: str
        Short description (e.g. alert title or turn limit summary)
    url: str
        Local loopback URL to the approval/continue page
    tag: str | None
        Unique identifier for the notification to prevent Windows from
        silently dropping or deduplicating sequential toasts.

    Returns
    -------
    bool
        True if notification was posted successfully, False otherwise.
    """
    clean_title = _sanitize_toast_text(title, max_len=64) or "Triagent"
    clean_message = _sanitize_toast_text(message, max_len=100)
    clean_tag = _sanitize_toast_text(tag, max_len=64) if tag else f"tri_{uuid.uuid4().hex[:12]}"
    safe_url = str(url).strip()

    # Safety check: URL must be a loopback address
    if not (safe_url.startswith("http://127.0.0.1:") or safe_url.startswith("http://localhost:")):
        print(f"[!] Warning: Refusing to dispatch notification with non-loopback URL: {safe_url}")
        return False

    try:
        import winotify

        _ensure_winotify_priority(winotify)

        toast = winotify.Notification(
            app_id="Triagent",
            title=clean_title,
            msg=clean_message,
            duration="long",
            launch=safe_url,
        )
        toast.tag = clean_tag
        toast.group = "Triagent"
        try:
            toast.add_actions(label="Review Decision", launch=safe_url)
        except Exception:
            pass

        toast.show()
        return True
    except Exception as e:
        # Notifications should never crash the caller.
        # Direct URL is already printed to console by the server caller.
        print(f"[!] Toast notification skipped: {e}")
        return False
