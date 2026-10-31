"""
UI/HITL - Human-In-The-Loop Approval Subsystem

Exports:
- request_tool_approval: Requests human approval for sensitive actions (kill_process, quarantine_file).
- request_continue: Requests human approval to continue when max turns limit is hit.
- start_server_in_background: Starts the local HITL web server on a background daemon thread.
"""

from typing import Any

# Forward exports - will be populated by server and handler modules
def request_tool_approval(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from UI.HITL.server import request_tool_approval as _impl
    return _impl(*args, **kwargs)

def request_continue(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from UI.HITL.server import request_continue as _impl
    return _impl(*args, **kwargs)

def start_server_in_background(*args: Any, **kwargs: Any) -> Any:
    from UI.HITL.server import start_server_in_background as _impl
    return _impl(*args, **kwargs)

__all__ = [
    "request_tool_approval",
    "request_continue",
    "start_server_in_background",
]
