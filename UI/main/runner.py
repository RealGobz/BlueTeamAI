"""
UI/main/runner.py - Per-thread locks, active run registry, and background execution.

Manages:
1. Per-thread locks to prevent concurrent invocations on the same thread.
2. Global registry of active runs: thread_id -> {kind: 'alert' | 'chat', started: timestamp}.
3. Background execution of send_user_message with error isolation (writes incomplete verdict on crash).
4. Watcher alert run integration to register active runs so the UI shows 'working'.
5. Pending HITL request checking to prevent concurrent messages while human decision is pending.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from config import HITL_DB_PATH, RESULTS_DB_PATH
from agent.agent import workflow, send_user_message
from agent.results_db import record_incomplete_verdict, get_latest_verdict_for_thread

logger = logging.getLogger("UI.main.runner")

# Thread lock management
_REGISTRY_LOCK = threading.Lock()
_THREAD_LOCKS: dict[str, threading.Lock] = {}
_ACTIVE_RUNS: dict[str, dict[str, Any]] = {}


def get_thread_lock(thread_id: str) -> threading.Lock:
    """Get or create an exclusive lock for a specific thread_id."""
    with _REGISTRY_LOCK:
        if thread_id not in _THREAD_LOCKS:
            _THREAD_LOCKS[thread_id] = threading.Lock()
        return _THREAD_LOCKS[thread_id]


def register_run(thread_id: str, kind: str) -> bool:
    """
    Attempt to register an active run for a thread.
    Returns True if registered, False if already running.
    """
    with _REGISTRY_LOCK:
        if thread_id in _ACTIVE_RUNS:
            return False
        _ACTIVE_RUNS[thread_id] = {
            "kind": kind,
            "started": datetime.now(timezone.utc).isoformat(),
        }
        return True


def unregister_run(thread_id: str) -> None:
    """Remove a thread from the active runs registry."""
    with _REGISTRY_LOCK:
        _ACTIVE_RUNS.pop(thread_id, None)


def get_active_run(thread_id: str) -> dict[str, Any] | None:
    """Return active run metadata for a thread, or None if not active."""
    with _REGISTRY_LOCK:
        run = _ACTIVE_RUNS.get(thread_id)
        return dict(run) if run else None


def list_active_runs() -> dict[str, dict[str, Any]]:
    """Return a copy of all currently active runs."""
    with _REGISTRY_LOCK:
        return {tid: dict(info) for tid, info in _ACTIVE_RUNS.items()}


def has_pending_hitl(thread_id: str, db_path: Path | str = HITL_DB_PATH) -> bool:
    """
    Check if a thread currently has an active pending request in hitl.db.
    """
    path = Path(db_path)
    if not path.exists():
        return False

    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT 1 FROM requests WHERE thread_id = ? AND status = 'pending' LIMIT 1",
                (thread_id,),
            )
            return cur.fetchone() is not None
        finally:
            conn.close()
    except Exception:
        return False


def run_alert_investigation(
    thread_id: str,
    initial_state: dict[str, Any],
    workflow_instance=None,
    db_path: Path | str = RESULTS_DB_PATH,
) -> dict[str, Any]:
    """
    Synchronous investigation wrapper called by detection/watch.py.
    Acquires the thread lock, registers the active run, invokes the workflow,
    and cleans up registry upon completion or error.
    """
    lock = get_thread_lock(thread_id)
    wf = workflow_instance or workflow
    config = {"configurable": {"thread_id": thread_id}}

    acquired = lock.acquire(blocking=False)
    if not acquired:
        raise RuntimeError(f"Thread '{thread_id}' is already executing an active run.")

    if not register_run(thread_id, kind="alert"):
        lock.release()
        raise RuntimeError(f"Thread '{thread_id}' is already registered as active.")

    try:
        result = wf.invoke(initial_state, config=config)
        return result
    except Exception as err:
        logger.error(f"Error during alert investigation for thread '{thread_id}': {err}", exc_info=True)
        # Record incomplete verdict if none was recorded
        try:
            existing = get_latest_verdict_for_thread(thread_id, db_path=db_path)
            if not existing:
                record_incomplete_verdict(
                    thread_id=thread_id,
                    alert=initial_state.get("alert", {}),
                    sigma_rule=initial_state.get("sigma_rule", {}),
                    end_reason=f"error: {str(err)}",
                    turns=initial_state.get("turns", 0),
                    db_path=db_path,
                )
        except Exception:
            pass
        raise
    finally:
        try:
            from record_run import auto_record_run
            auto_record_run(thread_id, results_db_path=db_path)
        except Exception:
            pass
        unregister_run(thread_id)
        lock.release()


def start_user_message_thread(
    thread_id: str,
    text: str,
    on_complete: Callable[[dict[str, Any]], None] | None = None,
    on_error: Callable[[Exception], None] | None = None,
    workflow_instance=None,
    db_path: Path | str = RESULTS_DB_PATH,
) -> bool:
    """
    Launch send_user_message in a background daemon thread.
    Returns True if launched, False if the thread is currently busy or has pending HITL.
    """
    # 1. Check pending HITL
    if has_pending_hitl(thread_id):
        return False

    # 2. Try to acquire lock non-blocking
    lock = get_thread_lock(thread_id)
    if not lock.acquire(blocking=False):
        return False

    # 3. Try to register run
    if not register_run(thread_id, kind="chat"):
        lock.release()
        return False

    def _worker():
        try:
            result = send_user_message(
                thread_id=thread_id,
                text=text,
                workflow_instance=workflow_instance,
            )
            if on_complete:
                try:
                    on_complete(result)
                except Exception:
                    pass
        except Exception as err:
            logger.error(f"Background chat execution failed for thread '{thread_id}': {err}", exc_info=True)
            # If thread has no recorded verdict, write an incomplete record
            try:
                latest = get_latest_verdict_for_thread(thread_id, db_path=db_path)
                if not latest:
                    record_incomplete_verdict(
                        thread_id=thread_id,
                        end_reason=f"error: {str(err)}",
                        db_path=db_path,
                    )
            except Exception:
                pass
            if on_error:
                try:
                    on_error(err)
                except Exception:
                    pass
        finally:
            try:
                from record_run import auto_record_run
                auto_record_run(thread_id, results_db_path=db_path)
            except Exception:
                pass
            unregister_run(thread_id)
            lock.release()

    t = threading.Thread(target=_worker, name=f"chat_{thread_id}", daemon=True)
    t.start()
    return True
