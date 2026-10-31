"""
agent/memory.py - Persistent LangGraph Checkpointing & Chat History for BlueTeamingAI

Stores conversation checkpoints in tools/memory/ using LangGraph's built-in SqliteSaver.
Provides:
1. Thread ID generation for unique investigation sessions.
2. Checkpoint initialization and management in SQLite database.
3. Chat history retrieval formatted for UI consumption.
4. Thread listing, state inspection, and thread deletion.
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
from typing import Any
import uuid

from langchain_core.messages import BaseMessage
from langgraph.checkpoint.sqlite import SqliteSaver

from config import ROOT_DIR, MEMORY_DIR, MEMORY_DB_PATH


def get_memory_saver(db_path: Path | str = MEMORY_DB_PATH) -> SqliteSaver:
    """
    Initialize and return a LangGraph SqliteSaver checkpointer.
    Ensures the tools/memory directory exists and SQLite tables are initialized.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    saver = SqliteSaver(conn)
    saver.setup()
    return saver


def generate_thread_id(prefix: str = "thread_") -> str:
    """
    Generate a new random, unique thread ID for an alert investigation.
    """
    return f"{prefix}{uuid.uuid4().hex}"


def serialize_message(msg: Any) -> dict[str, Any]:
    """
    Convert a LangChain BaseMessage into a clean, UI-ready dictionary.
    """
    msg_type = getattr(msg, "type", type(msg).__name__.lower().replace("message", ""))
    role_map = {
        "human": "user",
        "user": "user",
        "ai": "assistant",
        "assistant": "assistant",
        "system": "system",
        "tool": "tool",
    }
    role = role_map.get(msg_type, msg_type)

    entry: dict[str, Any] = {
        "id": getattr(msg, "id", None),
        "type": msg_type,
        "role": role,
        "content": getattr(msg, "content", ""),
    }

    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls:
        entry["tool_calls"] = tool_calls

    tool_call_id = getattr(msg, "tool_call_id", None)
    if tool_call_id:
        entry["tool_call_id"] = tool_call_id

    name = getattr(msg, "name", None)
    if name:
        entry["name"] = name

    if hasattr(msg, "response_metadata") and msg.response_metadata:
        entry["metadata"] = msg.response_metadata

    return entry


def get_chat_history(
    thread_id: str,
    checkpointer: SqliteSaver | None = None,
    db_path: Path | str = MEMORY_DB_PATH,
    as_dicts: bool = True,
) -> list[dict[str, Any]] | list[BaseMessage]:
    """
    Retrieve the full chat history for a specific thread_id from the checkpointer.
    Returns serialized dictionaries (for UI) or raw BaseMessage instances.
    """
    should_close = False
    if checkpointer is None:
        saver = get_memory_saver(db_path)
        should_close = True
    else:
        saver = checkpointer

    try:
        config = {"configurable": {"thread_id": thread_id}}
        tuple_data = saver.get_tuple(config)
        if not tuple_data or not tuple_data.checkpoint:
            return []

        channel_values = tuple_data.checkpoint.get("channel_values", {})
        raw_messages = channel_values.get("messages", [])

        if not as_dicts:
            return raw_messages

        return [serialize_message(m) for m in raw_messages]
    finally:
        if should_close and hasattr(saver, "conn"):
            try:
                saver.conn.close()
            except Exception:
                pass


def get_thread_state(
    thread_id: str,
    checkpointer: SqliteSaver | None = None,
    db_path: Path | str = MEMORY_DB_PATH,
) -> dict[str, Any] | None:
    """
    Retrieve the latest state snapshot values for a specific thread_id.
    """
    should_close = False
    if checkpointer is None:
        saver = get_memory_saver(db_path)
        should_close = True
    else:
        saver = checkpointer

    try:
        config = {"configurable": {"thread_id": thread_id}}
        tuple_data = saver.get_tuple(config)
        if not tuple_data or not tuple_data.checkpoint:
            return None

        values = dict(tuple_data.checkpoint.get("channel_values", {}))
        values["thread_id"] = thread_id
        values["checkpoint_id"] = tuple_data.config.get("configurable", {}).get("checkpoint_id")
        return values
    finally:
        if should_close and hasattr(saver, "conn"):
            try:
                saver.conn.close()
            except Exception:
                pass


def list_chat_threads(
    checkpointer: SqliteSaver | None = None,
    db_path: Path | str = MEMORY_DB_PATH,
) -> list[dict[str, Any]]:
    """
    List all recorded investigation threads with metadata (useful for sidebar in UI).
    Returns thread summaries sorted by latest checkpoint.
    """
    should_close = False
    if checkpointer is None:
        saver = get_memory_saver(db_path)
        should_close = True
    else:
        saver = checkpointer

    try:
        threads_map: dict[str, dict[str, Any]] = {}

        for ckpt_tuple in saver.list(None):
            cfg = ckpt_tuple.config.get("configurable", {})
            t_id = cfg.get("thread_id")
            if not t_id or t_id in threads_map:
                continue

            c_values = ckpt_tuple.checkpoint.get("channel_values", {})
            alert_info = c_values.get("alert", {})
            rule_info = c_values.get("sigma_rule", {})
            msgs = c_values.get("messages", [])

            title = alert_info.get("rule_name") or rule_info.get("title") or "Unknown Alert"
            severity = alert_info.get("severity") or rule_info.get("level") or "unknown"

            threads_map[t_id] = {
                "thread_id": t_id,
                "alert_title": title,
                "severity": str(severity).upper(),
                "message_count": len(msgs),
                "turns": c_values.get("turns", 0),
                "checkpoint_id": cfg.get("checkpoint_id"),
            }

        return list(threads_map.values())
    finally:
        if should_close and hasattr(saver, "conn"):
            try:
                saver.conn.close()
            except Exception:
                pass



def delete_thread(
    thread_id: str,
    db_path: Path | str = MEMORY_DB_PATH,
) -> bool:
    """
    Delete a conversation thread and all its checkpoints from the memory DB.
    """
    path = Path(db_path)
    if not path.exists():
        return False

    try:
        conn = sqlite3.connect(str(path))
        with conn:
            conn.execute("DELETE FROM writes WHERE thread_id = ?", (thread_id,))
            conn.execute("DELETE FROM checkpoints WHERE thread_id = ?", (thread_id,))
        conn.close()
        return True
    except Exception:
        return False
