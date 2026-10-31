"""
detection/dispatch.py - Alert Deduplication & Dispatcher

This module implements:
1. JSON-backed on-disk alert caching (survives restarts, zero RAM drain).
2. Fingerprinting alerts by rule name + target program + command line.
3. Suppressing repeat alerts within ALERT_WINDOW (default: 300 seconds / 5 mins).
4. Storing dispatched alerts to tools/db/alerts.jsonl.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

# Ensure project root is accessible for config import
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import ALERT_WINDOW, ALERTS_PATH, CACHE_PATH


def compute_alert_fingerprint(alert: dict[str, Any]) -> str:
    """
    Generate a stable unique hash for an alert based on its rule, target image, and command line.
    Identical repeated attacks produce the exact same fingerprint.
    """
    rule_name = str(alert.get("rule_name", ""))
    event = alert.get("event", {})
    image = str(event.get("image") or "").lower()
    command_line = str(event.get("command_line") or "").lower()

    raw_key = f"{rule_name}|{image}|{command_line}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]


def load_alert_cache(cache_path: Path | str = CACHE_PATH) -> dict[str, float]:
    """Load the JSON-backed alert cache from disk. Returns empty dict if missing or invalid."""
    path = Path(cache_path)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return {str(k): float(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_alert_cache(
    cache: dict[str, float],
    cache_path: Path | str = CACHE_PATH,
    window_seconds: int = ALERT_WINDOW,
) -> None:
    """
    Prune expired entries and atomically save the cache dictionary to disk.
    Auto-pruning ensures the JSON file stays tiny and uses virtually zero disk space.
    """
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    now = time.time()
    # Auto-prune entries older than the alert window
    cleaned_cache = {
        fp: ts for fp, ts in cache.items() if (now - ts) < window_seconds
    }

    # Write atomically using a temporary file to avoid corruption
    temp_path = path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(cleaned_cache, f, indent=2)
    temp_path.replace(path)


def is_alert_cached(
    alert: dict[str, Any],
    window_seconds: int = ALERT_WINDOW,
    cache_path: Path | str = CACHE_PATH,
) -> bool:
    """Check if an alert was already seen within window_seconds."""
    fingerprint = compute_alert_fingerprint(alert)
    cache = load_alert_cache(cache_path)
    now = time.time()

    if fingerprint in cache:
        last_seen = cache[fingerprint]
        if (now - last_seen) < window_seconds:
            return True
    return False


def dispatch_alert(
    alert: dict[str, Any],
    window_seconds: int = ALERT_WINDOW,
    cache_path: Path | str = CACHE_PATH,
    alerts_path: Path | str = ALERTS_PATH,
) -> tuple[bool, str]:
    """
    Dispatch an alert with deduplication:
    - If the alert is already cached within ALERT_WINDOW, it is discarded (returns False).
    - If the alert is fresh, it is cached to disk and saved to alerts.jsonl (returns True).
    """
    fingerprint = compute_alert_fingerprint(alert)
    cache = load_alert_cache(cache_path)
    now = time.time()

    # 1. Check if cached within the active alert window
    if fingerprint in cache:
        last_seen = cache[fingerprint]
        if (now - last_seen) < window_seconds:
            return (
                False,
                f"Discarded: Duplicate alert within {window_seconds}s window (fingerprint: {fingerprint})",
            )

    # 2. Update cache with current timestamp and save on disk
    cache[fingerprint] = now
    save_alert_cache(cache, cache_path, window_seconds)

    # 3. Store the alert to alerts.jsonl on disk
    out_path = Path(alerts_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")

    return (
        True,
        f"Dispatched: Alert saved and dispatched (fingerprint: {fingerprint})",
    )


def get_dispatched_alerts(
    alerts_path: Path | str = ALERTS_PATH,
) -> list[dict[str, Any]]:
    """Retrieve all stored alerts from alerts.jsonl."""
    path = Path(alerts_path)
    if not path.exists():
        return []
    alerts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    pass
    return alerts


def clear_alert_cache(cache_path: Path | str = CACHE_PATH) -> None:
    """Helper to remove the alert cache file (used for testing or reset)."""
    path = Path(cache_path)
    if path.exists():
        try:
            path.unlink()
        except Exception:
            pass
