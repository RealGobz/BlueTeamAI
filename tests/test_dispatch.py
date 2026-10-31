"""
tests/test_dispatch.py - Unit tests for alert dispatch and on-disk JSON deduplication
"""

import os
from pathlib import Path
import tempfile
import time
import unittest

from detection.dispatch import (
    clear_alert_cache,
    compute_alert_fingerprint,
    dispatch_alert,
    get_dispatched_alerts,
    is_alert_cached,
    load_alert_cache,
)


class TestDispatch(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.temp_dir.name, "alert_cache.json")
        self.alerts_path = os.path.join(self.temp_dir.name, "alerts.jsonl")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _sample_alert(self, rule="Rule A", image="C:\\evil.exe", cmd="evil.exe -run"):
        return {
            "alert_id": "test-alert-1",
            "rule_name": rule,
            "severity": "high",
            "event": {
                "image": image,
                "command_line": cmd,
                "process_id": 1234,
            },
        }

    def test_compute_fingerprint_stability(self):
        alert1 = self._sample_alert()
        alert2 = self._sample_alert()
        alert3 = self._sample_alert(cmd="different.exe")

        fp1 = compute_alert_fingerprint(alert1)
        fp2 = compute_alert_fingerprint(alert2)
        fp3 = compute_alert_fingerprint(alert3)

        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)

    def test_dispatch_and_deduplicate(self):
        alert = self._sample_alert()

        # 1. First time alert is seen: should be dispatched
        dispatched, msg = dispatch_alert(
            alert,
            window_seconds=10,
            cache_path=self.cache_path,
            alerts_path=self.alerts_path,
        )
        self.assertTrue(dispatched)
        self.assertIn("Dispatched", msg)

        # Cache file should now exist on disk
        self.assertTrue(os.path.exists(self.cache_path))
        cache_data = load_alert_cache(self.cache_path)
        self.assertEqual(len(cache_data), 1)

        # Alerts log should contain 1 alert
        stored_alerts = get_dispatched_alerts(self.alerts_path)
        self.assertEqual(len(stored_alerts), 1)
        self.assertEqual(stored_alerts[0]["rule_name"], "Rule A")

        # 2. Second identical alert immediately after: should be DISCARDED
        dispatched2, msg2 = dispatch_alert(
            alert,
            window_seconds=10,
            cache_path=self.cache_path,
            alerts_path=self.alerts_path,
        )
        self.assertFalse(dispatched2)
        self.assertIn("Discarded", msg2)

        # No duplicate added to alerts.jsonl
        stored_alerts = get_dispatched_alerts(self.alerts_path)
        self.assertEqual(len(stored_alerts), 1)

    def test_different_alert_dispatches(self):
        alert1 = self._sample_alert(rule="Rule 1")
        alert2 = self._sample_alert(rule="Rule 2")

        d1, _ = dispatch_alert(alert1, cache_path=self.cache_path, alerts_path=self.alerts_path)
        d2, _ = dispatch_alert(alert2, cache_path=self.cache_path, alerts_path=self.alerts_path)

        self.assertTrue(d1)
        self.assertTrue(d2)
        self.assertEqual(len(get_dispatched_alerts(self.alerts_path)), 2)

    def test_alert_window_expiration(self):
        alert = self._sample_alert()

        # Dispatch with a very short 1-second window
        dispatch_alert(alert, window_seconds=1, cache_path=self.cache_path, alerts_path=self.alerts_path)

        # Wait for window to expire
        time.sleep(1.1)

        # Now it should NOT be cached anymore and should dispatch again
        self.assertFalse(is_alert_cached(alert, window_seconds=1, cache_path=self.cache_path))
        d, _ = dispatch_alert(alert, window_seconds=1, cache_path=self.cache_path, alerts_path=self.alerts_path)
        self.assertTrue(d)
        self.assertEqual(len(get_dispatched_alerts(self.alerts_path)), 2)


if __name__ == "__main__":
    unittest.main()
