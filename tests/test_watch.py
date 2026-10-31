"""
tests/test_watch.py - Unit tests for detection/watch.py pipeline
"""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from detection.dispatch import clear_alert_cache
from detection.watch import pipeline


class TestWatchPipeline(unittest.TestCase):

    def setUp(self):
        clear_alert_cache()

    def test_pipeline_normal_event(self):
        event = {
            "EventID": 1,
            "ProcessId": 1234,
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe",
            "ParentImage": "C:\\Windows\\explorer.exe",
        }
        result = pipeline(event)
        self.assertEqual(result, 0)

    @patch("detection.watch.workflow.invoke")
    def test_pipeline_attack_event(self, mock_invoke):
        # Suspicious pcalua execution event
        attack_event = {
            "EventID": 1,
            "ProcessId": 4321,
            "Image": "C:\\Windows\\System32\\pcalua.exe",
            "CommandLine": "pcalua.exe -a calc.exe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        }
        result = pipeline(attack_event)
        self.assertEqual(result, 0)
        # Verify workflow was invoked with expected state keys
        self.assertTrue(mock_invoke.called)
        call_args = mock_invoke.call_args[0][0]
        self.assertIn("alert", call_args)
        self.assertIn("sigma_rule", call_args)
        self.assertEqual(call_args["plan"], [])
        self.assertEqual(call_args["turns"], 0)
        self.assertEqual(call_args["messages"], [])


if __name__ == "__main__":
    unittest.main()
