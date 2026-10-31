"""
tests/test_utils.py - Unit and Integration Tests for utils.py
"""

import os
import unittest
from utils import (
    evaluate_event,
    format_alert,
    load_sigma_rule,
    match_event,
    parse_event_xml,
    read_evtx,
    scan_evtx_file,
)


class TestUtils(unittest.TestCase):

    def test_parse_event_xml(self):
        sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Sysmon"/>
                <EventID>1</EventID>
                <TimeCreated SystemTime="2026-10-26T12:00:00.0000000Z"/>
                <Computer>TEST-DESKTOP</Computer>
                <EventRecordID>42</EventRecordID>
            </System>
            <EventData>
                <Data Name="ProcessId">1024</Data>
                <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
                <Data Name="CommandLine">cmd.exe /c whoami</Data>
                <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
            </EventData>
        </Event>"""

        event = parse_event_xml(sample_xml)
        self.assertEqual(event["EventID"], 1)
        self.assertEqual(event["Computer"], "TEST-DESKTOP")
        self.assertEqual(event["RecordID"], 42)
        self.assertEqual(event["ProcessId"], 1024)
        self.assertEqual(event["Image"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(event["CommandLine"], "cmd.exe /c whoami")
        self.assertEqual(event["ParentImage"], "C:\\Windows\\explorer.exe")

    def test_match_event_single_selection(self):
        rule = {
            "title": "Test Pcalua",
            "detection": {
                "selection": {
                    "Image|endswith": "\\pcalua.exe",
                    "CommandLine|contains": " -a",
                },
                "condition": "selection",
            },
        }

        # Matching event
        matching_event = {
            "Image": "C:\\Windows\\System32\\pcalua.exe",
            "CommandLine": "pcalua.exe -a calc.exe",
        }
        matched, info = match_event(matching_event, rule)
        self.assertTrue(matched)
        self.assertIsNotNone(info)
        self.assertEqual(info["rule_title"], "Test Pcalua")

        # Non-matching event (different command line)
        non_matching_event = {
            "Image": "C:\\Windows\\System32\\pcalua.exe",
            "CommandLine": "pcalua.exe -help",
        }
        matched, info = match_event(non_matching_event, rule)
        self.assertFalse(matched)
        self.assertIsNone(info)

    def test_evaluate_event_pipeline(self):
        rule1 = {
            "id": "rule-01",
            "title": "Detect Mimikatz",
            "detection": {
                "selection": {
                    "CommandLine|contains": ["mimikatz", "sekurlsa::"],
                },
                "condition": "selection",
            },
        }
        rules = [rule1]

        event = {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -c sekurlsa::logonpasswords",
        }

        detected, matches = evaluate_event(event, rules)
        self.assertTrue(detected)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_title"], "Detect Mimikatz")

    def test_real_evtx_and_sigma_rule(self):
        """Integration test on the real downloaded sample and Sigma rule."""
        evtx_path = os.path.join(
            "detection", "test_data", "exec_sysmon_1_lolbin_pcalua.evtx"
        )
        rule_path = os.path.join(
            "detection", "rules", "proc_creation_win_lolbin_pcalua.yml"
        )

        if not os.path.exists(evtx_path) or not os.path.exists(rule_path):
            self.skipTest("Sample evtx or rule file not found on disk.")

        rule = load_sigma_rule(rule_path)
        events = read_evtx(evtx_path)
        self.assertGreater(len(events), 0)

        matches = scan_evtx_file(evtx_path, [rule])
        self.assertGreater(len(matches), 0)
        first_match = matches[0]
        self.assertEqual(first_match["rule_title"], "Use of Pcalua For Execution")
        self.assertIn("pcalua.exe", first_match["event"]["Image"].lower())

    def test_format_alert(self):
        match_info = {
            "rule_id": "test-id",
            "rule_title": "Suspicious PowerShell",
            "level": "high",
            "tags": ["attack.execution", "attack.t1059.001"],
            "matched_fields": {"CommandLine": "powershell.exe -enc"},
            "event": {
                "EventID": 1,
                "ProcessId": 1234,
                "ProcessGuid": "{7e67f797-5fc2-6adf-ba2d-000000002500}",
                "Image": "C:\\Windows\\System32\\powershell.exe",
                "CommandLine": "powershell.exe -enc AAAA",
                "User": "CORP\\Alice",
                "Computer": "WORKSTATION1",
                "ParentProcessId": 4321,
                "ParentProcessGuid": "{7e67f797-5ec6-6adf-872d-000000002500}",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "explorer.exe",
            },
        }

        alert = format_alert(match_info)
        self.assertTrue(alert["alert_id"].startswith("alert-"))
        self.assertEqual(alert["rule_id"], "test-id")
        self.assertEqual(alert["rule_name"], "Suspicious PowerShell")
        self.assertEqual(alert["severity"], "high")
        self.assertIn("attack.execution", alert["attack_tags"])
        self.assertEqual(alert["process_guid"], "{7e67f797-5fc2-6adf-ba2d-000000002500}")
        self.assertEqual(alert["parent_process_guid"], "{7e67f797-5ec6-6adf-872d-000000002500}")
        self.assertEqual(alert["event"]["process_id"], 1234)
        self.assertEqual(alert["event"]["process_guid"], "{7e67f797-5fc2-6adf-ba2d-000000002500}")
        self.assertEqual(alert["parent_process"]["parent_image"], "C:\\Windows\\explorer.exe")
        self.assertEqual(alert["parent_process"]["parent_process_id"], 4321)
        self.assertEqual(alert["parent_process"]["parent_process_guid"], "{7e67f797-5ec6-6adf-872d-000000002500}")


if __name__ == "__main__":
    unittest.main()
