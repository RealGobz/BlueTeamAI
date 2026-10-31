from datetime import datetime, timezone
import os
import socket
import subprocess
import tempfile
import unittest

import psutil

import hashlib
import json
import sys
from unittest.mock import patch

from agent.tools.tools import (
    get_children,
    get_events_by_hash,
    get_events_for_process,
    get_events_in_window,
    get_file_info,
    get_file_signature,
    get_live_connections,
    get_process_tree,
    get_rule_context,
    get_tools,
    is_process_running,
    kill_process,
    lookup_hash,
    quarantine_file,
    ask_user,
    plan,
    exa_search,
)
from detection.record import record_events_batch
from utils import (
    VirusTotalRateLimiter,
    check_file_signature,
    check_process_running,
    check_protected_process,
    check_protected_file,
    classify_ip,
    fetch_events_by_hash,
    fetch_events_for_process,
    fetch_events_in_window,
    fetch_hash_reputation,
    fetch_live_connections,
    fetch_process_children,
    fetch_process_tree,
    fetch_rule_context,
    file_info,
    format_approval_screen,
    format_quarantine_approval_screen,
    is_in_alert_tree,
    log_audit_kill,
    terminate_process,
    quarantine_file_action,
    restore_quarantined_file,
    validate_ask_user_input,
    fetch_exa_search,
)


class TestProcessTools(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = os.path.join(self.temp_dir.name, "test_events.db")
        self.test_audit_path = os.path.join(self.temp_dir.name, "test_audit.jsonl")
        self.test_quarantine_dir = os.path.join(self.temp_dir.name, "quarantine")

        # Create sample events hierarchy, activity, and hashes
        self.events = [
            {
                "EventID": 1,
                "TimeCreated": "2026-10-27T10:00:00.000000Z",
                "ProcessId": 100,
                "ProcessGuid": "{guid-grandparent}",
                "ParentProcessGuid": "{guid-root}",
                "Image": "C:\\Windows\\explorer.exe",
                "CommandLine": "explorer.exe",
                "ParentImage": "userinit.exe",
                "User": "admin",
            },
            {
                "EventID": 1,
                "TimeCreated": "2026-10-27T10:05:00.000000Z",
                "ProcessId": 200,
                "ProcessGuid": "{guid-parent}",
                "ParentProcessGuid": "{guid-grandparent}",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "User": "admin",
            },
            {
                "EventID": 1,
                "TimeCreated": "2026-10-27T10:10:00.000000Z",
                "ProcessId": 300,
                "ProcessGuid": "{guid-child1}",
                "ParentProcessGuid": "{guid-parent}",
                "Image": "C:\\Windows\\System32\\calc.exe",
                "CommandLine": "calc.exe",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "Hashes": "SHA256=17F746D82695FA9B35493B41859D39D786D32B23A9D2E00F4011DEC7A02402AE,MD5=AD7B9C14083B52BC532FBA5948342B98",
                "User": "admin",
            },
            {
                "EventID": 1,
                "TimeCreated": "2026-10-27T10:15:00.000000Z",
                "ProcessId": 305,
                "ProcessGuid": "{guid-child-dup}",
                "ParentProcessGuid": "{guid-grandparent}",
                "Image": "C:\\Users\\AppData\\calc.exe",
                "CommandLine": "calc.exe",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Hashes": "SHA256=17F746D82695FA9B35493B41859D39D786D32B23A9D2E00F4011DEC7A02402AE",
                "User": "admin",
            },
            {
                "EventID": 3,
                "TimeCreated": "2026-10-27T10:11:00.000000Z",
                "ProcessId": 300,
                "ProcessGuid": "{guid-child1}",
                "Image": "C:\\Windows\\System32\\calc.exe",
                "DestinationIp": "192.168.1.50",
                "DestinationPort": 443,
            },
            {
                "EventID": 11,
                "TimeCreated": "2026-10-27T10:12:00.000000Z",
                "ProcessId": 300,
                "ProcessGuid": "{guid-child1}",
                "Image": "C:\\Windows\\System32\\calc.exe",
                "TargetFilename": "C:\\Users\\Temp\\payload.bin",
            },
            {
                "EventID": 22,
                "TimeCreated": "2026-10-27T10:13:00.000000Z",
                "ProcessId": 300,
                "ProcessGuid": "{guid-child1}",
                "Image": "C:\\Windows\\System32\\calc.exe",
                "QueryName": "malicious-c2.com",
            },
            {
                "EventID": 13,
                "TimeCreated": "2026-10-27T10:14:00.000000Z",
                "ProcessId": 300,
                "ProcessGuid": "{guid-child1}",
                "Image": "C:\\Windows\\System32\\calc.exe",
                "TargetObject": "HKLM\\Software\\Run",
            },
        ]
        record_events_batch(self.events, db_path=self.test_db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_fetch_process_tree_hierarchy(self):
        tree = fetch_process_tree("{guid-child1}", db_path=self.test_db_path)
        self.assertEqual(len(tree), 3)
        self.assertEqual(tree[0]["image"], "C:\\Windows\\System32\\calc.exe")
        self.assertEqual(tree[1]["image"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(tree[2]["image"], "C:\\Windows\\explorer.exe")

    def test_fetch_process_children(self):
        children = fetch_process_children("{guid-parent}", db_path=self.test_db_path, depth=1)
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0]["image"], "C:\\Windows\\System32\\calc.exe")

    def test_fetch_events_for_process_grouping(self):
        grouped = fetch_events_for_process("{guid-child1}", db_path=self.test_db_path)
        self.assertEqual(len(grouped["process"]), 1)
        self.assertEqual(len(grouped["network"]), 1)
        self.assertEqual(grouped["network"][0]["DestinationIp"], "192.168.1.50")
        self.assertEqual(len(grouped["file"]), 1)
        self.assertEqual(grouped["file"][0]["TargetFilename"], "C:\\Users\\Temp\\payload.bin")
        self.assertEqual(len(grouped["dns"]), 1)
        self.assertEqual(grouped["dns"][0]["QueryName"], "malicious-c2.com")
        self.assertEqual(len(grouped["registry"]), 1)
        self.assertEqual(grouped["registry"][0]["TargetObject"], "HKLM\\Software\\Run")

    def test_fetch_events_in_window(self):
        events = fetch_events_in_window(
            start="2026-10-27T10:08:00",
            end="2026-10-27T10:12:30",
            db_path=self.test_db_path,
        )
        self.assertEqual(len(events), 3)
        event_ids = [e["event_id"] for e in events]
        self.assertIn(1, event_ids)
        self.assertIn(3, event_ids)
        self.assertIn(11, event_ids)

    def test_fetch_events_in_window_with_event_id_filter(self):
        events = fetch_events_in_window(
            start="2026-10-27T10:00:00",
            end="2026-10-27T10:30:00",
            event_id=3,
            db_path=self.test_db_path,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], 3)

    def test_fetch_events_by_hash_invalid(self):
        res = fetch_events_by_hash("not-a-hash", db_path=self.test_db_path)
        self.assertIn("error", res)

    def test_fetch_events_by_hash_valid(self):
        sha = "17F746D82695FA9B35493B41859D39D786D32B23A9D2E00F4011DEC7A02402AE"
        res = fetch_events_by_hash(sha.lower(), db_path=self.test_db_path)
        self.assertEqual(res["sha256"], sha)
        self.assertEqual(res["total_runs"], 2)
        self.assertEqual(res["distinct_paths"], 2)
        self.assertIsNotNone(res["store_window"]["oldest_event"])
        self.assertIsNotNone(res["store_window"]["newest_event"])
        images = [p["image"] for p in res["paths"]]
        self.assertIn("C:\\Windows\\System32\\calc.exe", images)
        self.assertIn("C:\\Users\\AppData\\calc.exe", images)

    def test_fetch_events_by_hash_non_existent(self):
        sha = "0000000000000000000000000000000000000000000000000000000000000000"
        res = fetch_events_by_hash(sha, db_path=self.test_db_path)
        self.assertEqual(res["total_runs"], 0)
        self.assertEqual(res["distinct_paths"], 0)
        self.assertEqual(res["paths"], [])

    def test_fetch_rule_context_valid(self):
        rule_id = "0955e4e1-c281-4fb9-9ee1-5ee7b4b754d2"
        res = fetch_rule_context(rule_id)
        self.assertNotIn("error", res)
        self.assertEqual(res["rule_id"], rule_id)
        self.assertIn("Pcalua", res["title"])
        self.assertTrue(len(res["description"]) > 0)
        self.assertIsInstance(res["falsepositives"], list)
        self.assertEqual(res["level"], "medium")
        self.assertIsInstance(res["tags"], list)
        self.assertIn("attack.execution", res["tags"])
        self.assertIsInstance(res["references"], list)

    def test_fetch_rule_context_non_existent(self):
        res = fetch_rule_context("non-existent-rule-id")
        self.assertIn("error", res)
        self.assertIn("non-existent-rule-id", res["error"])

    def test_file_info_existing_system_file(self):
        path = "C:\\Windows\\System32\\pcalua.exe"
        res = file_info(path)
        self.assertTrue(res["exists"])
        self.assertEqual(res["path"], os.path.realpath(path))
        self.assertIn("sha256_now", res)
        self.assertFalse(res["in_risky_folder"])
        self.assertGreater(res["size_bytes"], 0)

    def test_file_info_hash_comparison(self):
        path = "C:\\Windows\\System32\\pcalua.exe"
        info = file_info(path)
        sha = info["sha256_now"]
        res_match = file_info(path, expected_sha256=sha)
        self.assertTrue(res_match["hash_matches_alert"])
        res_mismatch = file_info(path, expected_sha256="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        self.assertFalse(res_mismatch["hash_matches_alert"])

    def test_file_info_non_existent(self):
        res = file_info("C:\\Windows\\System32\\definitely_missing_file_xyz_123.exe")
        self.assertFalse(res["exists"])
        self.assertIn("File not found", res["note"])

    def test_file_info_network_path_rejected(self):
        res = file_info("\\\\someserver\\share\\file.exe")
        self.assertIn("error", res)
        self.assertIn("path rejected", res["error"])

    def test_file_info_risky_folder(self):
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "test_risky_file.exe")
        with open(temp_file, "w") as f:
            f.write("fake exe")
        try:
            res = file_info(temp_file)
            self.assertTrue(res["exists"])
            self.assertTrue(res["in_risky_folder"])
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_check_file_signature_windows_system_file(self):
        res = check_file_signature("C:\\Windows\\System32\\pcalua.exe")
        self.assertEqual(res["status"], "Valid")
        self.assertIsNotNone(res["signer"])
        self.assertIn("Microsoft", res["signer"])

    def test_check_file_signature_installed_program(self):
        import sys
        res = check_file_signature(sys.executable)
        self.assertEqual(res["status"], "Valid")
        self.assertIsNotNone(res["signer"])
        self.assertIn("Python", res["signer"])

    def test_check_file_signature_unsigned_script(self):
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "unsigned_script_test.ps1")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("Write-Output 'unsigned'")
        try:
            res = check_file_signature(temp_file)
            self.assertEqual(res["status"], "NotSigned")
            self.assertIsNone(res["signer"])
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_check_file_signature_non_existent(self):
        res = check_file_signature("C:\\Windows\\System32\\definitely_missing_file_xyz_123.exe")
        self.assertEqual(res["status"], "FileNotFound")
        self.assertIn("error", res)
        self.assertIn("File not found", res["error"])

    def test_check_file_signature_network_path_rejected(self):
        res = check_file_signature("\\\\someserver\\share\\x.exe")
        self.assertIn("error", res)
        self.assertIn("path rejected", res["error"])

    def test_check_file_signature_special_characters_filename(self):
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "test & ; ' special.ps1")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("Write-Output 'safe'")
        try:
            res = check_file_signature(temp_file)
            self.assertEqual(res["status"], "NotSigned")
            self.assertIsNone(res["signer"])
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_is_process_running_live_process_and_exit(self):
        # Start a real harmless process
        subproc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        try:
            pid = subproc.pid
            p = psutil.Process(pid)
            live_exe = p.exe()
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            guid = "{11223344-5566-7788-99aa-bbccddeeff00}"
            event1 = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": pid,
                "ProcessGuid": guid,
                "Image": live_exe,
                "CommandLine": "cmd.exe",
            }
            record_events_batch([event1], self.test_db_path)

            # 1. Test while running
            res = check_process_running(guid, db_path=self.test_db_path)
            self.assertTrue(res["running"])
            self.assertEqual(res["pid"], pid)
            self.assertEqual(res["image"], live_exe)

            # 2. Terminate the process
            subproc.terminate()
            subproc.wait(timeout=5)

            # 3. Test after exit
            res_exited = check_process_running(guid, db_path=self.test_db_path)
            self.assertFalse(res_exited["running"])
            self.assertIn("exited", res_exited["reason"].lower())
        finally:
            if subproc.poll() is None:
                subproc.kill()

    def test_is_process_running_pid_reuse_time_mismatch(self):
        pid = os.getpid()
        p = psutil.Process(pid)
        live_exe = p.exe()

        guid = "{22334455-6677-8899-aabb-ccddeeff0011}"
        event1 = {
            "EventID": 1,
            "TimeCreated": "2020-01-01 10:00:00.000",
            "UtcTime": "2020-01-01 10:00:00.000",
            "ProcessId": pid,
            "ProcessGuid": guid,
            "Image": live_exe,
            "CommandLine": "python.exe",
        }
        record_events_batch([event1], self.test_db_path)

        res = check_process_running(guid, db_path=self.test_db_path)
        self.assertFalse(res["running"])
        self.assertIn("reused", res["reason"].lower())

    def test_is_process_running_pid_reuse_image_mismatch(self):
        pid = os.getpid()
        p = psutil.Process(pid)
        live_ct = p.create_time()
        live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        guid = "{33445566-7788-99aa-bbcc-ddeeff001122}"
        event1 = {
            "EventID": 1,
            "TimeCreated": live_utc_str,
            "UtcTime": live_utc_str,
            "ProcessId": pid,
            "ProcessGuid": guid,
            "Image": "C:\\Windows\\System32\\fake_malware.exe",
            "CommandLine": "fake_malware.exe",
        }
        record_events_batch([event1], self.test_db_path)

        res = check_process_running(guid, db_path=self.test_db_path)
        self.assertFalse(res["running"])
        self.assertIn("different process", res["reason"].lower())

    def test_is_process_running_guid_not_in_store(self):
        guid = "{44556677-8899-aabb-ccdd-eeff00112233}"
        res = check_process_running(guid, db_path=self.test_db_path)
        self.assertEqual(res["running"], "unknown")
        self.assertIn("not found in event history", res["reason"])

    def test_is_process_running_malformed_guid(self):
        res1 = check_process_running("abc", db_path=self.test_db_path)
        self.assertEqual(res1["running"], "unknown")
        self.assertIn("Invalid GUID format", res1["reason"])

        res2 = check_process_running("'; DROP TABLE events;--", db_path=self.test_db_path)
        self.assertEqual(res2["running"], "unknown")
        self.assertIn("Invalid GUID format", res2["reason"])

    def test_is_process_running_with_event_5_exit_time(self):
        guid = "{55667788-99aa-bbcc-ddee-ff0011223344}"
        event1 = {
            "EventID": 1,
            "TimeCreated": "2026-10-27 10:00:00.000",
            "UtcTime": "2026-10-27 10:00:00.000",
            "ProcessId": 9999999,
            "ProcessGuid": guid,
            "Image": "C:\\Windows\\System32\\cmd.exe",
        }
        event5 = {
            "EventID": 5,
            "TimeCreated": "2026-10-27 10:00:02.500",
            "UtcTime": "2026-10-27 10:00:02.500",
            "ProcessId": 9999999,
            "ProcessGuid": guid,
            "Image": "C:\\Windows\\System32\\cmd.exe",
        }
        record_events_batch([event1, event5], self.test_db_path)

        res = check_process_running(guid, db_path=self.test_db_path)
        self.assertFalse(res["running"])
        self.assertEqual(res["exit_time"], "2026-10-27 10:00:02.500")

    def test_is_process_running_access_denied(self):
        from unittest.mock import patch
        pid = 1234
        guid = "{66778899-aabb-ccdd-eeff-001122334455}"
        event1 = {
            "EventID": 1,
            "TimeCreated": "2026-10-27 10:00:00.000",
            "UtcTime": "2026-10-27 10:00:00.000",
            "ProcessId": pid,
            "ProcessGuid": guid,
            "Image": "C:\\Windows\\System32\\lsass.exe",
        }
        record_events_batch([event1], self.test_db_path)

        with patch("utils.psutil.Process") as mock_proc:
            mock_proc.side_effect = psutil.AccessDenied()
            res = check_process_running(guid, db_path=self.test_db_path)
            self.assertEqual(res["running"], "unknown")
            self.assertIn("denied access", res["reason"])

    def test_classify_ip(self):
        self.assertIsNone(classify_ip(None))
        self.assertIsNone(classify_ip(""))
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("::1"), "loopback")
        self.assertEqual(classify_ip("192.168.1.1"), "private")
        self.assertEqual(classify_ip("10.0.0.5"), "private")
        self.assertEqual(classify_ip("172.16.0.1"), "private")
        self.assertEqual(classify_ip("fe80::1"), "private")
        self.assertEqual(classify_ip("8.8.8.8"), "public")
        self.assertEqual(classify_ip("93.184.216.34"), "public")
        self.assertEqual(classify_ip("2001:4860:4860::8888"), "public")
        self.assertEqual(classify_ip("not-an-ip"), "unknown")

    def test_fetch_live_connections_listener(self):
        # Create a real listening socket in current process
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        listen_port = server_sock.getsockname()[1]

        try:
            pid = os.getpid()
            p = psutil.Process(pid)
            live_exe = p.exe()
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            guid = "{778899aa-bbcc-ddee-ff00-112233445566}"
            event1 = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": pid,
                "ProcessGuid": guid,
                "Image": live_exe,
                "CommandLine": "python.exe",
            }
            record_events_batch([event1], self.test_db_path)

            res = fetch_live_connections(guid, db_path=self.test_db_path)
            self.assertTrue(res["process_running"])
            self.assertGreaterEqual(res["total_connections"], 1)

            # Check that our listener is reported
            matching = [
                c for c in res["connections"]
                if c["protocol"] == "tcp" and c["local_port"] == listen_port
            ]
            self.assertTrue(len(matching) >= 1)
            self.assertEqual(matching[0]["state"], "LISTEN")
            self.assertEqual(matching[0]["local_address"], "127.0.0.1")
            self.assertIsNone(matching[0]["remote_address"])
            self.assertIsNone(matching[0]["remote_scope"])
        finally:
            server_sock.close()

    def test_fetch_live_connections_established_loopback(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        listen_port = server_sock.getsockname()[1]

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", listen_port))
        conn_sock, _ = server_sock.accept()

        try:
            pid = os.getpid()
            p = psutil.Process(pid)
            live_exe = p.exe()
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            guid = "{8899aabb-ccdd-eeff-0011-223344556677}"
            event1 = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": pid,
                "ProcessGuid": guid,
                "Image": live_exe,
                "CommandLine": "python.exe",
            }
            record_events_batch([event1], self.test_db_path)

            res = fetch_live_connections(guid, db_path=self.test_db_path)
            self.assertTrue(res["process_running"])

            established = [
                c for c in res["connections"]
                if c["remote_port"] == listen_port and c["remote_address"] == "127.0.0.1"
            ]
            self.assertTrue(len(established) >= 1)
            self.assertEqual(established[0]["remote_scope"], "loopback")
        finally:
            conn_sock.close()
            client_sock.close()
            server_sock.close()

    def test_fetch_live_connections_exited_process(self):
        guid = "{99aabbcc-ddee-ff00-1122-334455667788}"
        event1 = {
            "EventID": 1,
            "TimeCreated": "2026-10-27 10:00:00.000",
            "UtcTime": "2026-10-27 10:00:00.000",
            "ProcessId": 9999999,
            "ProcessGuid": guid,
            "Image": "C:\\Windows\\System32\\cmd.exe",
        }
        record_events_batch([event1], self.test_db_path)

        res = fetch_live_connections(guid, db_path=self.test_db_path)
        self.assertFalse(res["process_running"])
        self.assertEqual(res["connections"], [])
        self.assertEqual(res["total_connections"], 0)
        self.assertIn("exited", res["reason"].lower())
        self.assertIn("empty list does not mean", res["reason"].lower())

    def test_fetch_live_connections_pid_reuse(self):
        pid = os.getpid()
        p = psutil.Process(pid)
        live_exe = p.exe()

        guid = "{aabbccdd-eeff-0011-2233-445566778899}"
        event1 = {
            "EventID": 1,
            "TimeCreated": "2020-01-01 10:00:00.000",
            "UtcTime": "2020-01-01 10:00:00.000",
            "ProcessId": pid,
            "ProcessGuid": guid,
            "Image": live_exe,
            "CommandLine": "python.exe",
        }
        record_events_batch([event1], self.test_db_path)

        res = fetch_live_connections(guid, db_path=self.test_db_path)
        self.assertFalse(res["process_running"])
        self.assertEqual(res["connections"], [])
        self.assertIn("reused", res["reason"].lower())

    def test_fetch_live_connections_invalid_and_unknown_guid(self):
        res1 = fetch_live_connections("bad-guid", db_path=self.test_db_path)
        self.assertEqual(res1["process_running"], "unknown")
        self.assertIn("Invalid GUID format", res1["reason"])

        res2 = fetch_live_connections("{00000000-1111-2222-3333-444444444444}", db_path=self.test_db_path)
        self.assertEqual(res2["process_running"], "unknown")
        self.assertIn("not found in event history", res2["reason"])

    def test_fetch_live_connections_access_denied(self):
        from unittest.mock import patch, MagicMock
        pid = os.getpid()
        p = psutil.Process(pid)
        live_exe = p.exe()
        live_ct = p.create_time()
        live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        guid = "{bbccddee-ff00-1122-3344-5566778899aa}"
        event1 = {
            "EventID": 1,
            "TimeCreated": live_utc_str,
            "UtcTime": live_utc_str,
            "ProcessId": pid,
            "ProcessGuid": guid,
            "Image": live_exe,
            "CommandLine": "python.exe",
        }
        record_events_batch([event1], self.test_db_path)

        with patch("utils.resolve_live_process") as mock_resolve:
            mock_proc = MagicMock()
            mock_proc.net_connections.side_effect = psutil.AccessDenied()
            mock_resolve.return_value = {
                "status": "running",
                "guid": guid,
                "pid": pid,
                "image": live_exe,
                "proc": mock_proc,
            }
            res = fetch_live_connections(guid, db_path=self.test_db_path)
            self.assertEqual(res["process_running"], "unknown")
            self.assertIn("denied access", res["reason"].lower())

    def test_fetch_live_connections_capping(self):
        from unittest.mock import patch, MagicMock
        pid = os.getpid()
        p = psutil.Process(pid)
        live_exe = p.exe()

        guid = "{ccddeeff-0011-2233-4455-66778899aabb}"
        # Create 60 mock connections
        mock_conns = []
        for i in range(60):
            conn = MagicMock()
            conn.type = socket.SOCK_STREAM
            conn.laddr = ("127.0.0.1", 10000 + i)
            conn.raddr = ("93.184.216.34", 80)
            conn.status = "ESTABLISHED"
            mock_conns.append(conn)

        with patch("utils.resolve_live_process") as mock_resolve:
            mock_proc = MagicMock()
            mock_proc.net_connections.return_value = mock_conns
            mock_resolve.return_value = {
                "status": "running",
                "guid": guid,
                "pid": pid,
                "image": live_exe,
                "proc": mock_proc,
            }
            res = fetch_live_connections(guid, db_path=self.test_db_path, max_connections=50)
            self.assertTrue(res["process_running"])
            self.assertEqual(res["total_connections"], 60)
            self.assertEqual(res["returned_connections"], 50)
            self.assertEqual(len(res["connections"]), 50)
            self.assertIn("10 more connection(s) omitted", res["omitted_connections"])

    def test_lookup_hash_invalid_input(self):
        res = fetch_hash_reputation("", db_path=self.test_db_path)
        self.assertEqual(res["status"], "invalid_input")

        res = fetch_hash_reputation("12345", db_path=self.test_db_path)
        self.assertEqual(res["status"], "invalid_input")

        non_hex = "Z" * 64
        res = fetch_hash_reputation(non_hex, db_path=self.test_db_path)
        self.assertEqual(res["status"], "invalid_input")

    def test_lookup_hash_missing_api_key(self):
        sha = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        res = fetch_hash_reputation(sha, api_key="", db_path=self.test_db_path)
        self.assertEqual(res["status"], "unavailable")
        self.assertIn("No VirusTotal API key configured", res["reason"])

    def test_lookup_hash_found_and_cached(self):
        from unittest.mock import patch, MagicMock
        sha = "AA" * 32
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 35,
                        "suspicious": 2,
                        "harmless": 0,
                        "undetected": 33,
                    },
                    "first_submission_date": 1600000000,
                    "last_analysis_date": 1650000000,
                }
            }
        }

        limiter = VirusTotalRateLimiter(min_interval_seconds=0.0)
        with patch("utils.requests.get", return_value=mock_resp) as mock_get:
            res1 = fetch_hash_reputation(
                sha, api_key="test_key", db_path=self.test_db_path, rate_limiter=limiter
            )
            self.assertEqual(res1["status"], "found")
            self.assertEqual(res1["malicious"], 35)
            self.assertEqual(res1["suspicious"], 2)
            self.assertEqual(res1["undetected"], 33)
            self.assertEqual(res1["total_engines"], 70)
            self.assertFalse(res1["from_cache"])
            self.assertEqual(mock_get.call_count, 1)

            # Second call should be served from SQLite cache without network call
            res2 = fetch_hash_reputation(
                sha, api_key="test_key", db_path=self.test_db_path, rate_limiter=limiter
            )
            self.assertEqual(res2["status"], "found")
            self.assertEqual(res2["malicious"], 35)
            self.assertTrue(res2["from_cache"])
            self.assertEqual(mock_get.call_count, 1)

    def test_lookup_hash_not_found_and_cached(self):
        from unittest.mock import patch, MagicMock
        sha = "BB" * 32
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        limiter = VirusTotalRateLimiter(min_interval_seconds=0.0)
        with patch("utils.requests.get", return_value=mock_resp) as mock_get:
            res1 = fetch_hash_reputation(
                sha, api_key="test_key", db_path=self.test_db_path, rate_limiter=limiter
            )
            self.assertEqual(res1["status"], "not_found")
            self.assertFalse(res1["from_cache"])
            self.assertEqual(mock_get.call_count, 1)

            # Second call from cache
            res2 = fetch_hash_reputation(
                sha, api_key="test_key", db_path=self.test_db_path, rate_limiter=limiter
            )
            self.assertEqual(res2["status"], "not_found")
            self.assertTrue(res2["from_cache"])
            self.assertEqual(mock_get.call_count, 1)

    def test_lookup_hash_rate_limited(self):
        from unittest.mock import patch, MagicMock
        sha = "CC" * 32

        # 1. HTTP 429 from VirusTotal
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        limiter = VirusTotalRateLimiter(min_interval_seconds=0.0)
        with patch("utils.requests.get", return_value=mock_resp):
            res = fetch_hash_reputation(
                sha, api_key="test_key", db_path=self.test_db_path, rate_limiter=limiter
            )
            self.assertEqual(res["status"], "rate_limited")
            self.assertIn("Do not retry", res["reason"])

        # 2. Local daily quota exceeded
        exhausted_limiter = VirusTotalRateLimiter(min_interval_seconds=0.0, daily_limit=5)
        exhausted_limiter.daily_count = 5
        res_limit = fetch_hash_reputation(
            sha, api_key="test_key", db_path=self.test_db_path, rate_limiter=exhausted_limiter
        )
        self.assertEqual(res_limit["status"], "rate_limited")
        self.assertIn("Daily VirusTotal query quota", res_limit["reason"])

    def test_lookup_hash_unavailable_errors(self):
        from unittest.mock import patch, MagicMock
        import requests
        sha = "DD" * 32
        limiter = VirusTotalRateLimiter(min_interval_seconds=0.0)

        mock_401 = MagicMock(status_code=401)
        with patch("utils.requests.get", return_value=mock_401):
            res = fetch_hash_reputation(
                sha, api_key="bad_key", db_path=self.test_db_path, rate_limiter=limiter
            )
            self.assertEqual(res["status"], "unavailable")
            self.assertIn("401", res["reason"])

        with patch("utils.requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            res = fetch_hash_reputation(
                sha, api_key="test_key", db_path=self.test_db_path, rate_limiter=limiter
            )
            self.assertEqual(res["status"], "unavailable")
            self.assertIn("timed out", res["reason"].lower())

    def test_exa_search_invalid_input(self):
        res1 = fetch_exa_search("", api_key="test_key", db_path=self.test_db_path)
        self.assertEqual(res1["status"], "invalid_input")
        self.assertIn("required", res1["reason"])

        res2 = fetch_exa_search("a" * 501, api_key="test_key", db_path=self.test_db_path)
        self.assertEqual(res2["status"], "invalid_input")
        self.assertIn("exceeds 500 characters", res2["reason"])

    def test_exa_search_missing_api_key(self):
        with patch("utils.EXAAI_SEARCH_API_KEY", ""):
            res = fetch_exa_search("certutil lolbin", api_key="", db_path=self.test_db_path)
            self.assertEqual(res["status"], "unavailable")
            self.assertIn("No Exa AI API key", res["reason"])

    def test_exa_search_success_and_cache(self):
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": [
                {
                    "title": "Certutil | LOLBAS",
                    "url": "https://lolbas-project.github.io/lolbas/Binaries/Certutil/",
                    "publishedDate": "2024-01-01T00:00:00Z",
                    "text": "Certutil is a Windows LOLBin used for downloading files.",
                },
                {
                    "title": "Certutil Abuse Guide",
                    "url": "https://example.com/certutil",
                    "publishedDate": "2024-02-01T00:00:00Z",
                    "text": "Living-off-the-land techniques using certutil -urlcache.",
                },
            ]
        }

        with patch("utils.requests.post", return_value=mock_resp) as mock_post:
            res1 = fetch_exa_search("certutil lolbin", api_key="valid_key", db_path=self.test_db_path)
            self.assertEqual(res1["status"], "success")
            self.assertEqual(res1["total_results"], 2)
            self.assertEqual(len(res1["results"]), 2)
            self.assertEqual(res1["results"][0]["title"], "Certutil | LOLBAS")
            self.assertFalse(res1.get("from_cache", False))
            self.assertEqual(mock_post.call_count, 1)

            # Second call should be served from SQLite cache
            res2 = fetch_exa_search("certutil lolbin", api_key="valid_key", db_path=self.test_db_path)
            self.assertEqual(res2["status"], "success")
            self.assertTrue(res2.get("from_cache", False))
            self.assertEqual(mock_post.call_count, 1)

    def test_exa_search_not_found_and_cached(self):
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": []}

        with patch("utils.requests.post", return_value=mock_resp) as mock_post:
            res1 = fetch_exa_search("completely_unknown_term_xyz_123", api_key="valid_key", db_path=self.test_db_path)
            self.assertEqual(res1["status"], "not_found")
            self.assertEqual(res1["results"], [])
            self.assertEqual(mock_post.call_count, 1)

            # Second call should be from cache
            res2 = fetch_exa_search("completely_unknown_term_xyz_123", api_key="valid_key", db_path=self.test_db_path)
            self.assertEqual(res2["status"], "not_found")
            self.assertTrue(res2.get("from_cache", False))
            self.assertEqual(mock_post.call_count, 1)

    def test_exa_search_rate_limited(self):
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock(status_code=429)
        with patch("utils.requests.post", return_value=mock_resp):
            res = fetch_exa_search("test query", api_key="valid_key", db_path=self.test_db_path)
            self.assertEqual(res["status"], "rate_limited")
            self.assertIn("rate limit", res["reason"].lower())

    def test_exa_search_unavailable_and_timeout(self):
        from unittest.mock import patch, MagicMock
        import requests
        mock_401 = MagicMock(status_code=401)
        with patch("utils.requests.post", return_value=mock_401):
            res = fetch_exa_search("test query", api_key="bad_key", db_path=self.test_db_path)
            self.assertEqual(res["status"], "unavailable")
            self.assertIn("authentication failed", res["reason"].lower())

        with patch("utils.requests.post", side_effect=requests.exceptions.Timeout("timed out")):
            res = fetch_exa_search("test query", api_key="test_key", db_path=self.test_db_path)
            self.assertEqual(res["status"], "unavailable")
            self.assertIn("timed out", res["reason"].lower())

    def test_kill_process_dry_run_on_notepad(self):
        # 1. Dry-run on Notepad: start Notepad, get its GUID, propose the kill. Expect dry_run, and Notepad still open.
        proc = subprocess.Popen(["notepad.exe"])
        try:
            guid = "{11111111-2222-3333-4444-555555555555}"
            p = psutil.Process(proc.pid)
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            live_exe = p.exe()

            event = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": proc.pid,
                "ProcessGuid": guid,
                "Image": live_exe,
                "CommandLine": "notepad.exe",
                "User": "TESTUSER",
            }
            record_events_batch([event], self.test_db_path)

            res = terminate_process(
                guid=guid,
                reason="Testing dry-run on Notepad",
                alert_guid=guid,
                approved=True,
                dry_run=True,
                db_path=self.test_db_path,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "dry_run")
            self.assertIn("DRY RUN active", res["reason"])
            # Notepad should still be open
            self.assertIsNone(proc.poll())
            self.assertTrue(os.path.exists(self.test_audit_path))
            with open(self.test_audit_path, "r", encoding="utf-8") as f:
                logs = [json.loads(line) for line in f]
            self.assertEqual(logs[-1]["status"], "dry_run")
            self.assertTrue(logs[-1]["dry_run"])
        finally:
            proc.kill()
            proc.wait()

    def test_kill_process_reject(self):
        # 2. Reject: run it with dry-run off and reject. Expect rejected_by_user, and Notepad still open.
        proc = subprocess.Popen(["notepad.exe"])
        try:
            guid = "{22222222-3333-4444-5555-666666666666}"
            p = psutil.Process(proc.pid)
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            live_exe = p.exe()

            event = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": proc.pid,
                "ProcessGuid": guid,
                "Image": live_exe,
                "CommandLine": "notepad.exe",
            }
            record_events_batch([event], self.test_db_path)

            res = terminate_process(
                guid=guid,
                reason="Testing rejection",
                alert_guid=guid,
                approved=False,
                dry_run=False,
                db_path=self.test_db_path,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "rejected_by_user")
            self.assertIn("rejected", res["reason"].lower())
            # Notepad should still be open
            self.assertIsNone(proc.poll())
            with open(self.test_audit_path, "r", encoding="utf-8") as f:
                logs = [json.loads(line) for line in f]
            self.assertEqual(logs[-1]["status"], "rejected_by_user")
            self.assertFalse(logs[-1]["approved"])
        finally:
            proc.kill()
            proc.wait()

    def test_kill_process_approved_real_kill(self):
        # 3. Approve a real kill of Notepad: expect executed, Notepad gone, and an audit entry.
        proc = subprocess.Popen(["notepad.exe"])
        guid = "{33333333-4444-5555-6666-777777777777}"
        p = psutil.Process(proc.pid)
        live_ct = p.create_time()
        live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        live_exe = p.exe()

        event = {
            "EventID": 1,
            "TimeCreated": live_utc_str,
            "UtcTime": live_utc_str,
            "ProcessId": proc.pid,
            "ProcessGuid": guid,
            "Image": live_exe,
            "CommandLine": "notepad.exe",
        }
        record_events_batch([event], self.test_db_path)

        res = terminate_process(
            guid=guid,
            reason="Confirmed malicious execution",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "executed")
        self.assertIn("terminated and confirmed gone", res["reason"])
        # Notepad should be dead
        proc.wait(timeout=5)
        self.assertIsNotNone(proc.poll())

        with open(self.test_audit_path, "r", encoding="utf-8") as f:
            logs = [json.loads(line) for line in f]
        self.assertEqual(logs[-1]["status"], "executed")
        self.assertEqual(logs[-1]["target_pid"], proc.pid)

    def test_kill_process_already_exited(self):
        # 4. Already exited: use exited PID. Expect already_exited.
        guid = "{44444444-5555-6666-7777-888888888888}"
        event = {
            "EventID": 1,
            "TimeCreated": "2026-10-27 10:00:00.000",
            "UtcTime": "2026-10-27 10:00:00.000",
            "ProcessId": 999998,
            "ProcessGuid": guid,
            "Image": "C:\\Windows\\System32\\calc.exe",
        }
        record_events_batch([event], self.test_db_path)

        res = terminate_process(
            guid=guid,
            reason="Test already exited",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "already_exited")

    def test_kill_process_approve_after_it_exited(self):
        # 5. Approve after it exited: propose the kill of Notepad, close it yourself, then approve.
        proc = subprocess.Popen(["notepad.exe"])
        guid = "{55555555-6666-7777-8888-999999999999}"
        p = psutil.Process(proc.pid)
        live_ct = p.create_time()
        live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        live_exe = p.exe()

        event = {
            "EventID": 1,
            "TimeCreated": live_utc_str,
            "UtcTime": live_utc_str,
            "ProcessId": proc.pid,
            "ProcessGuid": guid,
            "Image": live_exe,
        }
        record_events_batch([event], self.test_db_path)

        # Close Notepad before approval / execution
        proc.kill()
        proc.wait()

        res = terminate_process(
            guid=guid,
            reason="Approve after exited",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "already_exited")

    def test_kill_process_not_in_alert_tree(self):
        # 6. Not in the alert's tree: propose a GUID that isn't related to the alert.
        proc = subprocess.Popen(["notepad.exe"])
        try:
            target_guid = "{66666666-7777-8888-9999-aaaaaaaaaaaa}"
            alert_guid = "{99999999-0000-1111-2222-333333333333}"
            p = psutil.Process(proc.pid)
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            live_exe = p.exe()

            # Target process has an unrelated parent
            target_event = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": proc.pid,
                "ProcessGuid": target_guid,
                "ParentProcessGuid": "{unrelated-parent-guid}",
                "Image": live_exe,
            }
            record_events_batch([target_event], self.test_db_path)

            res = terminate_process(
                guid=target_guid,
                reason="Proposing unrelated process",
                alert_guid=alert_guid,
                approved=True,
                dry_run=False,
                db_path=self.test_db_path,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "not_allowed_target")
            self.assertIn("not in the alert's process tree", res["reason"])
            self.assertIsNone(proc.poll())
        finally:
            proc.kill()
            proc.wait()

    def test_kill_process_pid_reuse(self):
        # 7. PID reuse: start time mismatch -> not_same_process
        proc = subprocess.Popen(["notepad.exe"])
        try:
            guid = "{77777777-8888-9999-aaaa-bbbbbbbbbbbb}"
            event = {
                "EventID": 1,
                "TimeCreated": "2020-01-01 00:00:00.000",
                "UtcTime": "2020-01-01 00:00:00.000",
                "ProcessId": proc.pid,
                "ProcessGuid": guid,
                "Image": "C:\\Windows\\notepad.exe",
            }
            record_events_batch([event], self.test_db_path)

            res = terminate_process(
                guid=guid,
                reason="PID reuse test",
                alert_guid=guid,
                approved=True,
                dry_run=True,
                db_path=self.test_db_path,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "not_same_process")
        finally:
            proc.kill()
            proc.wait()

    def test_kill_process_protected_processes(self):
        # 8. Protected processes: lsass.exe and csrss.exe -> blocked_protected
        for idx, name in enumerate(("lsass.exe", "csrss.exe"), start=1):
            guid = f"{{88888888-9999-aaaa-bbbb-00000000000{idx}}}"
            event = {
                "EventID": 1,
                "TimeCreated": "2026-10-27 10:00:00.000",
                "UtcTime": "2026-10-27 10:00:00.000",
                "ProcessId": 500,
                "ProcessGuid": guid,
                "Image": f"C:\\Windows\\System32\\{name}",
            }
            record_events_batch([event], self.test_db_path)

            res = terminate_process(
                guid=guid,
                reason=f"Attempting to kill {name}",
                alert_guid=guid,
                approved=True,
                dry_run=True,
                db_path=self.test_db_path,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "blocked_protected")
            self.assertIn("Protected", res["reason"])

    def test_kill_process_fake_protected_name_allowed(self):
        # 9. Fake protected name: lsass.exe running from Temp folder
        is_prot, is_masq, reason = check_protected_process(
            pid=2000,
            image_path=r"C:\Users\Alice\AppData\Local\Temp\lsass.exe",
        )
        self.assertFalse(is_prot)
        self.assertTrue(is_masq)
        self.assertIn("masquerading", reason.lower())

        # Test approval screen includes warning
        guid = "{99999999-aaaa-bbbb-cccc-dddddddddddd}"
        event = {
            "EventID": 1,
            "TimeCreated": "2026-10-27 10:00:00.000",
            "UtcTime": "2026-10-27 10:00:00.000",
            "ProcessId": 2000,
            "ProcessGuid": guid,
            "Image": r"C:\Users\Alice\AppData\Local\Temp\lsass.exe",
            "CommandLine": r"C:\Users\Alice\AppData\Local\Temp\lsass.exe --mimikatz",
        }
        record_events_batch([event], self.test_db_path)
        screen = format_approval_screen(guid=guid, reason="Masquerading malware", db_path=self.test_db_path)
        self.assertIn("MASQUERADING WARNING", screen)

    def test_kill_process_own_tool_blocked(self):
        # 10. Your own tool: propose PID of Python process
        pid = os.getpid()
        guid = "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"
        event = {
            "EventID": 1,
            "TimeCreated": "2026-10-27 10:00:00.000",
            "UtcTime": "2026-10-27 10:00:00.000",
            "ProcessId": pid,
            "ProcessGuid": guid,
            "Image": sys.executable,
        }
        record_events_batch([event], self.test_db_path)

        res = terminate_process(
            guid=guid,
            reason="Propose own python process",
            alert_guid=guid,
            approved=True,
            dry_run=True,
            db_path=self.test_db_path,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "blocked_protected")
        self.assertIn("core system or agent/tool", res["reason"])

    def test_kill_process_access_denied(self):
        # 11. Access denied: Windows refuses
        guid = "{bbbbbbbb-cccc-dddd-eeee-ffffffffffff}"
        event = {
            "EventID": 1,
            "TimeCreated": "2026-10-27 10:00:00.000",
            "UtcTime": "2026-10-27 10:00:00.000",
            "ProcessId": 1234,
            "ProcessGuid": guid,
            "Image": "C:\\Program Files\\App\\app.exe",
        }
        record_events_batch([event], self.test_db_path)

        with patch("utils.psutil.Process") as mock_proc:
            mock_proc.side_effect = psutil.AccessDenied()
            res = terminate_process(
                guid=guid,
                reason="Access denied test",
                alert_guid=guid,
                approved=True,
                dry_run=False,
                db_path=self.test_db_path,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "access_denied")

    def test_kill_process_approval_cant_be_skipped(self):
        # 12. Approval cannot be skipped: call tool directly with default approved=False
        proc = subprocess.Popen(["notepad.exe"])
        try:
            guid = "{cccccccc-dddd-eeee-ffff-000000000000}"
            p = psutil.Process(proc.pid)
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            live_exe = p.exe()

            event = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": proc.pid,
                "ProcessGuid": guid,
                "Image": live_exe,
            }
            record_events_batch([event], self.test_db_path)

            # Call kill_process tool directly without approval
            res = kill_process.invoke({
                "guid": guid,
                "reason": "Agent calls tool directly without approval",
                "alert_guid": guid,
                "db_path": self.test_db_path,
                "audit_path": self.test_audit_path,
            })
            self.assertEqual(res["status"], "rejected_by_user")
            self.assertIsNone(proc.poll())
        finally:
            proc.kill()
            proc.wait()

    def test_kill_process_timeout_or_no_answer(self):
        # 13. Timeout / no answer counts as rejection
        proc = subprocess.Popen(["notepad.exe"])
        try:
            guid = "{dddddddd-eeee-ffff-0000-222222222222}"
            p = psutil.Process(proc.pid)
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            live_exe = p.exe()

            event = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": proc.pid,
                "ProcessGuid": guid,
                "Image": live_exe,
            }
            record_events_batch([event], self.test_db_path)

            res = terminate_process(
                guid=guid,
                reason="Timed out waiting for user response",
                alert_guid=guid,
                approved=False,
                dry_run=False,
                db_path=self.test_db_path,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "rejected_by_user")
            self.assertIsNone(proc.poll())
        finally:
            proc.kill()
            proc.wait()

    def test_kill_process_malformed_guid(self):
        # 14. Malformed GUID: 'abc', '; DROP TABLE x;--'
        for bad_guid in ("abc", "'; DROP TABLE events;--", "", "   "):
            res = terminate_process(
                guid=bad_guid,
                reason="Malformed guid test",
                alert_guid="{00000000-0000-0000-0000-000000000000}",
                approved=True,
                db_path=self.test_db_path,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "invalid_input")

    def test_kill_process_is_in_alert_tree_hierarchy(self):
        # Test tree containment with root -> child -> grandchild
        root_guid = "{root-guid-0001}"
        child_guid = "{child-guid-0002}"
        grandchild_guid = "{grandchild-guid-0003}"
        unrelated_guid = "{unrelated-guid-0004}"

        events = [
            {
                "EventID": 1,
                "ProcessGuid": root_guid,
                "ParentProcessGuid": "{parent-of-root}",
                "ProcessId": 1001,
                "Image": "cmd.exe",
            },
            {
                "EventID": 1,
                "ProcessGuid": child_guid,
                "ParentProcessGuid": root_guid,
                "ProcessId": 1002,
                "Image": "powershell.exe",
            },
            {
                "EventID": 1,
                "ProcessGuid": grandchild_guid,
                "ParentProcessGuid": child_guid,
                "ProcessId": 1003,
                "Image": "whoami.exe",
            },
            {
                "EventID": 1,
                "ProcessGuid": unrelated_guid,
                "ParentProcessGuid": "{some-other-parent}",
                "ProcessId": 1004,
                "Image": "calc.exe",
            },
        ]
        record_events_batch(events, self.test_db_path)

        # Root itself is in tree
        self.assertTrue(is_in_alert_tree(root_guid, root_guid, db_path=self.test_db_path))
        # Child is in tree
        self.assertTrue(is_in_alert_tree(child_guid, root_guid, db_path=self.test_db_path))
        # Grandchild is in tree
        self.assertTrue(is_in_alert_tree(grandchild_guid, root_guid, db_path=self.test_db_path))
        # Unrelated is NOT in tree
        self.assertFalse(is_in_alert_tree(unrelated_guid, root_guid, db_path=self.test_db_path))
        # Parent / ancestor of alert process IS in tree (e.g. launcher shell like PowerShell)
        self.assertTrue(is_in_alert_tree("{parent-of-root}", root_guid, db_path=self.test_db_path))
        self.assertTrue(is_in_alert_tree(child_guid, grandchild_guid, db_path=self.test_db_path))

    def test_hitl_tool_node_execution(self):
        from agent.agent import hitl_tool_node
        from langchain_core.messages import AIMessage

        proc = subprocess.Popen(["notepad.exe"])
        try:
            guid = "{dddddddd-eeee-ffff-0000-111111111111}"
            p = psutil.Process(proc.pid)
            live_ct = p.create_time()
            live_utc_str = datetime.fromtimestamp(live_ct, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            live_exe = p.exe()

            event = {
                "EventID": 1,
                "TimeCreated": live_utc_str,
                "UtcTime": live_utc_str,
                "ProcessId": proc.pid,
                "ProcessGuid": guid,
                "Image": live_exe,
            }
            record_events_batch([event], self.test_db_path)

            tool_call = {
                "id": "call_12345",
                "name": "kill_process",
                "args": {
                    "guid": guid,
                    "reason": "Agent determined process is malicious",
                },
            }
            ai_msg = AIMessage(content="", tool_calls=[tool_call])
            state = {
                "messages": [ai_msg],
                "alert": {
                    "rule_name": "Test Rule",
                    "severity": "high",
                    "event": {"process_guid": guid},
                },
                "sigma_rule": {"title": "Test Sigma Rule", "level": "high"},
                "plan": ["check", "terminate"],
                "turns": 1,
            }

            # In dev mode, hitl_tool_node prints the screen and auto-approves
            with patch("agent.agent.HITL_MODE", "auto"), \
                 patch("agent.agent.DRY_RUN", True), \
                 patch("agent.agent.DB_PATH", self.test_db_path), \
                 patch("agent.agent.AUDIT_LOG_PATH", self.test_audit_path):
                res = hitl_tool_node(state)
            self.assertEqual(res["turns"], 2)
            self.assertEqual(len(res["messages"]), 1)
            msg = res["messages"][0]
            self.assertEqual(msg.tool_call_id, "call_12345")
            self.assertIn("dry_run", msg.content.lower())
        finally:
            proc.kill()
            proc.wait()

    def _create_linked_file(self, filename="fake_malware.txt", content=b"malicious payload 123", alert_guid="{11111111-2222-3333-4444-555555555555}"):
        file_path = os.path.join(self.temp_dir.name, filename)
        with open(file_path, "wb") as f:
            f.write(content)
        file_hash = hashlib.sha256(content).hexdigest()

        events = [
            {
                "EventID": 1,
                "TimeCreated": "2026-10-27T10:00:00.000000Z",
                "ProcessId": 5000,
                "ProcessGuid": alert_guid,
                "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
                "Image": "C:\\malware\\dropper.exe",
                "CommandLine": "dropper.exe",
                "Hashes": "SHA256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            },
            {
                "EventID": 11,
                "TimeCreated": "2026-10-27T10:01:00.000000Z",
                "ProcessId": 5000,
                "ProcessGuid": alert_guid,
                "TargetFilename": file_path,
                "Hashes": f"SHA256={file_hash}",
            },
        ]
        record_events_batch(events, db_path=self.test_db_path)
        return file_path, file_hash, alert_guid

    def test_quarantine_01_dry_run(self):
        path, fhash, guid = self._create_linked_file("fake_malware_dryrun.txt")
        res = quarantine_file_action(
            path=path,
            reason="Malicious payload created by dropper",
            alert_guid=guid,
            approved=True,
            dry_run=True,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "dry_run")
        self.assertEqual(res["sha256"].upper(), fhash.upper())
        self.assertTrue(os.path.exists(path))

    def test_quarantine_02_reject(self):
        path, fhash, guid = self._create_linked_file("fake_malware_reject.txt")
        res = quarantine_file_action(
            path=path,
            reason="Malicious file proposal",
            alert_guid=guid,
            approved=False,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "rejected_by_user")
        self.assertTrue(os.path.exists(path))

    def test_quarantine_03_approve_real(self):
        path, fhash, guid = self._create_linked_file("fake_malware_real.txt")
        res = quarantine_file_action(
            path=path,
            reason="Approved malware quarantine",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "quarantined")
        self.assertEqual(res["sha256"].upper(), fhash.upper())
        self.assertFalse(os.path.exists(path))

        quarantined_path = os.path.join(self.test_quarantine_dir, f"{fhash.upper()}.quarantine")
        meta_path = os.path.join(self.test_quarantine_dir, f"{fhash.upper()}.json")
        self.assertTrue(os.path.exists(quarantined_path))
        self.assertTrue(os.path.exists(meta_path))

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["original_path"], path)
        self.assertEqual(meta["sha256"].upper(), fhash.upper())
        self.assertEqual(meta["alert_guid"], guid)

    def test_quarantine_04_restore(self):
        path, fhash, guid = self._create_linked_file("fake_malware_restore.txt")
        quarantine_res = quarantine_file_action(
            path=path,
            reason="Temporary quarantine before restore",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(quarantine_res["status"], "quarantined")
        self.assertFalse(os.path.exists(path))

        restore_res = restore_quarantined_file(
            sha256=fhash.upper(),
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(restore_res["status"], "restored")
        self.assertTrue(os.path.exists(path))
        with open(path, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest().upper(), fhash.upper())

        quarantined_path = os.path.join(self.test_quarantine_dir, f"{fhash.upper()}.quarantine")
        meta_path = os.path.join(self.test_quarantine_dir, f"{fhash.upper()}.json")
        self.assertFalse(os.path.exists(quarantined_path))
        self.assertFalse(os.path.exists(meta_path))

    def test_quarantine_05_file_changed(self):
        path, fhash, guid = self._create_linked_file("fake_malware_changed.txt")
        with open(path, "ab") as f:
            f.write(b"modified after event")

        res = quarantine_file_action(
            path=path,
            reason="Tampered file quarantine attempt",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "hash_mismatch")
        self.assertTrue(os.path.exists(path))

    def test_quarantine_06_file_in_use(self):
        import time
        system_cmd = r"C:\Windows\System32\cmd.exe"
        temp_exe = os.path.join(self.temp_dir.name, "locked_binary.exe")
        with open(system_cmd, "rb") as src, open(temp_exe, "wb") as dst:
            dst.write(src.read())

        with open(temp_exe, "rb") as f:
            fhash = hashlib.sha256(f.read()).hexdigest()

        proc_guid = "{99999999-1111-2222-3333-444444444444}"
        events = [
            {
                "EventID": 1,
                "TimeCreated": "2026-10-27T10:00:00.000000Z",
                "ProcessId": 6000,
                "ProcessGuid": proc_guid,
                "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
                "Image": temp_exe,
                "CommandLine": "locked_binary.exe",
                "Hashes": f"SHA256={fhash}",
            }
        ]
        record_events_batch(events, db_path=self.test_db_path)

        proc = subprocess.Popen([temp_exe, "/k"], stdin=subprocess.PIPE)
        time.sleep(0.3)
        try:
            res = quarantine_file_action(
                path=temp_exe,
                reason="Running locked binary",
                alert_guid=proc_guid,
                approved=True,
                dry_run=False,
                db_path=self.test_db_path,
                quarantine_dir=self.test_quarantine_dir,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "file_in_use")
            self.assertTrue(os.path.exists(temp_exe))
        finally:
            proc.kill()
            proc.wait()

    def test_quarantine_07_already_gone(self):
        ghost_path = os.path.join(self.temp_dir.name, "deleted_by_attacker.exe")
        guid = "{77777777-1111-2222-3333-444444444444}"
        events = [
            {
                "EventID": 1,
                "TimeCreated": "2026-10-27T10:00:00.000000Z",
                "ProcessId": 7000,
                "ProcessGuid": guid,
                "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
                "Image": ghost_path,
                "CommandLine": "deleted_by_attacker.exe",
                "Hashes": "SHA256=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            }
        ]
        record_events_batch(events, db_path=self.test_db_path)

        res = quarantine_file_action(
            path=ghost_path,
            reason="Deleted malware file",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "not_found")

    def test_quarantine_08_not_linked_to_alert(self):
        unlinked_path = os.path.join(self.temp_dir.name, "unrelated_document.pdf")
        with open(unlinked_path, "wb") as f:
            f.write(b"not related to alert")
        guid = "{88888888-1111-2222-3333-444444444444}"

        res = quarantine_file_action(
            path=unlinked_path,
            reason="Attempting to quarantine unlinked file",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "not_allowed_target")
        self.assertTrue(os.path.exists(unlinked_path))

    def test_quarantine_09_protected_path(self):
        pcalua_path = r"C:\Windows\System32\pcalua.exe"
        guid = "{99999999-1111-2222-3333-444444444444}"
        res = quarantine_file_action(
            path=pcalua_path,
            reason="Attempting to quarantine Windows pcalua.exe",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "blocked_protected")

    def test_quarantine_10_copy_of_system_file_in_temp(self):
        calc_copy = os.path.join(self.temp_dir.name, "calc.exe")
        content = b"fake calc copy in temp"
        with open(calc_copy, "wb") as f:
            f.write(content)
        fhash = hashlib.sha256(content).hexdigest()

        guid = "{aaaa1111-2222-3333-4444-555555555555}"
        events = [
            {
                "EventID": 1,
                "TimeCreated": "2026-10-27T10:00:00.000000Z",
                "ProcessId": 8000,
                "ProcessGuid": guid,
                "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
                "Image": calc_copy,
                "CommandLine": "calc.exe",
                "Hashes": f"SHA256={fhash}",
            }
        ]
        record_events_batch(events, db_path=self.test_db_path)

        res = quarantine_file_action(
            path=calc_copy,
            reason="Dropped copy of calc.exe in temp",
            alert_guid=guid,
            approved=True,
            dry_run=True,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "dry_run")
        self.assertTrue(os.path.exists(calc_copy))

    def test_quarantine_11_own_files(self):
        guid = "{bbbb1111-2222-3333-4444-555555555555}"
        for own_file in [self.test_audit_path, self.test_quarantine_dir]:
            res = quarantine_file_action(
                path=own_file,
                reason="Quarantine own file",
                alert_guid=guid,
                approved=True,
                dry_run=False,
                db_path=self.test_db_path,
                quarantine_dir=self.test_quarantine_dir,
                audit_path=self.test_audit_path,
            )
            self.assertEqual(res["status"], "blocked_protected")

    def test_quarantine_12_folder_and_wildcard(self):
        guid = "{cccc1111-2222-3333-4444-555555555555}"
        folder_res = quarantine_file_action(
            path=self.temp_dir.name,
            reason="Quarantine folder",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(folder_res["status"], "invalid_input")

        wildcard_path = os.path.join(self.temp_dir.name, "*.exe")
        wildcard_res = quarantine_file_action(
            path=wildcard_path,
            reason="Quarantine wildcard",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(wildcard_res["status"], "invalid_input")

    def test_quarantine_13_network_path(self):
        guid = "{dddd1111-2222-3333-4444-555555555555}"
        res = quarantine_file_action(
            path=r"\\someserver\share\malware.exe",
            reason="Quarantine network path",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "invalid_input")

    def test_quarantine_14_approval_cant_be_skipped(self):
        path, fhash, guid = self._create_linked_file("fake_skip_appr.txt")
        res = quarantine_file_action(
            path=path,
            reason="Unapproved quarantine attempt",
            alert_guid=guid,
            approved=False,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "rejected_by_user")
        self.assertTrue(os.path.exists(path))

    def test_quarantine_15_timeout(self):
        path, fhash, guid = self._create_linked_file("fake_timeout.txt")
        res = quarantine_file_action(
            path=path,
            reason="Timed out proposal",
            alert_guid=guid,
            approved=False,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        self.assertEqual(res["status"], "rejected_by_user")
        self.assertTrue(os.path.exists(path))

    def test_quarantine_16_audit_log(self):
        path, fhash, guid = self._create_linked_file("fake_audit_test.txt")
        # 1. Dry run attempt
        quarantine_file_action(
            path=path,
            reason="Audit dry run test",
            alert_guid=guid,
            approved=True,
            dry_run=True,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        # 2. Rejected attempt
        quarantine_file_action(
            path=path,
            reason="Audit reject test",
            alert_guid=guid,
            approved=False,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )
        # 3. Blocked protected attempt
        quarantine_file_action(
            path=r"C:\Windows\System32\pcalua.exe",
            reason="Audit blocked test",
            alert_guid=guid,
            approved=True,
            dry_run=False,
            db_path=self.test_db_path,
            quarantine_dir=self.test_quarantine_dir,
            audit_path=self.test_audit_path,
        )

        self.assertTrue(os.path.exists(self.test_audit_path))
        with open(self.test_audit_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertGreaterEqual(len(lines), 3)
        for line in lines:
            entry = json.loads(line.strip())
            self.assertIn("timestamp", entry)
            self.assertTrue("path" in entry or "original_path" in entry)
            self.assertTrue("outcome" in entry or "status" in entry)
            self.assertIn("dry_run", entry)
            self.assertIn("reason", entry)

    def test_quarantine_hitl_tool_node(self):
        from agent.agent import hitl_tool_node
        from langchain_core.messages import AIMessage

        path, fhash, guid = self._create_linked_file("fake_hitl_quarantine.txt")
        tool_call = {
            "id": "call_quarantine_123",
            "name": "quarantine_file",
            "args": {
                "path": path,
                "reason": "Agent determined file is a malicious dropper payload",
            },
        }
        ai_msg = AIMessage(content="", tool_calls=[tool_call])
        state = {
            "messages": [ai_msg],
            "alert": {
                "rule_name": "Test Dropper Rule",
                "severity": "critical",
                "event": {"process_guid": guid},
            },
            "sigma_rule": {"title": "Test Sigma Rule", "level": "critical"},
            "plan": ["investigate", "quarantine"],
            "turns": 1,
        }

        with patch("agent.agent.HITL_MODE", "auto"), \
             patch("agent.agent.DRY_RUN", True), \
             patch("agent.agent.DB_PATH", self.test_db_path), \
             patch("agent.agent.AUDIT_LOG_PATH", self.test_audit_path), \
             patch("agent.agent.QUARANTINE_DIR", self.test_quarantine_dir):
            res = hitl_tool_node(state)
        self.assertEqual(res["turns"], 2)
        self.assertEqual(len(res["messages"]), 1)
        msg = res["messages"][0]
        self.assertEqual(msg.tool_call_id, "call_quarantine_123")
        self.assertIn("dry_run", msg.content.lower())

    def test_plan_tool_invocation(self):
        steps = [
            "1. Inspect parent and ancestor process lineage",
            "2. Check spawned child commands",
            "3. Inspect file hashes on disk and VirusTotal",
        ]
        res1 = plan.invoke({"steps": steps})
        self.assertEqual(res1["status"], "plan_recorded")
        self.assertEqual(res1["plan"], steps)
        self.assertIn("3 steps", res1["message"])

        res2 = plan.invoke({"steps": "Step A\nStep B\nStep C"})
        self.assertEqual(res2["status"], "plan_recorded")
        self.assertEqual(res2["plan"], ["Step A", "Step B", "Step C"])

    def test_tools_node_updates_plan(self):
        from agent.agent import tools_node
        from langchain_core.messages import AIMessage

        tool_call = {
            "id": "call_plan_1",
            "name": "plan",
            "args": {
                "steps": [
                    "Reconstruct process tree",
                    "Query live network sockets",
                    "Determine verdict",
                ]
            },
        }
        ai_msg = AIMessage(content="", tool_calls=[tool_call])
        state = {
            "messages": [ai_msg],
            "alert": {},
            "sigma_rule": {},
            "plan": [],
            "turns": 0,
        }

        update = tools_node(state)
        self.assertEqual(update["turns"], 1)
        self.assertEqual(len(update["messages"]), 1)
        self.assertEqual(update["plan"], [
            "Reconstruct process tree",
            "Query live network sockets",
            "Determine verdict",
        ])

    def test_get_tools_registration(self):
        tools, mapping = get_tools()
        expected = [
            "plan",
            "get_process_tree",
            "get_children",
            "get_events_for_process",
            "get_events_in_window",
            "get_events_by_hash",
            "get_rule_context",
            "get_file_info",
            "get_file_signature",
            "is_process_running",
            "get_live_connections",
            "lookup_hash",
            "exa_search",
            "ask_user",
            "kill_process",
            "quarantine_file",
            "submit_verdict",
            "respond",
        ]
        self.assertEqual(len(tools), 18)
        for name in expected:
            self.assertIn(name, mapping)
        names = [t.name for t in tools]
        for name in expected:
            self.assertIn(name, names)


class TestAskUserValidation(unittest.TestCase):
    def test_valid_input(self):
        ok, res, errors = validate_ask_user_input(
            question="Did you execute this script intentionally?",
            choices=["Yes, it was me", "No, unrecognized"],
        )
        self.assertTrue(ok)
        self.assertEqual(len(errors), 0)
        self.assertEqual(res["question"], "Did you execute this script intentionally?")
        self.assertEqual(res["choices"], ["Yes, it was me", "No, unrecognized"])

    def test_question_length_boundaries(self):
        # Too short (< 10 chars)
        ok, _, errors = validate_ask_user_input("Why?", ["Yes", "No"])
        self.assertFalse(ok)
        self.assertTrue(any("at least 10 characters" in e for e in errors))

        # Exactly 10 chars
        ok, res, errors = validate_ask_user_input("1234567890", ["Yes", "No"])
        self.assertTrue(ok)
        self.assertEqual(len(res["question"]), 10)

        # Too long (> 300 chars)
        ok, _, errors = validate_ask_user_input("A" * 301, ["Yes", "No"])
        self.assertFalse(ok)
        self.assertTrue(any("at most 300 characters" in e for e in errors))

        # Exactly 300 chars
        ok, res, errors = validate_ask_user_input("A" * 300, ["Yes", "No"])
        self.assertTrue(ok)
        self.assertEqual(len(res["question"]), 300)

    def test_question_sanitization(self):
        # Newlines collapsed, control chars stripped
        raw = "Did you run\n\rthis command?\x00\x07  Please confirm.  "
        ok, res, errors = validate_ask_user_input(raw, ["Yes", "No"])
        self.assertTrue(ok)
        self.assertEqual(res["question"], "Did you run this command? Please confirm.")

    def test_choices_count_boundaries(self):
        # 1 choice -> error
        ok, _, errors = validate_ask_user_input("Valid question text?", ["Only choice"])
        self.assertFalse(ok)
        self.assertTrue(any("at least 2 valid, distinct choices" in e for e in errors))

        # 5 choices -> valid
        ok, res, errors = validate_ask_user_input("Valid question text?", ["C1", "C2", "C3", "C4", "C5"])
        self.assertTrue(ok)
        self.assertEqual(len(res["choices"]), 5)

        # 6 choices -> error
        ok, _, errors = validate_ask_user_input("Valid question text?", ["C1", "C2", "C3", "C4", "C5", "C6"])
        self.assertFalse(ok)
        self.assertTrue(any("at most 5 choices" in e for e in errors))

    def test_choices_length_and_duplicate_handling(self):
        # Choice too long (> 80 chars)
        ok, _, errors = validate_ask_user_input("Valid question text?", ["Short", "X" * 81])
        self.assertFalse(ok)
        self.assertTrue(any("exceeds maximum length of 80 characters" in e for e in errors))

        # Duplicate choices ignoring case
        ok, _, errors = validate_ask_user_input("Valid question text?", ["Option A", "option a"])
        self.assertFalse(ok)
        self.assertTrue(any("duplicate choice" in e for e in errors))

    def test_unsure_variants_removed(self):
        # Unsure option is stripped, remaining 2 choices valid
        raw_choices = ["Yes", "No", "I'm not sure", "don't know"]
        ok, res, errors = validate_ask_user_input("Valid question text?", raw_choices)
        self.assertTrue(ok)
        self.assertEqual(res["choices"], ["Yes", "No"])

        # Unsure stripped leaves only 1 choice -> fails
        raw_choices2 = ["Yes", "not sure"]
        ok, _, errors = validate_ask_user_input("Valid question text?", raw_choices2)
        self.assertFalse(ok)
        self.assertTrue(any("at least 2 valid, distinct choices" in e for e in errors))

    def test_ask_user_tool_invoke_invalid_input(self):
        res = ask_user.invoke({"question": "Short?", "choices": ["Yes"]})
        self.assertEqual(res["status"], "invalid_input")
        self.assertIn("errors", res)
        self.assertGreater(len(res["errors"]), 0)


if __name__ == "__main__":
    unittest.main()

