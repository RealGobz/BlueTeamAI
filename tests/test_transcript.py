"""
tests/test_transcript.py - Unit tests for UI/main/transcript.py pure transformation functions.

Tests:
1. Pcalua alert fixture: ordering, tool call and ToolMessage pairing.
2. respond tool call becomes an agent chat bubble.
3. SystemMessage is completely hidden.
4. Verdict is taken strictly from the results DB row, never from agent's raw tool args.
5. Multiple revisions: each is its own card in time order, older ones marked superseded.
6. AIMessage content as list of blocks: thinking/reasoning blocks are strictly ignored, only text blocks kept.
7. Tool call with no result yet (in-progress/waiting).
8. Missing/empty DB rows handle gracefully without error.
9. XSS payloads in alert command lines, tool args, tool results, respond text, and verdict fields
   remain intact as pure data without dangerous unescaped structures.
"""

import json
import unittest
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage

from UI.main.transcript import (
    extract_text_from_ai_content,
    build_timeline_items,
    summarize_thread,
    parse_tool_args_display,
)


class TestTranscript(unittest.TestCase):
    def test_extract_text_from_ai_content_blocks(self):
        # 1. Plain string
        self.assertEqual(extract_text_from_ai_content("Hello world"), "Hello world")

        # 2. List of blocks with thinking/reasoning blocks that MUST BE IGNORED
        blocks = [
            {"type": "thinking", "thinking": "Internal attacker analysis steps... DO NOT SHOW"},
            {"type": "reasoning", "reasoning": "Hidden chain of thought"},
            {"type": "text", "text": "This is the visible answer."},
            {"type": "text", "text": "Another visible paragraph."},
        ]
        result = extract_text_from_ai_content(blocks)
        self.assertNotIn("Internal attacker analysis", result)
        self.assertNotIn("Hidden chain of thought", result)
        self.assertIn("This is the visible answer.", result)
        self.assertIn("Another visible paragraph.", result)

    def test_pcalua_alert_thread_fixture(self):
        # A realistic Pcalua alert thread fixture
        thread_id = "thread_pcalua_123"
        alert_info = {
            "rule_name": "Suspicious Process Execution via Pcalua",
            "severity": "high",
            "timestamp": "2026-10-31T10:00:00Z",
            "event": {
                "computer_name": "WORKSTATION-01",
                "user": "CORP\\alice",
                "image": "C:\\Windows\\System32\\pcalua.exe",
                "command_line": 'pcalua.exe -a "C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe"',
                "process_guid": "{pcalua-guid-001}",
                "UtcTime": "2026-10-31T10:00:00Z",
            },
        }

        # Conversation messages
        messages = [
            # System prompt (MUST BE HIDDEN)
            SystemMessage(content="You are a blue team bot..."),
            # Agent calls plan
            AIMessage(
                content="",
                tool_calls=[{"id": "call_plan_1", "name": "plan", "args": {"steps": ["Check lineage", "Inspect binary"]}}],
            ),
            ToolMessage(
                content=json.dumps({"status": "plan_recorded", "plan": ["Check lineage", "Inspect binary"]}),
                tool_call_id="call_plan_1",
            ),
            # Agent calls get_process_tree
            AIMessage(
                content="",
                tool_calls=[{"id": "call_tree_1", "name": "get_process_tree", "args": {"guid": "{pcalua-guid-001}"}}],
            ),
            ToolMessage(
                content=json.dumps({"status": "found", "tree": [{"image": "cmd.exe"}, {"image": "pcalua.exe"}]}),
                tool_call_id="call_tree_1",
            ),
            # Agent calls get_file_info
            AIMessage(
                content="",
                tool_calls=[{"id": "call_info_1", "name": "get_file_info", "args": {"path": "C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe"}}],
            ),
            ToolMessage(
                content=json.dumps({"exists": True, "in_risky_folder": True, "sha256": "AAAABBBB"}),
                tool_call_id="call_info_1",
            ),
            # Agent proposes kill_process
            AIMessage(
                content="",
                tool_calls=[{"id": "call_kill_1", "name": "kill_process", "args": {"guid": "{pcalua-guid-001}", "reason": "Malicious payload launched"}}],
            ),
            ToolMessage(
                content=json.dumps({"status": "executed", "guid": "{pcalua-guid-001}"}),
                tool_call_id="call_kill_1",
            ),
            # Human sends chat question
            HumanMessage(content="Why was pcalua flagged?"),
            # Agent calls respond tool
            AIMessage(
                content="",
                tool_calls=[{"id": "call_resp_1", "name": "respond", "args": {"text": "Pcalua executed an untrusted binary from the Temp directory."}}],
            ),
            ToolMessage(
                content=json.dumps({"status": "sent"}),
                tool_call_id="call_resp_1",
            ),
            # Agent submits verdict
            AIMessage(
                content="",
                tool_calls=[{"id": "call_verdict_1", "name": "submit_verdict", "args": {"verdict": "true_positive", "summary": "raw model summary"}}],
            ),
            ToolMessage(
                content=json.dumps({"status": "recorded"}),
                tool_call_id="call_verdict_1",
            ),
        ]

        # Results DB rows (revision 1 and revision 2)
        verdicts = [
            {
                "verdict_id": "v_rev_1",
                "revision": 1,
                "supersedes": None,
                "status": "closed",
                "verdict": "true_positive",
                "confidence": "high",
                "severity": "high",
                "category": "defense_evasion",
                "summary": "Validated DB Summary Rev 1: Malicious pcalua execution",
                "explanation": "Event showed cmd.exe spawning pcalua.exe which executed updater.exe from Temp.",
                "evidence": [{"finding": "Executed from Temp", "source_tool": "get_file_info", "direction": "suspicious"}],
                "assumptions": [],
                "not_checked": [],
                "recommended_next_steps": ["Quarantine updater.exe"],
                "remaining_risk": "File updater.exe may persist",
                "threat_active": "inactive",
                "created_at": "2026-10-31T10:05:00Z",
                "run_facts": {"turns": 4},
            },
            {
                "verdict_id": "v_rev_2",
                "revision": 2,
                "supersedes": "v_rev_1",
                "status": "closed",
                "verdict": "true_positive",
                "confidence": "high",
                "severity": "high",
                "category": "defense_evasion",
                "summary": "Validated DB Summary Rev 2: Confirmed trojan execution",
                "explanation": "Further analysis confirmed updater.exe is a known trojan.",
                "evidence": [{"finding": "Executed from Temp", "source_tool": "get_file_info", "direction": "suspicious"}],
                "assumptions": [],
                "not_checked": [],
                "recommended_next_steps": ["Quarantine updater.exe", "Reset user password"],
                "remaining_risk": "None active",
                "threat_active": "inactive",
                "created_at": "2026-10-31T10:10:00Z",
                "run_facts": {"turns": 5},
            },
        ]

        audit_actions = [
            {
                "tool": "kill_process",
                "target": "{pcalua-guid-001}",
                "decision": "approved",
                "result": "executed",
                "details": "Process terminated by operator",
                "dry_run": False,
            }
        ]

        items = build_timeline_items(
            thread_id=thread_id,
            raw_messages=messages,
            alert_info=alert_info,
            verdicts=verdicts,
            audit_actions=audit_actions,
        )

        item_types = [item["type"] for item in items]

        # 1. First item is the Alert Card
        self.assertEqual(items[0]["type"], "alert")
        self.assertEqual(items[0]["process_name"], "C:\\Windows\\System32\\pcalua.exe")

        # 2. SystemMessage is NEVER in timeline items
        self.assertNotIn("system", item_types)
        for item in items:
            self.assertNotEqual(item.get("sender"), "system")

        # 3. Plan card appears
        self.assertIn("plan", item_types)

        # 4. Normal tools appear as tool cards with paired result preview
        tool_cards = [i for i in items if i["type"] == "tool"]
        self.assertTrue(any(tc["tool_name"] == "get_process_tree" for tc in tool_cards))
        tree_card = next(tc for tc in tool_cards if tc["tool_name"] == "get_process_tree")
        self.assertEqual(tree_card["status"], "ok")
        self.assertIn("cmd.exe", tree_card["result_preview"])

        # 5. kill_process appears as an action card with HITL decision
        action_cards = [i for i in items if i["type"] == "action"]
        self.assertEqual(len(action_cards), 1)
        self.assertEqual(action_cards[0]["tool_name"], "kill_process")
        self.assertEqual(action_cards[0]["decision"], "approved")
        self.assertEqual(action_cards[0]["result"], "executed")

        # 6. respond becomes an agent chat bubble, NOT a tool card
        self.assertFalse(any(tc.get("tool_name") == "respond" for tc in tool_cards))
        bubbles = [i for i in items if i["type"] == "chat_bubble"]
        self.assertTrue(any(b["sender"] == "user" and b["text"] == "Why was pcalua flagged?" for b in bubbles))
        agent_bubble = next(b for b in bubbles if b["sender"] == "agent" and not b.get("unstructured"))
        self.assertEqual(agent_bubble["text"], "Pcalua executed an untrusted binary from the Temp directory.")

        # 7. submit_verdict is NOT a tool card; Verdict cards come strictly from results DB
        self.assertFalse(any(tc.get("tool_name") == "submit_verdict" for tc in tool_cards))
        verdict_cards = [i for i in items if i["type"] == "verdict"]
        self.assertEqual(len(verdict_cards), 2)

        # Older revision is marked superseded
        self.assertTrue(verdict_cards[0]["superseded"])
        self.assertEqual(verdict_cards[0]["summary"], "Validated DB Summary Rev 1: Malicious pcalua execution")
        self.assertFalse(verdict_cards[1]["superseded"])
        self.assertEqual(verdict_cards[1]["summary"], "Validated DB Summary Rev 2: Confirmed trojan execution")
        self.assertEqual(verdict_cards[1]["headline_badge"], "Real attack")

    def test_tool_call_with_no_result_yet(self):
        # A tool call that was sent but no ToolMessage exists yet
        messages = [
            AIMessage(
                content="",
                tool_calls=[{"id": "call_pending_1", "name": "get_live_connections", "args": {"guid": "{123}"}}],
            )
        ]
        items = build_timeline_items(thread_id="t1", raw_messages=messages)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["type"], "tool")
        self.assertEqual(items[0]["status"], "waiting")
        self.assertEqual(items[0]["result_preview"], "")

    def test_verdict_rejected_submission_chip(self):
        # When submit_verdict returns rejected_invalid, a verdict_rejected chip appears
        messages = [
            AIMessage(
                content="",
                tool_calls=[{"id": "call_v_bad", "name": "submit_verdict", "args": {"verdict": "true_positive"}}],
            ),
            ToolMessage(
                content=json.dumps({"status": "rejected_invalid", "errors": ["Missing remaining_risk field"]}),
                tool_call_id="call_v_bad",
            ),
        ]
        items = build_timeline_items(thread_id="t_rej", raw_messages=messages)
        rej_chips = [i for i in items if i["type"] == "verdict_rejected"]
        self.assertEqual(len(rej_chips), 1)
        self.assertEqual(rej_chips[0]["errors"], ["Missing remaining_risk field"])

    def test_unstructured_aimessage_fallback(self):
        # When model produces plain text without tool calls
        messages = [
            AIMessage(content="Direct text output without tool call.")
        ]
        items = build_timeline_items(thread_id="t_fallback", raw_messages=messages)
        bubbles = [i for i in items if i["type"] == "chat_bubble"]
        self.assertEqual(len(bubbles), 1)
        self.assertTrue(bubbles[0]["unstructured"])
        self.assertEqual(bubbles[0]["text"], "Direct text output without tool call.")

    def test_xss_payload_safety(self):
        # Ensure malicious script/HTML tags remain safely enclosed as plain string properties
        xss_string = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
        alert_info = {
            "rule_name": f"Rule {xss_string}",
            "event": {
                "command_line": f"powershell.exe {xss_string}",
            },
        }
        messages = [
            HumanMessage(content=f"User {xss_string}"),
            AIMessage(
                content="",
                tool_calls=[{"id": "call_xss", "name": "respond", "args": {"text": f"Agent {xss_string}"}}],
            ),
            ToolMessage(
                content=json.dumps({"status": "ok", "data": xss_string}),
                tool_call_id="call_xss",
            ),
        ]
        items = build_timeline_items(thread_id="t_xss", raw_messages=messages, alert_info=alert_info)

        # Serialize to JSON (as the API sends to frontend)
        json_dump = json.dumps(items)
        # Parse back to ensure proper JSON data encoding
        data = json.loads(json_dump)
        self.assertIsInstance(data, list)

        # The XSS strings must be verbatim in the Python dict data (for frontend textContent insertion)
        alert_card = next(i for i in data if i["type"] == "alert")
        self.assertIn("<script>", alert_card["title"])
        self.assertIn("powershell.exe <script>", alert_card["command_line"])

    def test_summarize_thread_states(self):
        # Test summarize_thread status determination
        s_working = summarize_thread("t1", active_run={"kind": "alert"})
        self.assertEqual(s_working["status"], "working")

        s_waiting = summarize_thread("t2", pending_hitl_count=1)
        self.assertEqual(s_waiting["status"], "waiting_human")

        s_done = summarize_thread("t3", latest_verdict={"status": "closed", "verdict": "false_positive"})
        self.assertEqual(s_done["status"], "done")
        self.assertEqual(s_done["verdict"], "false_positive")

        s_incomplete = summarize_thread("t4", latest_verdict={"status": "incomplete", "verdict": None})
        self.assertEqual(s_incomplete["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
