"""
tests/test_respond_tool.py - Unit tests for respond tool and graph workflow changes.

Tests (fake model, no real LLM):
1. respond runs only when awaiting_reply
2. during an alert run it returns not_executed and the loop continues
3. successful respond ends the run without a turn
4. failed respond costs a turn and is capped
5. mixed respond + normal tool runs only the tool
6. mixed respond + submit_verdict records the verdict
7. a ToolMessage exists for every call so the thread resumes cleanly after respond
8. send_user_message resets turns and verdict_retries
9. resume cap enforced
10. no-tool-call fallback ends cleanly
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from langchain_core.messages import AIMessage, ToolMessage, HumanMessage
from langgraph.graph import END

from agent.agent import (
    respond_node,
    respond_router,
    classify_tools_router,
    should_continue_router,
    tools_node,
    verdict_node,
    send_user_message,
    resume_investigation,
    AgentState,
    create_workflow,
)
from agent.memory import get_memory_saver, generate_thread_id
from utils import validate_respond_input, respond_action
from config import MAX_TURNS_PER_ALERT, MAX_RESUMES_PER_THREAD, RESPOND_TOOLS


class TestRespondTool(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        self.memory_db_path = self.test_dir / "checkpoints.sqlite"
        self.results_db_path = self.test_dir / "results.db"

    def tearDown(self):
        if hasattr(self, "saver") and hasattr(self.saver, "conn"):
            try:
                self.saver.conn.close()
            except Exception:
                pass
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _make_state(
        self,
        tool_calls,
        awaiting_reply=False,
        turns=0,
        reply_sent=False,
        verdict_status="in_progress",
    ):
        msg = AIMessage(content="", tool_calls=tool_calls)
        return {
            "messages": [msg],
            "turns": turns,
            "awaiting_reply": awaiting_reply,
            "reply_sent": reply_sent,
            "verdict_status": verdict_status,
            "verdict_retries": 0,
            "resumes": 0,
            "continues": 0,
            "alert": {"event": {"process_guid": "{11111111-1111-1111-1111-111111111111}"}},
            "sigma_rule": {"title": "Test Rule", "level": "high"},
            "plan": ["check lineage"],
        }

    # 1. respond runs only when awaiting_reply
    def test_respond_runs_only_when_awaiting_reply(self):
        # When awaiting_reply is False: returns not_executed, turns incremented
        state_no_wait = self._make_state(
            [{"id": "call_resp_1", "name": "respond", "args": {"text": "All clear."}}],
            awaiting_reply=False,
            turns=1,
        )
        res_no_wait = respond_node(state_no_wait)
        self.assertFalse(res_no_wait.get("reply_sent"))
        self.assertEqual(res_no_wait.get("turns"), 2)
        self.assertEqual(len(res_no_wait["messages"]), 1)
        data = json.loads(res_no_wait["messages"][0].content)
        self.assertEqual(data["status"], "not_executed")
        self.assertIn("No user message is waiting", data["reason"])

        # When awaiting_reply is True: returns sent, awaiting_reply=False, reply_sent=True, turns not in dict (unchanged)
        state_waiting = self._make_state(
            [{"id": "call_resp_2", "name": "respond", "args": {"text": "Process looks normal."}}],
            awaiting_reply=True,
            turns=1,
        )
        res_waiting = respond_node(state_waiting)
        self.assertTrue(res_waiting.get("reply_sent"))
        self.assertFalse(res_waiting.get("awaiting_reply"))
        self.assertNotIn("turns", res_waiting)  # Does not change turns
        data = json.loads(res_waiting["messages"][0].content)
        self.assertEqual(data["status"], "sent")

    # 2. during an alert run it returns not_executed and the loop continues
    def test_alert_run_respond_not_executed_and_continues(self):
        state = self._make_state(
            [{"id": "call_alert_resp", "name": "respond", "args": {"text": "Investigating alert."}}],
            awaiting_reply=False,
            turns=1,
        )
        node_res = respond_node(state)
        data = json.loads(node_res["messages"][0].content)
        self.assertEqual(data["status"], "not_executed")

        # Merge state and test router
        updated_state = dict(state)
        updated_state.update(node_res)
        route = respond_router(updated_state)
        # Should continue to agent_node since turns (2) < MAX_TURNS_PER_ALERT
        self.assertEqual(route, "agent_node")

    # 3. successful respond ends the run without a turn
    def test_successful_respond_ends_run_without_turn(self):
        state = self._make_state(
            [{"id": "call_succ", "name": "respond", "args": {"text": "Here is what happened."}}],
            awaiting_reply=True,
            turns=2,
        )
        node_res = respond_node(state)
        self.assertNotIn("turns", node_res)
        self.assertTrue(node_res["reply_sent"])

        updated_state = dict(state)
        updated_state.update(node_res)
        route = respond_router(updated_state)
        self.assertEqual(route, END)

    # 4. failed respond costs a turn and is capped
    def test_failed_respond_costs_turn_and_is_capped(self):
        # Empty text fails validation
        state = self._make_state(
            [{"id": "call_fail", "name": "respond", "args": {"text": ""}}],
            awaiting_reply=True,
            turns=MAX_TURNS_PER_ALERT - 1,
        )
        node_res = respond_node(state)
        self.assertFalse(node_res["reply_sent"])
        self.assertEqual(node_res["turns"], MAX_TURNS_PER_ALERT)
        data = json.loads(node_res["messages"][0].content)
        self.assertEqual(data["status"], "invalid_input")

        updated_state = dict(state)
        updated_state.update(node_res)
        route = respond_router(updated_state)
        # Turns reached limit, routes to ask_user_continue
        self.assertEqual(route, "ask_user_continue")

    # 5. mixed respond + normal tool runs only the tool
    def test_mixed_respond_and_normal_tool_runs_only_tool(self):
        tool_calls = [
            {"id": "call_plan", "name": "plan", "args": {"steps": ["check parent"]}},
            {"id": "call_resp", "name": "respond", "args": {"text": "hello"}},
        ]
        state = self._make_state(tool_calls, awaiting_reply=True)

        # Router priority: normal tool > respond (not all calls are respond)
        router_choice = classify_tools_router(state)
        self.assertEqual(router_choice, "tools_node")

        # tools_node executes plan, and marks respond as not_executed
        node_res = tools_node(state)
        self.assertEqual(len(node_res["messages"]), 2)

        # 1st is plan result
        plan_out = json.loads(node_res["messages"][0].content)
        self.assertEqual(plan_out["status"], "plan_recorded")
        self.assertEqual(node_res["messages"][0].tool_call_id, "call_plan")

        # 2nd is respond marked not_executed
        resp_out = json.loads(node_res["messages"][1].content)
        self.assertEqual(resp_out["status"], "not_executed")
        self.assertEqual(resp_out["reason"], "call this tool separately")
        self.assertEqual(node_res["messages"][1].tool_call_id, "call_resp")

    # 6. mixed respond + submit_verdict records the verdict
    @patch("agent.agent.process_verdict_submission")
    def test_mixed_respond_and_submit_verdict_records_verdict(self, mock_verdict_proc):
        mock_verdict_proc.return_value = ({"status": "recorded"}, 0)

        tool_calls = [
            {"id": "call_verdict", "name": "submit_verdict", "args": {"verdict": "false_positive"}},
            {"id": "call_resp", "name": "respond", "args": {"text": "Finished."}},
        ]
        state = self._make_state(tool_calls, awaiting_reply=True)

        # Router priority: submit_verdict > respond
        router_choice = classify_tools_router(state)
        self.assertEqual(router_choice, "verdict_node")

        node_res = verdict_node(state)
        self.assertEqual(len(node_res["messages"]), 2)

        # verdict was processed
        v_out = json.loads(node_res["messages"][0].content)
        self.assertEqual(v_out["status"], "recorded")
        self.assertFalse(node_res["awaiting_reply"])

        # respond was marked not_executed
        resp_out = json.loads(node_res["messages"][1].content)
        self.assertEqual(resp_out["status"], "not_executed")
        self.assertEqual(resp_out["reason"], "call this tool separately")

    # 7. a ToolMessage exists for every call so the thread resumes cleanly after respond
    def test_tool_message_exists_for_every_call(self):
        tool_calls = [
            {"id": "call_r1", "name": "respond", "args": {"text": "First reply."}},
            {"id": "call_r2", "name": "respond", "args": {"text": "Duplicate reply."}},
            {"id": "call_other", "name": "get_process_tree", "args": {"guid": "{123}"}},
        ]
        state = self._make_state(tool_calls, awaiting_reply=True)
        node_res = respond_node(state)

        # Every tool call ID has a matching ToolMessage
        call_ids = [tc["id"] for tc in tool_calls]
        msg_ids = [m.tool_call_id for m in node_res["messages"]]
        self.assertEqual(call_ids, msg_ids)

        r1_out = json.loads(node_res["messages"][0].content)
        self.assertEqual(r1_out["status"], "sent")

        r2_out = json.loads(node_res["messages"][1].content)
        self.assertEqual(r2_out["status"], "not_executed")

        r3_out = json.loads(node_res["messages"][2].content)
        self.assertEqual(r3_out["status"], "not_executed")

    # 8. send_user_message resets turns and verdict_retries
    def test_send_user_message_resets_turns_and_retries(self):
        self.saver = get_memory_saver(self.memory_db_path)
        wf = create_workflow(checkpointer=self.saver)
        thread_id = generate_thread_id()

        # Seed initial state in checkpointer
        config = {"configurable": {"thread_id": thread_id}}
        initial_state = {
            "messages": [HumanMessage(content="initial alert")],
            "turns": 4,
            "verdict_retries": 2,
            "resumes": 1,
            "awaiting_reply": False,
            "reply_sent": True,
            "verdict_status": "recorded",
            "alert": {"event": {"process_guid": "{123}"}},
            "sigma_rule": {"title": "Test"},
            "plan": [],
        }
        wf.update_state(config, initial_state)

        # Mock workflow.invoke to inspect passed inputs
        with patch.object(wf, "invoke") as mock_invoke:
            mock_invoke.return_value = {"messages": []}
            send_user_message(thread_id, "What is the verdict?", workflow_instance=wf)

            call_args, call_kwargs = mock_invoke.call_args
            passed_inputs = call_args[0]
            self.assertEqual(passed_inputs["turns"], 0)
            self.assertEqual(passed_inputs["verdict_retries"], 0)
            self.assertTrue(passed_inputs["awaiting_reply"])
            self.assertFalse(passed_inputs["reply_sent"])
            self.assertEqual(passed_inputs["verdict_status"], "in_progress")
            self.assertEqual(passed_inputs["resumes"], 2)
            self.assertEqual(passed_inputs["messages"][0].content, "What is the verdict?")

    # 9. resume cap enforced
    def test_resume_cap_enforced(self):
        self.saver = get_memory_saver(self.memory_db_path)
        wf = create_workflow(checkpointer=self.saver)
        thread_id = generate_thread_id()

        config = {"configurable": {"thread_id": thread_id}}
        initial_state = {
            "messages": [HumanMessage(content="seed")],
            "resumes": MAX_RESUMES_PER_THREAD,
            "turns": 0,
        }
        wf.update_state(config, initial_state)

        # Attempting to send user message when resumes == MAX_RESUMES_PER_THREAD should raise RuntimeError
        with self.assertRaises(RuntimeError) as cm:
            send_user_message(thread_id, "Another question", workflow_instance=wf)
        self.assertIn("maximum allowed resumes", str(cm.exception))

        # Attempting to resume_investigation also raises RuntimeError
        with self.assertRaises(RuntimeError) as cm2:
            resume_investigation(thread_id, "Another question", workflow_instance=wf)
        self.assertIn("maximum allowed resumes", str(cm2.exception))

    # 10. no-tool-call fallback ends cleanly
    def test_no_tool_call_fallback_ends_cleanly(self):
        # Model returns plain text (no tool calls)
        msg_plain = AIMessage(content="I am replying with plain text directly.")
        state = {
            "messages": [msg_plain],
            "turns": 1,
            "awaiting_reply": True,
        }
        route = classify_tools_router(state)
        self.assertEqual(route, END)

    # 11. text sanitization and length bounds
    def test_validate_respond_input(self):
        # Valid text
        is_val, san, errs = validate_respond_input("Everything is clean and checked.\x00\x07")
        self.assertTrue(is_val)
        self.assertEqual(san, "Everything is clean and checked.")
        self.assertEqual(errs, [])

        # Empty text
        is_val, san, errs = validate_respond_input("   ")
        self.assertFalse(is_val)
        self.assertIn("cannot be empty", errs[0])

        # Exceeds 1500 chars
        is_val, san, errs = validate_respond_input("A" * 1501)
        self.assertFalse(is_val)
        self.assertIn("exceeds maximum length of 1500", errs[0])


if __name__ == "__main__":
    unittest.main()
