"""
tests/test_memory.py - Unit tests for persistent LangGraph checkpointer & chat history
"""

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, START, END

from agent.memory import (
    get_memory_saver,
    generate_thread_id,
    serialize_message,
    get_chat_history,
    get_thread_state,
    list_chat_threads,
    delete_thread,
    MEMORY_DB_PATH,
    MEMORY_DIR,
)
from agent.agent import AgentState, create_workflow
from detection.dispatch import clear_alert_cache
from detection.watch import pipeline


class TestAgentMemory(unittest.TestCase):

    def setUp(self):
        clear_alert_cache()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "memory" / "checkpoints.sqlite"
        self.savers = []

    def tearDown(self):
        for s in self.savers:
            if hasattr(s, "conn") and s.conn:
                try:
                    s.conn.close()
                except Exception:
                    pass
        self.temp_dir.cleanup()

    def test_get_memory_saver_creates_db_and_tables(self):
        saver = get_memory_saver(self.test_db_path)
        self.savers.append(saver)
        self.assertTrue(self.test_db_path.exists())

        conn = sqlite3.connect(str(self.test_db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        self.assertIn("checkpoints", tables)
        self.assertIn("writes", tables)

    def test_generate_thread_id_format_and_uniqueness(self):
        t1 = generate_thread_id()
        t2 = generate_thread_id()
        self.assertTrue(t1.startswith("thread_"))
        self.assertTrue(t2.startswith("thread_"))
        self.assertNotEqual(t1, t2)
        self.assertGreater(len(t1), 15)

    def test_serialize_message(self):
        sys_msg = SystemMessage(content="You are a blue teamer")
        s_dict = serialize_message(sys_msg)
        self.assertEqual(s_dict["role"], "system")
        self.assertEqual(s_dict["content"], "You are a blue teamer")

        human_msg = HumanMessage(content="Why was calc.exe spawned?")
        h_dict = serialize_message(human_msg)
        self.assertEqual(h_dict["role"], "user")
        self.assertEqual(h_dict["content"], "Why was calc.exe spawned?")

        ai_msg = AIMessage(
            content="Checking process tree",
            tool_calls=[{"name": "get_process_tree", "args": {"guid": "{123}"}, "id": "call_1"}],
        )
        ai_dict = serialize_message(ai_msg)
        self.assertEqual(ai_dict["role"], "assistant")
        self.assertEqual(ai_dict["content"], "Checking process tree")
        self.assertEqual(len(ai_dict["tool_calls"]), 1)
        self.assertEqual(ai_dict["tool_calls"][0]["name"], "get_process_tree")

        tool_msg = ToolMessage(content="[{'image': 'calc.exe'}]", tool_call_id="call_1", name="get_process_tree")
        t_dict = serialize_message(tool_msg)
        self.assertEqual(t_dict["role"], "tool")
        self.assertEqual(t_dict["tool_call_id"], "call_1")
        self.assertEqual(t_dict["name"], "get_process_tree")

    def test_workflow_persists_state_and_retrieves_chat_history(self):
        saver = get_memory_saver(self.test_db_path)
        self.savers.append(saver)

        # Build a small dummy graph matching AgentState structure
        test_graph = StateGraph(AgentState)

        def mock_agent_node(state: AgentState):
            msgs = list(state.get("messages", []))
            if not msgs:
                msgs.append(SystemMessage(content="Investigate alert"))
            msgs.append(AIMessage(content="Analyzed alert successfully"))
            return {"messages": msgs, "turns": state.get("turns", 0) + 1}

        test_graph.add_node("agent", mock_agent_node)
        test_graph.add_edge(START, "agent")
        test_graph.add_edge("agent", END)
        app = test_graph.compile(checkpointer=saver)

        thread_id = "test_investigation_001"
        config = {"configurable": {"thread_id": thread_id}}
        initial_state = {
            "alert": {"rule_name": "Suspicious Executable Execution", "severity": "high"},
            "sigma_rule": {"title": "Suspicious Executable Execution", "level": "high"},
            "plan": ["check process tree"],
            "turns": 0,
            "messages": [],
        }

        # 1. Run the workflow
        result = app.invoke(initial_state, config=config)
        self.assertGreaterEqual(len(result["messages"]), 2)

        # 2. Retrieve chat history for UI
        history = get_chat_history(thread_id, checkpointer=saver, as_dicts=True)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["role"], "system")
        self.assertEqual(history[0]["content"], "Investigate alert")
        self.assertEqual(history[1]["role"], "assistant")
        self.assertEqual(history[1]["content"], "Analyzed alert successfully")

        # 3. Retrieve raw BaseMessage instances
        raw_history = get_chat_history(thread_id, checkpointer=saver, as_dicts=False)
        self.assertEqual(len(raw_history), 2)
        self.assertIsInstance(raw_history[0], SystemMessage)
        self.assertIsInstance(raw_history[1], AIMessage)

        # 4. Retrieve complete thread state
        state = get_thread_state(thread_id, checkpointer=saver)
        self.assertIsNotNone(state)
        self.assertEqual(state["thread_id"], thread_id)
        self.assertEqual(state["alert"]["rule_name"], "Suspicious Executable Execution")
        self.assertEqual(state["turns"], 1)

    def test_list_chat_threads_and_delete_thread(self):
        saver = get_memory_saver(self.test_db_path)
        self.savers.append(saver)

        test_graph = StateGraph(AgentState)

        def mock_node(state: AgentState):
            return {"messages": [AIMessage(content="Done")], "turns": 1}

        test_graph.add_node("agent", mock_node)
        test_graph.add_edge(START, "agent")
        test_graph.add_edge("agent", END)
        app = test_graph.compile(checkpointer=saver)

        # Save Thread A
        app.invoke(
            {
                "alert": {"rule_name": "Ransomware Detected", "severity": "critical"},
                "sigma_rule": {"title": "Ransomware Rule", "level": "critical"},
                "plan": ["contain"],
                "turns": 0,
                "messages": [HumanMessage(content="Investigate Ransomware")],
            },
            config={"configurable": {"thread_id": "thread_A"}},
        )

        # Save Thread B
        app.invoke(
            {
                "alert": {"rule_name": "Persistence Registry Key", "severity": "medium"},
                "sigma_rule": {"title": "Persistence Rule", "level": "medium"},
                "plan": ["inspect"],
                "turns": 0,
                "messages": [HumanMessage(content="Investigate Persistence")],
            },
            config={"configurable": {"thread_id": "thread_B"}},
        )

        threads = list_chat_threads(checkpointer=saver)
        self.assertEqual(len(threads), 2)
        thread_ids = [t["thread_id"] for t in threads]
        self.assertIn("thread_A", thread_ids)
        self.assertIn("thread_B", thread_ids)

        # Delete Thread A
        deleted = delete_thread("thread_A", db_path=self.test_db_path)
        self.assertTrue(deleted)

        # Confirm Thread A is gone and Thread B is intact
        remaining = list_chat_threads(checkpointer=saver)
        remaining_ids = [t["thread_id"] for t in remaining]
        self.assertNotIn("thread_A", remaining_ids)
        self.assertIn("thread_B", remaining_ids)
        self.assertEqual(get_chat_history("thread_A", checkpointer=saver), [])
        self.assertGreater(len(get_chat_history("thread_B", checkpointer=saver)), 0)

    @patch("detection.watch.workflow.invoke")
    def test_watch_pipeline_generates_random_thread_id(self, mock_invoke):
        mock_invoke.return_value = {"messages": [AIMessage(content="Investigation complete")]}

        event1 = {
            "EventID": 1,
            "ProcessId": 5001,
            "Image": "C:\\Windows\\System32\\pcalua.exe",
            "CommandLine": "pcalua.exe -a malware.exe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        }
        res1 = pipeline(event1)
        self.assertEqual(res1, 0)
        self.assertTrue(mock_invoke.called)
        first_call_config = mock_invoke.call_args[1].get("config", {})
        t1 = first_call_config.get("configurable", {}).get("thread_id")
        self.assertIsNotNone(t1)
        self.assertTrue(t1.startswith("thread_"))

        # Clear cache and run a second detection
        clear_alert_cache()
        event2 = {
            "EventID": 1,
            "ProcessId": 5002,
            "Image": "C:\\Windows\\System32\\pcalua.exe",
            "CommandLine": "pcalua.exe -a trojan.exe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        }
        res2 = pipeline(event2)
        self.assertEqual(res2, 0)
        second_call_config = mock_invoke.call_args[1].get("config", {})
        t2 = second_call_config.get("configurable", {}).get("thread_id")
        self.assertIsNotNone(t2)
        self.assertTrue(t2.startswith("thread_"))

        # Assert every detection gets a new, random thread ID
        self.assertNotEqual(t1, t2)


if __name__ == "__main__":
    unittest.main()
