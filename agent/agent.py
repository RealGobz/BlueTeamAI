import os
import sys
from pathlib import Path
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

load_dotenv()

from azure.identity import DefaultAzureCredential
from langchain_azure_ai.chat_models import AzureAIChatCompletionsModel
import json
from typing import Any
from langchain_core.messages import SystemMessage, ToolMessage, HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import MessagesState, START, END, StateGraph
from agent.tools import get_tools
from config import (
    SYSTEM_PROMPT,
    HITL_TOOLS,
    END_TOOLS,
    RESPOND_TOOLS,
    LLM_TOOL_CHOICE,
    MAX_TURNS_PER_ALERT,
    MAX_RESUMES_PER_THREAD,
    MEMORY_DB_PATH,
    RESULTS_DB_PATH,
    DRY_RUN,
    DB_PATH,
    AUDIT_LOG_PATH,
    QUARANTINE_DIR,
    QUARANTINE_AUDIT_LOG_PATH,
    HITL_DB_PATH,
    HITL_TIMEOUT_SECONDS,
    HITL_CONTINUE_TIMEOUT_SECONDS,
    ASK_USER_TIMEOUT_SECONDS,
    MAX_CONTINUES_PER_THREAD,
    HITL_MODE,
)
from utils import (
    format_approval_screen,
    format_quarantine_approval_screen,
    format_ask_user_system_context,
    terminate_process,
    quarantine_file_action,
    validate_ask_user_input,
    validate_respond_input,
)
from UI.HITL.server import request_tool_approval, request_continue, request_ask_user
from UI.HITL.store import compute_action_hash, find_prior_rejection
from agent.memory import (
    get_memory_saver,
    generate_thread_id,
    get_chat_history,
    list_chat_threads,
    get_thread_state,
    delete_thread,
)
from agent.results_db import record_incomplete_verdict
from agent.verdict import process_verdict_submission


PROJECT_ENDPOINT = os.getenv("PROJECT_ENDPOINT")
LLM_DEPLOYMENT_NAME = os.getenv("LLM_DEPLOYMENT_NAME", "agent_llm")
PROJECT_LOCATION = os.getenv("PROJECT_LOCATION")
AZURE_API_KEY = os.getenv("AZURE_OPENAI_API_KEY") or os.getenv("AZURE_AI_KEY") or os.getenv("PROJECT_KEY")

if AZURE_API_KEY:
    from azure.core.credentials import AzureKeyCredential
    credential = AzureKeyCredential(AZURE_API_KEY)
else:
    credential = DefaultAzureCredential()

endpoint = PROJECT_ENDPOINT
if endpoint:
    if "/api/projects/" in endpoint:
        endpoint = endpoint.split("/api/projects/")[0]
        if ".services.ai.azure.com" in endpoint:
            endpoint = endpoint.replace(".services.ai.azure.com", ".cognitiveservices.azure.com")
        endpoint = endpoint.rstrip("/") + "/openai/v1"
    elif not endpoint.endswith("/openai/v1"):
        endpoint = endpoint.rstrip("/") + "/openai/v1"

llm = AzureAIChatCompletionsModel(
    endpoint=endpoint,
    credential=credential,
    model_name=LLM_DEPLOYMENT_NAME, 
)

tools, mapping = get_tools()
agent = llm.bind_tools(tools, tool_choice=LLM_TOOL_CHOICE)

class AgentState(MessagesState):
    alert: dict
    sigma_rule: dict
    plan: list[str]
    turns: int
    continues: int
    verdict_status: str
    verdict_retries: int
    resumes: int
    thread_id: str
    awaiting_reply: bool
    reply_sent: bool


#nodes

def agent_node(state: AgentState):
    if not state["messages"]:
        plan_val = state.get("plan")
        prompt = SYSTEM_PROMPT.format(
            alert=state["alert"],
            sigma_rule=state["sigma_rule"],
            plan=plan_val if plan_val else "[]",
        )
        state["messages"].append(SystemMessage(content=prompt))
    
    response = agent.invoke(state["messages"])
    return {"messages": [response]}

def classify_tools_router(state: AgentState):
    if not state.get("messages"):
        return END
    last_message = state["messages"][-1]
    tool_calls = getattr(last_message, "tool_calls", None)
    if not tool_calls:
        return END

    tool_names = [tc["name"] for tc in tool_calls]
    # Route to respond_node ONLY if every tool call in the message is respond
    if all(name in RESPOND_TOOLS for name in tool_names):
        return "respond_node"
    elif any(name in END_TOOLS for name in tool_names):
        return "verdict_node"
    elif any(name in HITL_TOOLS for name in tool_names):
        return "hitl_tool_node"
    else:
        return "tools_node"

def hitl_tool_node(state: AgentState, config: RunnableConfig | None = None):
    """
    Human-In-The-Loop node for sensitive operations (e.g., kill_process, quarantine_file).
    Runs safety pre-checks before contacting the human.
    If pre-checks pass, checks prior rejection or requests human approval via local UI.
    Only approved actions are executed.
    """
    tool_calls = state["messages"][-1].tool_calls
    outputs = []

    cfg = config or {}
    configurable = cfg.get("configurable", {})
    thread_id = configurable.get("thread_id") or state.get("thread_id") or ""

    alert = state.get("alert") or {}
    sigma_rule = state.get("sigma_rule") or {}
    alert_event = alert.get("event") or {}
    alert_guid = alert_event.get("process_guid") or alert.get("process_guid") or alert.get("ProcessGuid")

    db_path = DB_PATH
    audit_path = AUDIT_LOG_PATH
    quarantine_dir = QUARANTINE_DIR
    quarantine_audit_path = QUARANTINE_AUDIT_LOG_PATH
    hitl_db_path = HITL_DB_PATH

    has_ask_user = any(tc["name"] == "ask_user" for tc in tool_calls)
    ask_user_executed = False

    for tc in tool_calls:
        tool_name = tc["name"]
        raw_args = dict(tc.get("args", {}))

        # Mixed tool call protection:
        # If ask_user is in this message, execute ONLY the first ask_user and answer all others with:
        # {"status": "not_executed", "reason": "call this tool after the answer"}
        if has_ask_user:
            if tool_name == "ask_user" and not ask_user_executed:
                pass
            else:
                outputs.append(
                    ToolMessage(
                        content=json.dumps({"status": "not_executed", "reason": "call this tool after the answer"}),
                        tool_call_id=tc["id"],
                    )
                )
                continue
        elif tool_name not in HITL_TOOLS:
            outputs.append(
                ToolMessage(
                    content=json.dumps({"status": "not_executed", "reason": "call this tool separately"}),
                    tool_call_id=tc["id"],
                )
            )
            continue

        # Purge any model-supplied internal fields
        for field in ("approved", "alert_guid", "thread_id", "db_path", "audit_path", "quarantine_dir", "dry_run", "hitl_db_path"):
            raw_args.pop(field, None)

        if tool_name == "ask_user":
            q_val = raw_args.get("question")
            c_val = raw_args.get("choices")

            is_valid, sanitized, errors = validate_ask_user_input(q_val, c_val)
            if not is_valid:
                res = {"status": "invalid_input", "errors": errors}
                outputs.append(ToolMessage(content=json.dumps(res), tool_call_id=tc["id"]))
                ask_user_executed = True
                continue

            system_ctx = format_ask_user_system_context(alert=alert, rule=sigma_rule, db_path=db_path)
            res = request_ask_user(
                thread_id=thread_id,
                question=sanitized["question"],
                choices=sanitized["choices"],
                alert=alert,
                rule=sigma_rule,
                system_context=system_ctx,
                db_path=hitl_db_path,
                timeout=ASK_USER_TIMEOUT_SECONDS,
            )
            outputs.append(ToolMessage(content=json.dumps(res), tool_call_id=tc["id"]))
            ask_user_executed = True
            continue

        if tool_name == "kill_process":
            guid = str(raw_args.get("guid", "")).strip()
            reason = str(raw_args.get("reason", "")).strip()

            # 1. Pre-checks (approved=False): GUID valid, in alert tree, not protected, process alive
            pre_check = terminate_process(
                guid=guid,
                reason=reason,
                alert_guid=alert_guid,
                approved=False,
                dry_run=DRY_RUN,
                db_path=db_path,
                audit_path=audit_path,
                thread_id=thread_id,
            )
            if pre_check.get("status") != "rejected_by_user":
                # Pre-check failed on safety/validity; return failure directly without prompting human
                outputs.append(ToolMessage(content=json.dumps(pre_check), tool_call_id=tc["id"]))
                continue

            # 2. Check if this exact action was previously rejected by user in this thread
            action_hash = compute_action_hash(thread_id, "kill_process", {"guid": guid})
            prior = find_prior_rejection(thread_id, action_hash, db_path=hitl_db_path)
            if prior:
                note = prior.get("note", "") or "Declined"
                res = {
                    "guid": guid,
                    "status": "rejected_by_user",
                    "reason": f"Action was previously rejected by user: {note}",
                }
                outputs.append(ToolMessage(content=json.dumps(res), tool_call_id=tc["id"]))
                continue

            # 3. Solicit approval
            if HITL_MODE == "auto":
                result = terminate_process(
                    guid=guid,
                    reason=reason,
                    alert_guid=alert_guid,
                    approved=True,
                    dry_run=DRY_RUN,
                    db_path=db_path,
                    audit_path=audit_path,
                    thread_id=thread_id,
                )
            else:
                approval_screen = format_approval_screen(
                    guid=guid,
                    reason=reason,
                    alert=alert,
                    rule=sigma_rule,
                    db_path=db_path,
                    dry_run=DRY_RUN,
                )
                print(approval_screen)
                req_res = request_tool_approval(
                    thread_id=thread_id,
                    tool_name="kill_process",
                    tool_args={"guid": guid, "reason": reason},
                    alert=alert,
                    rule=sigma_rule,
                    approval_screen=approval_screen,
                    timeout=HITL_TIMEOUT_SECONDS,
                    db_path=hitl_db_path,
                )
                if req_res.get("decision") in ("approved", "approve"):
                    result = terminate_process(
                        guid=guid,
                        reason=reason,
                        alert_guid=alert_guid,
                        approved=True,
                        dry_run=DRY_RUN,
                        db_path=db_path,
                        audit_path=audit_path,
                        thread_id=thread_id,
                    )
                else:
                    note = req_res.get("note") or req_res.get("reason") or "Declined"
                    reason_msg = (
                        f"Human user rejected the kill_process proposal. Note: {note}"
                        if req_res.get("status") != "expired"
                        else f"Human approval request timed out ({HITL_TIMEOUT_SECONDS}s). Action not permitted."
                    )
                    result = {
                        "guid": guid,
                        "status": "rejected_by_user",
                        "reason": reason_msg,
                    }

            outputs.append(ToolMessage(content=json.dumps(result), tool_call_id=tc["id"]))

        elif tool_name == "quarantine_file":
            path_val = str(raw_args.get("path", "")).strip()
            reason = str(raw_args.get("reason", "")).strip()

            # 1. Pre-checks (approved=False): local file, exists, not protected, in alert tree, hash valid
            pre_check = quarantine_file_action(
                path=path_val,
                reason=reason,
                alert_guid=alert_guid,
                approved=False,
                dry_run=DRY_RUN,
                db_path=db_path,
                quarantine_dir=quarantine_dir,
                audit_path=quarantine_audit_path,
                thread_id=thread_id,
            )
            if pre_check.get("status") != "rejected_by_user":
                outputs.append(ToolMessage(content=json.dumps(pre_check), tool_call_id=tc["id"]))
                continue

            # 2. Check prior rejection
            action_hash = compute_action_hash(thread_id, "quarantine_file", {"path": path_val})
            prior = find_prior_rejection(thread_id, action_hash, db_path=hitl_db_path)
            if prior:
                note = prior.get("note", "") or "Declined"
                res = {
                    "path": path_val,
                    "status": "rejected_by_user",
                    "reason": f"Action was previously rejected by user: {note}",
                }
                outputs.append(ToolMessage(content=json.dumps(res), tool_call_id=tc["id"]))
                continue

            # 3. Solicit approval
            if HITL_MODE == "auto":
                result = quarantine_file_action(
                    path=path_val,
                    reason=reason,
                    alert_guid=alert_guid,
                    approved=True,
                    dry_run=DRY_RUN,
                    db_path=db_path,
                    quarantine_dir=quarantine_dir,
                    audit_path=quarantine_audit_path,
                    thread_id=thread_id,
                )
            else:
                approval_screen = format_quarantine_approval_screen(
                    path=path_val,
                    reason=reason,
                    alert=alert,
                    rule=sigma_rule,
                    db_path=db_path,
                    dry_run=DRY_RUN,
                )
                print(approval_screen)
                req_res = request_tool_approval(
                    thread_id=thread_id,
                    tool_name="quarantine_file",
                    tool_args={"path": path_val, "reason": reason},
                    alert=alert,
                    rule=sigma_rule,
                    approval_screen=approval_screen,
                    timeout=HITL_TIMEOUT_SECONDS,
                    db_path=hitl_db_path,
                )
                if req_res.get("decision") in ("approved", "approve"):
                    result = quarantine_file_action(
                        path=path_val,
                        reason=reason,
                        alert_guid=alert_guid,
                        approved=True,
                        dry_run=DRY_RUN,
                        db_path=db_path,
                        quarantine_dir=quarantine_dir,
                        audit_path=quarantine_audit_path,
                        thread_id=thread_id,
                    )
                else:
                    note = req_res.get("note") or req_res.get("reason") or "Declined"
                    reason_msg = (
                        f"Human user rejected the quarantine_file proposal. Note: {note}"
                        if req_res.get("status") != "expired"
                        else f"Human approval request timed out ({HITL_TIMEOUT_SECONDS}s). Action not permitted."
                    )
                    result = {
                        "path": path_val,
                        "status": "rejected_by_user",
                        "reason": reason_msg,
                    }

            outputs.append(ToolMessage(content=json.dumps(result), tool_call_id=tc["id"]))

    return {"messages": outputs, "turns": state["turns"] + 1}
    
def tools_node(state: AgentState):
    tool_calls = state["messages"][-1].tool_calls
    outputs = []
    updated_plan = None

    for tc in tool_calls:
        tool_name = tc["name"]
        args = tc.get("args", {})

        # Mixed tool call protection: tools_node runs ONLY normal tools
        if tool_name in HITL_TOOLS or tool_name in END_TOOLS or tool_name in RESPOND_TOOLS:
            outputs.append(
                ToolMessage(
                    content=json.dumps({"status": "not_executed", "reason": "call this tool separately"}),
                    tool_call_id=tc["id"],
                )
            )
            continue

        print(f"[*] Agent invoked tool '{tool_name}' with args: {args}")
        output = mapping[tool_name](args)
        if tool_name == "plan" and isinstance(output, dict) and "plan" in output:
            updated_plan = output["plan"]
        outputs.append(ToolMessage(content=json.dumps(output, default=str), tool_call_id=tc["id"]))

    update_dict = {"messages": outputs, "turns": state["turns"] + 1}
    if updated_plan is not None:
        update_dict["plan"] = updated_plan

    return update_dict

def verdict_node(state: AgentState, config: RunnableConfig | None = None):
    """
    Executes submit_verdict, validates the submission, appends the tool result
    to the conversation messages history (preventing API errors on resume), and
    records the verdict to the results database.
    """
    last_msg = state["messages"][-1]
    tool_calls = getattr(last_msg, "tool_calls", [])
    outputs = []

    cfg = config or {}
    configurable = cfg.get("configurable", {})
    thread_id = configurable.get("thread_id") or state.get("thread_id") or "default_thread"

    retries_so_far = state.get("verdict_retries", 0)
    db_path = RESULTS_DB_PATH

    final_status = "recorded"
    for tc in tool_calls:
        tool_name = tc["name"]
        args = tc.get("args", {})

        # Mixed tool call protection: verdict_node runs ONLY END_TOOLS
        if tool_name not in END_TOOLS:
            outputs.append(
                ToolMessage(
                    content=json.dumps({"status": "not_executed", "reason": "call this tool separately"}),
                    tool_call_id=tc["id"],
                )
            )
            continue

        print(f"[*] Agent invoked tool 'submit_verdict' for thread '{thread_id}'")
        output, new_retries = process_verdict_submission(
            args=args,
            thread_id=thread_id,
            alert=state.get("alert", {}),
            sigma_rule=state.get("sigma_rule", {}),
            messages=state.get("messages", []),
            turns=state.get("turns", 0),
            retries_so_far=retries_so_far,
            db_path=db_path,
        )
        retries_so_far = new_retries
        final_status = output.get("status", "recorded")
        outputs.append(ToolMessage(content=json.dumps(output), tool_call_id=tc["id"]))

    return {
        "messages": outputs,
        "turns": state["turns"] + 1,
        "verdict_status": final_status,
        "verdict_retries": retries_so_far,
        "awaiting_reply": False if final_status in ("recorded", "recorded_with_problems") else state.get("awaiting_reply", False),
    }

def respond_node(state: AgentState, config: RunnableConfig | None = None):
    """
    Executes the respond tool call.
    - Executes the first respond call only (extra calls get not_executed).
    - Guard: works only if state['awaiting_reply'] is True.
      Otherwise returns not_executed with 'No user message is waiting. Continue investigating and finish with submit_verdict.'
    - Success: awaiting_reply=False, reply_sent=True, do NOT change turns.
    - not_executed / invalid_input: turns + 1, reply_sent=False, and route through should_continue_router.
    - Every tool call receives a ToolMessage so the thread can be resumed cleanly.
    """
    last_msg = state["messages"][-1]
    tool_calls = getattr(last_msg, "tool_calls", [])
    outputs = []

    awaiting_reply = state.get("awaiting_reply", False)
    executed_respond = False
    reply_success = False

    for tc in tool_calls:
        tool_name = tc.get("name")
        args = tc.get("args", {})

        if tool_name not in RESPOND_TOOLS:
            outputs.append(
                ToolMessage(
                    content=json.dumps({"status": "not_executed", "reason": "call this tool separately"}),
                    tool_call_id=tc["id"],
                )
            )
            continue

        if executed_respond:
            outputs.append(
                ToolMessage(
                    content=json.dumps({"status": "not_executed", "reason": "call this tool separately"}),
                    tool_call_id=tc["id"],
                )
            )
            continue

        # Guard: awaiting_reply must be True
        if not awaiting_reply:
            outputs.append(
                ToolMessage(
                    content=json.dumps({
                        "status": "not_executed",
                        "reason": "No user message is waiting. Continue investigating and finish with submit_verdict.",
                    }),
                    tool_call_id=tc["id"],
                )
            )
            executed_respond = True
            continue

        text_val = args.get("text", "")
        is_valid, sanitized_text, errors = validate_respond_input(text_val)
        if not is_valid:
            outputs.append(
                ToolMessage(
                    content=json.dumps({"status": "invalid_input", "errors": errors}),
                    tool_call_id=tc["id"],
                )
            )
            executed_respond = True
            continue

        outputs.append(
            ToolMessage(
                content=json.dumps({"status": "sent"}),
                tool_call_id=tc["id"],
            )
        )
        executed_respond = True
        reply_success = True

    if reply_success:
        return {
            "messages": outputs,
            "awaiting_reply": False,
            "reply_sent": True,
        }
    else:
        return {
            "messages": outputs,
            "turns": state.get("turns", 0) + 1,
            "reply_sent": False,
        }

def respond_router(state: AgentState):
    if state.get("reply_sent") is True:
        return END
    return should_continue_router(state)

def verdict_router(state: AgentState):
    status = state.get("verdict_status")
    if status in ("recorded", "recorded_with_problems"):
        return END
    else:
        return "agent_node"

def should_continue_router(state: AgentState):
    if state["turns"] >= MAX_TURNS_PER_ALERT:
        return "ask_user_continue"
    else:
        return "agent_node"

def ask_user_continue(state: AgentState, config: RunnableConfig | None = None):
    cfg = config or {}
    configurable = cfg.get("configurable", {})
    thread_id = configurable.get("thread_id") or state.get("thread_id") or "default_thread"
    db_path = RESULTS_DB_PATH
    hitl_db_path = HITL_DB_PATH

    continues_so_far = state.get("continues", 0)
    max_continues = MAX_CONTINUES_PER_THREAD

    # Enforce maximum continues limit per thread
    if continues_so_far >= max_continues:
        print(f"[-] Thread '{thread_id}' reached max continues limit ({max_continues}). Stopping.")
        record_incomplete_verdict(
            thread_id=thread_id,
            alert=state.get("alert", {}),
            sigma_rule=state.get("sigma_rule", {}),
            end_reason="max_turns_user_stopped",
            turns=state.get("turns", 0),
            messages=state.get("messages", []),
            db_path=db_path,
        )
        return {"turns": state.get("turns", MAX_TURNS_PER_ALERT)}

    # Request human decision via HITL Continue interface
    if HITL_MODE == "auto":
        print(f"[*] Auto-continuing thread '{thread_id}' (HITL_MODE=auto).")
        return {"turns": 0, "continues": continues_so_far + 1}

    # Extract tools used and last message for continue review
    messages = state.get("messages") or []
    last_msg_str = ""
    if messages:
        last_msg = messages[-1]
        last_msg_str = str(getattr(last_msg, "content", ""))[:200]

    tools_used = []
    for m in messages:
        tcs = getattr(m, "tool_calls", None)
        if tcs:
            for c in tcs:
                if isinstance(c, dict) and "name" in c and c["name"] not in tools_used:
                    tools_used.append(c["name"])

    req_res = request_continue(
        thread_id=thread_id,
        turns=state.get("turns", 0),
        turn_limit=MAX_TURNS_PER_ALERT,
        continues=continues_so_far,
        max_continues=max_continues,
        plan=state.get("plan"),
        tools_used=tools_used,
        last_message=last_msg_str,
        db_path=hitl_db_path,
        timeout=HITL_CONTINUE_TIMEOUT_SECONDS,
    )

    if req_res.get("decision") == "continue":
        print(f"[+] Human approved continuing thread '{thread_id}'. Resetting turns.")
        return {"turns": 0, "continues": continues_so_far + 1}
    else:
        decision = req_res.get("decision")
        end_reason = "max_turns_user_stopped" if decision == "stop" else "max_turns_no_response"
        print(f"[-] Human decision for thread '{thread_id}': {decision} ({end_reason}).")
        record_incomplete_verdict(
            thread_id=thread_id,
            alert=state.get("alert", {}),
            sigma_rule=state.get("sigma_rule", {}),
            end_reason=end_reason,
            turns=state.get("turns", 0),
            messages=state.get("messages", []),
            db_path=db_path,
        )
        return {"turns": state.get("turns", MAX_TURNS_PER_ALERT)}

def user_approved_continue_turns_router(state: AgentState):
    if state["turns"] != 0:
        return END
    return "agent_node"

# graph 

graph = StateGraph(AgentState)

graph.add_node("agent_node", agent_node)
graph.add_node("hitl_tool_node", hitl_tool_node)
graph.add_node("tools_node", tools_node)
graph.add_node("verdict_node", verdict_node)
graph.add_node("respond_node", respond_node)
graph.add_node("ask_user_continue", ask_user_continue)

graph.add_edge(START, "agent_node")
graph.add_conditional_edges(
    "agent_node",
    classify_tools_router,
    {
        END: END,
        "hitl_tool_node": "hitl_tool_node",
        "tools_node": "tools_node",
        "verdict_node": "verdict_node",
        "respond_node": "respond_node",
    },
)

graph.add_conditional_edges(
    "hitl_tool_node",
    should_continue_router,
    {"ask_user_continue": "ask_user_continue", "agent_node": "agent_node"},
)
graph.add_conditional_edges(
    "tools_node",
    should_continue_router,
    {"ask_user_continue": "ask_user_continue", "agent_node": "agent_node"},
)
graph.add_conditional_edges(
    "verdict_node",
    verdict_router,
    {END: END, "agent_node": "agent_node"},
)
graph.add_conditional_edges(
    "respond_node",
    respond_router,
    {
        END: END,
        "ask_user_continue": "ask_user_continue",
        "agent_node": "agent_node",
    },
)

graph.add_conditional_edges(
    "ask_user_continue",
    user_approved_continue_turns_router,
    {"agent_node": "agent_node", END: END},
)

def create_workflow(checkpointer=None, db_path=MEMORY_DB_PATH):
    """
    Compile and return the agent StateGraph workflow.
    Defaults to LangGraph's persistent SqliteSaver in tools/memory/checkpoints.sqlite.
    """
    if checkpointer is None:
        checkpointer = get_memory_saver(db_path)

    compiled = graph.compile(checkpointer=checkpointer)

    # Wrap invoke so that an automatic random thread_id is generated if not supplied
    _orig_invoke = compiled.invoke

    def _safe_invoke(input_data, config=None, **kwargs):
        cfg = dict(config or {})
        configurable = dict(cfg.get("configurable", {}))
        if "thread_id" not in configurable:
            configurable["thread_id"] = generate_thread_id()
        cfg["configurable"] = configurable
        return _orig_invoke(input_data, config=cfg, **kwargs)

    compiled.invoke = _safe_invoke
    return compiled


# Default persistent workflow instance saving to tools/memory/checkpoints.sqlite
memory_saver = get_memory_saver(MEMORY_DB_PATH)
workflow = create_workflow(checkpointer=memory_saver)


def resume_investigation(
    thread_id: str,
    user_question: str,
    workflow_instance=None,
    max_resumes: int = MAX_RESUMES_PER_THREAD,
) -> dict[str, Any]:
    """
    Resume an investigation on an existing thread_id.
    - Appends user's follow-up question as a HumanMessage to the existing thread.
    - Resets session turn counter.
    - Enforces hard cap on total resumes per thread to prevent runaway loops.
    - Agent continues investigation and writes a revision 2+ verdict on conclusion.
    """
    wf = workflow_instance or workflow
    config = {"configurable": {"thread_id": thread_id}}

    current_state = wf.get_state(config)
    if not current_state or not current_state.values:
        raise ValueError(f"No checkpointed state found for thread_id: '{thread_id}'")

    resumes = current_state.values.get("resumes", 0) + 1
    if resumes > max_resumes:
        raise RuntimeError(f"Thread '{thread_id}' has reached the maximum allowed resumes ({max_resumes}).")

    inputs = {
        "messages": [HumanMessage(content=user_question)],
        "turns": 0,
        "resumes": resumes,
        "verdict_status": "in_progress",
    }
    return wf.invoke(inputs, config=config)


def send_user_message(
    thread_id: str,
    text: str,
    workflow_instance=None,
    max_resumes: int = MAX_RESUMES_PER_THREAD,
) -> dict[str, Any]:
    """
    Send a user chat message to an existing investigation thread.
    - Appends user message as HumanMessage to the existing thread.
    - Sets turns=0, awaiting_reply=True, reply_sent=False, verdict_status='in_progress', verdict_retries=0.
    - Enforces hard cap on total resumes per thread from config (MAX_RESUMES_PER_THREAD).
    - A user message must never auto-approve or answer any pending HITL request.
    """
    wf = workflow_instance or workflow
    config = {"configurable": {"thread_id": thread_id}}

    current_state = wf.get_state(config)
    if not current_state or not current_state.values:
        raise ValueError(f"No checkpointed state found for thread_id: '{thread_id}'")

    resumes = current_state.values.get("resumes", 0) + 1
    if resumes > max_resumes:
        raise RuntimeError(f"Thread '{thread_id}' has reached the maximum allowed resumes ({max_resumes}).")

    inputs = {
        "messages": [HumanMessage(content=text)],
        "turns": 0,
        "awaiting_reply": True,
        "reply_sent": False,
        "verdict_status": "in_progress",
        "verdict_retries": 0,
        "resumes": resumes,
    }
    return wf.invoke(inputs, config=config)

