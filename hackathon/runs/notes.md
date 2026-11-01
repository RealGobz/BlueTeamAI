] HITL Approval Server active on http://127.0.0.1:8765/ (Background Thread)
[+] Main Investigation UI active at: http://127.0.0.1:8766/
[*] Investigation Web UI active at: http://127.0.0.1:8766
[*] Live Sysmon listener active on channel: Microsoft-Windows-Sysmon/Operational
[*] Loaded 619 Sigma detection rules.
[*] Watching Windows activity in real time (Press Ctrl+C to stop)...
detected a suspicious event... calling the agent.
[*] Starting agent investigation with thread_id: thread_b982fff0d9674dc98d58529e571ba1b6
[*] Agent invoked tool 'plan' with args: {'steps': ['Test the hypothesis that the double-extension executable is a masqueraded command shell used for phishing-driven execution and persistence, while considering an authorized simulation as an alternative.', 'Reconstruct the process lineage and enumerate descendants to determine how the file was launched and what it spawned.', 'Review process-scoped and nearby timeline events for file creation, registry Run-key persistence, network activity, and follow-on execution.', 'Assess local prevalence, on-disk identity, hash continuity, digital signature, and global hash reputation.', 'Check whether the process remains active and inspect live connections if applicable.', 'Use rule context and collected evidence to classify the alert; propose containment only if malicious activity is strongly supported, then submit a structured verdict.']}
[*] Agent invoked tool 'get_process_tree' with args: {'guid': '{b10b9455-dc47-6ae6-d003-000000000700}'}
[*] Agent invoked tool 'get_children' with args: {'guid': '{b10b9455-dc47-6ae6-d003-000000000700}', 'depth': 3}
[*] Agent invoked tool 'get_events_for_process' with args: {'guid': '{b10b9455-dc47-6ae6-d003-000000000700}'}
[*] Agent invoked tool 'get_events_by_hash' with args: {'sha256': '97AC98B1A92C286054CCE55239CFCCDFC23A5517BD07FE693072C9CA96C7DABB', 'limit': 20}
[*] Agent invoked tool 'get_rule_context' with args: {'rule_id': '1cdd9a09-06c9-4769-99ff-626e2b3991b8'}
[*] Agent invoked tool 'get_file_info' with args: {'path': 'C:\\Users\\lilyb\\Downloads\\Invoice_Payment_Due.pdf.exe', 'expected_sha256': '97AC98B1A92C286054CCE55239CFCCDFC23A5517BD07FE693072C9CA96C7DABB'}
[*] Agent invoked tool 'get_file_signature' with args: {'path': 'C:\\Users\\lilyb\\Downloads\\Invoice_Payment_Due.pdf.exe'}
[*] Agent invoked tool 'is_process_running' with args: {'guid': '{b10b9455-dc47-6ae6-d003-000000000700}'}
[*] Agent invoked tool 'lookup_hash' with args: {'sha256': '97AC98B1A92C286054CCE55239CFCCDFC23A5517BD07FE693072C9CA96C7DABB'}
[*] Agent invoked tool 'get_events_in_window' with args: {'start': '2026-11-01T06:05:00Z', 'end': '2026-11-01T06:35:00Z', 'row_limit': 200}
[*] Agent invoked tool 'get_live_connections' with args: {'guid': '{b10b9455-dc47-6ae6-d003-000000000700}'}
[*] Agent invoked tool 'get_events_for_process' with args: {'guid': '{b10b9455-d965-6ae6-8a03-000000000700}'}
[*] Agent invoked tool 'get_children' with args: {'guid': '{b10b9455-dc47-6ae6-d003-000000000700}', 'depth': 3}
[*] Agent invoked tool 'get_file_info' with args: {'path': 'C:\\Users\\lilyb\\AppData\\Local\\Temp\\svchost_updater.bat'}
Error during alert investigation for thread 'thread_b982fff0d9674dc98d58529e571ba1b6': Error code: 429 - Your requests to gpt-5.6-sol for agent_llm in eastus have exceeded token rate limit.
Traceback (most recent call last):
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langchain_openai\chat_models\base.py", line 1992, in _generate
    raw_response = self.client.with_raw_response.create(**payload)
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\openai\_legacy_response.py", line 364, in wrapped
    return cast(LegacyAPIResponse[R], func(*args, **kwargs))
                                      ^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\openai\_utils\_utils.py", line 298, in wrapper
    return func(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\openai\resources\chat\completions\completions.py", line 1611, in create
    return self._post(
           ^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\openai\_base_client.py", line 1474, in post
    return cast(ResponseT, self.request(cast_to, opts, stream=stream, stream_cls=stream_cls))
                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\openai\_base_client.py", line 1248, in request
    raise self._make_status_error_from_response(err.response) from None
openai.RateLimitError: Error code: 429 - Your requests to gpt-5.6-sol for agent_llm in eastus have exceeded token rate limit.

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\UI\main\runner.py", line 122, in run_alert_investigation
    result = wf.invoke(initial_state, config=config)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\agent\agent.py", line 760, in _safe_invoke
    return _orig_invoke(input_data, config=cfg, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langgraph\pregel\main.py", line 4000, in invoke
    for chunk in self.stream(
                 ^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langgraph\pregel\main.py", line 3060, in stream
    for _ in runner.tick(
             ^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langgraph\pregel\_runner.py", line 204, in tick
    run_with_retry(
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langgraph\pregel\_retry.py", line 618, in run_with_retry
    return task.proc.invoke(task.input, config)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langgraph\_internal\_runnable.py", line 794, in invoke
    input = context.run(step.invoke, input, config, **kwargs)
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langgraph\_internal\_runnable.py", line 479, in invoke
    ret = self.func(*args, **kwargs)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\agent\agent.py", line 121, in agent_node
    response = agent.invoke(state["messages"])
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langchain_core\runnables\base.py", line 6018, in invoke
    return self.bound.invoke(
           ^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langchain_core\language_models\chat_models.py", line 529, in invoke
    self.generate_prompt(
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langchain_core\language_models\chat_models.py", line 1920, in generate_prompt
    return self.generate(prompt_messages, stop=stop, callbacks=callbacks, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langchain_core\language_models\chat_models.py", line 1727, in generate
    self._generate_with_cache(
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langchain_core\language_models\chat_models.py", line 2065, in _generate_with_cache
    result = self._generate(
             ^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langchain_openai\chat_models\base.py", line 1997, in _generate
    _handle_openai_api_error(e)
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\langchain_openai\chat_models\base.py", line 736, in _handle_openai_api_error
    raise OpenAIRateLimitError(
langchain_openai.chat_models.base.OpenAIRateLimitError: Error code: 429 - Your requests to gpt-5.6-sol for agent_llm in eastus have exceeded token rate limit.
During task with name 'agent_node' and id 'be02e211-8d9d-f305-de7d-edf313521260'

[+] Auto-recorded run to C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\tools\db\conclusion_run.csv:
    Scenario: A1 | Verdict:  | Rule: 1cdd9a09-06c9-4769-99ff-626e2b3991b8 (none) | Turns: 0


[+] Auto-recorded run to C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\tools\db\conclusion_run.csv:
    Scenario: A1 | Verdict:  | Rule: 1cdd9a09-06c9-4769-99ff-626e2b3991b8 (none) | Turns: 0

[-] Agent execution error for thread_b982fff0d9674dc98d58529e571ba1b6: Error code: 429 - Your requests to gpt-5.6-sol for agent_llm in eastus have exceeded token rate limit.

[+] Auto-recorded run to C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\tools\db\conclusion_run.csv:
    Scenario: A1 | Verdict:  | Rule: 1cdd9a09-06c9-4769-99ff-626e2b3991b8 (none) | Turns: 0


[+] Auto-recorded run to C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\tools\db\conclusion_run.csv:
    Scenario: A1 | Verdict:  | Rule: 1cdd9a09-06c9-4769-99ff-626e2b3991b8 (none) | Turns: 0

