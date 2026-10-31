# Next Steps: The Investigator Agent

The detection layer works and produces alerts. This file covers what the agent needs: the questions it answers, the tools it gets, and the order to build them.

---

## 0. Fix first: use ProcessGuid, not process ID

**Problem:** the alert currently has `process_id` (PID) at the top level, but `ProcessGuid` only appears inside `raw_event`.

**Why it matters:** Windows reuses PIDs. After a process ends, a new, unrelated process can get the same number. If the agent looks things up by PID, it can mix up two different processes and reach a wrong conclusion. The GUID is unique to one process run, so it never has this problem.

**Change (small):**
- Add `process_guid` and `parent_process_guid` as top-level fields in the alert (copy them from `ProcessGuid` and `ParentProcessGuid`).
- Keep the PID too. It is still needed to kill a live process, but only after checking the process is still the same one (GUID matches).
- Every agent tool below takes a **GUID** as its input, not a PID, except the response tools at the end, which take both.

Example alert fields after the fix:

```json
{
  "process_guid": "{7e67f797-5fc2-6adf-ba2d-000000002500}",
  "parent_process_guid": "{7e67f797-5ec6-6adf-872d-000000002500}",
  "event": { "process_id": 17276 }
}
```

---

## 1. The 5 questions an analyst asks about every alert

Every tool exists to answer one of these.

1. **Is this normal here?** Who ran it, and does it match something the user would plausibly do?
2. **Where did it come from?** What launched it, and what launched that?
3. **What did it do next?** Child processes, network connections, files written, registry changes.
4. **Is the file itself bad?** Is it signed, and does a reputation service know the hash?
5. **Is it still going?** Is the process alive, or still talking to the network?

Example (the Pcalua alert): PowerShell launched `pcalua.exe -a calc.exe`. Pcalua is a real Windows tool that attackers abuse to launch programs while hiding the true parent. The agent should check what PowerShell did before and after, and whether the launched program is harmless.

---

## 2. Tool groups

### Group 1: Investigation (read-only, safe, no approval needed)

These read from the SQLite event store.

| Tool | Answers | What it does |
|---|---|---|
| `get_process_tree(guid)` | Q2 | Chain of ancestors (parent, grandparent, ...) |
| `get_children(guid)` | Q3 | Processes this process launched |
| `get_events_for_process(guid)` | Q3 | Network connections, file writes, registry changes by this process |
| `get_events_in_window(start, end)` | Q1, Q3 | Everything that happened around the alert time |
| `get_events_by_hash(sha256)` | Q1 | Has this file run elsewhere on the machine? |

### Group 2: Enrichment (read-only, still safe)

| Tool | Answers | What it does |
|---|---|---|
| `check_file_signature(path)` | Q4 | Is the file signed by Microsoft or a known vendor? (PowerShell `Get-AuthenticodeSignature`) |
| `lookup_hash(sha256)` | Q4 | VirusTotal free API: how many antivirus engines flag this hash. Sends only the hash, never the file |
| `is_process_running(guid)` | Q5 | Is the process still alive? |
| `get_live_connections(pid)` | Q5 | Current network connections of a running process |

### Group 3: Response (dangerous, ALWAYS needs human approval)

Start with only these two:

| Tool | What it does |
|---|---|
| `kill_process(guid, pid)` | Terminate the process (only if the GUID still matches the PID) |
| `quarantine_file(path)` | **Move** the file to a locked folder and log it. Never delete, so it can be undone |

Add later, one at a time:

| Tool | What it does |
|---|---|
| `block_ip(address)` | Add a Windows Firewall rule |
| `remove_persistence(...)` | Remove a scheduled task, service, or startup registry key the attack created |
| `isolate_host()` | Cut the network. Most drastic, so keep it last |

---

## 3. Safety rules for Group 3

- **Protected-process list.** The kill tool refuses `lsass.exe`, `csrss.exe`, `winlogon.exe`, `services.exe`, `explorer.exe`, `System`, and similar, no matter what the agent says.
- **The agent cannot call response tools directly.** It returns a *proposed action*. Your code shows it to you and runs it only after you approve.
- **The approval screen shows evidence:** verdict, reasoning, process tree, and the exact action to be run.
- **Log every action:** timestamp, what was done, who approved, and how to undo it.
- **Dry-run mode:** during testing, response tools only print what they would do.

---

## 4. What the agent returns

A structured verdict, not free text:

```json
{
  "verdict": "true_positive | false_positive | needs_more_info",
  "confidence": 0.0,
  "reasoning": "short explanation",
  "evidence": ["parent was PowerShell run by the user", "launched calc.exe only"],
  "proposed_actions": [
    { "tool": "kill_process", "args": { "guid": "{...}", "pid": 17276 } }
  ]
}
```

`needs_more_info` exists on purpose. Forcing a yes/no makes agents guess.

The agent's input for each run is **one alert JSON**. Everything else it learns comes from calling tools.

---

## 5. Build stages

### Stage 0: Alert fix
- Add `process_guid` and `parent_process_guid` to the alert (section 0).
- **Done when:** every new alert has both fields at the top level.

### Stage 1: Group 1 tools (investigation)
- Write the 5 functions against the SQLite store, each with typed inputs and outputs.
- Test them by hand on saved alerts, with no LLM involved.
- **Done when:** for your Pcalua alert, each function returns correct, sensible data.

### Stage 2: Group 2 tools (enrichment)
- Build in this order: `get_rule_context`, `get_file_info`, `check_file_signature`, `is_process_running`, `get_live_connections`, `lookup_hash` (last, needs an API key and rate-limit handling).
- **Done when:** each tool works on its own and fails gracefully (a clear error, never a crash) if the file or process is gone.

### Stage 3: The agent loop (read-only)
- Give the agent the alert plus the Group 1 and 2 tools. No response tools yet.
- Force the structured verdict (section 4), with `proposed_actions` empty or just described in text.
- Set a maximum number of tool calls per alert, to avoid endless loops and runaway cost.
- **Done when:** on a set of saved alerts with known answers, the verdicts are sensible, and every conclusion cites evidence from tool results.

### Stage 4: Evaluation set
- Collect 20 to 50 alerts with known labels: some true attacks (from your friend's simulated attacks and Atomic Red Team in the VM), some false positives (normal admin and developer activity).
- Measure: verdict accuracy, tool calls per alert, cost per alert, and how often it says `needs_more_info`.
- **Done when:** you have numbers, and you've read the cases where the agent was wrong.

### Stage 5: Human approval (HITL) with dry-run response tools
- Build the approval step: the agent proposes, you see the evidence, you approve or reject.
- Implement `kill_process` and `quarantine_file` in **dry-run mode only** (they print, they do not act).
- Add the protected-process list and the action log.
- **Done when:** the whole flow works end to end with dry-run, and rejected actions do nothing.

### Stage 6: Real response, in the VM only
- Turn dry-run off for `kill_process` and `quarantine_file`, inside the VM with a snapshot.
- Test with your friend's simulated attacks.
- **Done when:** approved actions work, rejected actions do nothing, and quarantined files can be restored.

### Stage 7: More response tools
- Add `block_ip`, then `remove_persistence`, then `isolate_host`, one at a time, each tested in the VM first.

### Stage 8: Later phases
- File and malware scanning (Windows Defender log and/or ClamAV), attached to the alert's `enrichment` field.
- UI.

## 6. Where to get blue-team knowledge

- **Your friend (eJPT):** use them for the attacker side. Ask them to run a few techniques on your VM (PowerShell download, creating a scheduled task, dumping credentials) so the agent gets realistic alerts.
- **MITRE ATT&CK:** look up each technique tag in your alerts (for example `T1059`). Each page explains what the attack is and how it is detected.
- **The Sigma rule file itself:** it lists known false positives and references.
- **Atomic Red Team:** tests are labeled by technique, so you know the right answer in advance.