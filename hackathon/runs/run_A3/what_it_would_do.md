# Scenario A3: Encoded PowerShell Download-and-Run

### What we ran (SIMULATED)
A PowerShell command was run with its payload hidden using Base64 encoding. It
downloaded a script from a test server and ran it. The script only writes a
harmless marker file; it does nothing destructive.

### What a real attacker could do next
*Illustrative, based on the documented technique (MITRE ATT&CK T1059.001,
https://attack.mitre.org/techniques/T1059/001/, and T1027,
https://attack.mitre.org/techniques/T1027/).*
1. **Why encoding:** hides the real command from anyone glancing at logs or
   the screen, and can dodge simple text-based filters.
2. **The downloaded script:** in a real attack, usually sets up a remote
   connection back to the attacker (a "beacon"), so they can send further
   commands.
3. **After that:** the attacker can explore the machine, steal files or
   credentials, and move to other devices on the network.

## What Triagent did (simulated attack)
- Alert: "Suspicious PowerShell Encoded Command Patterns" (high) at 10:57:38.
- Investigated the process chain; identified a hidden background `powershell.exe`
  instance executing a Base64 `-EncodedCommand` payload.
- Inspected the decoded script target (`files\lib\update-check.ps1`) and verified
  it was an unsigned script created immediately before launch.
- Confirmed with live system checks that the obfuscated PowerShell process was actively running.
- Asked the operator via HITL whether this hidden encoded PowerShell run was authorized;
  the operator confirmed: "No, I did not authorize it".
- Proposed terminating the live PowerShell process; the operator approved; the process was killed.
- Proposed quarantining `update-check.ps1`; the action was rejected by the engine's
  built-in workspace protection rule (the test ran inside the project folder).
- Verdict: real attack (`true_positive`), high confidence, at 3m 17s.

## What it stopped
The live, hidden high-integrity PowerShell process executing the obfuscated command
(terminating the simulated attacker's active execution thread).

## What it did NOT stop
- The dropped script on disk (`files\lib\update-check.ps1`).
- The execution artifact (`files\state\marker.txt`).
Triagent attempted to quarantine the script, but the action was blocked because the
file was located inside the project repository root.

## Numbers (to the first verdict)
Time: 3m 17s (197s), 26 tool calls across 7 turns, 772,554 tokens (~$0.31).