# Scenario A4: OS Credential Dumping via LSASS Memory

### What we ran (SIMULATED)
A process memory dump command was executed against process memory using built-in
Windows utilities to mimic an attacker extracting cached system credentials. The
simulation runs in a strictly confined test harness and creates a benign dump
marker file without accessing sensitive operating system secrets.

### What a real attacker could do next
*Illustrative, based on the documented technique (MITRE ATT&CK T1003.001,
https://attack.mitre.org/techniques/T1003/001/).*
1. **Why target LSASS:** The Local Security Authority Subsystem Service (`lsass.exe`)
   stores active authentication credentials in memory, including plaintext passwords,
   NTLM password hashes, and Kerberos tickets for logged-in users.
2. **The dump file:** Attackers use built-in tools (like `rundll32.exe comsvcs.dll` or
   `procdump.exe`) to copy LSASS memory into a `.dmp` file on disk, avoiding noisy
   custom malware that antivirus might block immediately.
3. **Offline cracking and lateral movement:** Once the memory file is captured, the
   attacker extracts password hashes and Kerberos tickets offline, allowing them
   to log into other workstations, servers, and domain controllers across the network.

## What Triagent did (simulated attack)
Two alerts fired on the same rundll32/comsvcs.dll MiniDump command line:
"Process Memory Dump Via Comsvcs.DLL" and "LSASS Dump Keyword In CommandLine",
12 seconds apart. Both investigations independently reached true_positive with
high confidence, without needing to ask the user: the agent treated a
comsvcs.dll memory dump command as having no benign explanation on its own,
consistent with how a real analyst would read it.

## What it stopped
The second alert proposed killing the process twice. The target had already
exited by the time of approval (it runs and exits almost immediately once the
dump command completes), and a second attempt returned invalid_input. So in
this run, nothing was actually terminated: the dump command had already
finished running before the agent could act on it. The verdict and the
reasoning were correct either way, but the response step did not succeed in
this particular run.

## What it did NOT stop
In a real attack, the LSASS dump file itself would remain on disk after the
process exits, and no tool in this run attempted to quarantine the dump file
produced by the simulation. We confine the dump to our own test folder on
purpose, so the quarantine's protected-path logic may have refused it here too,
the same as in A3. We treat the dump file as remaining risk: on a real host,
a human must remove or examine this file.

## Numbers
2 alerts, time to verdict 47s and 56s, combined cost ~$0.09.