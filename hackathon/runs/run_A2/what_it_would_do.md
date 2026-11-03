# Scenario A2: Ingress Tool Transfer via certutil

### What we ran (SIMULATED)
A built-in Windows tool was used to download a file named like a program from a
local test server into the user's Temp folder. The file is harmless text and was
never run.

### What a real attacker could do next
*Illustrative, based on the documented technique (MITRE ATT&CK T1105,
https://attack.mitre.org/techniques/T1105/).*
1. **Why this tool:** certutil is already on every Windows PC and is signed by
   Microsoft, so it avoids bringing extra tools that security software may flag.
2. **The download:** the file is usually the next stage of the attack (a remote
   access tool, a ransomware loader, or a password stealer), often named like a
   normal program so it blends in.
3. **After the download:** run it, set it to start again at login, connect back
   to the attacker, and try to disable protection.

## What Triagent did (simulated attack)
Three alerts fired (direct-IP download via certutil, execution of a non-existing
file, shell process spawning a suspicious program). All three investigations
ran, and all three returned false_positive with high confidence. No action was
proposed and nothing was blocked.

## What it stopped
Nothing. This attack was not stopped.

## What it did NOT stop
The simulated download was allowed to complete, and no human was asked to confirm.

## Why we believe it was missed
I suggested a plain-text payload, and that was a poor choice. get_file_signature returned UnknownError on the downloaded file, which is what you’d see for a file that isn’t a real program. A real dropper is an unsigned executable. Use a real, harmless, unsigned program that does nothing (compile a tiny “hello” console app).
The attacker server is on a private address, which reads as “internal and safe.” Real attacks use public addresses. Note this limit in the paper.
The agent never asked you. In A1 it asked, and here it called three high-severity downloads false positives without any confirmation, with high confidence.

We are documenting this as an honest limitation rather than
re-staging the test to force a pass.

## Numbers
3 alerts, time to verdict 57s / 1m8s / 1m45s, combined cost ~$0.30.