Shadow Copies Deletion Using Operating Systems Utilities
HIGH
Host:unknown
User:DESKTOP-2UIRK24\USER
Process:C:\Windows\System32\vssadmin.exe
Command:
Copy
"C:\WINDOWS\system32\vssadmin.exe" delete shadows /for=C: /shadow={00000000-0000-0000-0000-000000000000} /quiet
Raw Alert Event
Event data
Copy
{
  "alert_id": "alert-45166c9c",
  "timestamp": "2026-11-03T09:52:40.3204499Z",
  "rule_id": "c947b146-0abc-4c87-9c64-b17e9d7274a2",
  "rule_name": "Shadow Copies Deletion Using Operating Systems Utilities",
  "severity": "high",
  "attack_tags": [
    "attack.impact",
    "attack.stealth",
    "attack.t1070",
    "attack.t1490"
  ],
  "process_guid": "{7e67f797-aee8-6ae9-ac7e-010000002900}",
  "parent_process_guid": "{7e67f797-8636-6ae9-9358-010000002900}",
  "matched_fields": {
    "Image": "C:\\Windows\\System32\\vssadmin.exe",
    "CommandLine": "\"C:\\WINDOWS\\system32\\vssadmin.exe\" delete shadows /for=C: /shadow={00000000-0000-0000-0000-000000000000} /quiet "
  },
  "event": {
    "event_id": 1,
    "process_id": 11336,
    "process_guid": "{7e67f797-aee8-6ae9-ac7e-010000002900}",
    "image": "C:\\Windows\\System32\\vssadmin.exe",
    "command_line": "\"C:\\WINDOWS\\system32\\vssadmin.exe\" delete shadows /for=C: /shadow={00000000-0000-0000-0000-000000000000} /quiet ",
    "user": "DESKTOP-2UIRK24\\USER",
    "computer": "DESKTOP-2UIRK24"
  },
  "parent_process": {
    "parent_process_id": 20592,
    "parent_process_guid": "{7e67f797-8636-6ae9-9358-010000002900}",
    "parent_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "parent_command_line": "\"C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe\" "
  },
  "raw_event": {
    "EventID": 1,
    "Provider": "Microsoft-Windows-Sysmon",
    "TimeCreated": "2026-11-03T09:52:40.3204499Z",
    "Computer": "DESKTOP-2UIRK24",
    "RecordID": 124432,
    "RuleName": "-",
    "UtcTime": "2026-11-03 09:52:40.318",
    "ProcessGuid": "{7e67f797-aee8-6ae9-ac7e-010000002900}",
    "ProcessId": 11336,
    "Image": "C:\\Windows\\System32\\vssadmin.exe",
    "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)",
    "Description": "Command Line Interface for Microsoft\u00ae Volume Shadow Copy Service ",
    "Product": "Microsoft\u00ae Windows\u00ae Operating System",
    "Company": "Microsoft Corporation",
    "OriginalFileName": "VSSADMIN.EXE",
    "CommandLine": "\"C:\\WINDOWS\\system32\\vssadmin.exe\" delete shadows /for=C: /shadow={00000000-0000-0000-0000-000000000000} /quiet ",
    "CurrentDirectory": "F:\\Projects\\BlueTeamingAI\\",
    "User": "DESKTOP-2UIRK24\\USER",
    "LogonGuid": "{7e67f797-bccf-6ae6-abfa-050000000000}",
    "LogonId": "0x5faab",
    "TerminalSessionId": "1",
    "IntegrityLevel": "High",
    "Hashes": "MD5=B58073DB8892B67A672906C9358020EC,SHA256=8C1FABCC2196E4D096B7D155837C5F699AD7F55EDBF84571E4F8E03500B7A8B0,IMPHASH=C1EDC431CD345F0A0F32019895D13FCE",
    "ParentProcessGuid": "{7e67f797-8636-6ae9-9358-010000002900}",
    "ParentProcessId": 20592,
    "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "ParentCommandLine": "\"C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe\" ",
    "ParentUser": "DESKTOP-2UIRK24\\USER"
  },
  "thread_id": "thread_31352affe5314d3988f815bb202e516a"
}
Investigation Plan
Reconstruct the full PowerShell-to-vssadmin process lineage and determine what launched the PowerShell parent.
Inspect vssadmin, its PowerShell parent, and descendants for related commands, files, registry changes, DNS, or network activity.
Review events around 2026-11-03 09:52:40Z for ransomware-like behavior, additional backup deletion, scripting, encryption, or persistence.
Validate the vssadmin binary on disk, its signature, hash prevalence, global reputation, and whether the process remains active.
Review Sigma rule context and public documentation for this exact deletion pattern, including the all-zero shadow ID.
Use technical evidence to decide whether this was malicious; ask only whether the administrator explicitly authorized this backup deletion if forensic evidence remains ambiguous.
If confirmed malicious and still actionable, propose containment, then submit a structured verdict.
get_process_tree
ok
Arguments:
Copy
guid: {7e67f797-aee8-6ae9-ac7e-010000002900}
View tool output
get_children
ok
Arguments:
Copy
guid: {7e67f797-aee8-6ae9-ac7e-010000002900}
depth: 3
View tool output
get_events_for_process
ok
Arguments:
Copy
guid: {7e67f797-aee8-6ae9-ac7e-010000002900}
View tool output
get_events_for_process
ok
Arguments:
Copy
guid: {7e67f797-8636-6ae9-9358-010000002900}
View tool output
get_events_in_window
ok
Arguments:
Copy
start: 2026-11-03T09:47:40Z
end: 2026-11-03T09:57:40Z
event_id: None
row_limit: 200
View tool output
get_rule_context
ok
Arguments:
Copy
rule_id: c947b146-0abc-4c87-9c64-b17e9d7274a2
View tool output
get_process_tree
ok
Arguments:
Copy
guid: {7e67f797-8636-6ae9-9358-010000002900}
View tool output
get_children
ok
Arguments:
Copy
guid: {7e67f797-8636-6ae9-9358-010000002900}
depth: 3
View tool output
get_events_for_process
ok
Arguments:
Copy
guid: {7e67f797-aee7-6ae9-9e7e-010000002900}
View tool output
get_file_info
ok
Arguments:
Copy
path: C:\Windows\System32\vssadmin.exe
expected_sha256: 8C1FABCC2196E4D096B7D155837C5F699AD7F55EDBF84571E4F8E03500B7A8B0
View tool output
get_file_signature
ok
Arguments:
Copy
path: C:\Windows\System32\vssadmin.exe
View tool output
get_file_info
ok
Arguments:
Copy
path: F:\Projects\BlueTeamingAI\hackathon\runs\run_A5\files\lib\backup-cleaner.ps1
expected_sha256:
View tool output
get_file_signature
ok
Arguments:
Copy
path: F:\Projects\BlueTeamingAI\hackathon\runs\run_A5\files\lib\backup-cleaner.ps1
View tool output
get_events_by_hash
ok
Arguments:
Copy
sha256: 8C1FABCC2196E4D096B7D155837C5F699AD7F55EDBF84571E4F8E03500B7A8B0
limit: 20
View tool output
lookup_hash
ok
Arguments:
Copy
sha256: 8C1FABCC2196E4D096B7D155837C5F699AD7F55EDBF84571E4F8E03500B7A8B0
View tool output
is_process_running
ok
Arguments:
Copy
guid: {7e67f797-aee8-6ae9-ac7e-010000002900}
View tool output
is_process_running
ok
Arguments:
Copy
guid: {7e67f797-8636-6ae9-9358-010000002900}
View tool output
exa_search
ok
Arguments:
Copy
query: vssadmin delete shadows /shadow={00000000-0000-0000-0000-000000000000} meaning ransomware
num_results: 3
View tool output
Output text
Copy
{"query": "vssadmin delete shadows /shadow={00000000-0000-0000-0000-000000000000} meaning ransomware", "status": "success", "results": [{"title": "vssadmin delete shadows | Microsoft Learn", "url": "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-delete-shadows", "published_date": "2026-09-08T00:00:00.000Z", "snippet": "# vssadmin delete shadows | Microsoft Learn\n\nDeletes a specified volume's shadow copies. You can only delete shadow copies with the client-accessible type.\n\nNote\n\nIf you encounter the error \"Error: Snapshots were found, but they were outside of your allowed context,\" the shadow copies are not client-accessible and cannot be deleted with `vssadmin`. Use the diskshadow command instead to manage and delete those shadow copies.\n\n## Syntax\n\n```\nvssadmin delete shadows /for= [/oldest | /all | /shadow=] [/quiet]\n\n```\n\n### Parameters\n\n| Parameter | Description |\n| --- | --- |\n| /for=`` | Specifies which volume's shadow copy will be deleted. |\n| /oldest | Deletes only the oldest shadow copy. |\n| /all | Deletes all of the specified volume's shadow copies. |\n| /shadow=`` | De"}, {"title": "| CISA", "url": "https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0097", "published_date": "", "snippet": "| CISA\n\n### Details\n\n- ID: CM0097\n- Version: 1.0\n- Created: 14 March 2025\n- Modified: 14 March 2025\n- Type: Examine\n- Status: Active\n\n### Intended Outcome\n\nDetecting the deletion of shadow copies will alert defenders to an adversary attempting to destroy volume backups.\n\n### Introduction\n\nShadow copies are a form of Windows data backup. Ransomware actors commonly attempt to delete shadow copies before deploying ransomware to inhibit system recovery and make victim data inaccessible until a ransom is paid. This is typically accomplished using native Windows binaries (Vssadmin.exe, PowerShell.exe, and WMIC.exe).\n\n### Preparation\n\n- Ensure systems are frequently performing backups. Backups should be securely stored on a separate device that is inaccessible from the network. \n- Ensure comprehe"}, {"title": "CAR-2021-01-009: Detecting Shadow Copy Deletion or Resize | MITRE Cyber Analytics Repository", "url": "https://car.mitre.org/analytics/CAR-2021-01-009/", "published_date": "", "snippet": "CAR-2021-01-009: Detecting Shadow Copy Deletion or Resize | MITRE Cyber Analytics Repository\n\n# CAR-2021-01-009: Detecting Shadow Copy Deletion or Resize\n\nSubmission Date: 2020/12/11\n\nUpdate Date: 2022/02/03\n\nInformation Domain: Host\n\nData Subtypes: Process\n\nAnalytic Type: TTP\n\nApplicable Platforms: Windows\n\nContributors: Cyware Labs, Lucas Heiligenstein\n\n After compromising a network of systems, threat actors often try to delete/resize Shadow Copy in an attempt to prevent administrators from restoring the systems to versions present before the attack. This is often done via vssadmin, a legitimate Windows tool to interact with shadow copies. This action is often employed by ransomware, may lead to a failure in recovering systems after an attack. The pseudo code detection focus on Windows S"}], "total_results": 3, "from_cache": false, "fetched_at": "2026-11-03T09:53:17.961372+00:00"}
is_process_running
ok
Arguments:
Copy
guid: {7e67f797-aee7-6ae9-9e7e-010000002900}
View tool output
get_live_connections
ok
Arguments:
Copy
guid: {7e67f797-aee7-6ae9-9e7e-010000002900}
View tool output
get_children
ok
Arguments:
Copy
guid: {7e67f797-aee7-6ae9-9e7e-010000002900}
depth: 3
View tool output
get_events_by_hash
ok
Arguments:
Copy
sha256: 5ECF379FC40967B67739D53123FFE7A5CDF346E6B4168A2E06DFE2C36FADCF7C
limit: 20
View tool output
lookup_hash
ok
Arguments:
Copy
sha256: 5ECF379FC40967B67739D53123FFE7A5CDF346E6B4168A2E06DFE2C36FADCF7C
View tool output
kill_process: {7e67f797-aee7-6ae9-9e7e-010000002900}
You approved
Reason: This elevated hidden PowerShell process is running a newly created unsigned backup-cleaner.ps1 immediately alongside the seventh repeated vssadmin shadow-copy deletion. The behavior destroys recovery data and matches ransomware impact/defense-evasion activity.
Action payload
Copy
Process PID 2668 ('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') was successfully terminated and confirmed gone.
Real attack
HIGH
Confidence: high
Category: defense_evasion
An elevated hidden PowerShell script repeatedly invoked Windows backup-deletion tooling, attempting to remove recovery snapshots. This is confirmed destructive activity, although file encryption was not observed.
A long-lived elevated PowerShell session repeatedly created a new script named backup-cleaner.ps1, launched it hidden, and invoked vssadmin seven times between 07:00 and 09:52 UTC. The alert-time command silently targeted a C: shadow copy; VSSVC started immediately afterward, confirming interaction with the shadow-copy service. The script was created one second before execution, is unsigned, and its hash is unknown to VirusTotal. The vssadmin binary itself is the genuine Microsoft-signed system utility, showing abuse of a legitimate tool rather than a replaced executable. No child, network, registry, or encryption activity was recorded for the alert process. The alert vssadmin exited, while the associated hidden PowerShell remained live without network connections when checked. Containment was proposed for that live descendant. The repeated destructive pattern is not consistent with a one-off administrative cleanup and directly impairs recovery.

Verified Evidence
[SUSPICIOUS]Seven vssadmin executions from one elevated PowerShell parent used the same quiet shadow-copy deletion command over about three hours. (source: get_children,get_events_by_hash)
[SUSPICIOUS]The parent repeatedly created backup-cleaner.ps1 and launched it with hidden-window and no-profile options immediately before deletion activity. (source: get_events_for_process,get_events_in_window)
[SUSPICIOUS]The script exists, was created at 09:52:39Z just before the alert, is unsigned, and has SHA256 5ECF379F...FADCF7C. (source: get_file_info,get_file_signature)
[NEUTRAL]VirusTotal had never seen the script hash, and local hash history showed no directly recorded runs under that script hash. (source: lookup_hash,get_events_by_hash)
[SUSPICIOUS]VSSVC started immediately after vssadmin, corroborating interaction with the Windows shadow-copy service. (source: get_events_in_window)
[BENIGN]The alert binary is unchanged in System32, validly signed by Microsoft, and had 0 malicious or suspicious VirusTotal detections. (source: get_file_info,get_file_signature,lookup_hash)
[NEUTRAL]The alert vssadmin had exited and showed no children, network, file, registry, or DNS events of its own. (source: is_process_running,get_children,get_events_for_process)
[SUSPICIOUS]The hidden PowerShell script host was still running with no live network connections when checked. (source: is_process_running,get_live_connections)
What Triagent Couldn't Verify
Assumption: The all-zero shadow ID may have caused individual deletion attempts to fail; command success output was not available.
Assumption: The long-lived PowerShell parent is likely the automation source, but its own process-creation record and ancestor were unavailable.
Not checked: PowerShell script contents were not available through the forensic tools.
Not checked: Shadow-copy inventory before and after the commands was not available, so the exact number of deleted snapshots is unknown.
Not checked: No file-encryption telemetry was identified in the reviewed window.
Not checked: The long-lived parent PowerShell process could not be matched to a live process because its GUID was absent from process-creation history.
Recommended Next Steps
Isolate the host while checking for additional ransomware or unauthorized automation.
Preserve and analyze backup-cleaner.ps1 and the project run artifacts offline.
Verify the current shadow-copy and backup state, then restore protection from known-good backups if needed.
Review PowerShell operational logs and the originating session for the missing parent lineage.
Hunt the script hash and deletion command across other endpoints.
Remaining Risk & Threat Status
Threat Active: unknown

Remaining Risk: The unsigned script remains on disk, the unidentified long-lived PowerShell parent may still exist, and other copies or persistence were not ruled out. Shadow copies may already be damaged even though the observed child was addressed.

Revision: 1
Duration: 114s
Turns: 5
Tools Used: 14
did you delete the associated files? I fear they may still be there
get_file_info
ok
Arguments:
Copy
path: F:\Projects\BlueTeamingAI\hackathon\runs\run_A5\files\lib\backup-cleaner.ps1
expected_sha256: 5ECF379FC40967B67739D53123FFE7A5CDF346E6B4168A2E06DFE2C36FADCF7C
View tool output
No—I did not delete or quarantine the associated files; only the running hidden PowerShell process was terminated. I just verified that backup-cleaner.ps1 is still present and unchanged at F:\Projects\BlueTeamingAI\hackathon\runs\run_A5\files\lib\backup-cleaner.ps1, so it should be quarantined or removed after preserving a forensic copy.
so what do i do?
quarantine_file: F:\Projects\BlueTeamingAI\hackathon\runs\run_A5\files\lib\backup-cleaner.ps1
You approved
Reason: This unchanged unsigned script was created immediately before repeated elevated, hidden PowerShell activity that invoked vssadmin seven times to delete shadow copies. Quarantining it prevents reuse while preserving it for forensic recovery.
Action payload
Copy
File 'F:\Projects\BlueTeamingAI\hackathon\runs\run_A5\files\lib\backup-cleaner.ps1' was successfully moved to quarantine and neutralized as '5ECF379FC40967B67739D53123FFE7A5CDF346E6B4168A2E06DFE2C36FADCF7C.quarantine'.
I quarantined the malicious script, so it can no longer run from its original location, and the associated hidden PowerShell process was already stopped. Next, disconnect this PC from the network, verify whether shadow copies/backups were lost, run a full antivirus scan, and have the remaining project run artifacts and PowerShell logs reviewed for other malicious files or persistence.
