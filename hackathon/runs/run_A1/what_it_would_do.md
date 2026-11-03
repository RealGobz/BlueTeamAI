# Scenario A1: Spearphishing Trojan Dropper (.pdf.exe)

### The Real-World Scenario
An accounting employee receives a targeted email with an attachment named `Invoice_Payment_Due.pdf.exe`. Because Windows hides file extensions by default, it appears simply as `Invoice_Payment_Due.pdf` with a PDF icon. The user double-clicks it expecting an invoice.

### What a Real Attacker Does
1. **Decoy & Disguise:** Opens a fake, benign PDF in the foreground to avoid suspicion while malicious code runs silently in the background.
2. **Persistence:** Drops a malicious payload (e.g., script loader or Cobalt Strike beacon DLL) into `%TEMP%` or `%APPDATA%` and registers a Registry Run key (`HKCU\...\Run`) to survive reboots.
3. **Command & Control (C2):** Establishes an encrypted outbound connection to an external attacker server over HTTPS or DNS tunneling.
4. **Impact:** Dumps browser credentials and session tokens, maps internal network shares, moves laterally, and stages ransomware deployment or data theft.

## What Triagent did (simulated attack)
- Alert: "Suspicious Double Extension File Execution" (high) at 07:43:59.
- Investigated the process chain and the file; the file was a genuine Windows
  program renamed to look like a PDF, sitting in Downloads.
- Asked the user whether this was intentional; the answer was "No" (scripted).
- Proposed stopping the process; the user approved; the process was terminated.
- Proposed quarantining the file; the user approved; it was moved out of Downloads.
- Verdict: real attack, high confidence, at 07:46:59 (180 seconds after the alert).
- After the verdict, one follow-up chat request led to a second approved kill.

## What it stopped
The running process (stand-in for the attacker's live connection) and the
disguised file in Downloads.

## What it did NOT stop
- The Run key SystemUpdaterService: it would start the dropped script at next login.
- The dropped script in Temp (svchost_updater.bat).
Triagent listed these as remaining risk. A person must remove them.

## Numbers (to the first verdict)
Time 180s, tool calls 21, cost $0.16.