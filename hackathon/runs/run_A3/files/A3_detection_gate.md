# Scenario A3: Detection Gate & Technical Analysis

## MITRE ATT&CK Mapping
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1027**: Obfuscated Files or Information: Base64 Encoded Command

---

## 1. Exact Encoded Command Line
The spawned process executes without displaying the plaintext script or target path on the command line:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand JABTAGMAcgBpAHAAdABQAGEAdABoACAAPQAgACcARgA6AFwAUAByAG8AagBlAGMAdABzAFwAQgBsAHUAZQBUAGUAYQBtAGkAbgBnAEEASQBcAGgAYQBjAGsAYQB0AGgAbwBuAFwAcgB1AG4AcwBcAHIAdQBuAF8AQQAzAFwAZgBpAGwAZQBzAFwAbABpAGIAXAB1AHAAZABhAHQAZQAtAGMAaABlAGMAawAuAHAAcwAxACcAOwAgACYAIAAkAFMAYwByAGkAcAB0AFAAYQB0AGgAOwAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AUwBlAGMAbwBuAGQAcwAgADMAMAAwAA==
```

---

## 2. Plaintext Decoded Command
Decoded from UTF-16LE Base64:

```powershell
$ScriptPath = 'F:\Projects\BlueTeamingAI\hackathon\runs\run_A3\files\lib\update-check.ps1'; & $ScriptPath; Start-Sleep -Seconds 300
```

---

## 3. Key Detection Rule Log Fields
1. **`CommandLine` (Sysmon Event ID 1 / Windows Security 4688)**:
   Detection rules (such as Sigma `proc_creation_win_powershell_base64_encoded_cmd.yml` and `proc_creation_win_powershell_susp_parameter_variation.yml`) primarily match the presence of parameter flags `-EncodedCommand`, `-enc`, or `-e` coupled with UTF-16LE Base64 signatures (specifically the `JAB` prefix that signifies a variable initialization beginning with `$`).
2. **`ParentImage` / `ParentCommandLine`**:
   The parent process executing the PowerShell interpreter (e.g., an interactive console, shell, or background utility) provides vital contextual telemetry allowing the agent or SOC rule to differentiate legitimate enterprise administration scripts from suspicious script execution.

---

## 4. Test Environment Note (Desktop Safety Constraint)
Unlike Scenario A2 which involved an active HTTP server and network download tool transfer via `certutil.exe`, this A3 test replaces an external network download cradle with a locally staged script execution inside `files\` due to workstation safety constraints on an unisolated desktop.
