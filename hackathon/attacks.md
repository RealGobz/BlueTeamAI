# BlueTeamAI Attack Simulations

This directory contains harmless simulation scripts for evaluating BlueTeamAI in a Windows 10/11 VM.

---

## Scenario A1: Trojan Dropper Disguised as Document (.pdf.exe)

- **Behavior**: An employee receives a spearphishing email with a file named `Invoice_Payment_Due.pdf.exe`. Because Windows hides file extensions by default, the file appears as a standard PDF document. When double-clicked, it runs as an executable, drops a secondary payload into `%TEMP%`, and writes a registry Run key for persistence.
- **MITRE ATT&CK**:
  - `T1204.002`: User Execution (Malicious File)
  - `T1547.001`: Persistence (Registry Run Keys / Startup Folder)
  - `T1036.007`: Masquerading (Double Extension)
- **Expected Verdict**: `TRUE_POSITIVE`
- **Detection Signature**: `Suspicious Double Extension File Execution` (`proc_creation_win_susp_double_extension.yml`)

### How to Run:
In the VM, while `watch.py` is running:
```powershell
powershell -ExecutionPolicy Bypass -File .\hackathon\simulate_A1.ps1
```

Or run manually in PowerShell:
```powershell
Copy-Item "C:\Windows\System32\cmd.exe" "$env:USERPROFILE\Downloads\Invoice_Payment_Due.pdf.exe"
Start-Process "$env:USERPROFILE\Downloads\Invoice_Payment_Due.pdf.exe" -ArgumentList '/c "echo test > %TEMP%\test.bat & reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d %TEMP%\test.bat /f & ping 127.0.0.1 -n 45 >nul"'
```
