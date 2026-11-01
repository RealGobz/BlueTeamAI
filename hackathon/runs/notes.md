# Troubleshooting & Setup Notes: Windows 10/11 VMs

This document explains the two common Windows issues encountered during initial execution and how they are handled.

---

## Issue 1: PowerShell Script Execution Policy

### Error
```text
setup.ps1 cannot be loaded because running scripts is disabled on this system.
For more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
```

### Cause
Fresh Windows installations have a default execution policy of `Restricted`, which prohibits executing `.ps1` scripts directly from the shell without explicit permission.

### Solutions

#### Option A: Zero-Friction Launcher (Recommended)
Use the newly provided `setup.bat` launcher from CMD or PowerShell:
```cmd
.\setup.bat
```
or to run a specific attack scenario:
```cmd
.\setup.bat -Scenario A1
```
*Why this works*: Batch files (`.bat`) are not subject to PowerShell execution policy and invoke PowerShell internally using `-ExecutionPolicy Bypass`.

#### Option B: PowerShell Process-Level Bypass
Run the script passing the `-ExecutionPolicy Bypass` parameter:
```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1 -Scenario A1
```
Or temporarily enable execution for your current PowerShell terminal session:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup.ps1 -Scenario A1
```

---

## Issue 2: Windows App Execution Alias (Decoy `python.exe`)

### Error
```text
C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main> .\setup.ps1
==========================================================
 BlueTeamAI: Windows Setup & Live Runner
==========================================================

[1/8] Checking Python virtual environment (.venv)...
python.exe : Python was not found; run without arguments to install from the Microsoft Store, or
disable this shortcut from Settings > Apps > Advanced app settings > App execution aliases.
At C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\setup\setup.ps1:65 char:18
+ $PythonVersion = & $PythonCmd.Source --version 2>&1
+                  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (Python was not ...cution aliases.:String) [], Remote Exception
    + FullyQualifiedErrorId : NativeCommandError
```

### Cause
1. Windows 10 & 11 include default 0 KB execution redirectors located in:
   `%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe`
2. If Python 3.10+ is not yet installed (or was installed without checking *"Add python.exe to PATH"*), `Get-Command python.exe` resolves to this Microsoft Store redirector.
3. Querying `--version` on the shim writes an error to standard error. In PowerShell with `$ErrorActionPreference = "Stop"`, any stderr output is caught as a fatal `NativeCommandError`.

### How It Is Resolved

1. **Intelligent Python Discovery (`Get-RealPython`)**:
   - `setup/setup.ps1` now explicitly filters out any binaries located in `*WindowsApps*`.
   - It queries `py.exe -3 -c "import sys; print(sys.executable)"` to directly locate active interpreters.
   - It scans standard Windows installation locations (`LOCALAPPDATA\Programs\Python\Python31*`, `ProgramFiles\Python31*`, `C:\Python31*`).
   - It evaluates candidates under `$ErrorActionPreference = "Continue"` to prevent premature script aborts.

2. **Automatic Installation Fallback**:
   - If no real Python interpreter is found, the script automatically triggers `winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements`.
   - If `winget` is unavailable, it outputs a clean installation message with direct links.

### Manual Python Installation (If needed)
In an elevated PowerShell terminal:
```powershell
winget install -e --id Python.Python.3.12
```
Or download from: https://www.python.org/downloads/ (ensure **"Add python.exe to PATH"** is selected).