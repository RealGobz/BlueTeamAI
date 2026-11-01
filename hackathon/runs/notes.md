
PS C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main> .\setup.ps1
==========================================================
 BlueTeamAI: Windows Setup & Live Runner
==========================================================
      Using host Python: Python 3.12.10 (C:\Users\lilyb\AppData\Local\Programs\Python\Python312\python.exe)
      Creating virtual environment in .venv...
      Installing Python requirements (downloading 50+ packages, please wait)...
Collecting pywin32>=306 (from -r C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\requirements.txt (line 3))
  Downloading pywin32-312-cp312-cp312-win_amd64.whl.metadata (11 kB)
Collecting pyyaml>=6.0 (from -r C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\requirements.txt (line 4))
  Downloading pyyaml-6.0.3-cp312-cp312-win_amd64.whl.metadata (2.4 kB)
Collecting python-evtx>=0.7.4 (from -r C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\requirements.txt (line 5))
  Downloading python_evtx-0.8.1-py3-none-any.whl.metadata (6.0 kB)
Collecting python-dotenv (from -r C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\requirements.txt (line 6))
  Downloading python_dotenv-1.2.4-py3-none-any.whl.metadata (29 kB)
Collecting langchain-azure-ai (from -r C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\requirements.txt (line 7))
  Downloading langchain_azure_ai-1.2.12-py3-none-any.whl.metadata (38 kB)
ERROR: Exception:
Traceback (most recent call last):
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\cli\base_command.py", line 106, in _run_wrapper
    status = _inner_run()
             ^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\cli\base_command.py", line 97, in _inner_run
    return self.run(options, args)
           ^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\cli\req_command.py", line 67, in wrapper
    return func(self, options, args)
           ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\commands\install.py", line 386, in run
    requirement_set = resolver.resolve(
                      ^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\resolver.py", line 95, in resolve
    result = self._result = resolver.resolve(
                            ^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\resolvelib\resolvers.py", line 546, in resolve
    state = resolution.resolve(requirements, max_rounds=max_rounds)
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\resolvelib\resolvers.py", line 397, in resolve
    self._add_to_criteria(self.state.criteria, r, parent=None)
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\resolvelib\resolvers.py", line 173, in _add_to_criteria
    if not criterion.candidates:
           ^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\resolvelib\structs.py", line 156, in __bool__
    return bool(self._sequence)
           ^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\found_candidates.py", line 174, in __bool__
    return any(self)
           ^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\found_candidates.py", line 162, in <genexpr>
    return (c for c in iterator if id(c) not in self._incompatible_ids)
                       ^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\found_candidates.py", line 53, in _iter_built
    candidate = func()
                ^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\factory.py", line 187, in _make_candidate_from_link
    base: Optional[BaseCandidate] = self._make_base_candidate_from_link(
                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\factory.py", line 233, in _make_base_candidate_from_link
    self._link_candidate_cache[link] = LinkCandidate(
                                       ^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\candidates.py", line 304, in __init__
    super().__init__(
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\candidates.py", line 159, in __init__
    self.dist = self._prepare()
                ^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\candidates.py", line 248, in _prepare
    self._check_metadata_consistency(dist)
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\resolution\resolvelib\candidates.py", line 230, in _check_metadata_consistency
    list(dist.iter_dependencies(list(dist.iter_provided_extras())))
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\metadata\importlib\_dists.py", line 227, in iter_dependencies
    elif any(req.marker.evaluate(context) for context in contexts):                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^                                   File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_internal\metadata\importlib\_dists.py", line 227, in <genexpr>                                              elif any(req.marker.evaluate(context) for context in contexts):                                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^                                                            File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\packaging\markers.py", line 319, in evaluate
    return _evaluate_markers(
           ^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\packaging\markers.py", line 225, in _evaluate_markers
    groups[-1].append(_eval_op(lhs_value, op, rhs_value))
                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\packaging\markers.py", line 183, in _eval_op
    return spec.contains(lhs, prereleases=True)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\packaging\specifiers.py", line 552, in contains
    normalized_item = _coerce_version(item)
                      ^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\packaging\specifiers.py", line 28, in _coerce_version
    version = Version(version)
              ^^^^^^^^^^^^^^^^
  File "C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\.venv\Lib\site-packages\pip\_vendor\packaging\version.py", line 202, in __init__
    raise InvalidVersion(f"Invalid version: {version!r}")
pip._vendor.packaging.version.InvalidVersion: Invalid version: 'hosting'
      [OK] Python dependencies installed in .venv.

[2/8] Verifying directory structure and runtime storage...
      [EXISTS] C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\tools\db\conclusion_run.csv

[3/8] Checking Microsoft Sysmon configuration & service...
      [EXISTS] sysmonconfig-export.xml in: C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\tools\sysmon
      Downloading Microsoft Sysmon...
      [OK] Extracted Sysmon to: C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\tools\sysmon
      Installing and starting Microsoft Sysmon service...


System Monitor v15.22 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2026 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 4.50
Sysmon schema version: 4.91
Configuration file validated.
Sysmon64 installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon64..
Sysmon64 started.
      [OK] Sysmon service installed and started successfully.

[4/8] Checking sample attack logs in detection/test_data/...
      [EXISTS] exec_sysmon_1_lolbin_pcalua.evtx
      [EXISTS] babyshark_mimikatz_powershell.evtx
      [EXISTS] sysmon_mshta_sharpshooter_stageless_meterpreter.evtx

[5/8] Checking Sigma detection rules database...
      [OK] Found 619 Sigma rules in: C:\Users\lilyb\Downloads\BlueTeamAI-main\BlueTeamAI-main\detection\rules

[6/8] Checking Azure CLI (az) for DefaultAzureCredential...
      [!] Azure CLI not found in PATH. Installing Azure CLI...
Found Microsoft Azure CLI [Microsoft.AzureCLI] Version 2.91.0
This application is licensed to you by its owner.
Microsoft is not responsible for, nor does it grant any licenses to, third-party packages.
Downloading https://azcliprod.blob.core.windows.net/msi/azure-cli-2.91.0-x64.msi
   -











