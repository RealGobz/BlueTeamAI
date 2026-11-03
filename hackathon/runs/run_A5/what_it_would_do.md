# Scenario A5: Inhibiting System Recovery (Shadow Copies Deletion)

### What we ran (SIMULATED)
A command-line execution using built-in Windows administrative utilities
(`vssadmin.exe` / `wmic.exe`) to simulate the deletion of Volume Shadow Copies
and system recovery snapshots. The simulation runs within a confined test harness
and tests detection responsiveness without destroying legitimate user backups or
disrupting operating system stability.

### What a real attacker could do next
*Illustrative, based on the documented technique (MITRE ATT&CK T1490,
https://attack.mitre.org/techniques/T1490/, and T1070,
https://attack.mitre.org/techniques/T1070/).*
1. **Why destroy backups:** Windows Volume Shadow Copies allow users and
   administrators to recover previous versions of modified or encrypted files.
   Ransomware operators intentionally delete them so the victim cannot recover
   their data for free using built-in Windows restore features.
2. **The ransomware precursor:** Deleting shadow copies (such as
   `vssadmin.exe delete shadows /all /quiet` or `wmic shadowcopy delete`) is an
   almost universal warning sign of an impending ransomware deployment (seen in
   LockBit, WannaCry, Conti, and Ryuk). It ensures maximum extortion leverage.
3. **What follows:** Immediately after disabling recovery mechanisms, the
   attacker deploys the file encryption payload across local drives and network
   shares, disables Windows boot recovery options (`bcdedit`), and drops ransom notes
   demanding cryptocurrency payment for decryption keys.
