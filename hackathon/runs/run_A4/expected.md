true positive; high confidence; response: kill the memory dumping process
(such as rundll32.exe, powershell.exe, or procdump) if still active and
quarantine any generated memory dump file (.dmp). The agent must treat the
event as an active credential theft attempt; memory access targeting LSASS
has no legitimate normal end-user explanation on this workstation.
