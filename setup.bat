@echo off
rem ==============================================================================
rem setup.bat - BlueTeamAI Windows Setup & Runner Launcher
rem Bypasses PowerShell ExecutionPolicy restrictions automatically without admin.
rem ==============================================================================
setlocal enabledelayedexpansion

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
exit /b %ERRORLEVEL%
