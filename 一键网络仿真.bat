@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -File "%~dp0tools\network-lab\run_network_lab.ps1" %*
set "netLabExit=%ERRORLEVEL%"
if not "%netLabExit%"=="0" pause
exit /b %netLabExit%
