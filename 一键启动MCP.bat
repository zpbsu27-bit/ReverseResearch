@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
title ReverseResearch MCP
cd /d "%~dp0."
if errorlevel 1 goto root_error

set "RR_ROOT=%~dp0."
set "RR_ARTIFACT_MODULE=%~dp0tools\ops\runtime-artifact.psm1"
set "RR_EXE="
for /f "delims=" %%E in ('powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; Import-Module $env:RR_ARTIFACT_MODULE; Resolve-RRInstalledArtifact -Root $env:RR_ROOT"') do set "RR_EXE=%%E"
if exist "%RR_EXE%" goto start_mcp

echo [ERROR] Installed MCP executable not found. Build and promote the candidate first.
pause
exit /b 1

:root_error
echo [ERROR] Cannot open the project directory.
pause
exit /b 1

:start_mcp
echo [START] "%RR_EXE%"
echo [INFO] Press Ctrl+C to stop. Use --tunnel to enable the configured tunnel.
"%RR_EXE%" serve %*
set "RR_EXIT=%ERRORLEVEL%"
if "%RR_EXIT%"=="0" (
    echo [STOP] MCP service stopped.
) else (
    echo [ERROR] MCP exited with code %RR_EXIT%. See the log above.
)
pause
exit /b %RR_EXIT%
