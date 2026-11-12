@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
title ReverseResearch MCP Build
set "RR_PAUSE=1"
set "RR_PROMOTE=0"
:read_args
if "%~1"=="" goto args_done
if /I "%~1"=="--no-pause" (
    set "RR_PAUSE=0"
) else if /I "%~1"=="--promote" (
    set "RR_PROMOTE=1"
) else (
    echo [ERROR] Supported arguments: --no-pause --promote
    set "RR_BUILD_EXIT=1"
    goto finish
)
shift /1
goto read_args
:args_done
cd /d "%~dp0."
if errorlevel 1 goto root_error
if not exist "go.mod" goto root_error
if not exist "cmd\reverseresearch\main.go" goto root_error

if defined RR_GO_EXE goto check_go
for /f "delims=" %%G in ('where go.exe 2^>nul') do if not defined RR_GO_EXE set "RR_GO_EXE=%%G"
if defined RR_GO_EXE goto check_go
if exist "%ProgramW6432%\Go\bin\go.exe" set "RR_GO_EXE=%ProgramW6432%\Go\bin\go.exe"
if defined RR_GO_EXE goto check_go
if exist "%ProgramFiles%\Go\bin\go.exe" set "RR_GO_EXE=%ProgramFiles%\Go\bin\go.exe"
if not defined RR_GO_EXE goto go_error

:check_go
if not exist "%RR_GO_EXE%" goto go_error
"%RR_GO_EXE%" version
if errorlevel 1 goto go_error
set "RR_ROOT=%~dp0."
set "RR_ARTIFACT_MODULE=%~dp0tools\ops\runtime-artifact.psm1"
set "RR_BUILD_EXE="
for /f "delims=" %%E in ('powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; Import-Module $env:RR_ARTIFACT_MODULE; (Get-RRArtifactPaths -Root $env:RR_ROOT).Candidate"') do set "RR_BUILD_EXE=%%E"
if not defined RR_BUILD_EXE goto output_error
for %%D in ("%RR_BUILD_EXE%") do if not exist "%%~dpD" mkdir "%%~dpD"
set "GOOS=windows"
set "GOARCH=amd64"
echo [BUILD] Windows amd64 MCP/CLI executable
echo [OUTPUT] "%RR_BUILD_EXE%"
"%RR_GO_EXE%" build -trimpath -buildvcs=false -o "%RR_BUILD_EXE%" .\cmd\reverseresearch
set "RR_BUILD_EXIT=%ERRORLEVEL%"
if not "%RR_BUILD_EXIT%"=="0" goto build_error
if not exist "%RR_BUILD_EXE%" goto output_error

echo [BUILD OK] "%RR_BUILD_EXE%"
set "RR_BUILD_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%RR_BUILD_PS%" goto build_done
"%RR_BUILD_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $f=Get-Item -LiteralPath $env:RR_BUILD_EXE; Write-Output ('[FILE] {0} bytes, updated {1:yyyy-MM-dd HH:mm:ss}' -f $f.Length,$f.LastWriteTime); $s=[IO.File]::OpenRead($f.FullName); $h=[Security.Cryptography.SHA256]::Create(); try{$hash=[BitConverter]::ToString($h.ComputeHash($s)).Replace('-','').ToLowerInvariant()}finally{$s.Dispose();$h.Dispose()}; Write-Output ('[SHA256] '+$hash); Import-Module $env:RR_ARTIFACT_MODULE; $installed=Resolve-RRInstalledArtifact -Root $env:RR_ROOT; Write-Output ('[INSTALLED] '+$installed); $p=Get-Process -Name 'ReverseResearch*' -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $installed -or $_.Path -eq ($installed+'~')}; foreach($x in $p){Write-Output ('[RUNNING] MCP PID {0}, started {1:yyyy-MM-dd HH:mm:ss}' -f $x.Id,$x.StartTime)}; Write-Output '[CANDIDATE] Build does not replace the installed server.'; exit 0"
if errorlevel 1 echo [WARN] Build succeeded; detailed file/process inspection was unavailable.

:build_done
if "%RR_PROMOTE%"=="1" goto promote_build
echo [INFO] Candidate ready. Run this BAT with --promote to publish and gracefully restart.
echo [INFO] The start BAT uses the installed executable, not the candidate.
set "RR_BUILD_EXIT=0"
goto finish

:promote_build
"%RR_BUILD_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\ops\manage-promotion.ps1" -Action Promote -Root "%RR_ROOT%" -Candidate "%RR_BUILD_EXE%"
set "RR_BUILD_EXIT=%ERRORLEVEL%"
if not "%RR_BUILD_EXIT%"=="0" echo [ERROR] Promotion failed. Inspect the release receipt before retrying.
goto finish

:root_error
echo [ERROR] Cannot open the ReverseResearch source directory.
set "RR_BUILD_EXIT=1"
goto finish

:go_error
echo [ERROR] Go was not found or could not run. Install Go, or set RR_GO_EXE to go.exe.
set "RR_BUILD_EXIT=1"
goto finish

:output_error
echo [ERROR] Cannot create the dist output directory or executable.
set "RR_BUILD_EXIT=1"
goto finish

:build_error
echo [ERROR] Go build failed with exit code %RR_BUILD_EXIT%. See the compiler output above.

:finish
if "%RR_PAUSE%"=="1" pause
exit /b %RR_BUILD_EXIT%
