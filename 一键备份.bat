@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
set "PREVIEW_ARGUMENT="
set "NO_PAUSE=0"
set "EXIT_CODE=0"
set "PROFILE_ARGUMENT="

:parse_arguments
if "%~1"=="" goto :backup
if /i "%~1"=="--full" (
    set "PROFILE_ARGUMENT=-Profile Full"
    shift
    goto :parse_arguments
)
if /i "%~1"=="--preview" (
    set "PREVIEW_ARGUMENT=-Preview"
    shift
    goto :parse_arguments
)
if /i "%~1"=="--no-pause" (
    set "NO_PAUSE=1"
    shift
    goto :parse_arguments
)
echo [错误] 未知参数："%~1"
echo 用法：一键备份.bat [--full] [--preview] [--no-pause]
set "EXIT_CODE=2"
goto :finish

:backup
if not exist "%~dp0tools\ops\backup-source.ps1" (
    echo [错误] 未找到源码备份脚本，请将 BAT 保留在完整项目根目录。
    set "EXIT_CODE=1"
    goto :finish
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\ops\backup-source.ps1" -ProjectRoot "%~dp0." %PROFILE_ARGUMENT% %PREVIEW_ARGUMENT%
set "EXIT_CODE=%ERRORLEVEL%"

:finish
if "%NO_PAUSE%"=="0" pause
exit /b %EXIT_CODE%
