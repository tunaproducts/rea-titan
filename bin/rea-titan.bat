@echo off
setlocal
set "SCRIPT_DIR=%~dp0.."
set "PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%"

:: Check Python installation
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [REA-TITAN ERROR] Python was not found in PATH. Please install Python 3.10+ and add it to PATH.
    exit /b 1
)

python -m rea_titan.cli %*
endlocal
