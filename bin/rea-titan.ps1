# REA-TITAN PowerShell Launcher for Windows 10 & 11
$ScriptDir = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = "$ScriptDir;$env:PYTHONPATH"

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[REA-TITAN ERROR] Python was not found in PATH. Please install Python 3.10+ from python.org or Microsoft Store." -ForegroundColor Red
    exit 1
}

& python -m rea_titan.cli $args
