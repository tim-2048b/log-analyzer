# Create .venv and install dependencies (Windows PowerShell)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Write-Host "Done. Activate with: .\.venv\Scripts\Activate.ps1"