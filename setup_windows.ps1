$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python Launcher (py) was not found. Install Python 3.11+ with the launcher enabled.'
}

if (-not (Test-Path '.venv\Scripts\python.exe')) {
    py -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -c "from core import init_db, ensure_keys; ensure_keys(); init_db(); print('FieldSure setup complete')"
.\.venv\Scripts\python.exe generate_demo_images.py
Write-Host ''
Write-Host 'Setup complete. Run .\run_windows.bat to launch FieldSure.' -ForegroundColor Green
