$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path '.venv\Scripts\python.exe')) { py -m venv .venv }
if (-not (Test-Path 'offline_wheels')) { throw 'offline_wheels folder not found. Prepare it on a connected staging machine first.' }
.\.venv\Scripts\python.exe -m pip install --no-index --find-links .\offline_wheels -r requirements.txt
.\.venv\Scripts\python.exe -c "from core import init_db, ensure_keys; ensure_keys(); init_db(); print('Offline installation complete')"
