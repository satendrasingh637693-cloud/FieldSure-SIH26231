$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$wheelDir = Join-Path $PSScriptRoot 'offline_wheels'
New-Item -ItemType Directory -Force -Path $wheelDir | Out-Null
if (-not (Test-Path '.venv\Scripts\python.exe')) { py -m venv .venv }
.\.venv\Scripts\python.exe -m pip download --only-binary=:all: --dest $wheelDir -r requirements.txt
Write-Host "Offline wheel bundle prepared in $wheelDir" -ForegroundColor Green
