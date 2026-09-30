$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$release = Join-Path $PSScriptRoot 'release'
$stage = Join-Path $release 'FieldSure'
$zip = Join-Path $release 'FieldSure_SIH_P6_Release.zip'

Remove-Item $release -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage -Force | Out-Null

robocopy $PSScriptRoot $stage /E `
  /XD '.venv' '.git' '__pycache__' '.pytest_cache' 'release' `
  /XF 'field_tests.db' '*.pem' '*.key' '*.p12' 'secrets.toml' '*.zip' 'TST-*.jpg' | Out-Null

# Runtime-generated test evidence should never be bundled.
Get-ChildItem (Join-Path $stage 'images') -Filter 'TST-*.jpg' -ErrorAction SilentlyContinue | Remove-Item -Force

if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force

Write-Host ''
Write-Host 'Release created:' -ForegroundColor Green
Write-Host $zip
Write-Host 'Excluded: .git, .venv, database, private/public PEM keys, secrets.toml, runtime TST images.'
