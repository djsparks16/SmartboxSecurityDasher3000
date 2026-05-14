
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Building Smartbox Security Dasher 3000 EXE..."
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install pyinstaller
pyinstaller --onefile --windowed --name SmartboxSecurityDasher3000 sentinel.py
Write-Host "Done: dist\SmartboxSecurityDasher3000.exe"
