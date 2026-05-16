# EXE Unpacker - Windows PowerShell Launcher
# Run this in PowerShell to launch the application
# Usage: powershell -ExecutionPolicy Bypass -File run.ps1

param(
    [switch]$Setup = $false,
    [switch]$Clean = $false
)

Write-Host "========================================"
Write-Host "  EXE UNPACKER - Launcher"
Write-Host "========================================"
Write-Host ""

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[OK] Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Python 3.8+ from: https://www.python.org/"
    Write-Host "Make sure to check 'Add Python to PATH' during installation"
    Write-Host ""
    pause
    exit 1
}

# Clean old files if requested
if ($Clean) {
    Write-Host "[INFO] Cleaning old files..."
    Remove-Item -Path "$scriptDir\output" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$scriptDir\*.pyc" -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Cleaned" -ForegroundColor Green
}

# Run setup if requested or first time
if ($Setup -or -not (Test-Path "$scriptDir\src\gui.py")) {
    Write-Host "[INFO] Running setup..."
    Write-Host ""
    
    python "$scriptDir\setup.py"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "[ERROR] Setup failed!" -ForegroundColor Red
        pause
        exit 1
    }
}

# Launch the application
Write-Host ""
Write-Host "[INFO] Launching EXE Unpacker..." -ForegroundColor Cyan
Write-Host ""

Set-Location $scriptDir
python main.py

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ERROR] Application crashed!" -ForegroundColor Red
    Write-Host "Check the console output above for details"
    Write-Host ""
    pause
    exit 1
}

exit 0
