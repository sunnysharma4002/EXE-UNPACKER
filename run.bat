@echo off
REM EXE Unpacker - Windows Batch Launcher
REM This script runs the EXE Unpacker application on Windows

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Python is not installed or not in PATH
    echo.
    echo Please install Python 3.8+ from: https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

REM Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Found Python %PYTHON_VERSION%

REM Check if first time run (requirements not installed)
python -c "import tkinter" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] tkinter not available. Python may not be properly installed.
    echo.
    echo Solution: Reinstall Python and select "tcl/tk and idle" option
    echo.
    pause
    exit /b 1
)

REM Check if setup has been run
if not exist "%SCRIPT_DIR%\src\gui.py" (
    echo.
    echo [ERROR] Application files not found!
    echo.
    echo Please ensure you are running this from the correct directory
    echo.
    pause
    exit /b 1
)

REM Check if requirements are installed (first time setup)
python -c "import pyperclip" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [SETUP] First time setup - installing dependencies...
    echo.
    
    python setup.py
    
    if errorlevel 1 (
        echo.
        echo [ERROR] Setup failed!
        echo.
        pause
        exit /b 1
    )
)

REM Launch the application
echo.
echo [INFO] Launching EXE Unpacker...
echo.

cd /d "%SCRIPT_DIR%"
python main.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application crashed!
    echo.
    echo Check the console output above for details
    echo.
    pause
    exit /b 1
)

exit /b 0
