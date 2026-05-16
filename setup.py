"""
Quick Start Guide for EXE Unpacker
Run this file first time for setup
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_python_version():
    """Check Python version"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True

def check_required_modules():
    """Check if required modules are installed"""
    required = ['tkinter', 'json', 'struct', 'pathlib']
    missing = []
    
    for module in required:
        try:
            __import__(module)
            print(f"✅ {module} available")
        except ImportError:
            print(f"❌ {module} missing")
            missing.append(module)
    
    return len(missing) == 0

def install_dependencies():
    """Install pip dependencies"""
    print("\n📦 Installing Python dependencies...")
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("✅ Dependencies installed")
        return True
    except Exception as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def check_external_tools():
    """Check for external tools"""
    print("\n🔍 Checking for external tools...")
    
    tools = {
        'dnSpy': [
            r"D:\Downloads\Reverse Engeneering\dnSpy-net-win64\dnSpy.exe",
            r"C:\Program Files (x86)\dnSpy\dnSpy.exe",
        ],
        'Ghidra': [
            r"C:\ghidra",
            r"C:\Program Files\ghidra",
        ],
        'IDA Free': [
            r"D:\Program Files\IDA Professional 9.1\ida.exe",
        ]
    }
    
    found_tools = []
    
    for tool_name, paths in tools.items():
        found = False
        for path in paths:
            if os.path.exists(path):
                print(f"✅ {tool_name} found at {path}")
                found_tools.append(tool_name)
                found = True
                break
        
        if not found:
            print(f"⚠️  {tool_name} not found (optional for basic analysis)")
    
    return found_tools

def create_output_directory():
    """Create output directory"""
    output_dir = os.path.join(os.path.dirname(__file__), 'output')
    os.makedirs(output_dir, exist_ok=True)
    print(f"✅ Output directory created at {output_dir}")

def test_gui():
    """Test if GUI works"""
    print("\n🎨 Testing GUI components...")
    try:
        import tkinter as tk
        from tkinter import ttk
        print("✅ GUI framework (tkinter) available")
        return True
    except ImportError:
        print("❌ tkinter not available - GUI will not work")
        print("   Fix: Reinstall Python with tcl/tk option or run:")
        print("   pip install tk")
        return False

def main():
    """Run setup wizard"""
    print("=" * 60)
    print("    EXE UNPACKER - Setup Wizard")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        print("\n❌ Setup failed: Python 3.8+ required")
        return False
    
    # Check required modules
    print("\n📋 Checking required modules...")
    if not check_required_modules():
        print("⚠️  Some modules missing, will attempt to install")
    
    # Install dependencies
    if not install_dependencies():
        print("⚠️  Could not auto-install all dependencies")
    
    # Check external tools
    found_tools = check_external_tools()
    
    # Create directories
    print("\n📁 Creating directories...")
    create_output_directory()
    
    # Test GUI
    print()
    if not test_gui():
        print("⚠️  GUI test failed")
    
    # Summary
    print("\n" + "=" * 60)
    print("    Setup Summary")
    print("=" * 60)
    print(f"✅ Python: {sys.version_info.major}.{sys.version_info.minor}")
    print(f"✅ Output directory: {os.path.abspath('output')}")
    print(f"✅ Found tools: {', '.join(found_tools) if found_tools else 'None (will use basic analysis)'}")
    
    print("\n📖 Next steps:")
    print("1. Read README.md for detailed information")
    print("2. Run: python main.py")
    print("3. Select an executable file")
    print("4. Click analysis buttons")
    
    print("\n🔗 Download optional tools:")
    print("   dnSpy: https://github.com/dnSpy/dnSpy/releases")
    print("   Ghidra: https://ghidra-sre.org/")
    print("   IDA Free: https://www.hex-rays.com/ida-free/")
    
    print("\n" + "=" * 60)
    print("✅ Setup complete! Ready to unpack executables.")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
