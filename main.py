"""
EXE Unpacker - Main Application Entry Point
A comprehensive tool for unpacking and analyzing .NET and C++ executables
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

from src.gui import main

if __name__ == "__main__":
    main()
