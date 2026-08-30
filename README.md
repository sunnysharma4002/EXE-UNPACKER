# EXE Unpacker

A comprehensive tool for unpacking and analyzing **.NET** and **C++** executables. It combines GUI (tkinter) and CLI workflows to inspect binary structure, extract resources and strings, detect packers/protectors, and handle common protection schemes.

## Features

- **.NET analysis** — assembly metadata, managed structure, and embedded resource extraction (via dnSpy where available).
- **C++ / native analysis** — PE headers, sections, imports, architecture detection, and string extraction.
- **Packer / protector detection** — VMProtect, Themida, UPX, ASPack, PEtite, ConfuserEx, Code Virtualizer, and more.
- **Decryption helpers** — XOR, AES, RC4, LZMA-based decompression for common VM-protected files.
- **Batch analysis** — classify a whole folder of `.exe` files.
- **Reports** — JSON and plain-text output saved to `./output/`.
- **Drag-and-drop GUI** — dark-themed interface with package and license inspection tools.
- **Optional external tool integration** — dnSpy, Ghidra, IDA Free for advanced analysis.

## Requirements

- **Python 3.8+** (include `tcl/tk` during install for the GUI)
- Windows (launchers are for Windows; modules are largely OS-neutral)

### Python packages

See `requirements.txt`:

```
pyperclip==1.8.2
pefile==2023.2.7
tkinterdnd2==0.3.0
```

All other dependencies (`lzma`, `ctypes`, `struct`, `json`) are in the standard library.

## Installation

### Setup wizard (recommended)

```bat
python setup.py
```

This checks your Python version, installs pip dependencies, probes for optional external tools, and creates the `output/` directory.

## Usage

### GUI

```bat
python main.py
```

Or use the launcher scripts:

```bat
run.bat
```

```powershell
powershell -ExecutionPolicy Bypass -File run.ps1
```

The PowerShell launcher also accepts flags:

```powershell
.\run.ps1 -Setup       # force setup
.\run.ps1 -Clean       # remove previous output files first
```

### CLI examples

```bat
python examples.py
```

Choose an option to try, for example:
- `.NET` assembly analysis
- `.NET` resource extraction
- C++ binary information
- string extraction
- batch analysis
- comprehensive report generation

## Project Structure

```
EXE UNPACKER/
├── main.py                  # Application entry point
├── setup.py                 # Setup wizard / dependency installer
├── examples.py              # CLI usage examples (menu driven)
├── run.bat                  # Windows batch launcher
├── run.ps1                  # PowerShell launcher
├── requirements.txt         # Python dependencies
├── src/
│   ├── gui.py               # Tkinter GUI
│   ├── dotnet_unpacker.py   # .NET assembly analysis / resource extraction
│   ├── cpp_unpacker.py      # C++ / native binary analysis
│   ├── decryptor.py         # Protection detection & decryption helpers
│   ├── themida_unpacker.py  # Themida-specific handling
│   ├── vmprotect_unpacker.py# VMProtect-specific handling
│   ├── vmpunpacker.py       # LZMA-based VMProtect decompression
│   ├── license_patcher.py   # License / registration dialog scanner
│   ├── keyauth_patcher.py   # KeyAuth helper tooling
│   ├── keyauth_replacer.py  # KeyAuth panel / license server rewriting
│   └── __init__.py
└── output/                  # Generated reports and unpacked results
```

## License

For research, malware analysis, and educational use only.

> **Disclaimer:** This tool is intended for security research, interoperability, and analysis of software you own or are authorized to inspect. Circumventing license or protection mechanisms may violate laws or terms of service. You are solely responsible for using this tool lawfully and ethically.
