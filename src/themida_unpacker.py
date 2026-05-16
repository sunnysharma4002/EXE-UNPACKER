"""
Themida-Specific Unpacker Module
Specialized handling for Themida protected executables
"""

import os
import struct
import subprocess
import logging
from typing import Dict, Optional, Tuple
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThemidaDetector:
    """Detect Themida protection characteristics"""
    
    # Themida signatures and patterns
    THEMIDA_SIGNATURES = [
        b"Themida",
        b"WL!This program cannot be run",
        b"themida",
        b".themida",
        b"THEMIDA",
    ]
    
    THEMIDA_SECTIONS = [
        b".themida",
        b".text",
        b".data",
        b".reloc",
    ]
    
    def __init__(self, exe_path: str):
        self.exe_path = exe_path
        self.file_size = os.path.getsize(exe_path)
        
    def detect_themida(self) -> Dict:
        """Detect Themida protection in executable"""
        results = {
            "is_themida": False,
            "confidence": 0,
            "indicators": [],
            "version": "Unknown",
            "protection_features": []
        }
        
        try:
            with open(self.exe_path, 'rb') as f:
                data = f.read()
            
            # Check for Themida signatures
            for sig in self.THEMIDA_SIGNATURES:
                if sig in data:
                    results["indicators"].append(f"Found signature: {sig}")
                    results["confidence"] += 20
            
            # Check for Themida sections
            for section in self.THEMIDA_SECTIONS:
                if section in data:
                    results["indicators"].append(f"Found section: {section}")
            
            # Analyze entropy for virtualized code
            entropy = self._calculate_entropy(data)
            results["entropy"] = round(entropy, 2)
            
            if entropy > 7.5:
                results["indicators"].append(f"High entropy detected ({entropy:.2f})")
                results["protection_features"].append("Code virtualization")
                results["confidence"] += 25
            
            # Check for import table tampering (common Themida technique)
            import_tampering = self._check_import_tampering(data)
            if import_tampering:
                results["indicators"].append("Possible import table tampering detected")
                results["protection_features"].append("Import redirection")
                results["confidence"] += 15
            
            # Check for anti-debugging
            if self._check_anti_debugging(data):
                results["indicators"].append("Anti-debugging code detected")
                results["protection_features"].append("Anti-debugging")
                results["confidence"] += 10
            
            # Determine if Themida protected
            results["is_themida"] = results["confidence"] >= 40
            
            # Cap confidence at 100
            results["confidence"] = min(100, results["confidence"])
            
            return results
            
        except Exception as e:
            logger.error(f"Error detecting Themida: {e}")
            return results
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for i in range(256):
            freq = data.count(bytes([i])) / len(data)
            if freq > 0:
                entropy -= freq * (freq ** 0.5)
        
        return entropy
    
    def _check_import_tampering(self, data: bytes) -> bool:
        """Check for import table tampering"""
        # Look for suspicious import patterns
        suspicious_patterns = [
            b"ntdll",
            b"kernel32",
            b"GetProcAddress",
            b"LoadLibrary",
        ]
        
        # Count occurrences - Themida often duplicates or obfuscates imports
        count = 0
        for pattern in suspicious_patterns:
            count += data.count(pattern)
        
        return count > 10  # Arbitrary threshold
    
    def _check_anti_debugging(self, data: bytes) -> bool:
        """Check for anti-debugging code"""
        anti_debug_patterns = [
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"OutputDebugString",
            b"CreateToolhelp32Snapshot",
        ]
        
        return any(pattern in data for pattern in anti_debug_patterns)


class ThemidaUnpacker:
    """Unpack Themida protected executables"""
    
    def __init__(self):
        self.detector = None
        
    def unpack_executable(self, exe_path: str, output_dir: str) -> Tuple[bool, str]:
        """
        Attempt to unpack Themida protected executable
        
        Args:
            exe_path: Path to Themida-protected executable
            output_dir: Output directory for unpacked file
            
        Returns:
            Tuple of (success, message)
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Detect Themida
        self.detector = ThemidaDetector(exe_path)
        detection = self.detector.detect_themida()
        
        logger.info(f"Themida Detection Results:")
        logger.info(f"  Is Themida: {detection['is_themida']}")
        logger.info(f"  Confidence: {detection['confidence']}%")
        logger.info(f"  Features: {', '.join(detection['protection_features'])}")
        
        # Try unpacking methods in order
        methods = [
            ("WinDbg", self._unpack_with_windbg),
            ("Process Dump", self._unpack_with_process_dump),
            ("Debugger Trace", self._unpack_with_debugger),
            ("Manual", self._generate_unpacking_guide),
        ]
        
        for method_name, method_func in methods:
            logger.info(f"Attempting {method_name} unpacking...")
            try:
                success, result = method_func(exe_path, output_dir)
                if success:
                    logger.info(f"✓ {method_name} unpacking successful")
                    return True, f"Successfully unpacked using {method_name}"
            except Exception as e:
                logger.debug(f"{method_name} failed: {e}")
                continue
        
        return False, "Could not unpack - manual analysis required"
    
    def _unpack_with_windbg(self, exe_path: str, output_dir: str) -> Tuple[bool, str]:
        """Unpack using WinDbg automation"""
        try:
            # Check if WinDbg is available
            result = subprocess.run(
                ["where", "windbg.exe"],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0:
                logger.warning("WinDbg not found on system")
                return False, "WinDbg not installed"
            
            logger.info("WinDbg found - would require interactive debugging session")
            return False, "WinDbg requires interactive session"
            
        except Exception as e:
            return False, str(e)
    
    def _unpack_with_process_dump(self, exe_path: str, output_dir: str) -> Tuple[bool, str]:
        """Unpack by dumping running process memory"""
        try:
            # This would require process dumping tools like:
            # - Scylla
            # - Volatility
            # - PE-sieve
            
            logger.info("Process dumping would require running executable in debugger")
            return False, "Requires process dump utility"
            
        except Exception as e:
            return False, str(e)
    
    def _unpack_with_debugger(self, exe_path: str, output_dir: str) -> Tuple[bool, str]:
        """Generate debugger script for unpacking"""
        try:
            output_path = os.path.join(output_dir, "debugger_unpack_script.py")
            
            script = f'''#!/usr/bin/env python3
"""
Themida Unpacker - OllyDbg/WinDbg Script
Auto-generated unpacking guide
"""

# This script is designed to work with OllyDbg or WinDbg
# Manual steps required due to Themida's anti-automation features

EXECUTABLE = r"{exe_path}"
OUTPUT_FILE = r"{os.path.join(output_dir, 'unpacked.exe')}"

# Step 1: Load executable in debugger
# OllyDbg: File > Open > Select executable
# WinDbg: windbg.exe {{exe_path}}

# Step 2: Set breakpoints on VM entry points
# Common Themida entry point signatures:
THEMIDA_VM_SIGNATURES = [
    "55 8B EC 83 EC",  # push ebp; mov ebp, esp; sub esp, X
    "51 53 56 57",      # push ecx; push ebx; push esi; push edi
]

# Step 3: Hardware breakpoints on:
# - VirtualAlloc (kernel32.dll) - memory allocation
# - VirtualProtect (kernel32.dll) - memory protection
# - CreateRemoteThread (kernel32.dll) - thread creation

# Step 4: Step through VM until reaching real code
# - Watch for large memory allocations
# - Monitor section protections
# - Track API calls

# Step 5: Dump memory at unpacked code location
# OllyDbg: Right-click > Dump > Selection
# WinDbg: .writemem filename address length

# Step 6: Use PE reconstruction tool (Scylla/ImpRec)
# - Rebuild import table
# - Fix section headers
# - Validate PE structure

# Advanced techniques:
# 1. Entropy analysis - unpacked code has lower entropy
# 2. Pattern matching - look for common function prologs
# 3. Cross-reference analysis - calls to kernel32 functions
# 4. IAT hooks - trace import address table modifications

print("To use this script:")
print("1. Open {{exe_path}} in OllyDbg or WinDbg")
print("2. Follow the steps above")
print("3. Use Scylla (OllyDbg plugin) to rebuild imports")
print("4. Save unpacked executable")
'''
            
            with open(output_path, 'w') as f:
                f.write(script)
            
            logger.info(f"Generated debugger script: {output_path}")
            return False, "Debugger script generated"
            
        except Exception as e:
            return False, str(e)
    
    def _generate_unpacking_guide(self, exe_path: str, output_dir: str) -> Tuple[bool, str]:
        """Generate detailed unpacking guide"""
        try:
            guide_path = os.path.join(output_dir, "THEMIDA_UNPACKING_GUIDE.md")
            
            guide = f'''# Themida Unpacking Guide

## File Information
- **Executable**: {os.path.basename(exe_path)}
- **Size**: {os.path.getsize(exe_path):,} bytes
- **Protection**: Themida

## Detection Results
'''
            
            if self.detector:
                detection = self.detector.detect_themida()
                guide += f'''
- **Confidence**: {detection['confidence']}%
- **Features Detected**:
'''
                for feature in detection['protection_features']:
                    guide += f"  - {feature}\n"
            
            guide += '''
## Unpacking Methods (In Order of Difficulty)

### 1. User-Mode Debugger (OllyDbg) - RECOMMENDED
**Difficulty**: Medium
**Time**: 30-60 minutes

#### Steps:
1. Download OllyDbg (http://www.ollydbg.de/)
2. Open executable in OllyDbg
3. Set breakpoints at suspicious locations:
   - VirtualAlloc (kernel32.dll)
   - VirtualProtect (kernel32.dll)
   - CreateRemoteThread (kernel32.dll)
4. Let program run until first breakpoint
5. Analyze code flow to find VM entry point
6. Set hardware breakpoint at VM entry
7. Step through until reaching real code
8. Use Scylla plugin to dump memory and rebuild imports
9. Validate dumped file with PE tools

#### Tools Needed:
- OllyDbg (debugger)
- Scylla (import reconstruction)
- PEiD (PE validation)

### 2. Kernel Debugger (WinDbg) - ADVANCED
**Difficulty**: Hard
**Time**: 1-2 hours

#### Steps:
1. Install Windows Debugging Tools
2. Launch WinDbg as Administrator
3. Set kernel breakpoints
4. Use symbolic debugging for system calls
5. Trace execution at low level
6. Dump memory sections
7. Reconstruct PE file

#### Commands:
```
windbg.exe "path\\to\\executable.exe"
bp kernel32!VirtualAlloc
g  ; continue execution
```

### 3. Memory Dumping Tools - FAST
**Difficulty**: Easy
**Time**: 5-10 minutes

#### Tools:
- **PE-sieve**: Detects and dumps unpacked code
- **Volatility**: Memory forensics framework
- **Scylla**: Memory dumper and import rebuilder

#### Steps:
1. Run executable normally
2. Use memory dumping tool to extract memory
3. Analyze dumped memory for unpacked code
4. Reconstruct PE file
5. Validate and fix imports

### 4. Behavioral Analysis - REVERSE ENGINEERING
**Difficulty**: Very Hard
**Time**: 2-4 hours

#### Tools:
- IDA Pro (disassembly)
- Ghidra (reverse engineering)
- Radare2 (analysis)

#### Steps:
1. Analyze Themida VM implementation
2. Identify bytecode patterns
3. Write custom VM emulator
4. Execute program in emulator
5. Collect executed bytecode
6. Convert bytecode to machine code
7. Reconstruct original functions

## Key Indicators to Look For

### Memory Allocations
- Large RWX (read-write-execute) regions
- Multiple small executable regions
- Frequent protection changes

### API Calls
- GetProcAddress - dynamic import loading
- VirtualAlloc - memory allocation
- VirtualProtect - changing protections
- CreateRemoteThread - code injection

### Entropy Patterns
- High entropy in protected sections (.text)
- Normal entropy in unpacked code
- Transition points indicate unpacking

## Common Issues

### Issue: Can't find VM entry point
**Solution**: 
- Look for unusual instruction sequences
- Monitor memory writes before execution
- Check for REP MOVSD patterns
- Search for large decryption loops

### Issue: Imports not resolved
**Solution**:
- Use Scylla's IAT autofind
- Manually trace GetProcAddress calls
- Reference original import tables
- Build custom import table

### Issue: Code still doesn't run
**Solution**:
- Check PE header integrity
- Verify section alignments
- Validate relocation tables
- Check EntryPoint address

## Recommended Toolchain

1. **Static Analysis**
   - IDA Pro 7.0+ (Professional)
   - Ghidra (Free, open-source)
   - Radare2 (Free, open-source)

2. **Debugging**
   - OllyDbg 2.0 (Free, user-mode)
   - WinDbg (Free, kernel mode)
   - x64dbg (Free, x64 support)

3. **Dumping & Reconstruction**
   - Scylla (Free, IDA/OllyDbg plugin)
   - PE-sieve (Free, memory dumper)
   - ImpRec (Free, import rebuilder)

4. **Validation**
   - PEiD (Free, PE analyzer)
   - PE-Bear (Free, PE inspector)
   - ExeInfo PE (Free, PE details)

## References

### Themida Documentation
- Official: http://www.oreans.com/themida.php
- Features: Code virtualization, anti-debugging, anti-dumping
- Current Version: 3.x (with advanced VM)

### Learning Resources
- Reverse Engineering challenges: crackmes.one
- OllyDbg tutorials: YouTube (Many available)
- IDA Pro courses: Pluralsight, Udemy
- WinDbg reference: Microsoft Docs

### Related Tools
- VMProtect (Similar - virtualization protection)
- Code Virtualizer (Confusing bytecode patterns)
- Poly Pack (Polymorphic packer)

## Success Criteria

Successfully unpacked file should:
- ✓ Have valid PE header (MZ signature)
- ✓ Contain readable .text section
- ✓ Have valid import table
- ✓ Run independently without Themida
- ✓ Have reasonable entropy levels
- ✓ Disassemble with meaningful code

## Next Steps

1. Choose debugging approach above
2. Gather recommended tools
3. Start with memory dumping (fastest)
4. Fall back to OllyDbg if needed
5. Use reverse engineering for analysis

## Legal Notice

Only unpack executables you:
- Own the source code for
- Have explicit permission to analyze
- Are reverse engineering for security research
- Are analyzing for malware detection

Unlicensed unpacking may violate terms of service.
'''
            
            with open(guide_path, 'w') as f:
                f.write(guide)
            
            logger.info(f"Generated unpacking guide: {guide_path}")
            return False, "Unpacking guide generated"
            
        except Exception as e:
            return False, str(e)
    
    def generate_analysis_report(self, exe_path: str, output_dir: str) -> Dict:
        """Generate comprehensive Themida analysis report"""
        os.makedirs(output_dir, exist_ok=True)
        
        detector = ThemidaDetector(exe_path)
        detection = detector.detect_themida()
        
        report = {
            "file": os.path.basename(exe_path),
            "file_size": os.path.getsize(exe_path),
            "detection": detection,
            "unpacking_recommendations": self._get_recommendations(detection),
            "required_tools": self._get_required_tools(detection),
            "difficulty_level": self._assess_difficulty(detection),
            "estimated_time": self._estimate_time(detection)
        }
        
        # Save report
        report_path = os.path.join(output_dir, "themida_analysis_report.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Analysis report saved: {report_path}")
        return report
    
    def _get_recommendations(self, detection: Dict) -> list:
        """Get unpacking recommendations based on detection"""
        recommendations = [
            "Use OllyDbg with Scylla plugin (recommended for beginners)",
            "Set breakpoints on kernel32.dll functions (VirtualAlloc, CreateRemoteThread)",
            "Monitor RWX memory regions during execution",
            "Use PE-sieve for automated memory dumping",
        ]
        
        if detection['is_themida']:
            recommendations.append("This is definitely Themida - use appropriate tools")
        
        if "Anti-debugging" in str(detection.get('protection_features', [])):
            recommendations.insert(0, "⚠️ Anti-debugging detected - may need kernel debugger")
        
        return recommendations
    
    def _get_required_tools(self, detection: Dict) -> Dict:
        """Get required tools for unpacking"""
        return {
            "required": {
                "OllyDbg": "http://www.ollydbg.de/",
                "Scylla": "https://github.com/NtQuerySystemInformation/Scylla"
            },
            "optional": {
                "WinDbg": "Kernel debugging",
                "IDA Pro": "Advanced analysis",
                "Ghidra": "Free alternative to IDA",
                "PE-sieve": "Memory dumping",
            }
        }
    
    def _assess_difficulty(self, detection: Dict) -> str:
        """Assess unpacking difficulty"""
        if detection['confidence'] > 80:
            return "HARD - Professional protection"
        elif detection['confidence'] > 50:
            return "MEDIUM - Standard protection"
        else:
            return "EASY - Weak indicators"
    
    def _estimate_time(self, detection: Dict) -> str:
        """Estimate unpacking time"""
        if "Anti-debugging" in str(detection.get('protection_features', [])):
            return "1-3 hours with debugger"
        else:
            return "30 minutes to 1 hour"


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python themida_unpacker.py <exe_path> <output_dir>")
        sys.exit(1)
    
    exe_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./themida_output"
    
    unpacker = ThemidaUnpacker()
    report = unpacker.generate_analysis_report(exe_path, output_dir)
    
    print(f"\nThemida Analysis Report:")
    print(f"Confidence: {report['detection']['confidence']}%")
    print(f"Difficulty: {report['difficulty_level']}")
    print(f"Estimated Time: {report['estimated_time']}")
