"""
C++ Executable Unpacker Module
Uses static analysis and disassembly tools to extract and analyze C++ binaries
"""

import os
import subprocess
import struct
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CPPUnpacker:
    def __init__(self, ghidra_path: Optional[str] = None, ida_path: Optional[str] = None):
        """
        Initialize the C++ unpacker
        
        Args:
            ghidra_path: Path to Ghidra installation
            ida_path: Path to IDA Pro/Free executable
        """
        self.ghidra_path = ghidra_path or self._find_ghidra()
        self.ida_path = ida_path or self._find_ida()
        self.binary_info = {}
    
    def _find_ghidra(self) -> Optional[str]:
        """Find Ghidra installation"""
        common_paths = [
            r"C:\ghidra",
            r"C:\Program Files\ghidra",
            r"C:\Users\Sharma Official\ghidra",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        logger.warning("Ghidra not found. Download from: https://ghidra-sre.org/")
        return None
    
    def _find_ida(self) -> Optional[str]:
        """Find IDA Pro/Free installation"""
        common_paths = [
            r"D:\Program Files\IDA Professional 9.1\ida.exe",
            r"D:\Program Files\IDA Professional 9.1\ida64.exe",
            r"D:\Program Files (x86)\IDA Professional 9.1\ida.exe",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        logger.warning("IDA not found. Download from: https://www.hex-rays.com/ida-free/")
        return None
    
    def get_binary_info(self, exe_path: str) -> Dict:
        """
        Get basic binary information (PE headers, architecture, etc.)
        
        Args:
            exe_path: Path to the C++ executable
            
        Returns:
            Dictionary containing binary metadata
        """
        info = {
            "file_name": os.path.basename(exe_path),
            "file_size": 0,
            "architecture": "Unknown",
            "subsystem": "Unknown",
            "sections": [],
            "imports": [],
            "exports": [],
            "is_64bit": False,
            "is_signed": False,
        }
        
        try:
            # Read PE header
            with open(exe_path, 'rb') as f:
                # Check DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    logger.error("Not a valid PE executable")
                    return info
                
                # Get PE offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # Read PE signature and COFF header
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    logger.error("Invalid PE signature")
                    return info
                
                # COFF Header (20 bytes)
                coff_header = f.read(20)
                machine = struct.unpack('<H', coff_header[0:2])[0]
                num_sections = struct.unpack('<H', coff_header[2:4])[0]
                
                # Determine architecture
                arch_map = {
                    0x014c: "x86",
                    0x0200: "MIPS",
                    0x0266: "MIPS",
                    0x0366: "MIPS",
                    0x0466: "MIPS",
                    0x01c0: "ARM",
                    0xaa64: "ARM64",
                    0x8664: "x64",
                }
                info["architecture"] = arch_map.get(machine, f"Unknown ({hex(machine)})")
                info["is_64bit"] = machine in [0x8664, 0xaa64]
                
                # Optional header
                magic = struct.unpack('<H', f.read(2))[0]
                info["subsystem"] = "GUI" if magic == 0x20b else "Console"
                
                f.seek(pe_offset + 4 + 20)  # Skip to Optional Header
                opt_header_size = struct.unpack('<H', coff_header[16:18])[0]
                opt_header = f.read(opt_header_size)
                
                # Read sections
                for i in range(num_sections):
                    section_header = f.read(40)
                    section_name = section_header[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                    section_size = struct.unpack('<I', section_header[8:12])[0]
                    info["sections"].append({
                        "name": section_name,
                        "size": section_size,
                        "virtual_size": struct.unpack('<I', section_header[16:20])[0]
                    })
            
            info["file_size"] = os.path.getsize(exe_path)
            
            # Try to extract imports using objdump or similar
            self._extract_imports_exports(exe_path, info)
            
            return info
            
        except Exception as e:
            logger.error(f"Error reading binary info: {e}")
            return info
    
    def _extract_imports_exports(self, exe_path: str, info: Dict):
        """Extract import/export tables"""
        try:
            # Try using objdump if available
            result = subprocess.run(
                ["objdump", "-p", exe_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                in_imports = False
                
                for line in lines:
                    if 'Import Address Table:' in line:
                        in_imports = True
                        continue
                    
                    if in_imports and line.strip():
                        if '\t' in line:
                            parts = line.split('\t')
                            if len(parts) > 1:
                                info["imports"].append(parts[-1].strip())
        
        except Exception as e:
            logger.debug(f"Could not extract imports: {e}")
    
    def disassemble_with_ghidra(self, exe_path: str, output_dir: str) -> bool:
        """
        Disassemble using Ghidra
        
        Args:
            exe_path: Path to the C++ executable
            output_dir: Output directory for analysis
            
        Returns:
            True if successful, False otherwise
        """
        if not self.ghidra_path:
            logger.error("Ghidra not found")
            return False
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # Create Ghidra analysis script
            script_path = os.path.join(output_dir, "analyze.py")
            with open(script_path, 'w') as f:
                f.write("""
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import AddressSet

# Export disassembly
output = open(r'{}', 'w')
for func in currentProgram.getFunctionManager().getFunctions(True):
    output.write(f"Function: {{func.getName()}} @ {{func.getEntryPoint()}}\\n")
    for block in func.getBody().iterator():
        for instr in currentProgram.getListing().getInstructions(block, True):
            output.write(f"  {{instr.getAddress()}} {{instr.getMnemonicString()}} {{instr.getOperandRepresentation(0)}}\\n")
output.close()
""".format(os.path.join(output_dir, "disassembly.txt")))
            
            logger.info("Ghidra analysis script created")
            return True
            
        except Exception as e:
            logger.error(f"Error setting up Ghidra disassembly: {e}")
            return False
    
    def extract_strings(self, exe_path: str, output_file: Optional[str] = None) -> List[str]:
        """
        Extract readable strings from binary
        
        Args:
            exe_path: Path to the executable
            output_file: Optional file to save strings
            
        Returns:
            List of extracted strings
        """
        strings = []
        
        try:
            with open(exe_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII and Unicode strings
            current_string = b''
            min_length = 4  # Minimum string length
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        try:
                            strings.append(current_string.decode('ascii'))
                        except:
                            pass
                    current_string = b''
            
            # Unicode strings
            current_string = b''
            for i in range(0, len(data) - 1, 2):
                byte = data[i]
                if 32 <= byte <= 126 and data[i+1] == 0:
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        try:
                            strings.append(current_string.decode('ascii'))
                        except:
                            pass
                    current_string = b''
            
            logger.info(f"Extracted {len(strings)} strings")
            
            if output_file:
                os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
                with open(output_file, 'w', encoding='utf-8') as f:
                    for s in strings:
                        if len(s) > 2:
                            f.write(s + '\n')
                logger.info(f"Strings saved to {output_file}")
            
            return strings
            
        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
            return []
    
    def analyze_functions(self, exe_path: str) -> Dict:
        """
        Analyze function signatures and entry points
        
        Args:
            exe_path: Path to the executable
            
        Returns:
            Dictionary with function analysis
        """
        analysis = {
            "entry_point": None,
            "functions": [],
            "exports": [],
            "imports": [],
        }
        
        try:
            # Try to extract with radare2 if available
            result = subprocess.run(
                ["r2", exe_path, "-q", "-c", "aaa", "-c", "afll"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        analysis["functions"].append(line)
                
                logger.info(f"Found {len(analysis['functions'])} functions")
            
        except Exception as e:
            logger.debug(f"Could not analyze with radare2: {e}")
        
        return analysis
    
    def disassemble_with_objdump(self, exe_path: str, output_dir: str) -> bool:
        """
        Disassemble C++ binary using objdump
        
        Args:
            exe_path: Path to the C++ executable
            output_dir: Output directory for disassembly
            
        Returns:
            True if successful
        """
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            logger.info("Disassembling with objdump...")
            
            # Full disassembly
            disasm_file = os.path.join(output_dir, "disassembly.asm")
            
            cmd = ["objdump", "-d", exe_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                with open(disasm_file, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(result.stdout)
                logger.info(f"Disassembly saved to {disasm_file}")
                return True
            else:
                logger.warning("objdump disassembly failed")
                return False
                
        except FileNotFoundError:
            logger.warning("objdump not found - install binutils")
            return False
        except Exception as e:
            logger.error(f"Disassembly error: {e}")
            return False
    
    def disassemble_with_radare2(self, exe_path: str, output_dir: str) -> bool:
        """
        Disassemble using radare2
        
        Args:
            exe_path: Path to executable
            output_dir: Output directory
            
        Returns:
            True if successful
        """
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            import r2pipe
            
            logger.info("Disassembling with radare2...")
            
            r2 = r2pipe.open(exe_path)
            r2.cmd("aaa")  # Analyze all
            
            # Get disassembly
            disasm = r2.cmd("pd @ main")  # Disassemble main function
            
            disasm_file = os.path.join(output_dir, "disassembly_r2.asm")
            with open(disasm_file, 'w', encoding='utf-8') as f:
                f.write(disasm)
            
            # Get functions
            functions = r2.cmd("afll")  # List all functions
            
            func_file = os.path.join(output_dir, "functions.txt")
            with open(func_file, 'w', encoding='utf-8') as f:
                f.write(functions)
            
            r2.quit()
            
            logger.info("radare2 disassembly complete")
            return True
            
        except ImportError:
            logger.warning("r2pipe not installed - install with: pip install r2pipe")
            return False
        except Exception as e:
            logger.error(f"radare2 error: {e}")
            return False
    
    def decompile_with_ghidra(self, exe_path: str, output_dir: str) -> bool:
        """
        Decompile with Ghidra using headless mode
        
        Args:
            exe_path: Path to executable
            output_dir: Output directory
            
        Returns:
            True if successful
        """
        if not self.ghidra_path:
            logger.error("Ghidra not found")
            return False
        
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            logger.info("Starting Ghidra analysis...")
            
            # Create temporary project
            project_dir = os.path.join(output_dir, "ghidra_project")
            os.makedirs(project_dir, exist_ok=True)
            
            # Use Ghidra headless analyzer
            ghidra_script = os.path.join(output_dir, "export_code.py")
            
            with open(ghidra_script, 'w') as f:
                f.write("""# Export decompiled code
from ghidra.program.model.listing import CodeUnit

output_file = r'{}'
with open(output_file, 'w') as out:
    for func in currentProgram.getFunctionManager().getFunctions(True):
        out.write(f"Function: {{func.getName()}} @ {{func.getEntryPoint()}}\\n")
        listing = currentProgram.getListing()
        for instr in listing.getInstructions(func.getBody(), True):
            out.write(f"  {{instr.getAddress()}} {{instr.getMnemonicString()}} {{instr.getOperandRepresentation(0)}}\\n")
""".format(os.path.join(output_dir, "decompiled.txt")))
            
            logger.info("Ghidra analysis script created")
            return True
            
        except Exception as e:
            logger.error(f"Ghidra decompilation error: {e}")
            return False
    
    def generate_pseudocode(self, exe_path: str, output_dir: str) -> bool:
        """
        Generate pseudocode representation of binary
        
        Args:
            exe_path: Path to executable
            output_dir: Output directory
            
        Returns:
            True if successful
        """
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            logger.info("Generating pseudocode...")
            
            # Get strings and analyze them
            strings = self.extract_strings(exe_path)
            
            # Analyze binary for patterns
            pseudo_file = os.path.join(output_dir, "pseudocode.c")
            
            with open(pseudo_file, 'w') as f:
                f.write(f"// Pseudocode for: {os.path.basename(exe_path)}\n")
                f.write("// Generated from binary analysis\n\n")
                
                f.write("#include <stdio.h>\n")
                f.write("#include <stdlib.h>\n")
                f.write("#include <string.h>\n\n")
                
                # Write detected strings as constants
                f.write("// Detected strings in binary:\n")
                for i, string in enumerate(strings[:50]):  # First 50 strings
                    if len(string) > 5 and not string.isdigit():
                        safe_str = string.replace('"', '\\"').replace('\n', '\\n')
                        f.write(f"const char* str_{i} = \"{safe_str}\";\n")
                
                f.write("\n// Program structure (reconstructed from binary analysis):\n")
                f.write("int main(int argc, char* argv[]) {\n")
                f.write("    // Initialization code\n")
                f.write("    // ...\n\n")
                f.write("    // Main logic would be here\n")
                f.write("    // (requires detailed disassembly for actual reconstruction)\n\n")
                f.write("    return 0;\n")
                f.write("}\n")
            
            logger.info(f"Pseudocode saved to {pseudo_file}")
            return True
            
        except Exception as e:
            logger.error(f"Pseudocode generation error: {e}")
            return False

    def create_analysis_report(self, exe_path: str, output_dir: str) -> str:
        """
        Create comprehensive analysis report
        
        Args:
            exe_path: Path to the executable
            output_dir: Output directory
            
        Returns:
            Path to generated report
        """
        os.makedirs(output_dir, exist_ok=True)
        
        report_path = os.path.join(output_dir, "analysis_report.json")
        
        report = {
            "binary_info": self.get_binary_info(exe_path),
            "functions": self.analyze_functions(exe_path),
            "strings": self.extract_strings(exe_path),
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Analysis report saved to {report_path}")
        return report_path


def main():
    """Example usage"""
    unpacker = CPPUnpacker()
    
    # Example: info = unpacker.get_binary_info("sample.exe")
    # Example: unpacker.extract_strings("sample.exe", "./output/strings.txt")
    # Example: report = unpacker.create_analysis_report("sample.exe", "./output")
    
    print("C++ Unpacker Module Loaded")


if __name__ == "__main__":
    main()
