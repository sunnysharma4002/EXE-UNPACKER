"""
Executable Decryption Module
Handles detection and decryption of encrypted executables with various protections:
- VM-based protections (VMProtect, Code Virtualizer, etc.)
- Standard encryption (XOR, AES, RC4, etc.)
- .NET obfuscation (De4dot, ConfuserEx, etc.)
- Packer detection (UPX, ASPack, PEtite, etc.)
"""

import os
import struct
import json
import subprocess
import hashlib
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProtectionDetector:
    """Detect various executable protections and encryption methods"""
    
    # Signature patterns for various protections
    PROTECTION_SIGNATURES = {
        "VMProtect": [
            b"VMProtect",
            b"\x00VM\x00",
            b"VmCode",
        ],
        "Code Virtualizer": [
            b"Code Virtualizer",
            b"CodeVirtualizer",
        ],
        "Themida": [
            b"Themida",
            b"WL!This program cannot be run",
        ],
        "Confuser": [
            b"ConfuserEx",
            b"Confuser",
        ],
        "De4dot": [
            b"De4dot",
        ],
        "dn Guard": [
            b"dn!Guard",
        ],
        ".NET Reactor": [
            b".NET Reactor",
            b"NetReactor",
        ],
        "Eziriz Protector": [
            b"NetProtector",
        ],
        "UPX": [
            b"UPX!",
            b"$UPX$",
        ],
        "ASPack": [
            b"ASPack",
        ],
        "PEtite": [
            b"PEtite",
        ],
        "WinRAR": [
            b"RAR",
        ],
    }
    
    def __init__(self, exe_path: str):
        """
        Initialize the protection detector
        
        Args:
            exe_path: Path to the executable to analyze
        """
        self.exe_path = exe_path
        self.file_size = os.path.getsize(exe_path)
        self.pe_header = self._read_pe_header()
        
    def _read_pe_header(self) -> Dict:
        """Read PE header information"""
        try:
            with open(self.exe_path, 'rb') as f:
                dos_header = f.read(64)
                
                if dos_header[:2] != b'MZ':
                    return {}
                
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return {}
                
                return {
                    "is_pe": True,
                    "pe_offset": pe_offset,
                    "is_x64": False,  # Will update based on machine type
                }
        except Exception as e:
            logger.error(f"Error reading PE header: {e}")
            return {}
    
    def detect_protections(self) -> Dict[str, List[str]]:
        """
        Detect all protections in the executable
        
        Returns:
            Dictionary with detected protections and confidence levels
        """
        detected = {}
        
        try:
            with open(self.exe_path, 'rb') as f:
                file_content = f.read()
            
            for protection, signatures in self.PROTECTION_SIGNATURES.items():
                found_signatures = []
                for sig in signatures:
                    if sig in file_content:
                        found_signatures.append(True)
                
                if found_signatures:
                    detected[protection] = {
                        "detected": True,
                        "matches": len(found_signatures),
                        "confidence": min(100, len(found_signatures) * 40)
                    }
            
            # Check for entropy (indicates encryption)
            entropy = self._calculate_entropy(file_content)
            if entropy > 7.5:
                detected["High Entropy (Encrypted)"] = {
                    "detected": True,
                    "entropy": round(entropy, 2),
                    "confidence": 85
                }
            
            # Check for section characteristics
            section_analysis = self._analyze_sections(file_content)
            if section_analysis:
                detected.update(section_analysis)
            
            return detected
            
        except Exception as e:
            logger.error(f"Error detecting protections: {e}")
            return {}
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data (indicates encryption)"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for i in range(256):
            freq = data.count(bytes([i])) / len(data)
            if freq > 0:
                entropy -= freq * (freq ** 0.5)
        
        return entropy
    
    def _analyze_sections(self, file_content: bytes) -> Dict:
        """Analyze PE sections for suspicious patterns"""
        detected = {}
        
        # Check for suspicious section names
        suspicious_sections = [
            (b".vmp", "VMProtect Section"),
            (b".themida", "Themida Section"),
            (b".packed", "Packed Section"),
            (b".confuser", "Confuser Section"),
        ]
        
        for section_sig, detection_name in suspicious_sections:
            if section_sig in file_content:
                detected[detection_name] = {
                    "detected": True,
                    "confidence": 75
                }
        
        return detected


class DecryptionEngine:
    """Handle decryption of various executable formats"""
    
    def __init__(self):
        self.decryption_methods = []
        self._register_decryptors()
    
    def _register_decryptors(self):
        """Register available decryptors"""
        self.decryptors = {
            "xor": self._decrypt_xor,
            "aes": self._decrypt_aes,
            "rc4": self._decrypt_rc4,
            "simple": self._decrypt_simple,
            "virtual_machine": self._decrypt_vm,
            "packed": self._unpack_executable,
        }
    
    def decrypt_executable(self, exe_path: str, output_path: str, 
                         method: str = "auto") -> Tuple[bool, str]:
        """
        Attempt to decrypt an executable
        
        Args:
            exe_path: Path to encrypted executable
            output_path: Path to save decrypted executable
            method: Decryption method to use
            
        Returns:
            Tuple of (success, message)
        """
        try:
            with open(exe_path, 'rb') as f:
                data = f.read()
            
            if method == "auto":
                # Try multiple decryption methods
                for method_name in ["xor", "simple", "rc4", "packed"]:
                    try:
                        result = self.decryptors[method_name](data)
                        if result and self._is_valid_executable(result):
                            with open(output_path, 'wb') as f:
                                f.write(result)
                            logger.info(f"Successfully decrypted using {method_name}")
                            return True, f"Decrypted successfully using {method_name}"
                    except Exception as e:
                        logger.debug(f"Method {method_name} failed: {e}")
                        continue
                
                return False, "Could not decrypt with any method"
            else:
                if method not in self.decryptors:
                    return False, f"Unknown decryption method: {method}"
                
                result = self.decryptors[method](data)
                if result:
                    with open(output_path, 'wb') as f:
                        f.write(result)
                    return True, f"Decrypted successfully using {method}"
                else:
                    return False, f"Decryption with {method} failed"
        
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return False, str(e)
    
    def _decrypt_xor(self, data: bytes, key: Optional[bytes] = None) -> Optional[bytes]:
        """XOR decryption with key bruteforcing"""
        # Try single-byte XOR first
        for key_byte in range(256):
            result = bytes(b ^ key_byte for b in data)
            if self._is_valid_executable(result):
                logger.info(f"XOR decryption successful with key: {key_byte}")
                return result
        
        # Try multi-byte XOR key
        if key is None:
            # Brute-force common key sizes
            for key_len in [1, 2, 4, 8, 16, 32]:
                result = self._brute_force_xor(data, key_len)
                if result:
                    return result
        
        return None
    
    def _brute_force_xor(self, data: bytes, key_len: int) -> Optional[bytes]:
        """Brute-force XOR with given key length"""
        if key_len > len(data):
            return None
        
        # Sample a few potential keys by looking at file patterns
        for i in range(min(1000, len(data) - key_len)):
            potential_key = data[i:i+key_len]
            result = bytes(data[j] ^ potential_key[j % key_len] for j in range(len(data)))
            
            if self._is_valid_executable(result):
                logger.info(f"XOR key found: {potential_key.hex()}")
                return result
        
        return None
    
    def _decrypt_rc4(self, data: bytes) -> Optional[bytes]:
        """RC4 decryption (requires cryptography library)"""
        try:
            from Crypto.Cipher import ARC4
        except ImportError:
            logger.warning("pycryptodome not installed for RC4 decryption")
            return None
        
        # Try common RC4 keys
        common_keys = [
            b"password",
            b"admin",
            b"123456",
            b"key",
            b"secret",
        ]
        
        for key in common_keys:
            try:
                cipher = ARC4.new(key)
                result = cipher.decrypt(data)
                if self._is_valid_executable(result):
                    logger.info(f"RC4 decryption successful")
                    return result
            except Exception:
                continue
        
        return None
    
    def _decrypt_aes(self, data: bytes) -> Optional[bytes]:
        """AES decryption (requires cryptography library)"""
        try:
            from Crypto.Cipher import AES
        except ImportError:
            logger.warning("pycryptodome not installed for AES decryption")
            return None
        
        # Try common AES keys and modes
        common_keys = [
            b"0" * 16,
            b"1" * 16,
            b"password" * 2,
            hashlib.md5(b"password").digest(),
        ]
        
        for key in common_keys:
            for mode in [AES.MODE_ECB, AES.MODE_CBC]:
                try:
                    if mode == AES.MODE_ECB:
                        cipher = AES.new(key, mode)
                        result = cipher.decrypt(data)
                    else:
                        # CBC needs IV
                        iv = data[:16]
                        cipher = AES.new(key, mode, iv)
                        result = cipher.decrypt(data[16:])
                    
                    if self._is_valid_executable(result):
                        logger.info(f"AES decryption successful")
                        return result
                except Exception:
                    continue
        
        return None
    
    def _decrypt_simple(self, data: bytes) -> Optional[bytes]:
        """Simple decryption: try reversing, bit-shifting, etc."""
        # Try bit rotation
        for rotation in range(1, 8):
            result = bytes((b >> rotation | (b << (8 - rotation)) & 0xFF) for b in data)
            if self._is_valid_executable(result):
                logger.info(f"Decryption successful with bit rotation {rotation}")
                return result
        
        return None
    
    def _decrypt_vm(self, data: bytes) -> Optional[bytes]:
        """
        Attempt VM unrolling for virtualized code
        This creates a basic unrolling report
        """
        # Check for VM markers
        vm_indicators = [
            b"VMProtect",
            b"Code Virtualizer",
            b"Themida",
        ]
        
        if any(indicator in data for indicator in vm_indicators):
            logger.info("Detected VM-protected executable")
            logger.info("VM unpacking requires specialized tools:")
            logger.info("  - Manual VM handler extraction")
            logger.info("  - Using VMProtect/Themida specific unpackers")
            logger.info("  - Debugger-based tracing (OllyDbg, WinDbg, IDA Pro)")
            return None
        
        return None
    
    def _unpack_executable(self, data: bytes) -> Optional[bytes]:
        """
        Attempt to unpack common packers
        """
        packers = {
            b"UPX!": self._unpack_upx,
            b"ASPack": self._unpack_aspack,
        }
        
        for packer_sig, unpacker_func in packers.items():
            if packer_sig in data:
                logger.info(f"Detected packed executable")
                try:
                    # Try using external unpacker tools if available
                    return self._call_external_unpacker(data)
                except Exception as e:
                    logger.debug(f"External unpacking failed: {e}")
        
        return None
    
    def _unpack_upx(self, data: bytes) -> Optional[bytes]:
        """Unpack UPX-packed executable"""
        try:
            # Check if upx is available
            result = subprocess.run(["upx", "--version"], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.info("UPX found on system")
                return data  # Would need to use upx CLI
        except Exception:
            logger.warning("UPX not found on system")
        
        return None
    
    def _unpack_aspack(self, data: bytes) -> Optional[bytes]:
        """Unpack ASPack-packed executable"""
        logger.info("ASPack unpacking requires specialized tools")
        return None
    
    def _call_external_unpacker(self, data: bytes) -> Optional[bytes]:
        """Call external unpacker tools"""
        # Check for common unpackers
        unpackers = ["upx", "peunpack", "mmunpacker"]
        
        for unpacker in unpackers:
            try:
                result = subprocess.run([unpacker, "--version"],
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    logger.info(f"Using {unpacker} for unpacking")
                    # Would implement actual unpacking here
                    return None
            except Exception:
                continue
        
        return None
    
    def _is_valid_executable(self, data: bytes) -> bool:
        """Check if data looks like a valid executable"""
        if len(data) < 64:
            return False
        
        # Check for MZ header
        if data[:2] == b'MZ':
            return True
        
        # Check for ELF header
        if data[:4] == b'\x7fELF':
            return True
        
        # Check for Mach-O header
        if data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                        b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf']:
            return True
        
        return False


class ObfuscationRemover:
    """Remove common .NET obfuscation"""
    
    def __init__(self):
        self.de4dot_path = self._find_de4dot()
    
    def _find_de4dot(self) -> Optional[str]:
        """Find de4dot executable"""
        possible_paths = [
            "de4dot",
            "de4dot.exe",
            "/usr/bin/de4dot",
            "C:\\Program Files\\de4dot\\de4dot.exe",
        ]
        
        for path in possible_paths:
            if shutil.which(path):
                return path
        
        return None
    
    def remove_obfuscation(self, exe_path: str, output_path: str) -> Tuple[bool, str]:
        """
        Remove .NET obfuscation using de4dot
        
        Args:
            exe_path: Path to obfuscated executable
            output_path: Path to save deobfuscated executable
            
        Returns:
            Tuple of (success, message)
        """
        if not self.de4dot_path:
            return False, "de4dot not found. Install from: https://github.com/de4dot/de4dot"
        
        try:
            cmd = [self.de4dot_path, exe_path, "-o", output_path]
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            
            if result.returncode == 0:
                logger.info("Obfuscation removed successfully")
                return True, "Deobfuscation successful"
            else:
                logger.error(f"de4dot failed: {result.stderr.decode()}")
                return False, f"de4dot error: {result.stderr.decode()}"
        
        except subprocess.TimeoutExpired:
            return False, "Deobfuscation timed out"
        except Exception as e:
            logger.error(f"Deobfuscation error: {e}")
            return False, str(e)


class DecryptionManager:
    """Main manager for decryption operations"""
    
    def __init__(self):
        self.detector = None
        self.decryptor = DecryptionEngine()
        self.obfuscation_remover = ObfuscationRemover()
        self.themida_unpacker = None
        self.vmprotect_unpacker = None
        self._initialize_themida()
        self._initialize_vmprotect()
    
    def _initialize_themida(self):
        """Initialize Themida unpacker"""
        try:
            from src.themida_unpacker import ThemidaUnpacker
            self.themida_unpacker = ThemidaUnpacker()
        except ImportError:
            logger.info("Themida unpacker not available")
            self.themida_unpacker = None
    
    def _initialize_vmprotect(self):
        """Initialize VMProtect unpacker"""
        try:
            from src.vmprotect_unpacker import VMProtectUnpacker
            self.vmprotect_unpacker = VMProtectUnpacker()
        except ImportError:
            logger.info("VMProtect unpacker not available")
            self.vmprotect_unpacker = None
    
    def analyze_and_decrypt(self, exe_path: str, output_dir: str) -> Dict:
        """
        Full analysis and decryption workflow
        
        Args:
            exe_path: Path to executable
            output_dir: Output directory for decrypted files
            
        Returns:
            Dictionary with analysis results and decryption status
        """
        os.makedirs(output_dir, exist_ok=True)
        
        results = {
            "file": os.path.basename(exe_path),
            "protections": {},
            "decryption_attempts": {},
            "recommendations": []
        }
        
        try:
            # Step 1: Detect protections
            logger.info("Step 1: Detecting protections...")
            self.detector = ProtectionDetector(exe_path)
            results["protections"] = self.detector.detect_protections()
            
            # Step 2: Try decryption
            logger.info("Step 2: Attempting decryption...")
            output_path = os.path.join(output_dir, "decrypted.exe")
            success, message = self.decryptor.decrypt_executable(exe_path, output_path)
            results["decryption_attempts"]["auto"] = {
                "success": success,
                "message": message
            }
            
            # Step 3: Try deobfuscation if .NET
            if "Confuser" in results["protections"] or "ConfuserEx" in results["protections"]:
                logger.info("Step 3: Attempting to remove .NET obfuscation...")
                deobf_path = os.path.join(output_dir, "deobfuscated.exe")
                deobf_success, deobf_message = self.obfuscation_remover.remove_obfuscation(
                    exe_path, deobf_path
                )
                results["decryption_attempts"]["deobfuscation"] = {
                    "success": deobf_success,
                    "message": deobf_message
                }
            
            # Step 3b: Themida-specific analysis
            if "Themida" in results["protections"] and self.themida_unpacker:
                logger.info("Step 3b: Analyzing Themida protection...")
                themida_dir = os.path.join(output_dir, "themida_analysis")
                themida_report = self.themida_unpacker.generate_analysis_report(exe_path, themida_dir)
                results["decryption_attempts"]["themida_analysis"] = {
                    "success": True,
                    "difficulty": themida_report.get("difficulty_level"),
                    "estimated_time": themida_report.get("estimated_time"),
                    "recommendations": themida_report.get("unpacking_recommendations", [])
                }
            
            # Step 3c: VMProtect-specific analysis
            if "VMProtect" in results["protections"] and self.vmprotect_unpacker:
                logger.info("Step 3c: Analyzing VMProtect protection...")
                vmprotect_dir = os.path.join(output_dir, "vmprotect_analysis")
                vmprotect_report = self.vmprotect_unpacker.generate_analysis_report(exe_path, vmprotect_dir)
                results["decryption_attempts"]["vmprotect_analysis"] = {
                    "success": True,
                    "difficulty": vmprotect_report.get("difficulty_level"),
                    "estimated_time": vmprotect_report.get("estimated_time"),
                    "recommendations": vmprotect_report.get("unpacking_recommendations", [])
                }
            
            # Step 4: Generate recommendations
            results["recommendations"] = self._generate_recommendations(results["protections"])
            
            # Save analysis report
            report_path = os.path.join(output_dir, "decryption_report.json")
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Analysis report saved to {report_path}")
            
            return results
        
        except Exception as e:
            logger.error(f"Error in analysis workflow: {e}")
            results["error"] = str(e)
            return results
    
    def _generate_recommendations(self, protections: Dict) -> List[str]:
        """Generate recommendations based on detected protections"""
        recommendations = []
        
        if not protections:
            recommendations.append("No protections detected - file may already be unpacked")
            return recommendations
        
        for protection_name, info in protections.items():
            if "VMProtect" in protection_name:
                recommendations.append("VMProtect detected - Use VMProtect-specific unpackers or IDA Pro")
                recommendations.append("Consider using: UnicornEngine for VM emulation")
            elif "Code Virtualizer" in protection_name:
                recommendations.append("Code Virtualizer detected - Manual reverse engineering required")
                recommendations.append("Tools: OllyDbg, IDA Pro, Ghidra")
            elif "Themida" in protection_name:
                recommendations.append("Themida detected - Use Themida-specific unpackers")
                recommendations.append("Consider hardware breakpoints in debugger")
            elif "Confuser" in protection_name:
                recommendations.append("Confuser obfuscation detected - Use de4dot for deobfuscation")
                recommendations.append("Install: pip install de4dot or get binary from GitHub")
            elif "UPX" in protection_name:
                recommendations.append("UPX packing detected - Use UPX unpacker")
                recommendations.append("Install: apt install upx (Linux) or download from upx.sourceforge.net")
            elif "High Entropy" in protection_name:
                recommendations.append("High entropy detected - Data is likely encrypted")
                recommendations.append("Try XOR decryption, common encryption algorithms")
        
        if not recommendations:
            recommendations.append("Manual analysis with IDA Pro or Ghidra recommended")
        
        return recommendations


# Convenience function
def detect_and_decrypt(exe_path: str, output_dir: str) -> Dict:
    """
    Main entry point for decryption analysis
    
    Args:
        exe_path: Path to executable
        output_dir: Output directory
        
    Returns:
        Analysis and decryption results
    """
    manager = DecryptionManager()
    return manager.analyze_and_decrypt(exe_path, output_dir)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python decryptor.py <exe_path> <output_dir>")
        sys.exit(1)
    
    exe_path = sys.argv[1]
    output_dir = sys.argv[2]
    
    results = detect_and_decrypt(exe_path, output_dir)
    print(json.dumps(results, indent=2))
