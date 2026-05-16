"""
.NET Executable Unpacker Module
Uses dnSpy for decompilation and extraction of .NET assemblies
"""

import os
import subprocess
import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional
import logging
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Check if pythonnet is available and working
HAS_CLR = False
PYTHONNET_LOADED = False
try:
    import clr
    PYTHONNET_LOADED = True
    # Verify we can actually use it - pythonnet 3.x requires AddReference
    try:
        # Try to load a basic .NET assembly
        clr.AddReference("System")
        from System import Reflection
        HAS_CLR = True
    except (ImportError, AttributeError, TypeError) as e:
        logger.warning(f"pythonnet (clr) installed but not fully functional: {e}")
except ImportError:
    logger.info("pythonnet (clr) not available - using basic PE parsing instead")


class DotNETUnpacker:
    def __init__(self, dnspy_path: Optional[str] = None):
        """
        Initialize the .NET unpacker

        Args:
            dnspy_path: Path to dnSpy executable (if not in PATH)
        """
        self.dnspy_path = dnspy_path or self._find_dnspy()
        self.assembly_info = {}
        self.python_architecture = self._get_python_architecture()

    def _get_python_architecture(self) -> str:
        """Get the architecture of the current Python interpreter"""
        import platform
        machine = platform.machine().lower()
        if machine in ['amd64', 'x86_64']:
            return 'x64'
        elif machine in ['i386', 'i686', 'x86']:
            return 'x86'
        else:
            return machine

    def _get_assembly_architecture(self, exe_path: str) -> str:
        """Get the architecture of a .NET assembly from PE header"""
        try:
            import pefile
            pe = pefile.PE(exe_path)
            machine = pe.FILE_HEADER.Machine

            # Common machine types
            if machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
                return 'x86'
            elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                return 'x64'
            elif machine == 0x01c4:  # IMAGE_FILE_MACHINE_ARMNT
                return 'arm'
            elif machine == 0xaa64:  # IMAGE_FILE_MACHINE_ARM64
                return 'arm64'
            else:
                return f'unknown_{machine:04x}'

        except Exception:
            return 'unknown'

    def _is_architecture_compatible(self, exe_path: str) -> bool:
        """Check if the assembly architecture is compatible with Python"""
        if not HAS_CLR:
            return False

        assembly_arch = self._get_assembly_architecture(exe_path)
        return assembly_arch == self.python_architecture

    def _find_dnspy(self) -> str:
        """Find dnSpy in system PATH or common locations"""
        common_paths = [
            r"D:\Downloads\Reverse Engeneering\dnSpy-net-win64\dnSpy.exe",
            r"D:\Downloads\Reverse Engeneering\dnSpy-net-win64\dnSpy.exe",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Try to find in PATH
        dnspy = shutil.which("dnSpy.exe")
        if dnspy:
            return dnspy
        
        logger.warning("dnSpy not found. Download from: https://github.com/dnSpy/dnSpy/releases")
        return None
    
    def extract_metadata(self, exe_path: str) -> Dict:
        """
        Extract metadata from .NET assembly

        Args:
            exe_path: Path to the .NET executable

        Returns:
            Dictionary containing assembly metadata
        """
        if not self._is_architecture_compatible(exe_path):
            logger.info(f"Assembly architecture not compatible with Python ({self.python_architecture}) - using basic PE parsing")
            return self._extract_metadata_basic(exe_path)

        if not HAS_CLR:
            logger.warning("pythonnet not installed - using basic binary parsing")
            return self._extract_metadata_basic(exe_path)

        try:
            import clr
            clr.AddReference("System")
            from System import Reflection

            assembly = Reflection.Assembly.LoadFrom(exe_path)

            metadata = {
                "name": assembly.GetName().Name,
                "version": str(assembly.GetName().Version),
                "types": [],
                "methods": [],
                "namespaces": set()
            }

            for type_info in assembly.GetTypes():
                metadata["types"].append(type_info.FullName)
                metadata["namespaces"].add(type_info.Namespace)

                for method in type_info.GetMethods():
                    metadata["methods"].append(f"{type_info.Name}.{method.Name}")

            metadata["namespaces"] = list(metadata["namespaces"])
            return metadata

        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")
            return self._extract_metadata_basic(exe_path)
    
    def _extract_metadata_basic(self, exe_path: str) -> Dict:
        """
        Extract basic metadata using PE parsing (no pythonnet needed)
        """
        try:
            import pefile
            
            pe = pefile.PE(exe_path)
            
            metadata = {
                "name": os.path.basename(exe_path),
                "version": "Unknown",
                "types": [],
                "methods": [],
                "namespaces": ["(Using PE parsing - limited info)"]
            }
            
            # Try to extract from .NET metadata section
            for section in pe.sections:
                if section.Name.decode('utf-8', errors='ignore').startswith('.'):
                    metadata["types"].append(section.Name.decode('utf-8', errors='ignore'))
            
            return metadata
            
        except ImportError:
            logger.warning("pefile not available - returning basic info")
            return {
                "name": os.path.basename(exe_path),
                "version": "Unknown",
                "error": "Install pefile or pythonnet for detailed metadata"
            }
        except Exception as e:
            logger.error(f"Error in basic metadata extraction: {e}")
            return {"error": str(e)}
    
    def decompile_to_csharp(self, exe_path: str, output_dir: str) -> bool:
        """
        Decompile .NET assembly to C# source code
        
        Args:
            exe_path: Path to the .NET executable
            output_dir: Output directory for decompiled code
            
        Returns:
            True if successful, False otherwise
        """
        if not self.dnspy_path:
            logger.error("dnSpy not found. Please install dnSpy first.")
            return False
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # DNSpy command line arguments for export
            cmd = [
                self.dnspy_path,
                exe_path,
                "-o", output_dir,
                "-p",  # Plugin path
                "--dont-show-moduldefs",
            ]
            
            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully decompiled to {output_dir}")
                return True
            else:
                logger.error(f"Decompilation failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error during decompilation: {e}")
            return False
    
    def extract_resources(self, exe_path: str, output_dir: str) -> List[str]:
        """
        Extract embedded resources from .NET assembly

        Args:
            exe_path: Path to the .NET executable
            output_dir: Output directory for resources

        Returns:
            List of extracted resource paths
        """
        if not self._is_architecture_compatible(exe_path):
            logger.info(f"Assembly architecture not compatible with Python ({self.python_architecture}) - resource extraction not available")
            return []

        extracted = []

        if not HAS_CLR:
            logger.warning("pythonnet not available - resource extraction limited")
            logger.info("Install pythonnet for full resource extraction:")
            logger.info("  pip install pythonnet")
            return []

        try:
            import clr
            clr.AddReference("System")
            from System import Reflection

            assembly = Reflection.Assembly.LoadFrom(exe_path)
            resources = assembly.GetManifestResourceNames()

            os.makedirs(output_dir, exist_ok=True)

            for resource_name in resources:
                try:
                    stream = assembly.GetManifestResourceStream(resource_name)
                    if stream is None:
                        continue

                    resource_path = os.path.join(output_dir, resource_name)

                    os.makedirs(os.path.dirname(resource_path), exist_ok=True)

                    # Read stream data
                    stream_length = stream.Length
                    data = stream.ReadByte() if stream_length > 0 else b''

                    with open(resource_path, 'wb') as f:
                        if isinstance(data, bytes):
                            f.write(data)
                        else:
                            # Fallback for different pythonnet versions
                            f.write(bytes([data]))

                    extracted.append(resource_path)
                    logger.info(f"Extracted resource: {resource_name}")

                except Exception as e:
                    logger.warning(f"Failed to extract {resource_name}: {e}")

            return extracted

        except Exception as e:
            logger.error(f"Error extracting resources: {e}")
            return []
    
    def decompile_to_csharp_ilspy(self, exe_path: str, output_dir: str) -> bool:
        """
        Decompile .NET assembly using dnSpy or ILSpy
        
        Args:
            exe_path: Path to the .NET executable
            output_dir: Output directory for decompiled code
            
        Returns:
            True if successful, False otherwise
        """
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            # Try dnSpy first
            if self.dnspy_path:
                logger.info(f"Using dnSpy for decompilation")
                # dnSpy can export to CSharp
                return self._decompile_with_dnspy(exe_path, output_dir)
            
            # Fallback: Extract what we can
            logger.info("Using assembly reflection for code extraction")
            return self._extract_code_via_reflection(exe_path, output_dir)
            
        except Exception as e:
            logger.error(f"Error during decompilation: {e}")
            return False
    
    def _decompile_with_dnspy(self, exe_path: str, output_dir: str) -> bool:
        """Helper to decompile with dnSpy"""
        try:
            csharp_output = os.path.join(output_dir, "decompiled.csharp")
            
            cmd = [
                self.dnspy_path,
                exe_path,
                "-o", csharp_output,
            ]
            
            logger.info(f"Running dnSpy: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                logger.info(f"Decompilation successful")
                return True
            else:
                logger.warning(f"dnSpy output: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"dnSpy decompilation error: {e}")
            return False
    
    def _extract_code_via_reflection(self, exe_path: str, output_dir: str) -> bool:
        """Extract C# code structure via .NET reflection"""
        if not self._is_architecture_compatible(exe_path):
            logger.info(f"Assembly architecture not compatible with Python ({self.python_architecture}) - cannot extract via reflection")
            return False

        if not HAS_CLR:
            logger.warning("pythonnet not installed - cannot extract via reflection")
            logger.info("Install pythonnet for .NET code extraction:")
            logger.info("  pip install pythonnet")
            return False

        try:
            import clr
            clr.AddReference("System")
            from System import Reflection

            assembly = Reflection.Assembly.LoadFrom(exe_path)

            # Create main file
            cs_file = os.path.join(output_dir, "decompiled.cs")

            with open(cs_file, 'w', encoding='utf-8') as f:
                f.write(f"// Decompiled from: {os.path.basename(exe_path)}\n")
                f.write(f"// Assembly: {assembly.GetName().Name}\n")
                f.write(f"// Version: {assembly.GetName().Version}\n\n")

                # Write using statements
                f.write("using System;\n")
                f.write("using System.Collections;\n")
                f.write("using System.Collections.Generic;\n")
                f.write("using System.Linq;\n\n")

                # Write namespaces and types
                for type_info in assembly.GetTypes():
                    self._write_type_definition(f, type_info)

            logger.info(f"Code extracted to {cs_file}")
            return True

        except Exception as e:
            logger.error(f"Reflection extraction error: {e}")
            return False
    
    def _write_type_definition(self, f, type_info):
        """Write a type definition to file"""
        try:
            ns = type_info.Namespace or "Global"
            
            # Namespace declaration
            if ns:
                f.write(f"namespace {ns}\n{{\n")
            
            # Type declaration
            type_keyword = "class"
            if type_info.IsInterface:
                type_keyword = "interface"
            elif type_info.IsEnum:
                type_keyword = "enum"
            elif type_info.IsValueType:
                type_keyword = "struct"
            
            base_type = type_info.BaseType
            base_str = ""
            if base_type and base_type.Name != "Object" and not type_info.IsInterface:
                base_str = f" : {base_type.Name}"
            
            f.write(f"    public {type_keyword} {type_info.Name}{base_str}\n    {{\n")
            
            # Write methods
            for method in type_info.GetMethods():
                if not method.IsSpecialName:
                    params = ", ".join([f"{p.ParameterType.Name} {p.Name}" 
                                       for p in method.GetParameters()])
                    f.write(f"        public {method.ReturnType.Name} {method.Name}({params})\n")
                    f.write(f"        {{\n")
                    f.write(f"            // Method implementation\n")
                    f.write(f"        }}\n\n")
            
            # Write properties
            for prop in type_info.GetProperties():
                f.write(f"        public {prop.PropertyType.Name} {prop.Name} {{ get; set; }}\n")
            
            f.write("    }\n")
            
            if ns:
                f.write("}\n")
            
            f.write("\n")
            
        except Exception as e:
            logger.warning(f"Error writing type {type_info.Name}: {e}")

    def analyze_assembly(self, exe_path: str) -> Dict:
        """
        Analyze .NET assembly structure

        Args:
            exe_path: Path to the .NET executable

        Returns:
            Detailed analysis dictionary
        """
        if not self._is_architecture_compatible(exe_path):
            logger.info(f"Assembly architecture not compatible with Python ({self.python_architecture}) - using basic PE analysis")
            return self._analyze_assembly_basic(exe_path)

        analysis = {
            "file_info": {},
            "assembly_info": {},
            "references": [],
            "namespaces": {},
            "entry_point": None
        }

        if not HAS_CLR:
            logger.warning("pythonnet not installed - using basic PE analysis")
            return self._analyze_assembly_basic(exe_path)

        try:
            import clr
            clr.AddReference("System")
            from System import Reflection

            # File info
            file_stat = os.stat(exe_path)
            analysis["file_info"] = {
                "name": os.path.basename(exe_path),
                "size": file_stat.st_size,
                "path": exe_path
            }

            # Assembly info
            assembly = Reflection.Assembly.LoadFrom(exe_path)
            analysis["assembly_info"] = {
                "name": assembly.GetName().Name,
                "version": str(assembly.GetName().Version),
                "culture": str(assembly.GetName().CultureInfo),
                "is_signed": assembly.GetName().GetPublicKey() is not None
            }

            # Referenced assemblies
            for ref in assembly.GetReferencedAssemblies():
                analysis["references"].append(str(ref))

            # Entry point
            entry = assembly.EntryPoint
            if entry:
                analysis["entry_point"] = f"{entry.DeclaringType.Name}.{entry.Name}"

            # Namespace analysis
            for type_info in assembly.GetTypes():
                ns = type_info.Namespace or "Global"
                if ns not in analysis["namespaces"]:
                    analysis["namespaces"][ns] = []

                analysis["namespaces"][ns].append({
                    "name": type_info.Name,
                    "type": str(type_info.BaseType),
                    "methods": len(type_info.GetMethods())
                })

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing assembly: {e}")
            return self._analyze_assembly_basic(exe_path)
    
    def _analyze_assembly_basic(self, exe_path: str) -> Dict:
        """
        Basic assembly analysis using PE parsing (no pythonnet needed)
        """
        try:
            import pefile
            
            pe = pefile.PE(exe_path)
            
            analysis = {
                "file_info": {
                    "name": os.path.basename(exe_path),
                    "size": os.path.getsize(exe_path),
                    "path": exe_path
                },
                "assembly_info": {
                    "name": os.path.splitext(os.path.basename(exe_path))[0],
                    "is_net": False
                },
                "references": [],
                "namespaces": {}
            }
            
            # Check for .NET signature
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore')
                if '.text' in section_name or '.reloc' in section_name:
                    analysis["assembly_info"]["is_net"] = "Possibly"
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in basic analysis: {e}")
            return {
                "error": f"Could not analyze: {e}",
                "file_info": {"name": os.path.basename(exe_path)},
                "note": "Install pythonnet for .NET analysis: pip install pythonnet"
            }


def main():
    """Example usage"""
    unpacker = DotNETUnpacker()
    
    # Example: unpacker.analyze_assembly("sample.exe")
    # Example: unpacker.decompile_to_csharp("sample.exe", "./output/csharp")
    
    print("DotNET Unpacker Module Loaded")


if __name__ == "__main__":
    main()
