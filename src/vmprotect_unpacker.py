"""
VMProtect Unpacker Module
Specialized handling for VMProtect protected executables
Reference: vmpunpacker.py - LZMA-based decompression for VMProtect
"""

import os
import struct
import lzma
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import json

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# PE file format constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
LZMA_PROPERTIES_SIZE = 5  # Standard LZMA properties size


def to_hex_string(val, prefix=True):
    """Convert value to hexadecimal string for better error message display"""
    return f"0x{val:x}" if prefix else f"{val:x}"


@dataclass
class PACKER_INFO:
    """Python implementation of PACKER_INFO structure"""
    Src: int  # uint32 - Source RVA (compression info or compressed data)
    Dst: int  # uint32 - Destination RVA (for properties) or decompression target


class VMProtectDetector:
    """Detect VMProtect protection characteristics"""
    
    # VMProtect signatures and patterns
    VMPROTECT_SIGNATURES = [
        b"VMProtect",
        b"VmCode",
        b"VmData",
        b".vmp",
        b".vmp0",
        b".vmp1",
    ]
    
    def __init__(self, exe_path: str):
        self.exe_path = exe_path
        self.file_size = os.path.getsize(exe_path)
        self.pe = None
        self._load_pe()
        
    def _load_pe(self):
        """Load PE file if pefile available"""
        if HAS_PEFILE:
            try:
                self.pe = pefile.PE(self.exe_path)
            except Exception as e:
                logger.warning(f"Could not load PE: {e}")
    
    def detect_vmprotect(self) -> Dict:
        """Detect VMProtect protection in executable"""
        results = {
            "is_vmprotect": False,
            "confidence": 0,
            "indicators": [],
            "version": "Unknown",
            "protection_features": [],
            "vmprotect_sections": []
        }
        
        try:
            with open(self.exe_path, 'rb') as f:
                data = f.read()
            
            # Check for VMProtect signatures
            for sig in self.VMPROTECT_SIGNATURES:
                if sig in data:
                    results["indicators"].append(f"Found signature: {sig}")
                    results["confidence"] += 20
            
            # Check PE sections
            if self.pe:
                for section in self.pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    if any(vmp_str in section_name for vmp_str in ['.vmp', '.vmp0', '.vmp1']):
                        results["vmprotect_sections"].append(section_name)
                        results["indicators"].append(f"Found VMProtect section: {section_name}")
                        results["confidence"] += 25
                
                # Check for suspicious characteristics
                if results["vmprotect_sections"]:
                    results["protection_features"].append("Code virtualization")
                    results["confidence"] += 15
            
            # Analyze entropy
            entropy = self._calculate_entropy(data)
            results["entropy"] = round(entropy, 2)
            
            if entropy > 7.5:
                results["indicators"].append(f"High entropy detected ({entropy:.2f})")
                results["protection_features"].append("Compressed/encrypted code")
                results["confidence"] += 15
            
            # Check for LZMA markers
            if b'LZMA' in data or self._detect_lzma_markers(data):
                results["indicators"].append("LZMA compression detected")
                results["protection_features"].append("LZMA compression")
                results["confidence"] += 20
            
            # Determine if VMProtect protected
            results["is_vmprotect"] = results["confidence"] >= 40
            results["confidence"] = min(100, results["confidence"])
            
            return results
            
        except Exception as e:
            logger.error(f"Error detecting VMProtect: {e}")
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
    
    def _detect_lzma_markers(self, data: bytes) -> bool:
        """Detect LZMA compression markers"""
        # LZMA magic doesn't always appear, but PACKER_INFO structure does
        # Look for patterns that suggest PACKER_INFO arrays
        
        # Common LZMA properties patterns
        lzma_markers = [
            b'\x5D\x00\x00\x10\x00',  # Common LZMA header
            b'\x6D\x00\x00\x08\x00',  # Another variant
        ]
        
        return any(marker in data for marker in lzma_markers)


class VMProtectUnpacker:
    """Unpack VMProtect protected executables"""

    def __init__(self):
        if not HAS_PEFILE:
            logger.warning("pefile not installed - VMProtect unpacking limited. Install with: pip install pefile")
        self.detector = None

    def unpack_pe(self, packed_pe_data: bytes) -> bytes:
        """
        Unpack a VMProtect protected PE file

        Args:
            packed_pe_data: Byte content of the packed PE file

        Returns:
            Unpacked PE file byte content
        """
        if not packed_pe_data:
            raise RuntimeError("Packed PE data is null or empty.")

        # Use pefile library to parse PE file
        try:
            pe = pefile.PE(data=packed_pe_data)
        except pefile.PEFormatError as e:
            raise RuntimeError(f"Invalid PE file format: {str(e)}")

        # Get basic PE information
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
        size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        number_of_sections = pe.FILE_HEADER.NumberOfSections

        # Create unpacked image
        unpacked_image = bytearray(size_of_image)

        # Copy PE headers
        unpacked_image[:size_of_headers] = packed_pe_data[:size_of_headers]

        # Collect RVA patterns to locate PACKER_INFO array
        rva_patterns_array = []
        for section in pe.sections:
            # Check conditions: no raw data but has virtual address, and not uninitialized data section
            condition1 = (section.SizeOfRawData == 0)
            condition2 = (section.PointerToRawData == 0)
            condition3 = not (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)

            if condition1 and condition2 and condition3:
                # 64-bit mode: high 32 bits is VirtualAddress, low 32 bits is 0xFFFFFFFF (wildcard)
                pattern_value = ((section.VirtualAddress << 32) | 0xFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
                pattern_bytes = struct.pack("<Q", pattern_value)
                rva_patterns_array.append(pattern_bytes)

        # Find PACKER_INFO array
        packer_info_array = []
        num_packer_entries = 0

        if rva_patterns_array:
            # Convert patterns to a single byte sequence
            pattern_bytes = b''.join(rva_patterns_array)

            # Search for pattern
            pattern_pos = self._find_pattern(packed_pe_data, pattern_bytes)

            if pattern_pos is not None:
                # PACKER_INFO array is located before the matching pattern sequence
                if pattern_pos < 8:  # sizeof(PACKER_INFO) = 8
                    raise RuntimeError("Located RVA pattern is too close to the beginning of the file to precede PACKER_INFO[0].")

                packer_info_offset = pattern_pos - 8
                num_packer_entries = len(rva_patterns_array)

                # Verify reading this array won't go beyond packed_pe_data boundaries
                if num_packer_entries > 0:
                    end_of_packer_info_array = packer_info_offset + (num_packer_entries + 1) * 8
                    if end_of_packer_info_array > len(packed_pe_data) or packer_info_offset < 0:
                        raise RuntimeError("Located PACKER_INFO array extends beyond packed PE buffer or has invalid start.")

                # Extract PACKER_INFO array
                for j in range(num_packer_entries + 1):  # +1 because original code includes the first entry
                    info_offset = packer_info_offset + j * 8
                    src = struct.unpack("<I", packed_pe_data[info_offset:info_offset+4])[0]
                    dst = struct.unpack("<I", packed_pe_data[info_offset+4:info_offset+8])[0]
                    packer_info_array.append(PACKER_INFO(src, dst))

            elif rva_patterns_array:
                raise RuntimeError("RVA pattern sequence for PACKER_INFO not found in packed PE, but patterns were expected.")
        else:
            print("Warning: RVA pattern array is empty. No PACKER_INFO entries to process for LZMA.")

        # Copy section data and update section headers in unpacked image
        for i, section in enumerate(pe.sections):
            # Original section header
            virtual_address = section.VirtualAddress
            virtual_size = section.Misc_VirtualSize
            size_of_raw_data = section.SizeOfRawData
            pointer_to_raw_data = section.PointerToRawData
            section_name = section.Name.decode('ascii', errors='ignore').strip('\0')

            # Copy section data
            if pointer_to_raw_data != 0 and size_of_raw_data > 0:
                if pointer_to_raw_data + size_of_raw_data <= len(packed_pe_data) and virtual_address + size_of_raw_data <= size_of_image:
                    section_data = packed_pe_data[pointer_to_raw_data:pointer_to_raw_data+size_of_raw_data]
                    unpacked_image[virtual_address:virtual_address+len(section_data)] = section_data
                else:
                    print(f"Warning: Section {section_name} data exceeds boundaries. RawOffset={to_hex_string(pointer_to_raw_data)}, "
                          f"RawSize={to_hex_string(size_of_raw_data)}, VA={to_hex_string(virtual_address)}. Skipping copy.")

            # Get section table offset in file
            section_offset = pe.OPTIONAL_HEADER.get_file_offset() + pe.FILE_HEADER.SizeOfOptionalHeader + i * 40

            # Update section header in unpacked image
            unpacked_section_offset = section_offset

            # Update PointerToRawData to VirtualAddress
            struct.pack_into("<I", unpacked_image, unpacked_section_offset+20, virtual_address)

            # If VirtualSize is non-zero, use it as SizeOfRawData
            if virtual_size > 0:
                struct.pack_into("<I", unpacked_image, unpacked_section_offset+16, virtual_size)

        # Handle LZMA decompression
        if packer_info_array and len(packer_info_array) > 1:
            # Get LZMA properties
            props_info = packer_info_array[0]
            # Use pefile's get_offset_from_rva method to convert RVA to file offset
            props_raw_offset = pe.get_offset_from_rva(props_info.Src)

            lzma_props_size = props_info.Dst
            lzma_props_data = packed_pe_data[props_raw_offset:props_raw_offset+lzma_props_size]

            if props_raw_offset + lzma_props_size > len(packed_pe_data):
                raise RuntimeError(f"LZMA properties data (RVA {to_hex_string(props_info.Src)} -> Raw {to_hex_string(props_raw_offset)}, "
                                  f"Size from Dst {lzma_props_size}) extends beyond packed PE size ({to_hex_string(len(packed_pe_data))}).")

            # Standard LZMA properties size is 5 bytes
            if lzma_props_size != LZMA_PROPERTIES_SIZE:
                print(f"Warning: PACKER_INFO[0].Dst (LZMA properties size) is {lzma_props_size}. Standard is {LZMA_PROPERTIES_SIZE}. Using provided size.")

            try:
                # Process each LZMA block
                for block_idx in range(1, len(packer_info_array)):
                    current_block_info = packer_info_array[block_idx]

                    compressed_data_rva = current_block_info.Src
                    uncompressed_target_rva = current_block_info.Dst

                    # Use pefile to get file offset
                    try:
                        compressed_block_raw_offset = pe.get_offset_from_rva(compressed_data_rva)
                    except Exception as e:
                        raise RuntimeError(f"Block {block_idx}: Cannot convert RVA to file offset: {str(e)}")

                    compressed_data = packed_pe_data[compressed_block_raw_offset:]

                    if uncompressed_target_rva >= size_of_image:
                        raise RuntimeError(f"Block {block_idx}: PACKER_INFO.Dst (decompression target RVA {to_hex_string(uncompressed_target_rva)}) "
                                          f"exceeds image boundary ({to_hex_string(size_of_image)}).")

                    # Use Python's lzma module to decompress data
                    # Note: We need to construct a properly formatted LZMA stream
                    lc = lzma_props_data[0] % 9
                    lp = (lzma_props_data[0] // 9) % 5
                    pb = lzma_props_data[0] // 45
                    dict_size = int.from_bytes(lzma_props_data[1:5], byteorder='little')

                    # Build LZMA compression filter
                    filters = [
                        {
                            "id": lzma.FILTER_LZMA1,
                            "dict_size": dict_size,
                            "lc": lc,
                            "lp": lp,
                            "pb": pb
                        }
                    ]

                    # Create an LZMA decompressor
                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)

                    # Decompress data
                    try:
                        decompressed_data = decompressor.decompress(compressed_data)

                        # Write decompressed data to target location
                        available_space = size_of_image - uncompressed_target_rva
                        if len(decompressed_data) <= available_space:
                            unpacked_image[uncompressed_target_rva:uncompressed_target_rva+len(decompressed_data)] = decompressed_data
                        else:
                            print(f"Warning: Block {block_idx}: Decompressed data size exceeds available space in image")
                            # Only write data that can fit
                            unpacked_image[uncompressed_target_rva:uncompressed_target_rva+available_space] = decompressed_data[:available_space]

                        print(f"Block {block_idx}: Decompressed. Output size={len(decompressed_data)}")

                    except lzma.LZMAError as e:
                        raise RuntimeError(f"LZMA decompression error: {str(e)}")

            except Exception as e:
                raise RuntimeError(f"Error processing LZMA data: {str(e)}")

        return bytes(unpacked_image)

    def to_hex_string(self, val, prefix=True):
        """Convert value to hexadecimal string for better error message display"""
        return f"0x{val:x}" if prefix else f"{val:x}"

    def find_pattern(self, data: bytes, pattern: bytes) -> Optional[int]:
        """
        Find pattern in data, supporting 0xFF as wildcard
        Returns position where found, or None if not found
        """
        if not pattern or len(data) < len(pattern):
            return None

        for i in range(len(data) - len(pattern) + 1):
            match = True
            for j in range(len(pattern)):
                if pattern[j] != 0xFF and data[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                return i
        return None

    def unpack_executable(self, exe_path: str, output_dir: str) -> Tuple[bool, str]:
        """
        Attempt to unpack VMProtect protected executable
        
        Args:
            exe_path: Path to VMProtect-protected executable
            output_dir: Output directory for unpacked file
            
        Returns:
            Tuple of (success, message)
        """
        if not HAS_PEFILE:
            return False, "pefile required for VMProtect unpacking. Install: pip install pefile"
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Detect VMProtect
        self.detector = VMProtectDetector(exe_path)
        detection = self.detector.detect_vmprotect()
        
        logger.info(f"VMProtect Detection Results:")
        logger.info(f"  Is VMProtect: {detection['is_vmprotect']}")
        logger.info(f"  Confidence: {detection['confidence']}%")
        logger.info(f"  Sections: {', '.join(detection['vmprotect_sections'])}")
        
        try:
            # Attempt unpacking with improved method
            with open(exe_path, 'rb') as f:
                packed_data = f.read()

            logger.info(f"Loaded executable ({len(packed_data):,} bytes), attempting PACKER_INFO-based unpacking...")

            # Try the new PACKER_INFO-based unpacking method first
            try:
                unpacked_data = self.unpack_pe(packed_data)
                if unpacked_data:
                    output_path = os.path.join(output_dir, "unpacked.exe")
                    with open(output_path, 'wb') as f:
                        f.write(unpacked_data)

                    logger.info(f"Successfully unpacked using PACKER_INFO method to {output_path}")
                    return True, f"Unpacked successfully using PACKER_INFO ({len(unpacked_data):,} bytes)"
            except Exception as e:
                logger.warning(f"PACKER_INFO unpacking failed: {e}")
                logger.info("Falling back to alternative methods...")

            # Try direct LZMA decompression method
            result = self._try_direct_lzma_unpacking(exe_path, packed_data, output_dir)
            if result:
                return True, result

            # Try section-based unpacking
            logger.info("Attempting section-based unpacking...")
            unpacked_data = self._unpack_pe_sections(exe_path, packed_data)

            if unpacked_data:
                output_path = os.path.join(output_dir, "unpacked.exe")
                with open(output_path, 'wb') as f:
                    f.write(unpacked_data)

                logger.info(f"Successfully unpacked to {output_path}")
                return True, f"Unpacked successfully ({len(unpacked_data):,} bytes)"

        except Exception as e:
            logger.debug(f"Unpacking error: {e}")
        
        # If automatic unpacking fails, generate guide
        logger.info("Generating manual unpacking guide...")
        return self._generate_unpacking_guide(exe_path, output_dir, detection)
    
    def _try_direct_lzma_unpacking(self, exe_path: str, packed_data: bytes, output_dir: str) -> Optional[str]:
        """
        Try direct LZMA decompression without full PE unpacking
        Useful when only LZMA-compressed code needs extraction
        """
        try:
            pe = pefile.PE(data=packed_data)
            
            # Look for and decompress LZMA blocks
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                if any(vmp in section_name for vmp in ['.vmp', '.vmp0', '.vmp1']):
                    logger.info(f"Processing section: {section_name}")
                    
                    offset = section.PointerToRawData
                    size = section.SizeOfRawData
                    
                    if offset > 0 and size > 0:
                        section_data = packed_data[offset:offset+size]
                        
                        # Try to find and decompress LZMA
                        blocks = self._extract_lzma_blocks_fast(section_data, max_blocks=10)
                        
                        if blocks:
                            logger.info(f"Found {len(blocks)} LZMA block(s)")
                            
                            # Create output file with decompressed content
                            output_path = os.path.join(output_dir, f"decompressed_{section_name}.bin")
                            
                            with open(output_path, 'wb') as f:
                                for block in blocks:
                                    f.write(block.get('decompressed', b''))
                            
                            logger.info(f"Extracted {len(blocks)} blocks to {output_path}")
                            return f"LZMA blocks decompressed ({len(blocks)} blocks)"
            
            return None
        
        except Exception as e:
            logger.debug(f"Direct LZMA unpacking failed: {e}")
            return None
    
    def _extract_lzma_blocks_fast(self, data: bytes, max_blocks: int = 10) -> list:
        """Fast LZMA block extraction - finds and decompresses blocks quickly"""
        blocks = []
        found = 0
        
        i = 0
        while i < len(data) and found < max_blocks:
            # Look for LZMA property byte pattern
            if i < len(data) - 5:
                prop_byte = data[i]
                
                # LZMA property validation
                if prop_byte <= 224:
                    try:
                        # Check if next 4 bytes look like dict_size
                        dict_size = int.from_bytes(data[i+1:i+5], byteorder='little')
                        
                        if 0 < dict_size <= 0x10000000:  # Reasonable size
                            # Found potential LZMA header
                            # Try to find the end of this LZMA stream
                            for test_size in [0x100000, 0x80000, 0x40000, 0x20000, 0x10000]:
                                if i + test_size > len(data):
                                    continue
                                
                                try:
                                    block_data = data[i:min(i+test_size, len(data))]
                                    decompressed = lzma.decompress(block_data)
                                    
                                    if decompressed and len(decompressed) > 0:
                                        blocks.append({
                                            'offset': i,
                                            'compressed': len(block_data),
                                            'decompressed': decompressed
                                        })
                                        found += 1
                                        i += len(block_data)
                                        logger.info(f"Block {found}: {len(block_data)} → {len(decompressed)} bytes")
                                        break
                                except:
                                    pass
                    except:
                        pass
            
            i += 1
        
        return blocks
    
    def _try_aggressive_lzma_extraction(self, packed_data: bytes, output_dir: str) -> Optional[Tuple[bool, str]]:
        """
        Aggressive LZMA extraction - try multiple approaches to decompress VMProtect sections
        """
        logger.info("Attempting aggressive LZMA extraction...")
        
        try:
            pe = pefile.PE(data=packed_data)
            
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                if any(vmp in section_name for vmp in ['.vmp', '.vmp0', '.vmp1']):
                    logger.info(f"Aggressively processing section: {section_name}")
                    
                    offset = section.PointerToRawData
                    size = section.SizeOfRawData
                    
                    if offset > 0 and size > 0:
                        section_data = packed_data[offset:offset+size]
                        
                        # Try multiple LZMA extraction approaches
                        for i in range(min(100, len(section_data) - 6)):
                            prop_byte = section_data[i]
                            
                            if prop_byte <= 224:
                                try:
                                    dict_size = int.from_bytes(section_data[i+1:i+5], byteorder='little')
                                    
                                    if 0 < dict_size <= 0x1000000 and dict_size != 0x5D000010:  # Skip standard headers
                                        # Try different dict sizes around this value
                                        for dict_attempt in [dict_size, dict_size // 2, dict_size * 2]:
                                            if dict_attempt < 0x10000 or dict_attempt > 0x1000000:
                                                continue
                                                
                                            for lc in range(9):
                                                for lp in range(5):
                                                    for pb in range(5):
                                                        try:
                                                            filters = [{
                                                                "id": lzma.FILTER_LZMA1,
                                                                "dict_size": dict_attempt,
                                                                "lc": lc,
                                                                "lp": lp,
                                                                "pb": pb
                                                            }]
                                                            
                                                            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
                                                            
                                                            # Try decompressing different amounts of data
                                                            for decomp_size in [0x10000, 0x40000, 0x100000, 0x400000]:
                                                                if i + decomp_size > len(section_data):
                                                                    decomp_size = len(section_data) - i
                                                                
                                                                try:
                                                                    test_data = section_data[i:i+decomp_size]
                                                                    decompressed = decompressor.decompress(test_data)
                                                                    
                                                                    if decompressed and len(decompressed) > 0x1000:  # Minimum size for meaningful code
                                                                        logger.info(f"Found LZMA data at offset {i}: {len(test_data)} → {len(decompressed)} bytes")
                                                                        
                                                                        # Write decompressed data
                                                                        output_path = os.path.join(output_dir, f"lzma_{section_name}_{i:x}.bin")
                                                                        with open(output_path, 'wb') as f:
                                                                            f.write(decompressed)
                                                                        
                                                                        logger.info(f"Saved to: {output_path}")
                                                                        return True, f"LZMA data extracted from {section_name} at offset 0x{i}"
                                                                except:
                                                                    pass
                                                        except:
                                                            pass
                                except:
                                    pass
            
            return None
        
        except Exception as e:
            logger.debug(f"Aggressive LZMA extraction failed: {e}")
            return None
    
    def _unpack_pe_sections(self, exe_path: str, packed_pe_data: bytes) -> Optional[bytes]:
        """
        Unpack VMProtect sections by copying and decompressing LZMA blocks
        More efficient than full PE memory reconstruction
        
        Args:
            exe_path: Path to exe for reference
            packed_pe_data: Byte content of packed PE file
            
        Returns:
            Unpacked PE file or None if failed
        """
        if not packed_pe_data:
            logger.error("Packed PE data is empty")
            return None
        
        try:
            pe = pefile.PE(data=packed_pe_data)
        except Exception as e:
            logger.error(f"Invalid PE: {e}")
            return None
        
        # For large files, just copy and return with hints for manual unpacking
        if len(packed_pe_data) > 50 * 1024 * 1024:  # > 50MB
            logger.warning("File too large for automatic LZMA unpacking")
            logger.info("Recommend using memory dump approach with debugger")
            return None
        
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
        
        try:
            unpacked = bytearray(size_of_image)
        except MemoryError:
            logger.error(f"Insufficient memory for {size_of_image:,} byte image")
            return None
        
        # Copy headers
        size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        unpacked[:size_of_headers] = packed_pe_data[:size_of_headers]
        
        decompressed_sections = 0
        
        # Process each section
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            virt_addr = section.VirtualAddress
            virt_size = section.Misc_VirtualSize
            ptr_raw = section.PointerToRawData
            size_raw = section.SizeOfRawData
            
            # Bounds check
            if ptr_raw + size_raw > len(packed_pe_data):
                continue
            if virt_addr + virt_size > size_of_image:
                continue
            
            if ptr_raw > 0 and size_raw > 0:
                section_data = packed_pe_data[ptr_raw:ptr_raw+size_raw]
                
                # Try to decompress if VMProtect section
                if any(vmp in section_name for vmp in ['.vmp', '.vmp0', '.vmp1']):
                    if self._try_decompress_section(section_data, unpacked, virt_addr, virt_size):
                        decompressed_sections += 1
                else:
                    # Normal section - just copy
                    unpacked[virt_addr:virt_addr+len(section_data)] = section_data
        
        if decompressed_sections > 0:
            logger.info(f"Successfully decompressed {decompressed_sections} sections")
            return bytes(unpacked)
        
        logger.warning("No sections successfully decompressed")
        return None
    
    def _try_decompress_section(self, section_data: bytes, unpacked_image: bytearray, 
                                virt_addr: int, virt_size: int) -> bool:
        """Try to decompress a section"""
        if len(section_data) < 6:
            return False
        
        try:
            # Try FORMAT_RAW decompression
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW)
            decompressed = decompressor.decompress(section_data)
            
            if decompressed and len(decompressed) > 0:
                copy_size = min(len(decompressed), virt_size, len(unpacked_image) - virt_addr)
                unpacked_image[virt_addr:virt_addr+copy_size] = decompressed[:copy_size]
                logger.info(f"Decompressed section: {len(section_data)} → {len(decompressed)} bytes")
                return True
        except:
            pass
        
        try:
            # Try standard LZMA format
            decompressed = lzma.decompress(section_data)
            
            if decompressed and len(decompressed) > 0:
                copy_size = min(len(decompressed), virt_size, len(unpacked_image) - virt_addr)
                unpacked_image[virt_addr:virt_addr+copy_size] = decompressed[:copy_size]
                logger.info(f"Decompressed section (std): {len(section_data)} → {len(decompressed)} bytes")
                return True
        except:
            pass
        
        return False
    
    def _find_lzma_blocks(self, section_data: bytes, base_rva: int, section_name: str = "", limit: int = None) -> list:
        """
        Find and extract LZMA compressed blocks from section data
        
        Args:
            section_data: Raw section data
            base_rva: Base RVA of section
            section_name: Name of section (for logging)
            limit: Maximum number of blocks to find (None = no limit)
            
        Returns:
            List of LZMA block info dicts
        """
        blocks = []
        
        if not section_data or len(section_data) < 12:
            return blocks
        
        # Look for LZMA block signatures and patterns
        i = 0
        found_count = 0
        
        while i < len(section_data) - 11:
            # Check for common LZMA property bytes
            prop_byte = section_data[i]
            
            # LZMA property byte: (pb*5 + lp)*9 + lc
            # Valid ranges: lc(0-8), lp(0-4), pb(0-4)
            if prop_byte <= 224:  # Max valid property byte
                # Check if this looks like LZMA header
                dict_size_bytes = section_data[i+1:i+5]
                
                if len(dict_size_bytes) == 4:
                    try:
                        dict_size = int.from_bytes(dict_size_bytes, byteorder='little')
                        
                        # Valid dictionary sizes are powers of 2 or specific values
                        if dict_size > 0 and dict_size <= 0x80000000:
                            # This looks like LZMA header, extract block
                            
                            # Try to decompress starting from this position
                            for block_size in [0x100000, 0x80000, 0x40000, 0x20000, 0x10000, 0x8000, 0x4000, 0x2000]:
                                if i + block_size > len(section_data):
                                    continue
                                
                                block_data = section_data[i:i+block_size]
                                
                                try:
                                    # Try to decompress as FORMAT_RAW
                                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW)
                                    decompressed = decompressor.decompress(block_data)
                                    
                                    if len(decompressed) > 0:
                                        blocks.append({
                                            'data': block_data,
                                            'offset': i,
                                            'target_rva': base_rva + i,
                                            'section': section_name,
                                            'compressed_size': len(block_data),
                                            'decompressed_size': len(decompressed)
                                        })
                                        
                                        logger.info(f"Found LZMA block in {section_name}: "
                                                   f"offset=0x{i:08x}, compressed={len(block_data)}, "
                                                   f"decompressed={len(decompressed)}")
                                        
                                        found_count += 1
                                        i += len(block_data) - 1
                                        break
                                
                                except:
                                    pass
                            
                            if limit and found_count >= limit:
                                break
                    
                    except:
                        pass
            
            i += 1
        
        return blocks
    
    def _find_pattern(self, data: bytes, pattern: bytes) -> Optional[int]:
        """
        Find pattern in data, supporting 0xFF as wildcard
        Returns position where found, or None if not found
        """
        if not pattern or len(data) < len(pattern):
            return None
        
        for i in range(len(data) - len(pattern) + 1):
            match = True
            for j in range(len(pattern)):
                if pattern[j] != 0xFF and data[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                return i
        return None
    
    def _generate_unpacking_guide(self, exe_path: str, output_dir: str, detection: Dict) -> Tuple[bool, str]:
        """Generate VMProtect unpacking guide"""
        try:
            guide_path = os.path.join(output_dir, "VMPROTECT_UNPACKING_GUIDE.md")
            
            guide = f'''# VMProtect Unpacking Guide

## File Information
- **Executable**: {os.path.basename(exe_path)}
- **Size**: {os.path.getsize(exe_path):,} bytes
- **Protection**: VMProtect

## Detection Results
- **Confidence**: {detection['confidence']}%
- **Features Detected**:
'''
            
            for feature in detection['protection_features']:
                guide += f"  - {feature}\n"
            
            guide += '''
## Unpacking Methods (In Order of Effectiveness)

### 1. User-Mode Debugger (OllyDbg) - RECOMMENDED
**Difficulty**: Medium
**Time**: 30-60 minutes

#### Steps:
1. Open executable in OllyDbg
2. Find OEP (Original Entry Point):
   - Look for virtualization VM entry code
   - Set breakpoint at first potential unpacked code
   - Search for patterns like: PUSH EBP; MOV EBP, ESP
3. Use Scylla plugin to dump memory
4. Rebuild Import Address Table (IAT)
5. Validate with PEiD or CFF Explorer

### 2. Dynamic Analysis with Process Dumping
**Difficulty**: Easy
**Time**: 10-20 minutes

#### Tools:
- PE-sieve (automatic memory dumping)
- Volatility (memory forensics)
- Scylla (import rebuilding)

#### Steps:
1. Let executable run (controlled environment!)
2. Use PE-sieve to detect and dump unpacked code
3. Analyze dump in IDA Pro
4. Use Scylla to fix imports

### 3. Static Analysis (Advanced)
**Difficulty**: Hard
**Time**: 2-4 hours

#### Tools:
- IDA Pro (with VMProtect plugins)
- Ghidra (free alternative)
- Radare2 (command-line analysis)

#### Steps:
1. Analyze virtualization patterns
2. Identify VM bytecode opcodes
3. Trace execution flow
4. Manually reconstruct functions
5. Build unobfuscated binary

## Key Detection Points

### Memory Sections
- .vmp0, .vmp1 - VMProtect virtualized code sections
- RWX (read-write-execute) regions - unpacked code location
- High entropy sections - encrypted code

### API Hooks
- VirtualAlloc - memory allocation for unpacked code
- VirtualProtect - modifying section protections
- GetProcAddress - dynamic imports

### Code Patterns
- Large switch statements (VM dispatcher)
- Unusual instruction sequences
- Indirect jumps and calls

## Recommended Tools

### Essential
- **OllyDbg 2.0**: Free, user-mode debugger
  - Download: http://www.ollydbg.de/
  - Required: Scylla plugin for memory dumping
  
- **Scylla**: Memory dumper and IAT rebuilder
  - Download: https://github.com/NtQuerySystemInformation/Scylla
  - Plugin for both OllyDbg and IDA Pro

### Optional but Helpful
- **IDA Pro 7.0+**: Professional disassembler
  - Cost: $$$
  - Worth it for professional work
  
- **Ghidra**: Free alternative to IDA Pro
  - Download: https://ghidra-sre.org/
  - NSA's open-source reverse engineering tool

- **PE-sieve**: Automatic memory dumping
  - Download: https://github.com/hasherezade/pe-sieve
  - Great for quick unpacking

### Validation
- **PEiD**: Check if unpacked correctly
- **CFF Explorer**: View/edit PE headers
- **Dependency Walker**: Check imports

## Common Issues & Solutions

### Issue: Can't find OEP
**Solutions:**
- Use hardware breakpoints on memory allocation
- Monitor RWX region changes
- Step through VM dispatcher code
- Look for section name ".text" being written

### Issue: Imports not working after unpacking
**Solutions:**
- Use Scylla's IAT autofind
- Manually trace GetProcAddress calls
- Rebuild import table
- Check for import address table hooks

### Issue: Unpacked file won't execute
**Solutions:**
- Verify PE header integrity
- Check section alignments
- Validate entry point (0x400000 + EntryPoint RVA)
- Look for relocations

## Advanced Techniques

### Hardware Breakpoints
```
In OllyDbg:
- Breakpoint on VirtualAlloc return
- Breakpoint on large memory writes
- Breakpoint on execution of newly allocated memory
```

### Memory Monitoring
```
Watch for:
- New RWX regions being created
- Section protection changes
- Large memcpy operations
- Decryption loops
```

### Pattern Matching
```
Look for signatures:
- VM entry: PUSH EBP; MOV EBP, ESP; SUB ESP
- VM handler: Large switch statement
- Unpacked code: Function prologues
```

## Success Criteria

Unpacked file should:
- Have valid PE header (MZ signature)
- Have reasonable entropy (not all high)
- Disassemble with meaningful code
- Have proper import table
- Execute without VMProtect
- Run in debugger without crashes

## References

- VMProtect Official: http://www.oreans.com/
- Reverse Engineering: crackmes.one
- OllyDbg Tutorials: YouTube
- IDA Pro Docs: https://hex-rays.com/ida-pro/

## Next Steps

1. Choose debugging approach above
2. Gather tools from recommended list
3. Practice on known samples
4. Start with memory dumping (fastest)
5. Fall back to OllyDbg if needed

## Legal Notice

Only unpack executables you own or have permission to analyze.
Unauthorized unpacking may violate software licensing.
'''
            
            with open(guide_path, 'w') as f:
                f.write(guide)
            
            logger.info(f"Generated unpacking guide: {guide_path}")
            return False, "Unpacking guide generated (manual analysis required)"
        
        except Exception as e:
            logger.error(f"Error generating guide: {e}")
            return False, str(e)
    
    def generate_analysis_report(self, exe_path: str, output_dir: str) -> Dict:
        """Generate comprehensive VMProtect analysis report"""
        os.makedirs(output_dir, exist_ok=True)

        detector = VMProtectDetector(exe_path)
        detection = detector.detect_vmprotect()

        report = {
            "file": os.path.basename(exe_path),
            "file_size": os.path.getsize(exe_path),
            "detection": detection,
            "unpacking_recommendations": self._get_recommendations(detection),
            "required_tools": self._get_required_tools(),
            "difficulty_level": self._assess_difficulty(detection),
            "estimated_time": self._estimate_time(detection)
        }

        # Save report
        report_path = os.path.join(output_dir, "vmprotect_analysis_report.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Analysis report saved: {report_path}")
        return report

    def load_analysis_report(self, report_path: str) -> Optional[Dict]:
        """Load and parse VMProtect analysis report from JSON file"""
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
            logger.info(f"Analysis report loaded: {report_path}")
            return report
        except Exception as e:
            logger.error(f"Failed to load analysis report: {e}")
            return None

    def unpack_from_report(self, exe_path: str, report_path: str, output_dir: str) -> Tuple[bool, str]:
        """
        Unpack executable using guidance from analysis report

        Args:
            exe_path: Path to executable to unpack
            report_path: Path to JSON analysis report
            output_dir: Output directory for unpacked file

        Returns:
            Tuple of (success, message)
        """
        # Load the analysis report
        report = self.load_analysis_report(report_path)
        if not report:
            return False, "Failed to load analysis report"

        logger.info("Using analysis report to guide unpacking process")
        logger.info(f"Report for: {report['file']} ({report['file_size']:,} bytes)")
        logger.info(f"Detection: {report['detection']['confidence']}% confidence")
        logger.info(f"Difficulty: {report['difficulty_level']}")
        logger.info(f"Estimated time: {report['estimated_time']}")

        if report['detection']['vmprotect_sections']:
            logger.info(f"VMProtect sections detected: {', '.join(report['detection']['vmprotect_sections'])}")

        # Use report recommendations to adjust unpacking strategy
        detection = report['detection']

        # If high confidence VMProtect, prioritize advanced unpacking
        if detection['confidence'] >= 80:
            logger.info("High confidence VMProtect detected - using advanced unpacking methods")
            return self._unpack_high_confidence_vmprotect(exe_path, output_dir, report)
        elif detection['confidence'] >= 40:
            logger.info("Medium confidence VMProtect detected - using standard unpacking methods")
            return self.unpack_executable(exe_path, output_dir)
        else:
            logger.info("Low confidence or no VMProtect detected - using basic reconstruction")
            return self._unpack_basic_reconstruction(exe_path, output_dir)

    def _unpack_high_confidence_vmprotect(self, exe_path: str, output_dir: str, report: Dict) -> Tuple[bool, str]:
        """
        Advanced unpacking for high-confidence VMProtect files using report guidance
        """
        logger.info("Applying high-confidence VMProtect unpacking strategy")

        try:
            # Load executable
            with open(exe_path, 'rb') as f:
                packed_data = f.read()

            logger.info(f"Loaded executable ({len(packed_data):,} bytes)")

            # Try PACKER_INFO method first (most effective for VMProtect)
            logger.info("Attempting PACKER_INFO-based unpacking...")
            try:
                unpacked_data = self.unpack_pe(packed_data)
                if unpacked_data:
                    output_path = os.path.join(output_dir, "unpacked.exe")
                    with open(output_path, 'wb') as f:
                        f.write(unpacked_data)

                    logger.info(f"✓ Successfully unpacked using PACKER_INFO method")
                    return True, f"Unpacked successfully using PACKER_INFO ({len(unpacked_data):,} bytes)"
            except Exception as e:
                logger.warning(f"PACKER_INFO unpacking failed: {e}")

            # Try section-based decompression for VMProtect sections
            vmprotect_sections = report['detection']['vmprotect_sections']
            if vmprotect_sections:
                logger.info(f"Attempting decompression of VMProtect sections: {vmprotect_sections}")
                result = self._unpack_vmprotect_sections(exe_path, packed_data, output_dir, vmprotect_sections)
                if result:
                    return result

            # Generate detailed unpacking guide based on report
            logger.info("Generating detailed unpacking guide based on analysis...")
            success, message = self._generate_unpacking_guide(exe_path, output_dir, report['detection'])
            return success, f"Advanced analysis completed. {message}"

        except Exception as e:
            logger.error(f"Error in high-confidence unpacking: {e}")
            return False, str(e)

    def _unpack_vmprotect_sections(self, exe_path: str, packed_data: bytes, output_dir: str, vmprotect_sections: list) -> Optional[Tuple[bool, str]]:
        """
        Attempt to decompress specific VMProtect sections
        """
        try:
            pe = pefile.PE(data=packed_data)

            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')

                if section_name in vmprotect_sections:
                    logger.info(f"Processing VMProtect section: {section_name}")

                    offset = section.PointerToRawData
                    size = section.SizeOfRawData

                    if offset > 0 and size > 0:
                        section_data = packed_data[offset:offset+size]

                        # Try LZMA decompression
                        blocks = self._extract_lzma_blocks_fast(section_data, max_blocks=5)

                        if blocks:
                            logger.info(f"Found {len(blocks)} LZMA blocks in {section_name}")

                            # Create output file
                            output_path = os.path.join(output_dir, f"decompressed_{section_name}.bin")

                            with open(output_path, 'wb') as f:
                                for block in blocks:
                                    f.write(block.get('decompressed', b''))

                            return True, f"Decompressed {len(blocks)} blocks from {section_name}"

            return None

        except Exception as e:
            logger.debug(f"Section decompression failed: {e}")
            return None

    def _unpack_basic_reconstruction(self, exe_path: str, output_dir: str) -> Tuple[bool, str]:
        """
        Basic PE reconstruction for non-VMProtect files
        """
        try:
            with open(exe_path, 'rb') as f:
                packed_data = f.read()

            logger.info(f"Performing basic PE reconstruction on {len(packed_data):,} byte file")

            # Use PACKER_INFO method (will just reconstruct without decompression)
            unpacked_data = self.unpack_pe(packed_data)

            if unpacked_data:
                output_path = os.path.join(output_dir, "reconstructed.exe")
                with open(output_path, 'wb') as f:
                    f.write(unpacked_data)

                logger.info(f"Basic reconstruction completed")
                return True, f"PE reconstructed successfully ({len(unpacked_data):,} bytes)"
            else:
                return False, "Basic reconstruction failed"

        except Exception as e:
            logger.error(f"Basic reconstruction error: {e}")
            return False, str(e)

    def display_report_summary(self, report_path: str) -> None:
        """
        Display a human-readable summary of the analysis report
        """
        report = self.load_analysis_report(report_path)
        if not report:
            print("Failed to load report")
            return

        print("\n" + "="*60)
        print("VMProtect Analysis Report Summary")
        print("="*60)

        detection = report['detection']
        print(f"File: {report['file']}")
        print(f"Size: {report['file_size']:,} bytes")
        print(f"VMProtect Confidence: {detection['confidence']}%")
        print(f"Is VMProtect: {detection['is_vmprotect']}")

        if detection['vmprotect_sections']:
            print(f"VMProtect Sections: {', '.join(detection['vmprotect_sections'])}")

        if detection['protection_features']:
            print(f"Protection Features: {', '.join(detection['protection_features'])}")

        print(f"Difficulty Level: {report['difficulty_level']}")
        print(f"Estimated Time: {report['estimated_time']}")

        print("\nUnpacking Recommendations:")
        for i, rec in enumerate(report['unpacking_recommendations'], 1):
            print(f"  {i}. {rec}")

        if report['required_tools']['required']:
            print("\nRequired Tools:")
            for tool, url in report['required_tools']['required'].items():
                print(f"  • {tool}: {url}")

        print("="*60)
    
    def _get_recommendations(self, detection: Dict) -> list:
        """Get unpacking recommendations"""
        recommendations = [
            "Use OllyDbg with Scylla plugin (recommended for beginners)",
            "Set breakpoints on memory allocation functions",
            "Monitor .vmp0 and .vmp1 sections",
            "Use PE-sieve for automated memory dumping",
            "Rebuild import table with Scylla after unpacking",
        ]
        
        if detection['is_vmprotect']:
            recommendations.insert(0, "This is definitely VMProtect - use appropriate tools")
        
        return recommendations
    
    def _get_required_tools(self) -> Dict:
        """Get required tools"""
        return {
            "required": {
                "OllyDbg": "http://www.ollydbg.de/",
                "Scylla": "https://github.com/NtQuerySystemInformation/Scylla"
            },
            "optional": {
                "IDA Pro": "Professional disassembly",
                "Ghidra": "Free reverse engineering",
                "PE-sieve": "Automatic memory dumping",
            }
        }
    
    def _assess_difficulty(self, detection: Dict) -> str:
        """Assess unpacking difficulty"""
        if detection['confidence'] > 80:
            return "MEDIUM - VMProtect virtualization requires debugging"
        elif detection['confidence'] > 50:
            return "MEDIUM - Likely VMProtect"
        else:
            return "EASY - Weak indicators"
    
    def _estimate_time(self, detection: Dict) -> str:
        """Estimate unpacking time"""
        if detection['confidence'] > 80:
            return "30 minutes to 2 hours with debugger"
        else:
            return "10-30 minutes with memory dumping"


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python vmprotect_unpacker.py <exe_path> <output_dir>")
        sys.exit(1)
    
    exe_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./vmprotect_output"
    
    unpacker = VMProtectUnpacker()
    report = unpacker.generate_analysis_report(exe_path, output_dir)
    
    print(f"\nVMProtect Analysis Report:")
    print(f"Confidence: {report['detection']['confidence']}%")
    print(f"Difficulty: {report['difficulty_level']}")
    print(f"Estimated Time: {report['estimated_time']}")
