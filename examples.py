"""
CLI Examples - Command Line Usage of EXE Unpacker
These are Python scripts demonstrating programmatic usage
"""

# ============================================================================
# Example 1: Simple .NET Assembly Analysis
# Save as: examples/analyze_dotnet.py
# Run: python examples/analyze_dotnet.py
# ============================================================================

def example_1_dotnet_analysis():
    """
    Analyze a .NET executable and display assembly information
    """
    from src.dotnet_unpacker import DotNETUnpacker
    import json
    
    # Initialize unpacker
    unpacker = DotNETUnpacker()
    
    # Analyze assembly
    exe_path = input("Enter path to .NET executable: ").strip('"')
    
    print("\n🔍 Analyzing .NET assembly...")
    analysis = unpacker.analyze_assembly(exe_path)
    
    # Display results
    print("\n📊 Assembly Information:")
    print(json.dumps(analysis, indent=2))
    
    # Save report
    output_file = exe_path.replace('.exe', '_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f"\n✅ Report saved to: {output_file}")


# ============================================================================
# Example 2: Extract Resources from .NET
# Save as: examples/extract_dotnet_resources.py
# Run: python examples/extract_dotnet_resources.py
# ============================================================================

def example_2_extract_resources():
    """
    Extract embedded resources from .NET executable
    """
    from src.dotnet_unpacker import DotNETUnpacker
    import os
    
    unpacker = DotNETUnpacker()
    
    exe_path = input("Enter path to .NET executable: ").strip('"')
    output_dir = input("Enter output directory (default: ./resources): ").strip() or "./resources"
    
    print(f"\n📦 Extracting resources...")
    extracted = unpacker.extract_resources(exe_path, output_dir)
    
    print(f"\n✅ Extracted {len(extracted)} resources:")
    for resource in extracted:
        print(f"   - {os.path.basename(resource)}")
    
    print(f"\n📁 Resources saved to: {os.path.abspath(output_dir)}")


# ============================================================================
# Example 3: C++ Binary Information
# Save as: examples/analyze_cpp.py
# Run: python examples/analyze_cpp.py
# ============================================================================

def example_3_cpp_binary_info():
    """
    Get detailed binary information from C++ executable
    """
    from src.cpp_unpacker import CPPUnpacker
    import json
    
    unpacker = CPPUnpacker()
    
    exe_path = input("Enter path to C++ executable: ").strip('"')
    
    print("\n🔍 Analyzing C++ binary...")
    info = unpacker.get_binary_info(exe_path)
    
    # Display important info
    print("\n📊 Binary Information:")
    print(f"  File: {info['file_name']}")
    print(f"  Size: {info['file_size']:,} bytes")
    print(f"  Architecture: {info['architecture']}")
    print(f"  64-bit: {info['is_64bit']}")
    print(f"  Sections: {len(info['sections'])}")
    print(f"  Imports: {len(info['imports'])}")
    
    print("\n📄 Sections:")
    for section in info['sections']:
        print(f"  - {section['name']}: {section['size']:,} bytes")
    
    # Save full report
    output_file = exe_path.replace('.exe', '_binary_info.json')
    with open(output_file, 'w') as f:
        json.dump(info, f, indent=2)
    
    print(f"\n✅ Full report saved to: {output_file}")


# ============================================================================
# Example 4: Extract Strings
# Save as: examples/extract_strings.py
# Run: python examples/extract_strings.py
# ============================================================================

def example_4_extract_strings():
    """
    Extract all strings from a binary file
    """
    from src.cpp_unpacker import CPPUnpacker
    
    unpacker = CPPUnpacker()
    
    exe_path = input("Enter path to executable: ").strip('"')
    output_file = exe_path.replace('.exe', '_strings.txt')
    
    print("\n🔍 Extracting strings...")
    strings = unpacker.extract_strings(exe_path, output_file)
    
    print(f"\n✅ Extracted {len(strings)} strings")
    print(f"📁 Saved to: {output_file}")
    
    # Show sample
    print("\n📋 Sample strings:")
    for string in strings[:10]:
        if len(string) > 60:
            print(f"  - {string[:60]}...")
        else:
            print(f"  - {string}")


# ============================================================================
# Example 5: Batch Analysis
# Save as: examples/batch_analysis.py
# Run: python examples/batch_analysis.py <folder>
# ============================================================================

def example_5_batch_analysis():
    """
    Analyze all .exe files in a directory
    """
    from src.dotnet_unpacker import DotNETUnpacker
    from src.cpp_unpacker import CPPUnpacker
    import os
    import sys
    
    if len(sys.argv) < 2:
        folder = input("Enter folder containing .exe files: ").strip()
    else:
        folder = sys.argv[1]
    
    if not os.path.isdir(folder):
        print(f"❌ Folder not found: {folder}")
        return
    
    # Find all exe files
    exe_files = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.lower().endswith('.exe'):
                exe_files.append(os.path.join(root, file))
    
    print(f"\n🔍 Found {len(exe_files)} .exe files")
    
    dotnet_unpacker = DotNETUnpacker()
    cpp_unpacker = CPPUnpacker()
    
    results = {
        'dotnet': [],
        'cpp': [],
        'unknown': []
    }
    
    for exe_path in exe_files:
        print(f"\nAnalyzing: {exe_path}")
        
        try:
            # Try .NET first
            analysis = dotnet_unpacker.analyze_assembly(exe_path)
            if analysis and 'name' in analysis:
                print(f"  ✅ .NET: {analysis.get('name', 'Unknown')}")
                results['dotnet'].append(exe_path)
                continue
        except:
            pass
        
        try:
            # Try C++
            info = cpp_unpacker.get_binary_info(exe_path)
            if info['architecture'] != 'Unknown':
                print(f"  ✅ C++: {info['architecture']}")
                results['cpp'].append(exe_path)
                continue
        except:
            pass
        
        print(f"  ⚠️  Unknown type")
        results['unknown'].append(exe_path)
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Batch Analysis Summary")
    print("=" * 60)
    print(f".NET executables: {len(results['dotnet'])}")
    print(f"C++ executables: {len(results['cpp'])}")
    print(f"Unknown: {len(results['unknown'])}")


# ============================================================================
# Example 6: Create Comprehensive Report
# Save as: examples/create_report.py
# Run: python examples/create_report.py
# ============================================================================

def example_6_create_report():
    """
    Create a comprehensive analysis report
    """
    from src.dotnet_unpacker import DotNETUnpacker
    from src.cpp_unpacker import CPPUnpacker
    import json
    import os
    from datetime import datetime
    
    exe_path = input("Enter path to executable: ").strip('"')
    
    if not os.path.exists(exe_path):
        print(f"❌ File not found: {exe_path}")
        return
    
    output_dir = os.path.join(os.path.dirname(exe_path), 
                              f"{os.path.splitext(os.path.basename(exe_path))[0]}_report")
    os.makedirs(output_dir, exist_ok=True)
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'file_path': exe_path,
        'file_size': os.path.getsize(exe_path),
        'dotnet_analysis': None,
        'cpp_analysis': None,
    }
    
    print("\n📊 Creating comprehensive report...")
    
    # Try .NET analysis
    try:
        print("  - Analyzing .NET components...")
        dotnet_unpacker = DotNETUnpacker()
        report['dotnet_analysis'] = dotnet_unpacker.analyze_assembly(exe_path)
    except Exception as e:
        print(f"    (Not a .NET executable: {e})")
    
    # Try C++ analysis
    try:
        print("  - Analyzing C++ components...")
        cpp_unpacker = CPPUnpacker()
        cpp_info = cpp_unpacker.get_binary_info(exe_path)
        cpp_strings = cpp_unpacker.extract_strings(exe_path)
        report['cpp_analysis'] = {
            'binary_info': cpp_info,
            'strings_count': len(cpp_strings),
            'strings_sample': cpp_strings[:50]
        }
    except Exception as e:
        print(f"    (C++ analysis failed: {e})")
    
    # Save report
    report_path = os.path.join(output_dir, 'analysis_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Report saved to: {report_path}")
    print(f"📁 Output directory: {output_dir}")


# ============================================================================
# Main Menu
# ============================================================================

def main():
    """Main menu for choosing examples"""
    print("=" * 60)
    print("   EXE Unpacker - CLI Examples")
    print("=" * 60)
    print("\n1. Analyze .NET Assembly")
    print("2. Extract .NET Resources")
    print("3. Analyze C++ Binary")
    print("4. Extract Strings")
    print("5. Batch Analysis")
    print("6. Create Comprehensive Report")
    print("0. Exit")
    
    choice = input("\nSelect example (0-6): ").strip()
    
    examples = {
        '1': example_1_dotnet_analysis,
        '2': example_2_extract_resources,
        '3': example_3_cpp_binary_info,
        '4': example_4_extract_strings,
        '5': example_5_batch_analysis,
        '6': example_6_create_report,
    }
    
    if choice in examples:
        try:
            examples[choice]()
        except Exception as e:
            print(f"\n❌ Error: {e}")
    elif choice != '0':
        print("❌ Invalid choice")


if __name__ == "__main__":
    main()
