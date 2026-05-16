"""
EXE Unpacker GUI Application
Easy-to-use interface for unpacking .NET and C++ executables
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import scrolledtext
import os
import threading
import json
from pathlib import Path
from datetime import datetime

from src.dotnet_unpacker import DotNETUnpacker
from src.cpp_unpacker import CPPUnpacker
from src.decryptor import DecryptionManager, ProtectionDetector
from src.themida_unpacker import ThemidaUnpacker
from src.vmprotect_unpacker import VMProtectUnpacker


class UnpackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EXE Unpacker - .NET & C++ Tool")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Set style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Initialize unpackers
        self.dotnet_unpacker = DotNETUnpacker()
        self.cpp_unpacker = CPPUnpacker()
        self.decryption_manager = DecryptionManager()
        
        self.selected_file = None
        self.current_output_dir = None
        
        self.setup_ui()
        self.add_log("Application started")
    
    def setup_ui(self):
        """Setup the user interface"""
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # === File Selection Section ===
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_frame, text="Select EXE:").grid(row=0, column=0, sticky=tk.W)
        self.file_label = ttk.Label(file_frame, text="No file selected", foreground="gray")
        self.file_label.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 10))
        
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5)
        
        # === File Info Section ===
        info_frame = ttk.LabelFrame(main_frame, text="Binary Information", padding="10")
        info_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        info_frame.columnconfigure(0, weight=1)
        
        self.info_text = scrolledtext.ScrolledText(info_frame, height=6, width=80, state=tk.DISABLED)
        self.info_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # === Actions Section ===
        actions_frame = ttk.LabelFrame(main_frame, text="Unpacking Actions", padding="10")
        actions_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # .NET Actions
        dotnet_label = ttk.Label(actions_frame, text=".NET Executables:")
        dotnet_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        dotnet_btn_frame = ttk.Frame(actions_frame)
        dotnet_btn_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=(20, 0), pady=(0, 10))
        
        ttk.Button(dotnet_btn_frame, text="Analyze .NET Assembly", 
                   command=lambda: self.analyze_dotnet()).pack(side=tk.LEFT, padx=5)
        ttk.Button(dotnet_btn_frame, text="Extract Metadata", 
                   command=lambda: self.extract_dotnet_metadata()).pack(side=tk.LEFT, padx=5)
        ttk.Button(dotnet_btn_frame, text="Extract Resources", 
                   command=lambda: self.extract_dotnet_resources()).pack(side=tk.LEFT, padx=5)
        ttk.Button(dotnet_btn_frame, text="🔍 Decompile to C#", 
                   command=lambda: self.decompile_dotnet()).pack(side=tk.LEFT, padx=5)
        
        # C++ Actions
        cpp_label = ttk.Label(actions_frame, text="C++ Executables:")
        cpp_label.grid(row=2, column=0, sticky=tk.W, pady=(10, 5))
        
        cpp_btn_frame = ttk.Frame(actions_frame)
        cpp_btn_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), padx=(20, 0))
        
        ttk.Button(cpp_btn_frame, text="Get Binary Info", 
                   command=lambda: self.get_cpp_info()).pack(side=tk.LEFT, padx=5)
        ttk.Button(cpp_btn_frame, text="Extract Strings", 
                   command=lambda: self.extract_cpp_strings()).pack(side=tk.LEFT, padx=5)
        ttk.Button(cpp_btn_frame, text="Create Analysis Report", 
                   command=lambda: self.create_cpp_report()).pack(side=tk.LEFT, padx=5)
        ttk.Button(cpp_btn_frame, text="🔍 Disassemble", 
                   command=lambda: self.disassemble_cpp()).pack(side=tk.LEFT, padx=5)
        
        # Decryption Actions
        decrypt_label = ttk.Label(actions_frame, text="Decryption & Protection Removal:")
        decrypt_label.grid(row=4, column=0, sticky=tk.W, pady=(10, 5))
        
        decrypt_btn_frame = ttk.Frame(actions_frame)
        decrypt_btn_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), padx=(20, 0))
        
        ttk.Button(decrypt_btn_frame, text="🔐 Detect Protections", 
                   command=lambda: self.detect_protections()).pack(side=tk.LEFT, padx=5)
        ttk.Button(decrypt_btn_frame, text="🔓 Decrypt/Unpack", 
                   command=lambda: self.decrypt_executable()).pack(side=tk.LEFT, padx=5)
        ttk.Button(decrypt_btn_frame, text="⚔️ Themida Unpack", 
                   command=lambda: self.unpack_themida()).pack(side=tk.LEFT, padx=5)
        ttk.Button(decrypt_btn_frame, text="�️ VMProtect Unpack", 
                   command=lambda: self.unpack_vmprotect()).pack(side=tk.LEFT, padx=5)
        ttk.Button(decrypt_btn_frame, text="�📋 Full Analysis", 
                   command=lambda: self.full_decryption_analysis()).pack(side=tk.LEFT, padx=5)
        
        # === Log Section ===
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=6, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=80, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # === Bottom Buttons ===
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=7, column=0, sticky=(tk.W, tk.E))
        
        ttk.Button(bottom_frame, text="Open Output Folder", 
                   command=self.open_output_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom_frame, text="Clear Log", 
                   command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom_frame, text="Exit", 
                   command=self.root.quit).pack(side=tk.RIGHT, padx=5)
    
    def browse_file(self):
        """Browse for an executable file"""
        file_path = filedialog.askopenfilename(
            title="Select an executable",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")]
        )
        
        if file_path:
            self.selected_file = file_path
            filename = os.path.basename(file_path)
            self.file_label.config(text=filename, foreground="black")
            self.add_log(f"Selected: {file_path}")
            
            # Create output directory
            output_name = Path(file_path).stem
            self.current_output_dir = os.path.join(
                os.path.dirname(__file__), "..", "output", output_name
            )
            os.makedirs(self.current_output_dir, exist_ok=True)
    
    def analyze_dotnet(self):
        """Analyze .NET assembly"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_analysis():
            try:
                self.add_log("Analyzing .NET assembly...")
                analysis = self.dotnet_unpacker.analyze_assembly(self.selected_file)
                
                self.display_info(analysis)
                
                # Save analysis
                report_path = os.path.join(self.current_output_dir, "dotnet_analysis.json")
                with open(report_path, 'w') as f:
                    json.dump(analysis, f, indent=2)
                
                self.add_log(f"✓ Analysis complete. Saved to {report_path}")
                messagebox.showinfo("Success", "Analysis complete!")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error analyzing assembly: {str(e)}")
        
        thread = threading.Thread(target=run_analysis, daemon=True)
        thread.start()
    
    def extract_dotnet_metadata(self):
        """Extract .NET metadata"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_extraction():
            try:
                self.add_log("Extracting .NET metadata...")
                metadata = self.dotnet_unpacker.extract_metadata(self.selected_file)
                
                self.display_info(metadata)
                
                # Save metadata
                report_path = os.path.join(self.current_output_dir, "dotnet_metadata.json")
                with open(report_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                self.add_log(f"✓ Metadata extracted. Saved to {report_path}")
                messagebox.showinfo("Success", "Metadata extraction complete!")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error extracting metadata: {str(e)}")
        
        thread = threading.Thread(target=run_extraction, daemon=True)
        thread.start()
    
    def extract_dotnet_resources(self):
        """Extract .NET resources"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_extraction():
            try:
                self.add_log("Extracting .NET resources...")
                resources_dir = os.path.join(self.current_output_dir, "resources")
                extracted = self.dotnet_unpacker.extract_resources(self.selected_file, resources_dir)
                
                self.add_log(f"✓ Extracted {len(extracted)} resources")
                for resource in extracted:
                    self.add_log(f"  - {os.path.basename(resource)}")
                
                messagebox.showinfo("Success", f"Extracted {len(extracted)} resources!")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error extracting resources: {str(e)}")
        
        thread = threading.Thread(target=run_extraction, daemon=True)
        thread.start()
    
    def decompile_dotnet(self):
        """Decompile .NET executable to C# source code"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_decompilation():
            try:
                self.add_log("🔍 Decompiling .NET assembly to C#...")
                decompiled_dir = os.path.join(self.current_output_dir, "decompiled_csharp")
                os.makedirs(decompiled_dir, exist_ok=True)
                
                success = self.dotnet_unpacker.decompile_to_csharp_ilspy(self.selected_file, decompiled_dir)
                
                if success:
                    self.add_log(f"✓ Decompilation complete!")
                    self.add_log(f"  Output: {decompiled_dir}")
                    messagebox.showinfo("Success", "C# source code decompiled successfully!")
                else:
                    self.add_log("⚠️ Decompilation completed with reflection method")
                    messagebox.showinfo("Success", "Source structure extracted via reflection!")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error decompiling: {str(e)}")
        
        thread = threading.Thread(target=run_decompilation, daemon=True)
        thread.start()
    
    def get_cpp_info(self):
        """Get C++ binary information"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_analysis():
            try:
                self.add_log("Analyzing C++ binary...")
                info = self.cpp_unpacker.get_binary_info(self.selected_file)
                
                self.display_info(info)
                
                # Save info
                report_path = os.path.join(self.current_output_dir, "cpp_binary_info.json")
                with open(report_path, 'w') as f:
                    json.dump(info, f, indent=2)
                
                self.add_log(f"✓ Binary analysis complete. Saved to {report_path}")
                messagebox.showinfo("Success", "Binary analysis complete!")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error analyzing binary: {str(e)}")
        
        thread = threading.Thread(target=run_analysis, daemon=True)
        thread.start()
    
    def extract_cpp_strings(self):
        """Extract strings from C++ binary"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_extraction():
            try:
                self.add_log("Extracting strings from binary...")
                strings_file = os.path.join(self.current_output_dir, "cpp_strings.txt")
                strings = self.cpp_unpacker.extract_strings(self.selected_file, strings_file)
                
                self.add_log(f"✓ Extracted {len(strings)} strings")
                self.add_log(f"Saved to: {strings_file}")
                
                messagebox.showinfo("Success", f"Extracted {len(strings)} strings!")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error extracting strings: {str(e)}")
        
        thread = threading.Thread(target=run_extraction, daemon=True)
        thread.start()
    
    def create_cpp_report(self):
        """Create comprehensive C++ analysis report"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_analysis():
            try:
                self.add_log("Creating comprehensive C++ analysis report...")
                report_path = self.cpp_unpacker.create_analysis_report(
                    self.selected_file, self.current_output_dir
                )
                
                self.add_log(f"✓ Report created: {report_path}")
                messagebox.showinfo("Success", "Analysis report created successfully!")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error creating report: {str(e)}")
        
        thread = threading.Thread(target=run_analysis, daemon=True)
        thread.start()
    
    def disassemble_cpp(self):
        """Disassemble C++ executable"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_disassembly():
            try:
                self.add_log("🔍 Disassembling C++ executable...")
                disasm_dir = os.path.join(self.current_output_dir, "disassembly")
                os.makedirs(disasm_dir, exist_ok=True)
                
                # Try radare2 first, then fallback to objdump
                success = False
                
                try:
                    self.add_log("  Attempting radare2 disassembly...")
                    success = self.cpp_unpacker.disassemble_with_radare2(self.selected_file, disasm_dir)
                except:
                    pass
                
                if not success:
                    self.add_log("  Attempting objdump disassembly...")
                    success = self.cpp_unpacker.disassemble_with_objdump(self.selected_file, disasm_dir)
                
                if success:
                    self.add_log(f"✓ Disassembly complete!")
                    self.add_log(f"  Assembly code saved to: {disasm_dir}")
                    messagebox.showinfo("Success", "Disassembly completed successfully!")
                else:
                    # Try generating pseudocode instead
                    self.add_log("⚠️ Generating pseudocode alternative...")
                    self.cpp_unpacker.generate_pseudocode(self.selected_file, disasm_dir)
                    self.add_log("✓ Pseudocode generated!")
                    messagebox.showinfo("Success", "Pseudocode generated (install radare2 or objdump for full disassembly)")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error disassembling: {str(e)}")
        
        thread = threading.Thread(target=run_disassembly, daemon=True)
        thread.start()
    
    def display_info(self, info_dict):
        """Display information in the info text area"""
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        
        if isinstance(info_dict, dict):
            formatted = json.dumps(info_dict, indent=2)
        else:
            formatted = str(info_dict)
        
        self.info_text.insert(tk.END, formatted)
        self.info_text.config(state=tk.DISABLED)
    
    def add_log(self, message):
        """Add message to log"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def clear_log(self):
        """Clear the log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def open_output_folder(self):
        """Open the output folder"""
        if self.current_output_dir and os.path.exists(self.current_output_dir):
            os.startfile(self.current_output_dir)
        else:
            messagebox.showinfo("Info", "Output folder not yet created. Process a file first.")
    
    def detect_protections(self):
        """Detect protections in the selected file"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_detection():
            try:
                self.add_log("🔐 Analyzing executable for protections...")
                detector = ProtectionDetector(self.selected_file)
                protections = detector.detect_protections()
                
                if not protections:
                    self.add_log("✓ No protections detected")
                    self.display_info({"status": "No protections detected", "file": os.path.basename(self.selected_file)})
                else:
                    self.add_log(f"✓ Found {len(protections)} protection(s):")
                    for protection, info in protections.items():
                        confidence = info.get('confidence', 'N/A')
                        self.add_log(f"  - {protection} (Confidence: {confidence}%)")
                    
                    self.display_info(protections)
                    
                    # Save to file
                    report_path = os.path.join(self.current_output_dir, "protections_detected.json")
                    with open(report_path, 'w') as f:
                        json.dump(protections, f, indent=2)
                    self.add_log(f"  Report saved to: {report_path}")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error detecting protections: {str(e)}")
        
        thread = threading.Thread(target=run_detection, daemon=True)
        thread.start()
    
    def decrypt_executable(self):
        """Decrypt or unpack the selected executable"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_decryption():
            try:
                self.add_log("🔓 Attempting to decrypt/unpack executable...")
                output_path = os.path.join(self.current_output_dir, "decrypted.exe")
                
                success, message = self.decryption_manager.decryptor.decrypt_executable(
                    self.selected_file, 
                    output_path,
                    method="auto"
                )
                
                if success:
                    self.add_log(f"✓ {message}")
                    self.add_log(f"  Decrypted file: {output_path}")
                    messagebox.showinfo("Success", message)
                else:
                    self.add_log(f"⚠️ {message}")
                    messagebox.showwarning("Incomplete", message)
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error during decryption: {str(e)}")
        
        thread = threading.Thread(target=run_decryption, daemon=True)
        thread.start()
    
    def full_decryption_analysis(self):
        """Perform full protection detection and decryption analysis"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_full_analysis():
            try:
                self.add_log("📋 Starting full decryption analysis...")
                decrypt_dir = os.path.join(self.current_output_dir, "decryption_analysis")
                os.makedirs(decrypt_dir, exist_ok=True)
                
                results = self.decryption_manager.analyze_and_decrypt(
                    self.selected_file,
                    decrypt_dir
                )
                
                self.add_log("✓ Analysis complete!")
                
                # Display results
                if results.get("protections"):
                    self.add_log("\n=== Protections Detected ===")
                    for protection, info in results["protections"].items():
                        self.add_log(f"  • {protection}")
                
                if results.get("recommendations"):
                    self.add_log("\n=== Recommendations ===")
                    for rec in results["recommendations"]:
                        self.add_log(f"  • {rec}")
                
                # Display info
                self.display_info(results)
                
                # Save report
                report_path = os.path.join(decrypt_dir, "decryption_analysis.json")
                with open(report_path, 'w') as f:
                    json.dump(results, f, indent=2)
                self.add_log(f"\nAnalysis saved to: {report_path}")
                
                messagebox.showinfo("Complete", "Full analysis completed! Check recommendations in the output.")
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error during analysis: {str(e)}")
        
        thread = threading.Thread(target=run_full_analysis, daemon=True)
        thread.start()
    
    def unpack_themida(self):
        """Unpack Themida-protected executable"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_themida_unpack():
            try:
                self.add_log("⚔️ Analyzing Themida protection...")
                themida_unpacker = ThemidaUnpacker()
                themida_dir = os.path.join(self.current_output_dir, "themida_unpack")
                os.makedirs(themida_dir, exist_ok=True)
                
                # Generate analysis report
                report = themida_unpacker.generate_analysis_report(self.selected_file, themida_dir)
                
                # Display results
                self.add_log(f"✓ Themida Analysis Complete")
                self.add_log(f"  Confidence: {report['detection']['confidence']}%")
                self.add_log(f"  Is Themida: {report['detection']['is_themida']}")
                self.add_log(f"  Difficulty: {report['difficulty_level']}")
                self.add_log(f"  Estimated Time: {report['estimated_time']}")
                
                if report['detection']['protection_features']:
                    self.add_log(f"\n  Protection Features:")
                    for feature in report['detection']['protection_features']:
                        self.add_log(f"    - {feature}")
                
                if report.get('unpacking_recommendations'):
                    self.add_log(f"\n  Unpacking Recommendations:")
                    for i, rec in enumerate(report['unpacking_recommendations'], 1):
                        self.add_log(f"    {i}. {rec}")
                
                # Display full report
                self.display_info(report)
                
                # Save detailed unpacking guide
                unpacking_guide_path = os.path.join(themida_dir, "THEMIDA_UNPACKING_GUIDE.md")
                self.add_log(f"\n📖 Unpacking guide: {unpacking_guide_path}")
                
                messagebox.showinfo(
                    "Themida Analysis",
                    f"Analysis complete!\n\n"
                    f"Difficulty: {report['difficulty_level']}\n"
                    f"Estimated Time: {report['estimated_time']}\n\n"
                    f"Check the output folder for detailed unpacking guide."
                )
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error analyzing Themida: {str(e)}")
        
        thread = threading.Thread(target=run_themida_unpack, daemon=True)
        thread.start()
    
    def unpack_vmprotect(self):
        """Unpack VMProtect-protected executable"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        def run_vmprotect_unpack():
            try:
                self.add_log("🛡️ Unpacking VMProtect protection...")
                vmprotect_unpacker = VMProtectUnpacker()
                vmprotect_dir = os.path.join(self.current_output_dir, "vmprotect_unpack")
                os.makedirs(vmprotect_dir, exist_ok=True)
                
                # Generate analysis report
                report = vmprotect_unpacker.generate_analysis_report(self.selected_file, vmprotect_dir)
                
                # Display results
                self.add_log(f"✓ VMProtect Analysis Complete")
                self.add_log(f"  Confidence: {report['detection']['confidence']}%")
                self.add_log(f"  Is VMProtect: {report['detection']['is_vmprotect']}")
                self.add_log(f"  Difficulty: {report['difficulty_level']}")
                
                if report['detection']['vmprotect_sections']:
                    self.add_log(f"\n  VMProtect Sections:")
                    for section in report['detection']['vmprotect_sections']:
                        self.add_log(f"    - {section}")
                
                if report['detection']['protection_features']:
                    self.add_log(f"\n  Protection Features:")
                    for feature in report['detection']['protection_features']:
                        self.add_log(f"    - {feature}")
                
                # Attempt to unpack the executable
                self.add_log("\n📦 Attempting to unpack executable...")
                decrypted_dir = os.path.join(self.current_output_dir, "decrypted_exe")
                os.makedirs(decrypted_dir, exist_ok=True)
                
                success, message = vmprotect_unpacker.unpack_executable(self.selected_file, decrypted_dir)
                
                if success:
                    self.add_log(f"✓ {message}")
                    
                    # Check for unpacked files
                    if os.path.exists(decrypted_dir):
                        files = os.listdir(decrypted_dir)
                        for file in files:
                            if file.endswith('.exe'):
                                self.add_log(f"  ✅ DECRYPTED EXE: {file}")
                else:
                    self.add_log(f"⚠️ Auto-unpack failed: {message}")
                    self.add_log("  Generating manual unpacking guide...")
                
                if report.get('unpacking_recommendations'):
                    self.add_log(f"\n  Unpacking Recommendations:")
                    for i, rec in enumerate(report['unpacking_recommendations'][:3], 1):
                        self.add_log(f"    {i}. {rec}")
                
                # Display full report
                self.display_info(report)
                
                # Save detailed unpacking guide
                unpacking_guide_path = os.path.join(vmprotect_dir, "VMPROTECT_UNPACKING_GUIDE.md")
                self.add_log(f"\n📖 Unpacking guide: {unpacking_guide_path}")
                
                messagebox.showinfo(
                    "VMProtect Analysis",
                    f"Analysis complete!\n\n"
                    f"Unpacked: {success}\n"
                    f"Difficulty: {report['difficulty_level']}\n"
                    f"Estimated Time: {report['estimated_time']}\n\n"
                    f"Check the output folder for decrypted EXE and guide."
                )
                
            except Exception as e:
                self.add_log(f"✗ Error: {str(e)}")
                messagebox.showerror("Error", f"Error analyzing VMProtect: {str(e)}")
        
        thread = threading.Thread(target=run_vmprotect_unpack, daemon=True)
        thread.start()
def main():
    root = tk.Tk()
    app = UnpackerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
