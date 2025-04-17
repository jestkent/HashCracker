import hashlib
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from typing import Optional, Dict, Any
import customtkinter as ctk  # You'll need to install this: pip install customtkinter

# Set appearance mode and default color theme
ctk.set_appearance_mode("System")  # Options: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

class HashCrackerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("Hash Cracker")
        self.geometry("900x600")
        self.minsize(800, 500)
        
        # Initialize variables
        self.wordlist_path = tk.StringVar(value="")
        self.hash_value = tk.StringVar(value="")
        self.algorithm = tk.StringVar(value="sha256")
        self.cracking_in_progress = False
        self.cancel_flag = False
        
        # Create UI elements
        self._create_widgets()
        self._create_layout()
        
    def _create_widgets(self):
        # Header frame
        self.header_frame = ctk.CTkFrame(self)
        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="🔐 Hash Cracker", 
            font=ctk.CTkFont(size=28, weight="bold")
        )
        self.subtitle_label = ctk.CTkLabel(
            self.header_frame,
            text="Crack password hashes using dictionary attack",
            font=ctk.CTkFont(size=14)
        )
        
        # Input frame
        self.input_frame = ctk.CTkFrame(self)
        
        # Hash input
        self.hash_label = ctk.CTkLabel(
            self.input_frame, 
            text="Hash to crack:", 
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.hash_entry = ctk.CTkEntry(
            self.input_frame, 
            textvariable=self.hash_value,
            placeholder_text="Enter hash value here...", 
            width=400,
            height=35
        )
        
        # Algorithm selection
        self.algo_label = ctk.CTkLabel(
            self.input_frame, 
            text="Algorithm:", 
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.algo_menu = ctk.CTkOptionMenu(
            self.input_frame,
            values=["md5", "sha1", "sha256", "sha512"],
            variable=self.algorithm,
            width=120,
            height=35
        )
        
        # Wordlist selection
        self.wordlist_label = ctk.CTkLabel(
            self.input_frame, 
            text="Wordlist:", 
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.wordlist_entry = ctk.CTkEntry(
            self.input_frame, 
            textvariable=self.wordlist_path,
            placeholder_text="Select wordlist file...", 
            width=300,
            height=35
        )
        self.browse_button = ctk.CTkButton(
            self.input_frame, 
            text="Browse", 
            command=self.browse_wordlist,
            width=80,
            height=35
        )
        
        # Action buttons frame
        self.button_frame = ctk.CTkFrame(self.input_frame)
        
        # Buttons
        self.crack_button = ctk.CTkButton(
            self.button_frame, 
            text="Start Cracking", 
            command=self.start_cracking,
            width=150,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.cancel_button = ctk.CTkButton(
            self.button_frame, 
            text="Cancel", 
            command=self.cancel_cracking,
            width=120,
            height=40,
            state="disabled",
            fg_color="#FF5252",
            hover_color="#FF1A1A"
        )
        self.generate_button = ctk.CTkButton(
            self.button_frame, 
            text="Generate Hash", 
            command=self.generate_hash,
            width=120,
            height=40
        )
        
        # Output frame
        self.output_frame = ctk.CTkFrame(self)
        
        # Progress bar
        self.progress_frame = ctk.CTkFrame(self.output_frame)
        self.progress_label = ctk.CTkLabel(
            self.progress_frame,
            text="Progress:",
            font=ctk.CTkFont(size=12)
        )
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame,
            width=680,
            mode="indeterminate"
        )
        self.progress_bar.set(0)
        self.progress_info = ctk.CTkLabel(
            self.progress_frame,
            text="Ready",
            font=ctk.CTkFont(size=12)
        )
        
        # Results
        self.result_label = ctk.CTkLabel(
            self.output_frame,
            text="Results:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.output_text = scrolledtext.ScrolledText(
            self.output_frame,
            wrap=tk.WORD,
            height=12,
            font=("Consolas", 11)
        )
        self.output_text.configure(bg="#F0F0F0" if ctk.get_appearance_mode() == "Light" else "#2B2B2B")
        self.output_text.tag_config('success', foreground='green')
        self.output_text.tag_config('error', foreground='red')
        self.output_text.tag_config('info', foreground='blue')
        
        # Status bar
        self.status_bar = ctk.CTkLabel(
            self,
            text="Ready",
            anchor="w",
            font=ctk.CTkFont(size=12)
        )
    
    def _create_layout(self):
        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # Place header
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        self.header_frame.grid_columnconfigure(0, weight=1)
        self.title_label.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        self.subtitle_label.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 10))
        
        # Place input frame
        self.input_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        self.input_frame.grid_columnconfigure(1, weight=1)
        
        # Hash input
        self.hash_label.grid(row=0, column=0, sticky="w", padx=10, pady=(15, 5))
        self.hash_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=(15, 5))
        
        # Algorithm selection
        self.algo_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.algo_menu.grid(row=1, column=1, sticky="w", padx=10, pady=5)
        
        # Wordlist selection
        self.wordlist_label.grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.wordlist_entry.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=5)
        self.browse_button.grid(row=2, column=2, sticky="w", padx=(5, 10), pady=5)
        
        # Action buttons
        self.button_frame.grid(row=3, column=0, columnspan=3, sticky="ew", padx=10, pady=(15, 10))
        self.button_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self.crack_button.grid(row=0, column=0, padx=10, pady=10)
        self.cancel_button.grid(row=0, column=1, padx=10, pady=10)
        self.generate_button.grid(row=0, column=2, padx=10, pady=10)
        
        # Output frame
        self.output_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)
        self.output_frame.grid_columnconfigure(0, weight=1)
        self.output_frame.grid_rowconfigure(2, weight=1)
        
        # Progress bar
        self.progress_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        self.progress_frame.grid_columnconfigure(1, weight=1)
        self.progress_label.grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.progress_bar.grid(row=0, column=1, sticky="ew", padx=10)
        self.progress_info.grid(row=0, column=2, sticky="e", padx=(10, 0))
        
        # Results
        self.result_label.grid(row=1, column=0, sticky="w", padx=10, pady=(15, 5))
        self.output_text.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        # Status bar
        self.status_bar.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 5))
    
    def browse_wordlist(self):
        """Open file dialog to select wordlist file"""
        filename = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.wordlist_path.set(filename)
            self.update_status(f"Wordlist selected: {os.path.basename(filename)}")
    
    def calculate_hash(self, text: str, algorithm: str) -> str:
        """Calculate hash of input text using specified algorithm"""
        text_bytes = text.encode('utf-8')
        
        if algorithm.lower() == 'md5':
            return hashlib.md5(text_bytes).hexdigest()
        elif algorithm.lower() == 'sha1':
            return hashlib.sha1(text_bytes).hexdigest()
        elif algorithm.lower() == 'sha256':
            return hashlib.sha256(text_bytes).hexdigest()
        elif algorithm.lower() == 'sha512':
            return hashlib.sha512(text_bytes).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    def generate_hash(self):
        """Generate a hash from text input"""
        # Ask for password to hash
        password_window = ctk.CTkInputDialog(
            text="Enter the password to hash:", 
            title="Generate Hash"
        )
        password = password_window.get_input()
        
        if password:
            algorithm = self.algorithm.get()
            try:
                hash_value = self.calculate_hash(password, algorithm)
                # Set the hash value in the entry field
                self.hash_value.set(hash_value)
                
                # Show in output
                self.clear_output()
                self.update_output(f"Generated {algorithm.upper()} hash for password: '{password}'", 'info')
                self.update_output(f"Hash: {hash_value}", 'success')
                self.update_status(f"Generated {algorithm.upper()} hash successfully")
            except Exception as e:
                self.update_output(f"Error generating hash: {str(e)}", 'error')
    
    def update_status(self, message):
        """Update the status bar message"""
        self.status_bar.configure(text=message)
    
    def update_output(self, message, tag=None):
        """Add message to output text area with optional tag"""
        self.output_text.configure(state='normal')
        if tag:
            self.output_text.insert(tk.END, message + "\n", tag)
        else:
            self.output_text.insert(tk.END, message + "\n")
        self.output_text.configure(state='disabled')
        self.output_text.see(tk.END)
    
    def clear_output(self):
        """Clear the output text area"""
        self.output_text.configure(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state='disabled')
    
    def update_progress(self, current, total=None):
        """Update progress information"""
        if total:
            percentage = (current / total) * 100
            self.progress_info.configure(text=f"{current} of {total} ({percentage:.1f}%)")
        else:
            self.progress_info.configure(text=f"Tried {current} passwords...")
    
    def reset_ui(self):
        """Reset UI to initial state"""
        self.crack_button.configure(state="normal")
        self.generate_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self.progress_bar.stop()
        self.progress_bar.set(0)
        self.progress_info.configure(text="Ready")
        self.cracking_in_progress = False
        self.cancel_flag = False
    
    def start_cracking(self):
        """Start the hash cracking process"""
        # Validate inputs
        hash_value = self.hash_value.get().strip()
        wordlist = self.wordlist_path.get().strip()
        algorithm = self.algorithm.get()
        
        if not hash_value:
            messagebox.showerror("Error", "Please enter a hash value to crack")
            return
        
        if not wordlist:
            messagebox.showerror("Error", "Please select a wordlist file")
            return
            
        if not os.path.isfile(wordlist):
            messagebox.showerror("Error", f"Wordlist file not found: {wordlist}")
            return
        
        # Update UI
        self.crack_button.configure(state="disabled")
        self.generate_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.clear_output()
        self.update_status("Cracking in progress...")
        
        # Start progress bar animation
        self.progress_bar.start()
        self.cracking_in_progress = True
        
        # Start cracking in a separate thread
        threading.Thread(target=self.crack_hash_thread, 
                        args=(hash_value, wordlist, algorithm)).start()
    
    def cancel_cracking(self):
        """Cancel ongoing cracking process"""
        if self.cracking_in_progress:
            self.cancel_flag = True
            self.update_status("Cancelling operation...")
            self.cancel_button.configure(state="disabled")
    
    def crack_hash_thread(self, target_hash: str, wordlist_path: str, algorithm: str):
        """
        Thread function to crack a hash using a dictionary attack.
        """
        try:
            # Show cracking parameters
            self.update_output(f"[+] Starting dictionary attack...", 'info')
            self.update_output(f"[+] Target hash: {target_hash}")
            self.update_output(f"[+] Algorithm: {algorithm.upper()}")
            self.update_output(f"[+] Wordlist: {wordlist_path}")
            self.update_output(f"[+] Cracking in progress...\n")
            
            # Count total words (if possible without consuming too much memory)
            total_words = 0
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for _ in f:
                        total_words += 1
            except:
                total_words = None
            
            # Start cracking
            result = None
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
                for line_num, word in enumerate(wordlist, 1):
                    if self.cancel_flag:
                        break
                        
                    password = word.strip()
                    if not password:  # Skip empty lines
                        continue
                        
                    current_hash = self.calculate_hash(password, algorithm)
                    
                    if line_num % 1000 == 0 or line_num == 1:
                        self.update_progress(line_num, total_words)
                    
                    if current_hash == target_hash:
                        result = password
                        break
            
            # Display result
            if self.cancel_flag:
                self.update_output("\n[CANCELLED] Operation was cancelled by user", 'info')
            elif result:
                self.update_output(f"\n[SUCCESS] Password found: {result}", 'success')
            else:
                self.update_output("\n[FAILED] Password not found in wordlist", 'error')
                self.update_output("Try using a different or larger wordlist")
            
            self.update_status("Operation completed")
            
        except Exception as e:
            self.update_output(f"\n[ERROR] {str(e)}", 'error')
            self.update_status("Error occurred")
        finally:
            # Reset UI in main thread
            self.after(0, self.reset_ui)


if __name__ == "__main__":
    # Check if customtkinter is installed
    try:
        import customtkinter
    except ImportError:
        root = tk.Tk()
        root.withdraw()
        if messagebox.askyesno(
            "Missing Dependency", 
            "This application requires 'customtkinter' package for the modern UI.\n\n"
            "Would you like to install it now? (requires internet connection)"
        ):
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"])
            messagebox.showinfo(
                "Installation Complete", 
                "Installation completed. The application will now start."
            )
        else:
            messagebox.showinfo(
                "Installation Required", 
                "Please install the required package manually using:\n"
                "pip install customtkinter"
            )
            sys.exit(1)
    
    # Start the application
    app = HashCrackerApp()
    app.mainloop()