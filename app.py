"""Crypter - Advanced Secure File Encryption Application."""

import customtkinter as ctk
from tkinterdnd2 import DND_FILES, TkinterDnD
from tkinter import filedialog, messagebox, StringVar
import os
import threading
from crypto_manager import CryptoManager

# Set theme
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

# Create a class that inherits from both CTk and TkinterDnD.Tk
class Tk(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)

class App(Tk):
    def __init__(self):
        super().__init__()

        self.title("Crypter Pro")
        self.geometry("600x750")
        self.resizable(False, False)
        self.crypto_manager = CryptoManager()
        self.selected_path = None
        self.is_processing = False

        # --- Layout Grid Config ---
        self.grid_columnconfigure(0, weight=1)
        
        # --- Header ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, pady=(30, 20))
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="Crypter Pro", font=("Segoe UI", 32, "bold"), text_color="#2c3e50")
        self.title_label.pack()
        self.developer_label = ctk.CTkLabel(self.header_frame, text="by: SBTabanar", font=("Segoe UI", 12), text_color="#7f8c8d")
        self.developer_label.pack()
        self.subtitle_label = ctk.CTkLabel(self.header_frame, text="Password Protected Encryption", font=("Segoe UI", 14), text_color="#7f8c8d")
        self.subtitle_label.pack()

        # --- Main Container ---
        self.main_frame = ctk.CTkFrame(self, fg_color="white", corner_radius=15)
        self.main_frame.grid(row=1, column=0, sticky="nsew", padx=30, pady=10)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # 1. Target Selection (Drag & Drop Area)
        self.lbl_target_title = ctk.CTkLabel(self.main_frame, text="1. Select Target", font=("Segoe UI", 14, "bold"), text_color="#34495e")
        self.lbl_target_title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 5))

        self.drop_frame = ctk.CTkFrame(self.main_frame, fg_color="#ecf0f1", border_width=2, border_color="#bdc3c7", corner_radius=10)
        self.drop_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=5)
        self.drop_frame.grid_columnconfigure(0, weight=1)

        self.lbl_drop_icon = ctk.CTkLabel(self.drop_frame, text="📂", font=("Segoe UI", 40))
        self.lbl_drop_icon.grid(row=0, column=0, pady=(20, 5))
        
        self.lbl_drop_text = ctk.CTkLabel(self.drop_frame, text="Drag & Drop File or Folder Here", font=("Segoe UI", 14), text_color="#7f8c8d")
        self.lbl_drop_text.grid(row=1, column=0, pady=(0, 20))

        # Register Drag & Drop
        self.drop_frame.drop_target_register(DND_FILES)
        self.drop_frame.dnd_bind('<<Drop>>', self.on_drop)
        self.drop_frame.bind("<Button-1>", lambda e: self.browse_target()) # Click to browse
        self.lbl_drop_text.bind("<Button-1>", lambda e: self.browse_target())
        self.lbl_drop_icon.bind("<Button-1>", lambda e: self.browse_target())

        self.lbl_selected_path = ctk.CTkLabel(self.main_frame, text="No target selected", text_color="#95a5a6", wraplength=400, font=("Consolas", 11))
        self.lbl_selected_path.grid(row=2, column=0, pady=(5, 15))

        # 2. Security (Password)
        self.lbl_pass_title = ctk.CTkLabel(self.main_frame, text="2. Security", font=("Segoe UI", 14, "bold"), text_color="#34495e")
        self.lbl_pass_title.grid(row=3, column=0, sticky="w", padx=20, pady=(10, 5))

        self.entry_password = ctk.CTkEntry(self.main_frame, placeholder_text="Enter Encryption Password", show="*", height=40, font=("Segoe UI", 13))
        self.entry_password.grid(row=4, column=0, sticky="ew", padx=20, pady=5)

        self.chk_shred = ctk.CTkCheckBox(self.main_frame, text="Securely Shred Original Files (Encrypt Only)", font=("Segoe UI", 12), text_color="#e74c3c", hover_color="#c0392b", fg_color="#e74c3c")
        self.chk_shred.grid(row=5, column=0, sticky="w", padx=20, pady=(10, 20))

        # 3. Actions
        self.action_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.action_frame.grid(row=6, column=0, sticky="ew", padx=20, pady=20)
        self.action_frame.grid_columnconfigure(0, weight=1)
        self.action_frame.grid_columnconfigure(1, weight=1)

        self.btn_encrypt = ctk.CTkButton(self.action_frame, text="ENCRYPT", command=self.start_encrypt, height=50, fg_color="#e74c3c", hover_color="#c0392b", font=("Segoe UI", 14, "bold"))
        self.btn_encrypt.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.btn_decrypt = ctk.CTkButton(self.action_frame, text="DECRYPT", command=self.start_decrypt, height=50, fg_color="#27ae60", hover_color="#2ecc71", font=("Segoe UI", 14, "bold"))
        self.btn_decrypt.grid(row=0, column=1, padx=(10, 0), sticky="ew")

        # --- Footer (Logs & Progress) ---
        self.progress_bar = ctk.CTkProgressBar(self, height=10)
        self.progress_bar.grid(row=2, column=0, sticky="ew", padx=30, pady=(10, 5))
        self.progress_bar.set(0)

        self.log_box = ctk.CTkTextbox(self, height=100, fg_color="#ecf0f1", text_color="#2c3e50", font=("Consolas", 11))
        self.log_box.grid(row=3, column=0, sticky="nsew", padx=30, pady=(5, 20))
        self.log("System Ready. Drag files above.")

    def log(self, message):
        self.log_box.insert("end", ">> " + message + "\n")
        self.log_box.see("end")

    def on_drop(self, event):
        path = event.data
        # Handle curly braces that TkinterDnD sometimes adds for paths with spaces
        if path.startswith('{') and path.endswith('}'):
            path = path[1:-1]
        
        self.set_target(path)

    def browse_target(self):
        # We can't easily pick "File OR Folder" in one dialog on Windows.
        # We'll default to File, but add a way to pick folder?
        # For simplicity, let's ask the user via a small popup or just default to file.
        # Let's just use File Dialog for now as it's most common.
        path = filedialog.askopenfilename() 
        if not path:
             path = filedialog.askdirectory() # Fallback if they cancel file dialog maybe they wanted folder?
        
        if path:
            self.set_target(path)

    def set_target(self, path):
        self.selected_path = path
        self.lbl_selected_path.configure(text=path, text_color="#2c3e50")
        self.log(f"Selected: {os.path.basename(path)}")
        self.lbl_drop_text.configure(text="Target Selected!")
        self.drop_frame.configure(border_color="#3498db")

    def validate_inputs(self):
        if not self.selected_path:
            messagebox.showwarning("Input Error", "Please select a file or folder first.")
            return False
        if not self.entry_password.get():
            messagebox.showwarning("Input Error", "Please enter a password.")
            return False
        return True

    def lock_ui(self, processing=True):
        state = "disabled" if processing else "normal"
        self.btn_encrypt.configure(state=state)
        self.btn_decrypt.configure(state=state)
        self.entry_password.configure(state=state)
        self.is_processing = processing
        if processing:
            self.progress_bar.start()
        else:
            self.progress_bar.stop()
            self.progress_bar.set(0)

    def start_encrypt(self):
        if not self.validate_inputs(): return
        if self.is_processing: return
        
        # Confirm Shredding
        shred = self.chk_shred.get()
        if shred:
            confirm = messagebox.askyesno("Confirm Shredding", "You chose to securely delete the original files.\nThis cannot be undone.\n\nAre you sure?")
            if not confirm: return

        self.lock_ui(True)
        threading.Thread(target=self.run_process, args=("encrypt", shred), daemon=True).start()

    def start_decrypt(self):
        if not self.validate_inputs(): return
        if self.is_processing: return
        
        self.lock_ui(True)
        threading.Thread(target=self.run_process, args=("decrypt", False), daemon=True).start()

    def run_process(self, mode, shred):
        password = self.entry_password.get()
        target = self.selected_path
        
        def progress_update(filename, msg):
            self.log(f"[{mode.upper()}] {filename}")

        try:
            success, total = self.crypto_manager.process_target(
                target, password, mode, shred, progress_callback=progress_update
            )
            self.log(f"\nCompleted: {success}/{total} files processed successfully.")
            messagebox.showinfo("Done", f"{mode.title()}ion Complete!\nProcessed {success}/{total} files.")
        except Exception as e:
            self.log(f"CRITICAL ERROR: {str(e)}")
            messagebox.showerror("Error", str(e))
        finally:
            self.lock_ui(False)

if __name__ == "__main__":
    app = App()
    app.mainloop()