"""
Crypter - Secure File Encryption Application
============================================

This module serves as the main entry point for the Crypter application.
It utilizes `customtkinter` to provide a modern, user-friendly GUI for
encrypting and decrypting files using symmetric key encryption.

Classes:
    App: The main application class inheriting from ctk.CTk, handling the UI and user interactions.
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
from crypto_manager import CryptoManager

# Set theme to Light
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    """
    The main GUI application class for Crypter.
    
    Attributes:
        crypto_manager (CryptoManager): Handles the encryption and decryption logic.
        selected_file_path (str): Stores the path of the currently selected file.
    """
    def __init__(self):
        super().__init__()

        self.title("Crypter")
        self.geometry("500x650")
        self.resizable(False, False)
        self.crypto_manager = CryptoManager()
        self.selected_file_path = None

        # --- Layout Grid Config ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0) # Title
        self.grid_rowconfigure(1, weight=0) # Status / Key
        self.grid_rowconfigure(2, weight=0) # File
        self.grid_rowconfigure(3, weight=0) # Actions
        self.grid_rowconfigure(4, weight=1) # Logs

        # --- Title ---
        self.title_label = ctk.CTkLabel(self, text="Crypter", font=("Segoe UI", 36, "bold"), text_color="#2c3e50")
        self.title_label.grid(row=0, column=0, pady=(40, 5))

        self.subtitle_label = ctk.CTkLabel(self, text="Secure File Encryption", font=("Segoe UI", 16), text_color="#7f8c8d")
        self.subtitle_label.grid(row=1, column=0, pady=(0, 30))

        # --- Main Container ---
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=2, column=0, sticky="ew", padx=40)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        # Key Management
        self.btn_gen_key = ctk.CTkButton(self.main_frame, text="Generate Key", command=self.generate_key, height=40, fg_color="#bdc3c7", text_color="#2c3e50", hover_color="#95a5a6", font=("Segoe UI", 13, "bold"))
        self.btn_gen_key.grid(row=0, column=0, padx=(0, 10), pady=10, sticky="ew")

        self.btn_load_key = ctk.CTkButton(self.main_frame, text="Load Key", command=self.load_key, height=40, fg_color="#bdc3c7", text_color="#2c3e50", hover_color="#95a5a6", font=("Segoe UI", 13, "bold"))
        self.btn_load_key.grid(row=0, column=1, padx=(10, 0), pady=10, sticky="ew")

        self.lbl_key_status = ctk.CTkLabel(self.main_frame, text="Status: No Key Loaded", text_color="#e74c3c", font=("Segoe UI", 12, "bold"))
        self.lbl_key_status.grid(row=1, column=0, columnspan=2, pady=(5, 20))

        # File Selection
        self.btn_browse = ctk.CTkButton(self.main_frame, text="Select File to Process", command=self.browse_file, height=50, font=("Segoe UI", 15, "bold"), fg_color="#3498db", hover_color="#2980b9")
        self.btn_browse.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

        self.lbl_file_path = ctk.CTkLabel(self.main_frame, text="No file selected", text_color="#7f8c8d", wraplength=400)
        self.lbl_file_path.grid(row=3, column=0, columnspan=2, pady=(0, 25))

        # --- Action Buttons ---
        self.btn_encrypt = ctk.CTkButton(self.main_frame, text="ENCRYPT", command=self.encrypt, height=55, fg_color="#e74c3c", hover_color="#c0392b", state="disabled", font=("Segoe UI", 16, "bold"))
        self.btn_encrypt.grid(row=4, column=0, padx=(0, 10), pady=10, sticky="ew")

        self.btn_decrypt = ctk.CTkButton(self.main_frame, text="DECRYPT", command=self.decrypt, height=55, fg_color="#2ecc71", hover_color="#27ae60", state="disabled", font=("Segoe UI", 16, "bold"))
        self.btn_decrypt.grid(row=4, column=1, padx=(10, 0), pady=10, sticky="ew")

        # --- Log Box ---
        self.log_box = ctk.CTkTextbox(self, height=140, fg_color="#ecf0f1", text_color="#2c3e50", font=("Consolas", 12), border_width=1, border_color="#bdc3c7")
        self.log_box.grid(row=4, column=0, padx=40, pady=(20, 30), sticky="nsew")
        self.log_box.insert("0.0", "System Ready...\n")

    def log(self, message):
        """Appends a message to the log text box."""
        self.log_box.insert("end", ">> " + message + "\n")
        self.log_box.see("end")

    def update_action_buttons(self):
        """Enables or disables action buttons based on app state."""
        if self.crypto_manager.key and self.selected_file_path:
            self.btn_encrypt.configure(state="normal")
            self.btn_decrypt.configure(state="normal")
        else:
            self.btn_encrypt.configure(state="disabled")
            self.btn_decrypt.configure(state="disabled")

    def generate_key(self):
        """Generates a new encryption key and saves it to a user-selected path."""
        path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if path:
            try:
                self.crypto_manager.generate_key(path)
                self.lbl_key_status.configure(text=f"Key: {os.path.basename(path)}", text_color="#27ae60")
                self.log(f"Key generated at: {path}")
                self.update_action_buttons()
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def load_key(self):
        """Loads an existing encryption key from a user-selected file."""
        path = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
        if path:
            try:
                self.crypto_manager.load_key(path)
                self.lbl_key_status.configure(text=f"Key: {os.path.basename(path)}", text_color="#27ae60")
                self.log(f"Key loaded from: {path}")
                self.update_action_buttons()
            except Exception as e:
                self.lbl_key_status.configure(text="Error Loading Key", text_color="#e74c3c")
                messagebox.showerror("Error", f"Failed to load key: {e}")

    def browse_file(self):
        """Opens a file dialog for the user to select a file to process."""
        path = filedialog.askopenfilename()
        if path:
            self.selected_file_path = path
            self.lbl_file_path.configure(text=f"{os.path.basename(path)}")
            self.log(f"File selected: {path}")
            self.update_action_buttons()

    def encrypt(self):
        """Encrypts the selected file using the loaded key."""
        if not self.selected_file_path: return
        try:
            out_path = self.crypto_manager.encrypt_file(self.selected_file_path)
            self.log(f"ENCRYPTED: {os.path.basename(out_path)}")
            messagebox.showinfo("Success", "File Encrypted Successfully!")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Encryption Error", str(e))

    def decrypt(self):
        """Decrypts the selected file using the loaded key."""
        if not self.selected_file_path: return
        try:
            out_path = self.crypto_manager.decrypt_file(self.selected_file_path)
            self.log(f"DECRYPTED: {os.path.basename(out_path)}")
            messagebox.showinfo("Success", "File Decrypted Successfully!")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Decryption Error", str(e))

if __name__ == "__main__":
    app = App()
    app.mainloop()
