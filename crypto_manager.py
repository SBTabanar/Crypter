"""
Crypto Manager Module
=====================

This module handles advanced cryptographic operations for the Crypter application.
It implements:
- Password-Based Encryption (PBKDF2HMAC) with automatic salt handling.
- Folder recursion for bulk processing.
- Secure file deletion (shredding).
- Callback support for progress tracking.
"""

import os
import secrets
import shutil
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoManager:
    """
    Manages encryption keys derived from passwords and file processing.
    """
    def __init__(self):
        self.chunk_size = 64 * 1024  # 64KB chunks for file reading

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a URL-safe base64-encoded key from a password and salt using PBKDF2HMAC.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_file(self, file_path, password, shred_original=False):
        """
        Encrypts a file using a password.
        Prepends a random 16-byte salt to the output file.
        """
        salt = secrets.token_bytes(16)
        key = self.derive_key(password, salt)
        fernet = Fernet(key)

        output_path = file_path + ".enc"
        
        with open(file_path, "rb") as f_in, open(output_path, "wb") as f_out:
            # Write the salt first
            f_out.write(salt)
            # Read and encrypt file content
            file_data = f_in.read()
            encrypted_data = fernet.encrypt(file_data)
            f_out.write(encrypted_data)

        if shred_original:
            self.secure_delete(file_path)

        return output_path

    def decrypt_file(self, file_path, password):
        """
        Decrypts a file using a password.
        Reads the salt from the first 16 bytes of the file.
        """
        with open(file_path, "rb") as f_in:
            salt = f_in.read(16)  # Read the salt
            if len(salt) != 16:
                raise ValueError("Invalid encrypted file format (missing salt).")
            
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            
            encrypted_data = f_in.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except Exception:
                raise ValueError("Decryption failed. Wrong password or corrupted file.")

        # Determine output path
        if file_path.endswith(".enc"):
            output_path = file_path[:-4]
        else:
            output_path = file_path + ".dec"

        with open(output_path, "wb") as f_out:
            f_out.write(decrypted_data)

        return output_path

    def process_target(self, target_path, password, mode="encrypt", shred_original=False, progress_callback=None):
        """
        Unified entry point to process a file or a folder recursively.
        
        Args:
            target_path (str): Path to file or folder.
            password (str): User password.
            mode (str): "encrypt" or "decrypt".
            shred_original (bool): Whether to securely delete original files (encrypt mode only).
            progress_callback (func): Function accepting (current_file_name, status_msg).
        """
        targets = []
        if os.path.isfile(target_path):
            targets.append(target_path)
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    # Skip already processed files to avoid loops if writing to same dir
                    if mode == "encrypt" and file.endswith(".enc"):
                        continue 
                    if mode == "decrypt" and not file.endswith(".enc"):
                        continue
                    targets.append(full_path)
        
        success_count = 0
        total = len(targets)
        
        for index, file_path in enumerate(targets):
            filename = os.path.basename(file_path)
            try:
                if progress_callback:
                    progress_callback(filename, f"Processing {index+1}/{total}")

                if mode == "encrypt":
                    self.encrypt_file(file_path, password, shred_original)
                else:
                    self.decrypt_file(file_path, password)
                
                success_count += 1
            except Exception as e:
                print(f"Failed to process {file_path}: {e}")
                # We continue processing other files even if one fails
        
        return success_count, total

    def secure_delete(self, file_path, passes=3):
        """
        Overwrites a file with random data multiple times before deleting it.
        """
        if not os.path.exists(file_path):
            return

        length = os.path.getsize(file_path)
        
        with open(file_path, "wb") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(length))
                f.flush()
                os.fsync(f.fileno())
        
        os.remove(file_path)