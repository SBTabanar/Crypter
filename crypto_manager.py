"""
Crypto Manager Module
=====================

This module handles the core cryptographic operations for the Crypter application.
It uses the `cryptography` library (Fernet) to generate keys and encrypt/decrypt file content.
"""

from cryptography.fernet import Fernet
import os

class CryptoManager:
    """
    Manages encryption keys and file processing.

    Attributes:
        key (bytes): The current symmetric encryption key.
        cipher (Fernet): The Fernet cipher instance initialized with the key.
    """
    def __init__(self):
        self.key = None
        self.cipher = None

    def generate_key(self, save_path="secret.key"):
        """
        Generates a new Fernet key and saves it to the specified file path.

        Args:
            save_path (str): The file path where the generated key will be saved.

        Returns:
            str: The path where the key was saved.
        """
        self.key = Fernet.generate_key()
        with open(save_path, "wb") as key_file:
            key_file.write(self.key)
        self.cipher = Fernet(self.key)
        return save_path

    def load_key(self, key_path):
        """
        Loads an existing Fernet key from the specified file path.

        Args:
            key_path (str): The path to the key file.

        Raises:
            FileNotFoundError: If the key file does not exist.
        """
        if not os.path.exists(key_path):
            raise FileNotFoundError("Key file not found.")
        
        with open(key_path, "rb") as key_file:
            self.key = key_file.read()
        self.cipher = Fernet(self.key)

    def encrypt_file(self, file_path):
        """
        Encrypts the specified file.

        Args:
            file_path (str): The path to the file to be encrypted.

        Returns:
            str: The path to the encrypted file (original filename + .enc).

        Raises:
            ValueError: If the encryption key has not been loaded.
        """
        if not self.cipher:
            raise ValueError("Key not loaded. Please load or generate a key first.")

        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_data = self.cipher.encrypt(file_data)

        # Output file name: example.txt -> example.txt.enc
        output_path = file_path + ".enc"
        
        with open(output_path, "wb") as file:
            file.write(encrypted_data)
        
        return output_path

    def decrypt_file(self, file_path):
        """
        Decrypts the specified file.

        Args:
            file_path (str): The path to the encrypted file.

        Returns:
            str: The path to the decrypted file.

        Raises:
            ValueError: If the key is not loaded or data is corrupted/invalid.
        """
        if not self.cipher:
            raise ValueError("Key not loaded. Please load or generate a key first.")

        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        try:
            decrypted_data = self.cipher.decrypt(encrypted_data)
        except Exception:
            raise ValueError("Invalid Key or Corrupted Data.")

        # Output file name: example.txt.enc -> example.txt
        # If it doesn't end with .enc, we just append .dec for safety
        if file_path.endswith(".enc"):
            output_path = file_path[:-4]
        else:
            output_path = file_path + ".dec"

        with open(output_path, "wb") as file:
            file.write(decrypted_data)
            
        return output_path
