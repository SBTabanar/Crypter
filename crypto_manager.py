from cryptography.fernet import Fernet
import os

class CryptoManager:
    def __init__(self):
        self.key = None
        self.cipher = None

    def generate_key(self, save_path="secret.key"):
        """Generates a key and saves it into a file."""
        self.key = Fernet.generate_key()
        with open(save_path, "wb") as key_file:
            key_file.write(self.key)
        self.cipher = Fernet(self.key)
        return save_path

    def load_key(self, key_path):
        """Loads the key from the current directory."""
        if not os.path.exists(key_path):
            raise FileNotFoundError("Key file not found.")
        
        with open(key_path, "rb") as key_file:
            self.key = key_file.read()
        self.cipher = Fernet(self.key)

    def encrypt_file(self, file_path):
        """Encrypts a file."""
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
        """Decrypts a file."""
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
