# Crypter - Secure File Encryption Tool

A modern, easy-to-use desktop application for encrypting and decrypting files, built with Python.

## 🌟 Features

*   **Secure Encryption:** Uses industry-standard Fernet (AES) symmetric encryption.
*   **Key Management:** Generate new unique keys or load existing ones.
*   **Drag & Drop Simplicity:** (File selection via standard system dialogs).
*   **Modern UI:** Clean, light-themed interface built with `customtkinter`.
*   **Visual Feedback:** Clear status updates and logs for all operations.

## 🛠️ Installation

1.  **Prerequisites:** Ensure you have Python 3.x installed.
2.  **Clone/Download:** Download this project folder.
3.  **Install Dependencies:**
    Open a terminal in the project folder and run:
    ```bash
    pip install -r requirements.txt
    ```

## 🚀 How to Run

**Option 1: The Easy Way (Windows)**
Double-click the `run_app.bat` file in the project folder.

**Option 2: via Terminal**
```bash
python app.py
```

## 📖 Usage Guide

1.  **Generate a Key:** 
    *   Click "Generate Key".
    *   Save the `.key` file in a secure location. **Do not lose this file!** Without it, you cannot decrypt your files.
2.  **Encrypt a File:**
    *   Load your key (if not already loaded).
    *   Click "Select File to Process" and choose your target file.
    *   Click "ENCRYPT". A new file ending in `.enc` will be created.
3.  **Decrypt a File:**
    *   Load the **same key** used for encryption.
    *   Select the `.enc` file.
    *   Click "DECRYPT". The file will be restored to its original state.

## 🧑‍💻 Developer

*   Sergei Benjamin Tabanar

## 📦 Dependencies

*   `customtkinter`: For the modern GUI.
*   `cryptography`: For secure encryption primitives.

## ⚠️ Security Notice

This tool uses symmetric encryption. This means the **same key** is used for both locking and unlocking.
*   **Keep your key safe.** Anyone with the key can read your files.
*   **Do not lose your key.** If you lose it, your encrypted files are unrecoverable.